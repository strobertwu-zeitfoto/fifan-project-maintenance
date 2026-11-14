"""Explicit same-volume directory archives, owned locators, and resumable recovery.

Journals are durable evidence, not cryptographic authorization. All mutations use
three runtime-authorized root locks and Darwin no-replace rename. External
writers must be paused; handle sampling and stat/hash checks cannot lock them.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import copy
import hashlib
import os
import json
import selectors
import time
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import uuid

from . import directory_common as common

DirectoryError = common.DirectoryError
PLAN = 'fifan-directory-plan'
JOURNAL = 'fifan-directory-journal'
RESTORE = 'fifan-directory-restore-plan'
KIND = 'directory-archive'


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino}


def _root_records(profile, archive, records):
    if common.digest(profile.data) != profile.sha256 or profile.budgets != profile.data['budgets']:
        raise DirectoryError('PROFILE_CONFLICT', 'directory profile changed after loading')
    roots = {name: {'path': str(root), **_identity(common.stat_entry(root, '.'))}
             for name, root in [('project', profile.root), ('archive', archive), ('records', records)]}
    common.validate_profile_root(profile)
    if len({item['device'] for item in roots.values()}) != 1:
        raise DirectoryError('CROSS_DEVICE', 'all archive roots must share one filesystem')
    return roots


@contextmanager
def _locks(profile, archive, records):
    with ExitStack() as stack:
        for root in sorted({profile.root, archive, records}, key=str):
            stack.enter_context(common.root_lock(root))
        yield


def _exists(root, rel):
    try:
        common.stat_entry(root, rel)
        return True
    except FileNotFoundError:
        return False


def _within(path, parent):
    path, parent = common.path_key(path), common.path_key(parent)
    return path == parent or path.startswith(parent + '/')


def _suffix(path, parent):
    if not _within(path, parent):
        raise DirectoryError('PROTECTED_PATH', 'path is outside its recorded batch')
    return '/'.join(path.split('/')[len(parent.split('/')):]) or '.'


def _allowed(profile, rel):
    common.relative(rel)
    if common.protected(profile, rel, archive=True):
        raise DirectoryError('PROTECTED_PATH', 'protected archive entry')
    for critical in profile.data['critical_paths']:
        if _within(rel, critical) or _within(critical, rel):
            raise DirectoryError('PROTECTED_PATH', 'archive overlaps a current critical path')


def _manifest(profile, base, rel, semantic, budget, *, hash_files=True):
    entries, files, total = [], 0, 0
    entry_keys = set()
    artifact_bytes = 0
    root_device = common.stat_entry(base, '.').st_dev
    def append(entry):
        nonlocal artifact_bytes
        key = common.path_key(entry['path'])
        if key in entry_keys:
            raise DirectoryError('PATH_ALIAS', 'manifest entries have equivalent path names')
        entry_keys.add(key)
        size = len(common.canonical(entry)) + 2
        if size > profile.budgets['max_artifact_bytes'] - artifact_bytes:
            raise DirectoryError('BUDGET_EXHAUSTED', 'manifest exceeds artifact byte limit')
        artifact_bytes += size
        entries.append(entry)
    def visit(path, suffix, depth):
        nonlocal files, total
        budget.check_time()
        if depth > profile.budgets['max_depth']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'manifest depth limit exhausted')
        _allowed(profile, semantic if suffix == '.' else semantic + '/' + suffix)
        budget.charge_entry()
        with common.open_dir(base, path) as fd:
            before = os.fstat(fd)
            if before.st_dev != root_device:
                raise DirectoryError('CROSS_DEVICE', 'manifest crosses a filesystem boundary')
            entry = {'path': suffix, 'kind': 'directory', 'mode': stat.S_IMODE(before.st_mode),
                     'mtime_ns': before.st_mtime_ns, **_identity(before)}
            append(entry)
            with os.scandir(fd) as children:
                for child in children:
                    budget.check_time()
                    child_suffix = child.name if suffix == '.' else suffix + '/' + child.name
                    child_path = path + '/' + child.name
                    _allowed(profile, semantic + '/' + child_suffix)
                    info = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                    if info.st_dev != root_device:
                        raise DirectoryError('CROSS_DEVICE', 'manifest entry crosses a filesystem boundary')
                    if stat.S_ISDIR(info.st_mode):
                        visit(child_path, child_suffix, depth + 1)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_nlink != 1:
                            raise DirectoryError('HARDLINK_UNSUPPORTED', 'shared hardlinks cannot be archived')
                        if hash_files:
                            item = common.stream_hash(profile, child_path, budget, root=base)
                            expected = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, stat.S_IMODE(info.st_mode))
                            if (item['device'], item['inode'], item['bytes'], item['mtime_ns'], item['mode']) != expected:
                                raise DirectoryError('SOURCE_CHANGED', 'manifest file changed before hashing')
                            item = {k: v for k, v in item.items() if k not in {'ctime_ns', 'path'}}
                        else:
                            budget.charge_entry()
                            item = {'kind': 'file', 'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
                                    'mtime_ns': info.st_mtime_ns, 'nlink': info.st_nlink, **_identity(info)}
                        item['path'] = child_suffix
                        append(item)
                        files += 1
                        total += info.st_size
                    else:
                        budget.charge_entry()
                        raise DirectoryError('ENTRY_UNSUPPORTED', 'links and special files cannot be archived')
            after = os.fstat(fd)
            named = common.stat_entry(base, path)
            stable = lambda st: (st.st_dev, st.st_ino, st.st_mtime_ns, stat.S_IMODE(st.st_mode))
            if stable(before) != stable(after) or stable(before) != stable(named):
                raise DirectoryError('SOURCE_CHANGED', 'directory changed during manifest enumeration')
    visit(rel, '.', 0)
    entries.sort(key=lambda item: item['path'])
    return {'entries': entries, 'file_count': files, 'directory_count': len(entries) - files,
            'file_bytes': total, 'attributes_verified': ['mode', 'mtime_ns'],
            'attributes_not_verified': ['ACL', 'xattr', 'physical_allocation']}


def _match_manifest(profile, base, rel, batch, budget, *, hashes=True):
    current = _manifest(profile, base, rel, batch['source'], budget, hash_files=hashes)
    expected = batch['manifest']
    if not hashes:
        expected = copy.deepcopy(expected)
        for item in expected['entries']:
            item.pop('sha256', None)
    if current != expected:
        raise DirectoryError('SOURCE_CHANGED', 'directory manifest no longer matches')


def _reserve_rounds(profile, batches):
    count = sum(len(b['manifest']['entries']) for b in batches)
    size = sum(b['manifest']['file_bytes'] for b in batches)
    if count * 2 > profile.budgets['max_hash_entries'] or size * 2 > profile.budgets['max_hash_bytes']:
        raise DirectoryError('BUDGET_EXHAUSTED', 'hash budget must cover preflight and post-move verification')


def _open_handles(profile, root, rel):
    executable = shutil.which('lsof')
    required = profile.data['archive']['require_no_open_handles']
    if executable is None:
        if required:
            raise DirectoryError('OPEN_HANDLES_CHECK_UNAVAILABLE', 'lsof is unavailable')
        return {'status': 'Unknown', 'reason_code': 'OPEN_HANDLES_CHECK_UNAVAILABLE', 'guarantee': 'sampling_only'}
    # PATH selects a tool, not permission to execute inspected material. Resolve
    # ordinary external tool symlinks once, and execute that canonical target.
    executable = common.canonical_destination(Path(executable).resolve(strict=True), allow_missing_parents=False)
    if any(executable == scope or executable.is_relative_to(scope) for scope in {common.safe_root(profile.root), common.safe_root(root)}):
        raise DirectoryError('PROTECTED_PATH', 'open-handle tool resolves inside inspected material')
    try:
        code, has_output, has_error = _sample_lsof(str(executable), root / rel, min(10, profile.budgets['max_seconds']))
    except (OSError, subprocess.TimeoutExpired):
        if required:
            raise DirectoryError('OPEN_HANDLES_CHECK_UNAVAILABLE', 'lsof sampling failed')
        return {'status': 'Unknown', 'reason_code': 'OPEN_HANDLES_CHECK_UNAVAILABLE', 'guarantee': 'sampling_only'}
    if has_output:
        raise DirectoryError('OPEN_HANDLES', 'candidate has an observed open handle')
    if code != 1 or has_error:
        if required:
            raise DirectoryError('OPEN_HANDLES_CHECK_UNAVAILABLE', 'lsof sampling was inconclusive')
        return {'status': 'Unknown', 'reason_code': 'OPEN_HANDLES_CHECK_UNAVAILABLE', 'guarantee': 'sampling_only'}
    return {'status': 'ClearSample', 'guarantee': 'sampling_only'}


def _impact(profile, request):
    from .directory_census import impact
    report = impact(profile, request)
    common.validate_seal(report)
    if report.get('unchecked_batches'):
        raise DirectoryError('BUDGET_EXHAUSTED', 'impact artifact budget cannot represent all requested batches')
    if report.get('status') != 'Passed' or len(report.get('batches', [])) != len(request['batches']):
        raise DirectoryError('IMPACT_NOT_ELIGIBLE', 'archive impact is incomplete or blocked')
    material = []
    for expected, batch in zip(request['batches'], report['batches']):
        if batch.get('source') != expected['source'] or batch.get('destination') != expected['destination'] or batch.get('eligible') is not True:
            raise DirectoryError('IMPACT_NOT_ELIGIBLE', 'archive batch is not eligible')
        material.append({key: value for key, value in batch.items() if key not in {'elapsed_seconds'}})
    if report.get('material_sha256') != common.digest(report.get('material')):
        raise DirectoryError('ARTIFACT_INVALID', 'impact material fingerprint is invalid')
    return report, report['material_sha256']


def _request(profile, request):
    if not isinstance(request, dict) or set(request) != {'schema_version', 'batches'} or request['schema_version'] != 1:
        raise DirectoryError('INVALID_INPUT', 'invalid directory archive request')
    batches = request['batches']
    if not isinstance(batches, list) or not 1 <= len(batches) <= 100:
        raise DirectoryError('INVALID_INPUT', 'expected 1..100 archive batches')
    sources, targets, source_identities = [], [], set()
    candidates = {common.path_key(path) for path in profile.data['archive']['candidates']}
    for batch in batches:
        if not isinstance(batch, dict) or set(batch) - {'source', 'destination', 'closure', 'historical_references', 'known_absent', 'dynamic_reference_resolutions'} or not {'source', 'destination', 'closure'} <= set(batch):
            raise DirectoryError('INVALID_INPUT', 'invalid archive batch')
        source, dest = common.relative(batch['source']), common.relative(batch['destination'])
        if common.path_key(source) not in candidates:
            raise DirectoryError('BODY_NOT_AUTHORIZED', 'candidate is not explicitly authorized')
        _allowed(profile, source)
        common.validate_path_spelling(profile.root, source, allow_missing=True)
        common.validate_path_spelling(Path(profile.data['archive']['archive_root']), dest, allow_missing=True)
        if common.protected(profile, dest, archive=True):
            raise DirectoryError('PROTECTED_PATH', 'protected archive destination')
        for collection, value in [(sources, source), (targets, dest)]:
            if any(_within(value, old) or _within(old, value) for old in collection):
                raise DirectoryError('MULTIPLE_WRITES', 'archive batches overlap')
            collection.append(value)
        try:
            info = common.stat_entry(profile.root, source)
        except FileNotFoundError:
            continue  # A bound archive/restore journal may legitimately lack it.
        identity = (info.st_dev, info.st_ino)
        if identity in source_identities:
            raise DirectoryError('MULTIPLE_WRITES', 'archive sources identify the same directory')
        source_identities.add(identity)
    return batches


def _locator_text(operation, batch, archive, journal, project_root):
    # The caller's profile file location is not part of the profile contract;
    # never guess it or silently create a second project configuration.
    return ('# Archived directory\n\nThis is a locator, not the original payload.\n'
            'Original scripts require an explicit restore before replay; their runtime was not tested.\n\n' +
            'Operation: ' + operation + '\nOriginal: ' + batch['source'] + '\nArchive: ' + str(archive / batch['destination']) +
            '\nManifest SHA256: ' + common.digest(batch['manifest']) + '\nJournal: ' + str(journal) +
            '\nRecovery command templates (replace DIRECTORY_PROFILE_JSON with the original authorized profile file):\n'
            'fifan-maintain directory restore-preview --project ' + shlex.quote(str(project_root)) + ' --profile DIRECTORY_PROFILE_JSON --journal ' + shlex.quote(str(journal)) +
            ' --archive-root ' + shlex.quote(str(archive)) + ' --plan ' + shlex.quote(str(journal.with_suffix('.restore-plan.json'))) + '\n'
            'fifan-maintain directory restore --project ' + shlex.quote(str(project_root)) + ' --profile DIRECTORY_PROFILE_JSON --plan ' + shlex.quote(str(journal.with_suffix('.restore-plan.json'))) +
            ' --archive-root ' + shlex.quote(str(archive)) + ' --records-dir ' + shlex.quote(str(journal.parent)) + '\n')


def archive_preview(profile, request, archive_root, records_dir):
    archive, records = common.external_roots(profile, archive_root, records_dir)
    raw = _request(profile, request)
    with _locks(profile, archive, records):
        roots = _root_records(profile, archive, records)
        report, material = _impact(profile, request)
        budget, batches = common.HashBudget(profile.budgets), []
        operation = uuid.uuid4().hex
        journal = records / (operation + '.directory.json')
        for batch in raw:
            if _exists(archive, batch['destination']):
                raise DirectoryError('DESTINATION_EXISTS', 'archive destination already exists')
            manifest = _manifest(profile, profile.root, batch['source'], batch['source'], budget)
            item = {'source': batch['source'], 'destination': batch['destination'], 'manifest': manifest,
                    'known_absent': copy.deepcopy(batch.get('known_absent', []))}
            item['open_handles'] = _open_handles(profile, profile.root, batch['source'])
            item['locator_text'] = _locator_text(operation, item, archive, journal, profile.root)
            item['locator_sha256'] = _sha(item['locator_text'].encode('utf-8'))
            batches.append(item)
        _reserve_rounds(profile, batches)
        plan = common.seal({'format': PLAN, 'schema_version': 1, 'kind': KIND, 'project_root': str(profile.root),
                            'profile_sha256': profile.sha256, 'config_sha256': common.digest(profile.config),
                            'request_sha256': common.digest(request), 'request': copy.deepcopy(request),
                            'operation_id': operation, 'roots': roots, 'batches': batches,
                            'impact': report, 'impact_material_sha256': material, 'hash_usage': budget.snapshot()})
        # Reserve progress/ownership receipt growth before any payload moves.
        if len(common.canonical(plan)) + len(batches) * 8192 + 8192 > profile.budgets['max_artifact_bytes']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'plan leaves insufficient journal capacity')
        return plan


def _validate_plan(profile, plan, archive, records):
    fields = {'format', 'schema_version', 'kind', 'project_root', 'profile_sha256', 'config_sha256', 'request_sha256',
              'request', 'operation_id', 'roots', 'batches', 'impact', 'impact_material_sha256', 'hash_usage', 'fingerprint'}
    common.validate_seal(plan)
    if set(plan) != fields or plan['format'] != PLAN or plan['schema_version'] != 1 or plan['kind'] != KIND:
        raise DirectoryError('ARTIFACT_INVALID', 'unsupported directory archive plan')
    if plan['project_root'] != str(profile.root) or plan['profile_sha256'] != profile.sha256 or plan['config_sha256'] != common.digest(profile.config):
        raise DirectoryError('PROFILE_CONFLICT', 'archive plan profile binding changed')
    if not isinstance(plan['operation_id'], str) or len(plan['operation_id']) != 32 or any(c not in '0123456789abcdef' for c in plan['operation_id']):
        raise DirectoryError('ARTIFACT_INVALID', 'invalid archive operation id')
    if plan['roots'] != _root_records(profile, archive, records) or plan['request_sha256'] != common.digest(plan['request']):
        raise DirectoryError('SOURCE_CHANGED', 'archive roots or request binding changed')
    raw = _request(profile, plan['request'])
    if len(raw) != len(plan['batches']):
        raise DirectoryError('ARTIFACT_INVALID', 'archive batch count mismatch')
    for expected, batch in zip(raw, plan['batches']):
        if set(batch) != {'source', 'destination', 'manifest', 'known_absent', 'open_handles', 'locator_text', 'locator_sha256'} or any(batch[k] != expected[k] for k in ('source', 'destination')) or batch['known_absent'] != expected.get('known_absent', []):
            raise DirectoryError('ARTIFACT_INVALID', 'archive batch schema mismatch')
        _validate_manifest(profile, batch)
        journal = records / (plan['operation_id'] + '.directory.json')
        if batch['locator_text'] != _locator_text(plan['operation_id'], batch, archive, journal, profile.root) or _sha(batch['locator_text'].encode()) != batch['locator_sha256']:
            raise DirectoryError('ARTIFACT_INVALID', 'locator binding mismatch')
    _validate_impact_record(profile, plan)
    _reserve_rounds(profile, plan['batches'])


def _validate_manifest(profile, batch):
    manifest = batch['manifest']
    if not isinstance(manifest, dict) or set(manifest) != {'entries', 'file_count', 'directory_count', 'file_bytes', 'attributes_verified', 'attributes_not_verified'}:
        raise DirectoryError('ARTIFACT_INVALID', 'invalid directory manifest')
    seen, seen_keys, files, total = set(), set(), 0, 0
    if not isinstance(manifest['entries'], list) or not manifest['entries']:
        raise DirectoryError('ARTIFACT_INVALID', 'manifest must include its root directory')
    for entry in manifest['entries']:
        path = common.relative(entry.get('path'), allow_dot=True)
        _allowed(profile, batch['source'] if path == '.' else batch['source'] + '/' + path)
        kind = entry.get('kind')
        fields = {'path', 'kind', 'mode', 'mtime_ns', 'device', 'inode'} | ({'bytes', 'sha256', 'nlink'} if kind == 'file' else set())
        if kind not in {'file', 'directory'} or set(entry) != fields or common.path_key(path) in seen_keys:
            raise DirectoryError('ARTIFACT_INVALID', 'invalid or aliased manifest entry')
        if any(type(entry[k]) is not int or entry[k] < 0 for k in ('mode', 'mtime_ns', 'device', 'inode')) or entry['mode'] > 0o7777:
            raise DirectoryError('ARTIFACT_INVALID', 'invalid manifest metadata')
        if kind == 'file':
            if type(entry['bytes']) is not int or entry['bytes'] < 0 or entry['nlink'] != 1 or not isinstance(entry['sha256'], str) or len(entry['sha256']) != 64 or any(c not in '0123456789abcdef' for c in entry['sha256']):
                raise DirectoryError('ARTIFACT_INVALID', 'invalid file manifest')
            files += 1
            total += entry['bytes']
        seen.add(path)
        seen_keys.add(common.path_key(path))
    by_path = {e['path']: e for e in manifest['entries']}
    if '.' not in by_path or by_path['.']['kind'] != 'directory' or any(str(Path(path).parent) not in by_path or by_path[str(Path(path).parent)]['kind'] != 'directory' for path in seen if path != '.'):
        raise DirectoryError('ARTIFACT_INVALID', 'manifest hierarchy is invalid')
    if (files, len(seen) - files, total) != (manifest['file_count'], manifest['directory_count'], manifest['file_bytes']):
        raise DirectoryError('ARTIFACT_INVALID', 'manifest totals mismatch')


def _save(record, profile, *, initial=False):
    path = Path(record['journal_path'])
    if not initial:
        previous = common.load_artifact(path, profile.budgets['max_artifact_bytes'])
        common.validate_seal(previous)
        if previous['fingerprint'] != record['fingerprint']:
            raise DirectoryError('JOURNAL_CHANGED', 'journal was changed by another writer')
    sealed = common.seal(record)
    common.write_artifact(path, sealed, replace=not initial, limit=profile.budgets['max_artifact_bytes'])
    record['fingerprint'] = sealed['fingerprint']


def _artifact(profile, value):
    if not isinstance(value, dict):
        return common.load_artifact(value, profile.budgets['max_artifact_bytes'])
    total = 0
    for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, allow_nan=False).iterencode(value):
        total += len(chunk.encode('ascii'))
        if total > profile.budgets['max_artifact_bytes']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'received artifact exceeds byte limit')
    return copy.deepcopy(value)


def _load_journal(profile, value, archive, records):
    record = _artifact(profile, value)
    common.validate_seal(record)
    fields = {'format', 'schema_version', 'kind', 'operation_id', 'journal_path', 'plan', 'state', 'progress', 'restore_plan', 'last_error', 'fingerprint'}
    if set(record) != fields or record['format'] != JOURNAL or record['schema_version'] != 1 or record['kind'] != KIND:
        raise DirectoryError('JOURNAL_INVALID', 'unsupported directory journal')
    _validate_plan(profile, record['plan'], archive, records)
    operation = record['plan']['operation_id']
    expected = records / (operation + '.directory.json')
    if record['operation_id'] != operation or record['journal_path'] != str(expected):
        raise DirectoryError('JOURNAL_INVALID', 'directory journal location mismatch')
    if not isinstance(value, dict) and Path(value).absolute() != expected:
        raise DirectoryError('JOURNAL_INVALID', 'directory journal was moved')
    current = common.load_artifact(expected, profile.budgets['max_artifact_bytes'])
    common.validate_seal(current)
    if current['fingerprint'] != record['fingerprint']:
        raise DirectoryError('JOURNAL_CHANGED', 'supplied journal is stale')
    if record['state'] not in {'Prepared', 'Archiving', 'Archived', 'Restoring', 'Restored', 'NeedsAttention'}:
        raise DirectoryError('JOURNAL_INVALID', 'unknown directory journal state')
    if not isinstance(record['progress'], list) or len(record['progress']) != len(record['plan']['batches']):
        raise DirectoryError('JOURNAL_INVALID', 'directory progress count mismatch')
    for index, progress in enumerate(record['progress']):
        if set(progress) != {'index', 'state', 'locator', 'staging_intent', 'retained_unknown_staging'} or progress['index'] != index:
            raise DirectoryError('JOURNAL_INVALID', 'invalid directory progress')
        if progress['state'] not in {'Pending', 'PrepareLocatorIntent', 'LocatorPrepared', 'MoveIntent', 'PayloadMoved', 'LocatorIntent', 'Archived', 'RestoreLocatorIntent', 'LocatorRetained', 'RestorePayloadIntent', 'Restored'}:
            raise DirectoryError('JOURNAL_INVALID', 'unknown batch progress')
        stage = progress['staging_intent']
        if stage is not None:
            _validate_stage(stage, operation, index)
        unknowns = progress['retained_unknown_staging']
        if not isinstance(unknowns, list) or len(unknowns) > 100:
            raise DirectoryError('JOURNAL_INVALID', 'invalid retained staging list')
        for stage in unknowns:
            _validate_stage(stage, operation, index)
        owner = progress['locator']
        if owner is not None:
            if set(owner) != {'stage', 'directory', 'file'} or owner['stage'] != progress['staging_intent']:
                raise DirectoryError('JOURNAL_INVALID', 'invalid locator owner')
            _validate_stage(owner['stage'], operation, index)
            for item, keys in [(owner['directory'], {'device', 'inode', 'mode', 'mtime_ns'}),
                               (owner['file'], {'device', 'inode', 'mode', 'mtime_ns', 'bytes', 'sha256'})]:
                if not isinstance(item, dict) or set(item) != keys or any(type(item[k]) is not int or item[k] < 0 for k in keys - {'sha256'}):
                    raise DirectoryError('JOURNAL_INVALID', 'invalid locator identity')
            text = record['plan']['batches'][index]['locator_text'].encode('utf-8')
            if owner['file']['sha256'] != _sha(text) or owner['file']['bytes'] != len(text):
                raise DirectoryError('JOURNAL_INVALID', 'locator content identity mismatch')
    return record


def _validate_stage(stage, operation, index):
    common.relative(stage)
    prefix = operation + '.locator-' + str(index) + '-'
    if '/' in stage or not stage.startswith(prefix) or len(stage) != len(prefix) + 32 or any(c not in '0123456789abcdef' for c in stage[-32:]):
        raise DirectoryError('JOURNAL_INVALID', 'invalid locator staging path')


def _mkdir_parents(base, rel):
    parts = common.relative(rel).split('/')[:-1]
    parent = '.'
    for part in parts:
        with common.open_dir(base, parent) as fd:
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError:
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode):
                    raise DirectoryError('DESTINATION_EXISTS', 'archive parent is occupied')
        parent = part if parent == '.' else parent + '/' + part


def _locator_match(base, rel, owner, text):
    with common.open_dir(base, rel) as fd:
        info = os.fstat(fd)
        actual = {**_identity(info), 'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns}
        if actual != owner['directory']:
            raise DirectoryError('OWNERSHIP_CHANGED', 'locator directory identity changed')
        with os.scandir(fd) as children:
            first = next(children, None)
            if first is None or first.name != 'ARCHIVED.md' or next(children, None) is not None:
                raise DirectoryError('SOURCE_OCCUPIED', 'locator directory contains unknown work')
        file_info = os.stat('ARCHIVED.md', dir_fd=fd, follow_symlinks=False)
        expected = owner['file']
        actual_file = {**_identity(file_info), 'mode': stat.S_IMODE(file_info.st_mode), 'mtime_ns': file_info.st_mtime_ns,
                       'bytes': file_info.st_size, 'sha256': _sha(common.read_file(base, rel + '/ARCHIVED.md', len(text) + 1))}
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1 or actual_file != expected:
            raise DirectoryError('OWNERSHIP_CHANGED', 'locator file was changed or replaced')
        if common.read_file(base, rel + '/ARCHIVED.md', len(text) + 1) != text:
            raise DirectoryError('SOURCE_CHANGED', 'locator content changed')


def _prepare_locator(profile, record, index, records):
    progress, batch = record['progress'][index], record['plan']['batches'][index]
    if progress['locator'] is not None:
        _locator_match(records, progress['locator']['stage'], progress['locator'], batch['locator_text'].encode())
        return
    previous = progress['staging_intent']
    if previous is not None and _exists(records, previous):
        # A crash before the ownership receipt cannot prove who created it.
        # Retain the unknown object and reserve a fresh no-clobber staging name.
        if len(progress['retained_unknown_staging']) >= 100:
            raise DirectoryError('BUDGET_EXHAUSTED', 'too many incomplete staging objects')
        progress['retained_unknown_staging'].append(previous)
    stage = record['operation_id'] + '.locator-' + str(index) + '-' + uuid.uuid4().hex
    progress.update(staging_intent=stage, state='PrepareLocatorIntent')
    _save(record, profile)
    with common.open_dir(records) as fd:
        os.mkdir(stage, 0o755, dir_fd=fd)
        os.fsync(fd)
    text = batch['locator_text'].encode('utf-8')
    with common.open_dir(records, stage) as fd:
        file_fd = os.open('ARCHIVED.md', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=fd)
        with os.fdopen(file_fd, 'wb') as stream:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.fsync(fd)
        directory = os.fstat(fd)
        file_info = os.stat('ARCHIVED.md', dir_fd=fd, follow_symlinks=False)
        owner = {'stage': stage, 'directory': {**_identity(directory), 'mode': stat.S_IMODE(directory.st_mode), 'mtime_ns': directory.st_mtime_ns},
                 'file': {**_identity(file_info), 'mode': stat.S_IMODE(file_info.st_mode), 'mtime_ns': file_info.st_mtime_ns,
                          'bytes': len(text), 'sha256': _sha(text)}}
    progress.update(locator=owner, state='LocatorPrepared')
    _save(record, profile)


def _observe(profile, record, index, archive, records, budget):
    batch, progress = record['plan']['batches'][index], record['progress'][index]
    source_exists = _exists(profile.root, batch['source'])
    target_exists = _exists(archive, batch['destination'])
    source_kind = None
    if source_exists:
        info = common.stat_entry(profile.root, batch['source'])
        payload_root = next(entry for entry in batch['manifest']['entries'] if entry['path'] == '.')
        if _identity(info) == {k: payload_root[k] for k in ('device', 'inode')}:
            _match_manifest(profile, profile.root, batch['source'], batch, budget)
            source_kind = 'Payload'
        elif progress['locator'] is not None:
            _locator_match(profile.root, batch['source'], progress['locator'], batch['locator_text'].encode())
            source_kind = 'Locator'
        else:
            raise DirectoryError('SOURCE_OCCUPIED', 'original path is occupied by unknown data')
    if target_exists:
        _match_manifest(profile, archive, batch['destination'], batch, budget)
    staged = False
    if progress['locator'] is not None and _exists(records, progress['locator']['stage']):
        _locator_match(records, progress['locator']['stage'], progress['locator'], batch['locator_text'].encode())
        staged = True
    if source_kind == 'Payload' and not target_exists:
        return {'location': 'Source', 'locator_staged': staged}
    if target_exists and source_kind in {None, 'Locator'}:
        if source_kind == 'Locator' and staged:
            raise DirectoryError('INTERRUPT_AMBIGUOUS', 'locator exists in both locations')
        return {'location': 'Archive', 'locator_present': source_kind == 'Locator', 'locator_staged': staged}
    raise DirectoryError('INTERRUPT_AMBIGUOUS', 'payload is missing or present at conflicting locations')


def _observe_all(profile, record, archive, records, budget):
    return [_observe(profile, record, i, archive, records, budget) for i in range(len(record['progress']))]


def _failure(record, profile, error):
    # Intent receipts already describe the last possible side effect. Failure
    # recording must not mask the original exception (e.g. full records volume).
    record['last_error'] = getattr(error, 'reason_code', type(error).__name__)
    try:
        _save(record, profile)
    except (OSError, ValueError):
        pass


def apply(profile, plan, archive_root, records_dir):
    archive, records = common.external_roots(profile, archive_root, records_dir)
    plan = _artifact(profile, plan)
    with _locks(profile, archive, records):
        _validate_plan(profile, plan, archive, records)
        journal_path = records / (plan['operation_id'] + '.directory.json')
        if _exists(records, journal_path.name):
            record = _load_journal(profile, journal_path, archive, records)
            if record['plan']['fingerprint'] != plan['fingerprint']:
                raise DirectoryError('JOURNAL_INVALID', 'operation id belongs to another plan')
            if record['state'] == 'Restored' or record['restore_plan'] is not None:
                raise DirectoryError('PLAN_ALREADY_RESTORED', 'restored operations require a fresh preview')
            _check_references(profile, record, archive)
            return _archive_continue(profile, record, archive, records)
        _, material = _impact(profile, plan['request'])
        if material != plan['impact_material_sha256']:
            raise DirectoryError('SOURCE_CHANGED', 'archive impact or closure evidence changed')
        budget = common.HashBudget(profile.budgets)
        for batch in plan['batches']:
            if _exists(archive, batch['destination']):
                raise DirectoryError('DESTINATION_EXISTS', 'archive destination already exists')
            _match_manifest(profile, profile.root, batch['source'], batch, budget)
            _open_handles(profile, profile.root, batch['source'])
        record = {'format': JOURNAL, 'schema_version': 1, 'kind': KIND, 'operation_id': plan['operation_id'],
                  'journal_path': str(journal_path), 'plan': plan, 'state': 'Prepared', 'last_error': None, 'restore_plan': None,
                  'progress': [{'index': i, 'state': 'Pending', 'locator': None, 'staging_intent': None, 'retained_unknown_staging': []}
                               for i in range(len(plan['batches']))]}
        _save(record, profile, initial=True)
        return _archive_continue(profile, record, archive, records, observations=[{'location': 'Source', 'locator_staged': False} for _ in plan['batches']], budget=budget)


def _archive_continue(profile, record, archive, records, observations=None, budget=None):
    budget = budget or common.HashBudget(profile.budgets)
    observations = observations if observations is not None else _observe_all(profile, record, archive, records, budget)
    if record['state'] == 'Archived':
        if all(item['location'] == 'Archive' and item['locator_present'] for item in observations):
            return record
        raise DirectoryError('SOURCE_CHANGED', 'completed archive was subsequently changed')
    try:
        record['state'] = 'Archiving'
        _save(record, profile)
        for index, observed in enumerate(observations):
            batch, progress = record['plan']['batches'][index], record['progress'][index]
            if observed['location'] == 'Source':
                if progress['state'] in {'Archived', 'RestoreLocatorIntent', 'LocatorRetained', 'RestorePayloadIntent', 'Restored'}:
                    raise DirectoryError('INTERRUPT_AMBIGUOUS', 'journal and source payload disagree')
                _prepare_locator(profile, record, index, records)
                _mkdir_parents(archive, batch['destination'])
                _match_manifest(profile, profile.root, batch['source'], batch, common.HashBudget(profile.budgets), hashes=False)
                _open_handles(profile, profile.root, batch['source'])
                _check_current_reference_set(profile, record, archive, phase_budget=budget, pending_source=batch['source'])
                budget.check_time()
                progress['state'] = 'MoveIntent'
                _save(record, profile)
                common.rename_noreplace(profile.root, batch['source'], archive, batch['destination'])
                progress['state'] = 'PayloadMoved'
                _save(record, profile)
                _match_manifest(profile, archive, batch['destination'], batch, budget)
                observed = {'location': 'Archive', 'locator_present': False, 'locator_staged': True}
            if observed['locator_present']:
                progress['state'] = 'Archived'
                _save(record, profile)
                continue
            if not observed['locator_staged'] or progress['locator'] is None:
                raise DirectoryError('INTERRUPT_AMBIGUOUS', 'owned locator staging is missing')
            _locator_match(records, progress['locator']['stage'], progress['locator'], batch['locator_text'].encode())
            progress['state'] = 'LocatorIntent'
            _save(record, profile)
            common.rename_noreplace(records, progress['locator']['stage'], profile.root, batch['source'])
            _locator_match(profile.root, batch['source'], progress['locator'], batch['locator_text'].encode())
            progress['state'] = 'Archived'
            _save(record, profile)
        record['state'] = 'Archived'
        record['last_error'] = None
        _save(record, profile)
        return record
    except BaseException as error:
        _failure(record, profile, error)
        raise


def _readonly_roots(profile, archive_root):
    records_dir = profile.data['archive'].get('records_dir')
    return common.external_roots(profile, archive_root, records_dir)


def _check_references(profile, record, archive):
    """Revalidate only the proof files already selected by the impact checker."""
    bindings = {}
    for item in record['plan']['impact']['batches']:
        for reference in item.get('reference_fingerprints', []):
            path, sha = reference['path'], reference['sha256']
            if path in bindings and bindings[path] != sha:
                raise DirectoryError('ARTIFACT_INVALID', 'conflicting impact reference fingerprints')
            bindings[path] = sha
        for evidence in item.get('closure', {}).get('evidence', []):
            path, sha = evidence['path'], evidence['sha256']
            if path in bindings and bindings[path] != sha:
                raise DirectoryError('ARTIFACT_INVALID', 'conflicting closure evidence fingerprints')
            bindings[path] = sha
    from .reference_batches import ReferenceHasher
    hasher = ReferenceHasher(profile)
    for path, expected in bindings.items():
        common.relative(path)
        if common.protected(profile, path):
            raise DirectoryError('PROTECTED_PATH', 'impact proof contains a protected reference')
        base, target = profile.root, path
        for batch in record['plan']['batches']:
            if _within(path, batch['source']) and common.path_key(path) != common.path_key(batch['source']) and _exists(archive, batch['destination']):
                suffix = _suffix(path, batch['source'])
                matched = [entry['path'] for entry in batch['manifest']['entries'] if common.path_key(entry['path']) == common.path_key(suffix)]
                if len(matched) != 1:
                    raise DirectoryError('ARTIFACT_INVALID', 'impact reference is not in the manifest')
                base, target = archive, batch['destination'] + '/' + matched[0]
                break
        if path not in profile.data.get('streaming_references', []) and common.stat_entry(base, target).st_size > profile.budgets['max_reference_file_bytes']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'nonstream reference exceeds per-file limit')
        item = hasher.read(target, reference_path=path, root=base)
        if item['sha256'] != expected:
            raise DirectoryError('SOURCE_CHANGED', 'impact reference or closure evidence changed')


def verify(profile, journal, archive_root):
    archive, records = _readonly_roots(profile, archive_root)
    with _locks(profile, archive, records):
        record = _load_journal(profile, journal, archive, records)
        issues, observations = [], []
        budget = common.HashBudget(profile.budgets)
        for index, progress in enumerate(record['progress']):
            try:
                observed = _observe(profile, record, index, archive, records, budget)
                observations.append({'index': index, **observed})
                if record['state'] == 'Archived' and (observed['location'] != 'Archive' or not observed.get('locator_present') or progress['state'] != 'Archived'):
                    raise DirectoryError('SOURCE_CHANGED', 'completed archive does not match its receipt')
                if record['state'] == 'Restored' and (observed['location'] != 'Source' or progress['state'] != 'Restored'):
                    raise DirectoryError('SOURCE_CHANGED', 'completed restoration does not match its receipt')
                if progress['state'] == 'Archived' and record['state'] != 'Restoring' and (observed['location'] != 'Archive' or not observed.get('locator_present')):
                    raise DirectoryError('SOURCE_CHANGED', 'archived batch changed after completion')
            except (OSError, ValueError) as error:
                issues.append({'index': index, 'reason_code': getattr(error, 'reason_code', 'READ_UNAVAILABLE')})
        try:
            _check_references(profile, record, archive)
        except (OSError, ValueError) as error:
            issues.append({'reason_code': getattr(error, 'reason_code', 'READ_UNAVAILABLE'), 'check': 'impact_bindings'})
        status = 'Failed' if issues else 'Passed' if record['state'] in {'Archived', 'Restored'} else 'Unknown'
        return {'schema_version': 1, 'kind': KIND, 'status': status, 'state': record['state'],
                'operation_id': record['operation_id'], 'journal_path': record['journal_path'],
                'journal_consistency': 'Failed' if issues else 'Passed', 'batches': observations, 'issues': issues,
                'retention': 'Passed' if not issues and record['state'] in {'Archived', 'Restored'} else 'Unknown',
                'hash_usage': budget.snapshot(), 'physical_space_released': None}


def locate(profile, journal, original, archive_root):
    archive, records = _readonly_roots(profile, archive_root)
    original = common.relative(original)
    with _locks(profile, archive, records):
        record = _load_journal(profile, journal, archive, records)
        for index, batch in enumerate(record['plan']['batches']):
            if _within(original, batch['source']):
                suffix = _suffix(original, batch['source'])
                matched = [entry['path'] for entry in batch['manifest']['entries'] if common.path_key(entry['path']) == common.path_key(suffix)]
                if len(matched) != 1:
                    raise DirectoryError('ORIGINAL_NOT_RECORDED', 'original path is not uniquely in the manifest')
                suffix = matched[0]
                observed = _observe(profile, record, index, archive, records, common.HashBudget(profile.budgets))
                archived = batch['destination'] + ('' if suffix == '.' else '/' + suffix)
                return {'schema_version': 1, 'kind': KIND, 'status': 'Passed', 'operation_id': record['operation_id'],
                        'original': original, 'original_payload_exists': observed['location'] == 'Source',
                        'original_path_status': 'Present' if observed['location'] == 'Source' else 'Missing',
                        'resolution': 'Restored' if observed['location'] == 'Source' else 'ArchivedResolved',
                        'archive_path': str(archive / archived), 'archive_present': observed['location'] == 'Archive',
                        'scripts_replayable_at_original': 'Not run' if observed['location'] == 'Source' else False}
    raise DirectoryError('ORIGINAL_NOT_RECORDED', 'original path does not belong to this archive')


def restore_preview(profile, journal, archive_root):
    archive, records = _readonly_roots(profile, archive_root)
    with _locks(profile, archive, records):
        record = _load_journal(profile, journal, archive, records)
        observations = _observe_all(profile, record, archive, records, common.HashBudget(profile.budgets))
        _check_references(profile, record, archive)
        if record['state'] == 'Restored':
            if not all(o['location'] == 'Source' for o in observations):
                raise DirectoryError('SOURCE_CHANGED', 'restored payload changed')
            return copy.deepcopy(record['restore_plan'])
        if record['restore_plan'] is not None:
            return copy.deepcopy(record['restore_plan'])
        if record['state'] != 'Archived' or not all(o['location'] == 'Archive' for o in observations):
            raise DirectoryError('INTERRUPT_AMBIGUOUS', 'finish archive recovery before planning restoration')
        for batch in record['plan']['batches']:
            _open_handles(profile, archive, batch['destination'])
        return common.seal({'format': RESTORE, 'schema_version': 1, 'kind': KIND,
                            'project_root': str(profile.root), 'profile_sha256': profile.sha256,
                            'config_sha256': common.digest(profile.config), 'roots': record['plan']['roots'],
                            'operation_id': uuid.uuid4().hex, 'archive_operation_id': record['operation_id'],
                            'journal_path': record['journal_path'], 'journal_fingerprint': record['fingerprint'],
                            'batches': [{'source': b['source'], 'destination': b['destination'],
                                         'manifest_sha256': common.digest(b['manifest']),
                                         'locator_action': 'RetainInRecords' if o.get('locator_present') else 'Absent'}
                                        for b, o in zip(record['plan']['batches'], observations)]})


def _validate_restore(profile, plan, record):
    common.validate_seal(plan)
    fields = {'format', 'schema_version', 'kind', 'project_root', 'profile_sha256', 'config_sha256', 'roots',
              'operation_id', 'archive_operation_id', 'journal_path', 'journal_fingerprint', 'batches', 'fingerprint'}
    if set(plan) != fields or plan['format'] != RESTORE or plan['schema_version'] != 1 or plan['kind'] != KIND:
        raise DirectoryError('ARTIFACT_INVALID', 'unsupported directory restore plan')
    archive_plan = record['plan']
    if any(plan[k] != archive_plan[k] for k in ('project_root', 'profile_sha256', 'config_sha256', 'roots')) or plan['archive_operation_id'] != record['operation_id'] or plan['journal_path'] != record['journal_path']:
        raise DirectoryError('PROFILE_CONFLICT', 'restore plan archive binding mismatch')
    if len(plan['batches']) != len(archive_plan['batches']):
        raise DirectoryError('ARTIFACT_INVALID', 'restore plan batch count mismatch')
    for batch, original in zip(plan['batches'], archive_plan['batches']):
        if set(batch) != {'source', 'destination', 'manifest_sha256', 'locator_action'} or batch['source'] != original['source'] or batch['destination'] != original['destination'] or batch['manifest_sha256'] != common.digest(original['manifest']) or batch['locator_action'] not in {'RetainInRecords', 'Absent'}:
            raise DirectoryError('ARTIFACT_INVALID', 'restore plan batch binding mismatch')


def restore(profile, plan, archive_root, records_dir):
    archive, records = common.external_roots(profile, archive_root, records_dir)
    plan = _artifact(profile, plan)
    with _locks(profile, archive, records):
        common.validate_seal(plan)
        record = _load_journal(profile, plan['journal_path'], archive, records)
        _validate_restore(profile, plan, record)
        if record['restore_plan'] is None:
            if record['state'] != 'Archived' or plan['journal_fingerprint'] != record['fingerprint']:
                raise DirectoryError('SOURCE_CHANGED', 'restore plan journal binding changed')
        elif record['restore_plan']['fingerprint'] != plan['fingerprint']:
            raise DirectoryError('SOURCE_CHANGED', 'another restoration is already in progress')
        return _restore_continue(profile, record, plan, archive, records)


def _restore_continue(profile, record, plan, archive, records):
    budget = common.HashBudget(profile.budgets)
    observations = _observe_all(profile, record, archive, records, budget)
    _check_references(profile, record, archive)
    if record['state'] == 'Restored':
        if all(o['location'] == 'Source' for o in observations):
            return record
        raise DirectoryError('SOURCE_CHANGED', 'completed restoration was subsequently changed')
    for observed in observations:
        if observed['location'] == 'Source' and record['restore_plan'] is None:
            raise DirectoryError('INTERRUPT_AMBIGUOUS', 'payload moved without a restore receipt')
    try:
        record['restore_plan'] = plan
        record['state'] = 'Restoring'
        _save(record, profile)
        for index in reversed(range(len(observations))):
            observed = observations[index]
            batch, progress = record['plan']['batches'][index], record['progress'][index]
            if observed['location'] == 'Source':
                progress['state'] = 'Restored'
                _save(record, profile)
                continue
            _open_handles(profile, archive, batch['destination'])
            if observed.get('locator_present'):
                owner = progress['locator']
                if owner is None:
                    raise DirectoryError('OWNERSHIP_CHANGED', 'locator ownership is unknown')
                _locator_match(profile.root, batch['source'], owner, batch['locator_text'].encode())
                if _exists(records, owner['stage']):
                    raise DirectoryError('DESTINATION_EXISTS', 'locator preservation path is occupied')
                progress['state'] = 'RestoreLocatorIntent'
                _save(record, profile)
                common.rename_noreplace(profile.root, batch['source'], records, owner['stage'])
                progress['state'] = 'LocatorRetained'
                _save(record, profile)
                _locator_match(records, owner['stage'], owner, batch['locator_text'].encode())
            elif observed.get('locator_staged'):
                _locator_match(records, progress['locator']['stage'], progress['locator'], batch['locator_text'].encode())
            _match_manifest(profile, archive, batch['destination'], batch, common.HashBudget(profile.budgets), hashes=False)
            budget.check_time()
            progress['state'] = 'RestorePayloadIntent'
            _save(record, profile)
            common.rename_noreplace(archive, batch['destination'], profile.root, batch['source'])
            _match_manifest(profile, profile.root, batch['source'], batch, budget)
            progress['state'] = 'Restored'
            _save(record, profile)
        record['state'] = 'Restored'
        record['last_error'] = None
        _save(record, profile)
        return record
    except BaseException as error:
        _failure(record, profile, error)
        raise


def recover(profile, journal, archive_root, records_dir):
    archive, records = common.external_roots(profile, archive_root, records_dir)
    with _locks(profile, archive, records):
        record = _load_journal(profile, journal, archive, records)
        _check_references(profile, record, archive)
        if record['restore_plan'] is not None:
            _validate_restore(profile, record['restore_plan'], record)
            return _restore_continue(profile, record, record['restore_plan'], archive, records)
        if record['state'] in {'Restoring', 'Restored'}:
            raise DirectoryError('JOURNAL_INVALID', 'restoration intent is missing')
        return _archive_continue(profile, record, archive, records)


def _sample_lsof(executable, candidate, timeout):
    """Bounded no-body handle sampling; never capture unbounded PID/error lists."""
    process = subprocess.Popen([executable, '-nP', '-t', '+D', str(candidate)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    deadline, total = time.monotonic() + timeout, 0
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ, 'stdout')
            ready.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired('lsof', timeout)
                events = ready.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired('lsof', timeout)
                for key, _ in events:
                    block = os.read(key.fileobj.fileno(), min(4096, 8193 - total))
                    if not block:
                        ready.unregister(key.fileobj)
                        continue
                    total += len(block)
                    if key.data == 'stdout' and block.strip():
                        return process.poll(), True, False
                    if key.data == 'stderr' and block.strip() or total > 8192:
                        return process.poll(), False, True
            return process.wait(timeout=max(0.001, deadline - time.monotonic())), False, False
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdout.close()
        process.stderr.close()


def _validate_impact_record(profile, plan):
    report = plan['impact']
    common.validate_seal(report)
    if (report.get('kind') != 'directory-impact' or report.get('schema_version') != 1 or report.get('project_root') != str(profile.root)
            or report.get('profile_sha256') != profile.sha256 or report.get('request_sha256') != plan['request_sha256']
            or report.get('status') != 'Passed' or report.get('coverage', {}).get('complete') is not True
            or report.get('material_sha256') != common.digest(report.get('material'))
            or plan['impact_material_sha256'] != report.get('material_sha256')
            or len(report.get('batches', [])) != len(plan['batches'])):
        raise DirectoryError('ARTIFACT_INVALID', 'impact proof binding mismatch')
    roots = [item['path'] for item in profile.data['reference_sources']]
    for batch, requested in zip(report['batches'], plan['request']['batches']):
        if (any(batch.get(k) != requested[k] for k in ('source', 'destination')) or batch.get('eligible') is not True
                or batch.get('status') != 'Passed' or batch.get('current_dependencies') or batch.get('unknowns') or batch.get('blockers')
                or batch.get('coverage', {}).get('complete') is not True):
            raise DirectoryError('ARTIFACT_INVALID', 'impact batch is not eligible')
        expected_evidence = requested['closure']['evidence']
        if batch.get('closure', {}).get('evidence') != expected_evidence:
            raise DirectoryError('ARTIFACT_INVALID', 'closure evidence binding mismatch')
        for reference in batch.get('reference_fingerprints', []) + expected_evidence:
            path = common.relative(reference['path'])
            if not any(_within(path, root) for root in roots):
                raise DirectoryError('BODY_NOT_AUTHORIZED', 'impact reference is outside authorized sources')
            value = reference.get('sha256')
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise DirectoryError('ARTIFACT_INVALID', 'invalid impact reference fingerprint')


def _current_reference_role(profile, path):
    # Exact native grants, not comparison keys, authorize this enumeration.
    # Match census: a historical child cannot downgrade any current parent.
    grants = [item for item in profile.data['reference_sources']
              if path == item['path'] or path.startswith(item['path'] + '/')]
    return 'current' if any(item['role'] == 'current' for item in grants) else 'historical' if grants else None


def _check_current_reference_set(profile, record, archive, phase_budget=None, pending_source=None):
    """Forward-only gate: new current consumers require a new impact preview.

    No new file bodies are read. Restoring original paths intentionally does not
    use this gate: new consumers may be precisely why rollback is necessary.
    Already-moved payload subtrees are enumerated through their bound manifest
    at ARC, so owned locator files do not impersonate changed reference sources.
    """
    if pending_source is not None and any(grant['role'] == 'current' and (_within(grant['path'], pending_source) or _within(pending_source, grant['path']))
                                          for grant in profile.data['reference_sources']):
        raise DirectoryError('CURRENT_REFERENCE_SOURCE', 'current reference material cannot be archived')
    expected = {item['path'] for batch in record['plan']['impact']['batches']
                for item in batch['reference_fingerprints'] if _current_reference_role(profile, item['path']) == 'current'}
    limits = profile.budgets
    started, entries, path_bytes = time.monotonic(), 0, 0
    observed, visited = set(), set()
    mappings = []
    for batch in record['plan']['batches']:
        if phase_budget is not None:
            phase_budget.check_time()
        if not _exists(archive, batch['destination']):
            continue
        info = common.stat_entry(archive, batch['destination'])
        owner = next(item for item in batch['manifest']['entries'] if item['path'] == '.')
        if (info.st_dev, info.st_ino) != (owner['device'], owner['inode']):
            raise DirectoryError('SOURCE_CHANGED', 'archive payload ownership changed')
        mappings.append((batch, {common.path_key(item['path']): item['path'] for item in batch['manifest']['entries']}))

    def check():
        common.validate_profile_root(profile)
        if phase_budget is not None:
            phase_budget.check_time()
        if time.monotonic() - started >= limits['max_seconds'] or entries >= limits['max_entries']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'current reference enumeration budget exhausted')

    def location(path):
        for batch, manifest_paths in mappings:
            if _within(path, batch['source']):
                suffix = _suffix(path, batch['source'])
                stored = manifest_paths.get(common.path_key(suffix))
                if stored is None:
                    raise DirectoryError('SOURCE_CHANGED', 'current reference is absent from its archived manifest')
                return archive, batch['destination'] + ('' if stored == '.' else '/' + stored)
        return profile.root, path

    def visit(path, depth):
        nonlocal entries, path_bytes
        if path in visited or _current_reference_role(profile, path) != 'current':
            return
        check()
        if depth > limits['max_depth']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'current reference depth limit exhausted')
        common.relative(path)
        if common.protected(profile, path):
            raise DirectoryError('SOURCE_CHANGED', 'current reference scope acquired protected material')
        cost = len(path.encode('utf-8')) + 128
        if cost > limits['max_artifact_bytes'] - path_bytes:
            raise DirectoryError('BUDGET_EXHAUSTED', 'current reference set exceeds the bounded metadata allowance')
        path_bytes += cost
        visited.add(path)
        entries += 1
        base, rel = location(path)
        common.validate_path_spelling(base, rel)
        info = common.stat_entry(base, rel)
        if stat.S_ISREG(info.st_mode):
            file_limit = profile.data.get('reference_batching', {}).get('max_total_files', limits['max_reference_files'])
            if len(observed) >= file_limit:
                raise DirectoryError('BUDGET_EXHAUSTED', 'current reference file count exhausted')
            observed.add(path)
            return
        if not stat.S_ISDIR(info.st_mode):
            raise DirectoryError('SOURCE_CHANGED', 'current reference acquired unsupported material')
        with common.open_dir(base, rel) as fd:
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (info.st_dev, info.st_ino):
                raise DirectoryError('SOURCE_CHANGED', 'current reference directory changed')
            with os.scandir(fd) as children:
                while True:
                    check()
                    try:
                        child = next(children)
                    except StopIteration:
                        break
                    visit(path + '/' + child.name, depth + 1)
    for grant in profile.data['reference_sources']:
        if grant['role'] == 'current':
            visit(grant['path'], 0)
    common.validate_profile_root(profile)
    if observed != expected:
        raise DirectoryError('SOURCE_CHANGED', 'current reference membership changed; create a new impact preview')
