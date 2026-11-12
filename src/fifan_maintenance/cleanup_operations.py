"""Explicit quarantine/restore and irreversible, per-entry purge of owned payloads.

Only the dedicated cleanup profile grants these operations. Integrity seals are
not human approval: every mutating action separately requires its plan hash.
Non-cooperating writers must be paused; there is no portable compare-and-unlink
syscall, and a multi-item operation is not an atomic transaction.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import copy
import fcntl
import hashlib
import json
import os
import selectors
import subprocess
import time
from pathlib import Path
import shutil
import stat
import uuid

from . import directory_common as dc

Error = dc.DirectoryError
PLAN = 'fifan-cleanup-plan'
JOURNAL = 'fifan-cleanup-journal'
REPORT = 'fifan-cleanup-report'
STATES = {'Prepared', 'Quarantining', 'Quarantined', 'Restoring', 'Restored',
          'Purging', 'PartiallyPurged', 'Purged', 'NeedsAttention'}
TERMINAL = {'Quarantined', 'Restored', 'Purged'}


def _policy():
    from . import cleanup_policy
    return cleanup_policy


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _hex(value, length=64):
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def _identity(info):
    return info.st_dev, info.st_ino


def _stat_fields(info, kind):
    value = {'kind': kind, 'device': info.st_dev, 'inode': info.st_ino,
             'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
    if kind == 'file':
        value.update(bytes=info.st_size, nlink=info.st_nlink)
    return value


def _stable(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns


def _sized(value, limit):
    total = 0
    for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, allow_nan=False).iterencode(value):
        total += len(chunk.encode('ascii'))
        if total > limit:
            raise Error('BUDGET_EXHAUSTED', 'cleanup artifact exceeds its byte limit')
    return total


def _abs_key(value):
    path = Path(value)
    if not isinstance(value, str) or not path.is_absolute() or '..' in path.parts:
        raise Error('ARTIFACT_INVALID', 'invalid cleanup root declaration')
    return dc.path_key('/'.join(path.parts[1:]))


def _bound(profile, value):
    if (value.get('root') != str(profile.root) or value.get('profile_sha256') != profile.sha256
            or value.get('config_sha256') != dc.digest(profile.config)):
        raise Error('PROFILE_CONFLICT', 'cleanup artifact binding mismatch')
    if dc.digest(profile.data) != profile.sha256 or profile.budgets != profile.data['budgets']:
        raise Error('PROFILE_CONFLICT', 'cleanup profile changed after loading')


def _roots(profile, quarantine_root, records_dir):
    quarantine, records = _policy().runtime_roots(profile, quarantine_root, records_dir)
    roots = {name: {'path': str(root), 'device': dc.stat_entry(root, '.').st_dev, 'inode': dc.stat_entry(root, '.').st_ino}
             for name, root in [('project', profile.root), ('quarantine', quarantine), ('records', records)]}
    if len({entry['device'] for entry in roots.values()}) != 1:
        raise Error('CROSS_DEVICE', 'cleanup requires three same-volume roots')
    if profile._root_identity and _identity(dc.stat_entry(profile.root, '.')) != profile._root_identity:
        raise Error('SOURCE_CHANGED', 'cleanup project root was replaced')
    return quarantine, records, roots


@contextmanager
def _locks(profile, quarantine, records, roots):
    # The inode we validate must be the inode we lock. Opening a second path
    # for flock could lock a replacement directory after the initial root read.
    held = {}
    with ExitStack() as stack:
        paths = {'project': profile.root, 'quarantine': quarantine, 'records': records}
        for label, root in sorted(paths.items(), key=lambda entry: str(entry[1])):
            fd = stack.enter_context(dc.open_dir(root))
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise Error('PROJECT_BUSY', 'cleanup root is held by another maintenance operation') from error
            except OSError as error:
                raise Error('SAFE_IO_UNAVAILABLE', 'cleanup root locking is unavailable') from error
            stack.callback(fcntl.flock, fd, fcntl.LOCK_UN)
            held[label] = fd
        identities = set()
        # Acquire and hold all three FDs before checking the complete namespace.
        # Compare to the earlier snapshot, never rebaseline it to new roots.
        for label, fd in held.items():
            expected = roots[label]
            actual = _identity(os.fstat(fd))
            named = _identity(dc.stat_entry(paths[label], '.'))
            if expected['path'] != str(paths[label]) or actual != (expected['device'], expected['inode']) or named != actual:
                raise Error('SOURCE_CHANGED', 'cleanup root changed before locks were acquired')
            identities.add(actual)
        if len(identities) != 3:
            raise Error('PROFILE_CONFLICT', 'cleanup roots are not distinct directories')
        yield


def _before_write(profile):
    _policy().validate_profile_root(profile)
    from .project import load_config
    if dc.digest(load_config(profile.root)) != dc.digest(profile.config):
        raise Error('SOURCE_CHANGED', 'project rules changed before cleanup')


def _exists(root, rel):
    try:
        dc.stat_entry(root, rel)
        return True
    except FileNotFoundError:
        return False


def _target(item, entry):
    return item['quarantine_relative'] + ('' if entry['path'] == '.' else '/' + entry['path'])


def _source(item, entry):
    return item['source'] + ('' if entry['path'] == '.' else '/' + entry['path'])


def _permitted(profile, semantic):
    dc.relative(semantic)
    if _policy().protected(profile, semantic):
        raise Error('PROTECTED_PATH', 'protected cleanup payload')


def _charge_meta(budget):
    budget.check_time()
    used = getattr(budget, '_cleanup_metadata', 0)
    if used >= budget.limits['max_entries']:
        raise Error('BUDGET_EXHAUSTED', 'cleanup metadata work limit exhausted')
    budget._cleanup_metadata = used + 1


def _hash_file(root, rel, budget):
    budget.charge_entry()
    with dc.parent_fd(root, rel) as (fd, name):
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(source)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise Error('ENTRY_UNSUPPORTED', 'cleanup rejects special files and shared hardlinks')
            if before.st_size > budget.limits['max_hash_file_bytes'] or before.st_size > budget.limits['max_hash_bytes'] - budget.bytes:
                raise Error('BUDGET_EXHAUSTED', 'cleanup file exceeds hash allowance')
            digest, size = hashlib.sha256(), 0
            while size < before.st_size:
                budget.check_time()
                raw = os.read(source, min(1024 * 1024, before.st_size - size))
                if not raw:
                    raise Error('SOURCE_CHANGED', 'cleanup file shrank during hashing')
                budget.charge_bytes(len(raw))
                digest.update(raw)
                size += len(raw)
            after = os.fstat(source)
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if _stable(before) != _stable(after) or _stable(before) != _stable(named):
                raise Error('SOURCE_CHANGED', 'cleanup file changed during hashing')
            return {**_stat_fields(before, 'file'), 'sha256': digest.hexdigest()}
        finally:
            os.close(source)


def _scan(profile, root, rel, semantic, budget, allowed=None):
    """Stream metadata; unknown names are rejected before their bodies are read."""
    result, keys, byte_cost = [], set(), 0
    root_device = dc.stat_entry(root, '.').st_dev
    def append(value):
        nonlocal byte_cost
        key = dc.path_key(value['path'])
        if key in keys:
            raise Error('PATH_ALIAS', 'cleanup manifest contains equivalent names')
        keys.add(key)
        cost = len(dc.canonical(value)) + 2
        if cost > profile.budgets['max_artifact_bytes'] - byte_cost:
            raise Error('BUDGET_EXHAUSTED', 'cleanup manifest exceeds artifact allowance')
        byte_cost += cost
        result.append(value)
    def visit(path, suffix, depth):
        _charge_meta(budget)
        if depth > budget.limits['max_depth']:
            raise Error('BUDGET_EXHAUSTED', 'cleanup manifest depth exhausted')
        _permitted(profile, semantic if suffix == '.' else semantic + '/' + suffix)
        if allowed is not None and suffix not in allowed:
            raise Error('SOURCE_CHANGED', 'cleanup payload contains an unrecorded entry')
        dc.validate_path_spelling(root, path)
        before = dc.stat_entry(root, path)
        if before.st_dev != root_device:
            raise Error('CROSS_DEVICE', 'cleanup payload crosses a filesystem boundary')
        if stat.S_ISREG(before.st_mode):
            value = _hash_file(root, path, budget)
            if _identity(before) != (value['device'], value['inode']):
                raise Error('SOURCE_CHANGED', 'cleanup file name changed')
            append({'path': suffix, **value})
            return
        if not stat.S_ISDIR(before.st_mode):
            raise Error('ENTRY_UNSUPPORTED', 'cleanup rejects links and special files')
        budget.charge_entry()
        append({'path': suffix, **_stat_fields(before, 'directory')})
        with dc.open_dir(root, path) as fd:
            if _identity(os.fstat(fd)) != _identity(before):
                raise Error('SOURCE_CHANGED', 'cleanup directory was replaced')
            with os.scandir(fd) as children:
                while True:
                    budget.check_time()
                    try:
                        child = next(children)
                    except StopIteration:
                        break
                    child_suffix = child.name if suffix == '.' else suffix + '/' + child.name
                    visit(path + '/' + child.name, child_suffix, depth + 1)
            after = os.fstat(fd)
            named = dc.stat_entry(root, path)
            stable = lambda info: (*_identity(info), info.st_mode, info.st_mtime_ns, info.st_ctime_ns)
            if stable(before) != stable(after) or stable(before) != stable(named):
                raise Error('SOURCE_CHANGED', 'cleanup directory changed during scanning')
    visit(rel, '.', 0)
    result.sort(key=lambda item: (item['path'] != '.', item['path']))
    return {'entries': result, 'root_kind': result[0]['kind'],
            'file_count': sum(e['kind'] == 'file' for e in result),
            'directory_count': sum(e['kind'] == 'directory' for e in result),
            'file_bytes': sum(e.get('bytes', 0) for e in result)}


def _observations(entries, original):
    result = {}
    for index, expected in enumerate(original):
        actual = entries.get(expected['path'])
        if actual is None:
            continue
        change = {key: actual[key] for key in ('mtime_ns', 'ctime_ns') if actual[key] != expected[key]}
        if change:
            result[str(index)] = change
    return result


def _expected(record, item_index, entry_index):
    value = dict(record['quarantine_plan']['items'][item_index]['manifest']['entries'][entry_index])
    value.update(record['items'][item_index]['observations'].get(str(entry_index), {}))
    return value


def _observe_payload(profile, record, item_index, root, *, source=False, root_ctime=False, budget=None):
    item = record['quarantine_plan']['items'][item_index]
    progress = record['items'][item_index]
    original = item['manifest']['entries']
    removed = set(progress['removed'])
    intent = record['intent']
    pending = intent['entry_index'] if intent and intent['action'] in {'unlink', 'rmdir'} and intent['item_index'] == item_index else None
    rel = item['source'] if source else item['quarantine_relative']
    exists = _exists(root, rel)
    if not exists:
        if removed == set(range(len(original))) or pending == 0 and removed == set(range(1, len(original))):
            return {}, pending == 0
        raise Error('SOURCE_CHANGED', 'cleanup payload is unexpectedly absent')
    allowed = {e['path'] for index, e in enumerate(original) if index not in removed}
    current = _scan(profile, root, rel, item['source'], budget or dc.HashBudget(profile.budgets), allowed=allowed)
    entries = {e['path']: e for e in current['entries']}
    missing = {index for index, entry in enumerate(original) if index not in removed and entry['path'] not in entries}
    if missing and missing != {pending}:
        raise Error('SOURCE_CHANGED', 'cleanup entries disappeared without matching intent')
    pending_missing = pending is not None and pending in missing
    changed_parent = str(Path(original[pending]['path']).parent) if pending_missing and original[pending]['path'] != '.' else None
    for index, entry in enumerate(original):
        actual = entries.get(entry['path'])
        if index in removed:
            if actual is not None:
                raise Error('SOURCE_CHANGED', 'a purged cleanup entry was recreated')
            continue
        if actual is None:
            continue
        expected = _expected(record, item_index, index)
        compare = dict(actual)
        if root_ctime and index == 0:
            expected['ctime_ns'] = compare['ctime_ns']
        if pending_missing and entry['kind'] == 'directory' and entry['path'] == changed_parent:
            expected['mtime_ns'], expected['ctime_ns'] = compare['mtime_ns'], compare['ctime_ns']
        if compare != expected:
            raise Error('SOURCE_CHANGED', 'cleanup payload metadata or identity changed')
    return entries, pending_missing


def _sample(profile, root, rel, quarantine, records):
    executable = shutil.which('lsof')
    required = profile.data.get('require_no_open_handles', True)
    if executable is None:
        if required:
            raise Error('OPEN_HANDLES_CHECK_UNAVAILABLE', 'lsof is unavailable')
        return {'status': 'Unknown', 'guarantee': 'sampling_only'}
    executable = dc.canonical_destination(Path(executable).resolve(strict=True), allow_missing_parents=False)
    if any(executable.is_relative_to(scope) for scope in {profile.root, quarantine, records}):
        raise Error('PROTECTED_PATH', 'cleanup will not execute inspected material')
    try:
        info = dc.stat_entry(root, rel)
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise Error('ENTRY_UNSUPPORTED', 'open-handle sampling requires an ordinary entry')
        code, opened, failed = _sample_handles(str(executable), root / rel, min(10, profile.budgets['max_seconds']), directory=stat.S_ISDIR(info.st_mode))
    except (OSError, TimeoutError, subprocess.TimeoutExpired):
        code, opened, failed = None, False, True
    if opened:
        raise Error('OPEN_HANDLES', 'cleanup payload has an observed open handle')
    if failed or code != 1:
        if required:
            raise Error('OPEN_HANDLES_CHECK_UNAVAILABLE', 'lsof sampling failed')
        return {'status': 'Unknown', 'guarantee': 'sampling_only'}
    return {'status': 'ClearSample', 'guarantee': 'sampling_only'}


def _qualification(profile, request, relocations=None):
    report = _policy().qualify(profile, request, relocations=relocations)
    dc.validate_seal(report)
    if report.get('status') != 'Passed' or report.get('material_sha256') != dc.digest(report.get('material')):
        raise Error('CLEANUP_NOT_QUALIFIED', 'cleanup qualification is blocked or incomplete')
    return report


def _relocations(record, quarantine):
    result = {}
    for item, progress in zip(record['quarantine_plan']['items'], record['items']):
        if 0 in progress['removed']:
            result[item['source']] = None
        elif progress['location'] == 'quarantine' or _exists(quarantine, item['quarantine_relative']):
            result[item['source']] = {'root': str(quarantine), 'path': item['quarantine_relative']}
    return result


def _forward(profile, record, quarantine, expected_material):
    report = _qualification(profile, record['quarantine_plan']['request'], _relocations(record, quarantine))
    if report['material_sha256'] != expected_material:
        raise Error('SOURCE_CHANGED', 'cleanup retained evidence or current reference set changed')
    return report


def _approve(plan, value):
    if not isinstance(value, str) or value != plan['fingerprint']:
        raise Error('APPROVAL_REQUIRED', 'an explicit matching action plan approval is required')


def _plan_base(profile, roots, kind, operation_id=None):
    return {'format': PLAN, 'schema_version': 1, 'kind': kind, 'root': str(profile.root),
            'profile_sha256': profile.sha256, 'config_sha256': dc.digest(profile.config),
            'roots': roots, 'operation_id': operation_id or uuid.uuid4().hex}


def preview(profile, request, quarantine_root, records_dir):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    request = _policy().validate_request(profile, request)
    with _locks(profile, quarantine, records, roots):
        qualification = _qualification(profile, request)
        operation = uuid.uuid4().hex
        namespace = 'project-' + dc.digest({'root': str(profile.root)})[:16]
        items, budget, source_keys = [], dc.HashBudget(profile.budgets), []
        for index, declared in enumerate(request['items']):
            source = dc.relative(declared['source'])
            dc.validate_path_spelling(profile.root, source)
            key = dc.path_key(source)
            if any(key == old or key.startswith(old + '/') or old.startswith(key + '/') for old in source_keys):
                raise Error('MULTIPLE_WRITES', 'cleanup candidates overlap')
            source_keys.append(key)
            manifest = _scan(profile, profile.root, source, source, budget)
            target = namespace + '/' + operation + '/payload-%04d' % index
            if _exists(quarantine, target):
                raise Error('DESTINATION_EXISTS', 'cleanup quarantine target already exists')
            items.append({'source': source, 'candidate_kind': declared['kind'], 'entry_kind': manifest['root_kind'],
                          'quarantine_relative': target, 'manifest': manifest,
                          'open_handles': _sample(profile, profile.root, source, quarantine, records)})
        _reserve(profile, items)
        plan = dc.seal({**_plan_base(profile, roots, 'quarantine', operation), 'request': request,
                        'request_sha256': dc.digest(request), 'qualification': qualification,
                        'material_sha256': qualification['material_sha256'], 'items': items})
        _reserve_artifact(profile, plan)
        return plan


def _reserve(profile, items):
    entries = sum(len(item['manifest']['entries']) for item in items)
    total = sum(item['manifest']['file_bytes'] for item in items)
    if entries * 2 > profile.budgets['max_hash_entries'] or total * 2 > profile.budgets['max_hash_bytes']:
        raise Error('BUDGET_EXHAUSTED', 'cleanup budget must cover preflight and mutation verification')


def _reserve_artifact(profile, plan):
    # Upper bound later progress and all deletion receipts before any mutation.
    growth = 8192 + sum(512 + len(item['manifest']['entries']) * 192 for item in plan['items'])
    if _sized(plan, profile.budgets['max_artifact_bytes']) + growth > profile.budgets['max_artifact_bytes']:
        raise Error('BUDGET_EXHAUSTED', 'cleanup plan leaves insufficient recovery journal capacity')


def _validate_manifest(profile, manifest):
    fields = {'entries', 'root_kind', 'file_count', 'directory_count', 'file_bytes'}
    if not isinstance(manifest, dict) or set(manifest) != fields or not isinstance(manifest['entries'], list) or not manifest['entries']:
        raise Error('ARTIFACT_INVALID', 'invalid cleanup manifest')
    keys, names, files, size = set(), {}, 0, 0
    for index, entry in enumerate(manifest['entries']):
        if not isinstance(entry, dict):
            raise Error('ARTIFACT_INVALID', 'invalid cleanup manifest entry')
        path = dc.relative(entry.get('path'), allow_dot=True)
        kind = entry.get('kind')
        expected = {'path', 'kind', 'device', 'inode', 'mode', 'mtime_ns', 'ctime_ns'} | ({'bytes', 'sha256', 'nlink'} if kind == 'file' else set())
        if kind not in {'file', 'directory'} or set(entry) != expected or dc.path_key(path) in keys:
            raise Error('ARTIFACT_INVALID', 'invalid or aliased cleanup manifest entry')
        if any(type(entry[k]) is not int or entry[k] < 0 for k in ('device', 'inode', 'mode', 'mtime_ns', 'ctime_ns')) or entry['mode'] > 0o7777:
            raise Error('ARTIFACT_INVALID', 'invalid cleanup entry metadata')
        if kind == 'file':
            if type(entry['bytes']) is not int or entry['bytes'] < 0 or type(entry['nlink']) is not int or entry['nlink'] != 1 or not _hex(entry['sha256']):
                raise Error('ARTIFACT_INVALID', 'invalid cleanup file metadata')
            files += 1
            size += entry['bytes']
        if index == 0 and path != '.':
            raise Error('ARTIFACT_INVALID', 'cleanup manifest root must be first')
        keys.add(dc.path_key(path))
        names[path] = kind
    if manifest['root_kind'] != names['.'] or names['.'] == 'file' and len(names) != 1:
        raise Error('ARTIFACT_INVALID', 'cleanup root kind mismatch')
    if any(str(Path(path).parent) not in names or names[str(Path(path).parent)] != 'directory' for path in names if path != '.'):
        raise Error('ARTIFACT_INVALID', 'cleanup manifest hierarchy mismatch')
    if (files, len(names) - files, size) != (manifest['file_count'], manifest['directory_count'], manifest['file_bytes']):
        raise Error('ARTIFACT_INVALID', 'cleanup manifest totals mismatch')
    if len(names) > profile.budgets['max_hash_entries']:
        raise Error('BUDGET_EXHAUSTED', 'cleanup manifest exceeds entry allowance')


def validate_plan(profile, plan):
    """Validate metadata only. Never stat roots, candidates, Q, or external files."""
    _sized(plan, profile.budgets['max_artifact_bytes'])
    dc.validate_seal(plan)
    common = {'format', 'schema_version', 'kind', 'root', 'profile_sha256', 'config_sha256', 'roots', 'operation_id', 'fingerprint'}
    if not isinstance(plan, dict) or plan.get('format') != PLAN or type(plan.get('schema_version')) is not int or plan['schema_version'] != 1 or plan.get('kind') not in {'quarantine', 'restore', 'purge'}:
        raise Error('ARTIFACT_INVALID', 'unsupported cleanup plan')
    _bound(profile, plan)
    if not _hex(plan.get('operation_id'), 32) or set(plan.get('roots', {})) != {'project', 'quarantine', 'records'}:
        raise Error('ARTIFACT_INVALID', 'invalid cleanup plan roots or operation')
    for label, value in plan['roots'].items():
        if not isinstance(value, dict) or set(value) != {'path', 'device', 'inode'} or any(type(value[k]) is not int or value[k] < 0 for k in ('device', 'inode')):
            raise Error('ARTIFACT_INVALID', 'invalid cleanup root identity')
        declared = str(profile.root) if label == 'project' else profile.data[label + '_root' if label == 'quarantine' else 'records_dir']
        if value['path'] != declared:
            raise Error('PROFILE_CONFLICT', 'cleanup root declaration differs')
    if profile._root_identity and (plan['roots']['project']['device'], plan['roots']['project']['inode']) != profile._root_identity:
        raise Error('PROFILE_CONFLICT', 'cleanup cached project identity differs')
    if len({value['device'] for value in plan['roots'].values()}) != 1 or len({(v['device'], v['inode']) for v in plan['roots'].values()}) != 3:
        raise Error('ARTIFACT_INVALID', 'cleanup root identities overlap or cross devices')
    if plan['kind'] == 'quarantine':
        if set(plan) != common | {'request', 'request_sha256', 'qualification', 'material_sha256', 'items'}:
            raise Error('ARTIFACT_INVALID', 'invalid quarantine plan fields')
        request = plan['request']
        if not isinstance(request, dict) or plan['request_sha256'] != dc.digest(request) or not isinstance(request.get('items'), list) or len(request['items']) != len(plan['items']) or not plan['items']:
            raise Error('ARTIFACT_INVALID', 'quarantine request binding mismatch')
        namespace = 'project-' + dc.digest({'root': str(profile.root)})[:16]
        source_keys = []
        for index, (item, requested) in enumerate(zip(plan['items'], request['items'])):
            if set(item) != {'source', 'candidate_kind', 'entry_kind', 'quarantine_relative', 'manifest', 'open_handles'} or item['source'] != requested['source'] or item['candidate_kind'] != requested['kind']:
                raise Error('ARTIFACT_INVALID', 'quarantine item binding mismatch')
            dc.relative(item['source'])
            key = dc.path_key(item['source'])
            if any(key == old or key.startswith(old + '/') or old.startswith(key + '/') for old in source_keys):
                raise Error('MULTIPLE_WRITES', 'quarantine items overlap')
            source_keys.append(key)
            if item['quarantine_relative'] != namespace + '/' + plan['operation_id'] + '/payload-%04d' % index:
                raise Error('ARTIFACT_INVALID', 'quarantine destination cannot be self-authorized')
            _validate_manifest(profile, item['manifest'])
            if item['entry_kind'] != item['manifest']['root_kind']:
                raise Error('ARTIFACT_INVALID', 'quarantine kind mismatch')
        qualification = plan['qualification']
        dc.validate_seal(qualification)
        if qualification.get('status') != 'Passed' or plan['material_sha256'] != qualification.get('material_sha256') or plan['material_sha256'] != dc.digest(qualification.get('material')):
            raise Error('ARTIFACT_INVALID', 'quarantine qualification binding mismatch')
        _reserve(profile, plan['items'])
        _reserve_artifact(profile, plan)
    else:
        expected = common | {'quarantine_operation_id', 'quarantine_fingerprint', 'journal_path', 'journal_fingerprint', 'journal_identity'}
        if plan['kind'] == 'purge':
            expected |= {'authorization', 'qualification', 'material_sha256', 'order'}
        if set(plan) != expected or not _hex(plan['quarantine_operation_id'], 32) or not _hex(plan['quarantine_fingerprint']) or not _hex(plan['journal_fingerprint']):
            raise Error('ARTIFACT_INVALID', 'invalid cleanup action plan fields')
        identity = plan['journal_identity']
        if not isinstance(identity, dict) or set(identity) != {'device', 'inode'} or any(type(x) is not int or x < 0 for x in identity.values()):
            raise Error('ARTIFACT_INVALID', 'invalid cleanup journal identity')
        wanted = str(Path(plan['roots']['records']['path']) / ('cleanup-' + plan['quarantine_operation_id']) / 'journal.json')
        if plan['journal_path'] != wanted:
            raise Error('ARTIFACT_INVALID', 'cleanup action journal path mismatch')
    return plan


def validate_record(profile, record):
    """Metadata-only validation for explicitly loaded REC history declarations."""
    _sized(record, profile.budgets['max_artifact_bytes'])
    dc.validate_seal(record)
    fields = {'format', 'schema_version', 'kind', 'root', 'profile_sha256', 'config_sha256', 'operation_id', 'journal_path',
              'quarantine_plan', 'record_directory', 'record_owner', 'quarantine_container', 'state', 'direction', 'intent', 'items',
              'restore_plan', 'purge_plan', 'last_error', 'fingerprint'}
    if not isinstance(record, dict) or set(record) not in (fields, fields | {'cancelled_purge'}) or record.get('format') != JOURNAL or type(record.get('schema_version')) is not int or record.get('schema_version') != 1 or record.get('kind') != 'cleanup':
        raise Error('JOURNAL_INVALID', 'unsupported cleanup journal')
    _bound(profile, record)
    plan = validate_plan(profile, record['quarantine_plan'])
    if plan['kind'] != 'quarantine' or record['operation_id'] != plan['operation_id'] or record['journal_path'] != str(Path(plan['roots']['records']['path']) / ('cleanup-' + plan['operation_id']) / 'journal.json'):
        raise Error('JOURNAL_INVALID', 'cleanup journal plan binding mismatch')
    if record.get('cancelled_purge') is not None and not _hex(record['cancelled_purge']):
        raise Error('JOURNAL_INVALID', 'invalid cancelled purge audit fingerprint')
    if record['state'] not in STATES or record['direction'] not in {'quarantine', 'restore', 'purge'}:
        raise Error('JOURNAL_INVALID', 'unknown cleanup state')
    for owner in (record['record_directory'], record['quarantine_container']):
        if owner is not None and (not isinstance(owner, dict) or set(owner) != {'device', 'inode', 'mode'} or any(type(v) is not int or v < 0 for v in owner.values()) or owner['mode'] != 0o700):
            raise Error('JOURNAL_INVALID', 'invalid cleanup private directory ownership')
    if not isinstance(record['record_owner'], dict) or set(record['record_owner']) != {'device', 'inode'} or any(type(x) is not int or x < 0 for x in record['record_owner'].values()):
        raise Error('JOURNAL_INVALID', 'invalid cleanup journal file identity')
    if record['record_directory'] is None or not isinstance(record['items'], list) or len(record['items']) != len(plan['items']):
        raise Error('JOURNAL_INVALID', 'cleanup progress count mismatch')
    for index, (progress, item) in enumerate(zip(record['items'], plan['items'])):
        if set(progress) != {'index', 'source', 'location', 'state', 'observations', 'removed', 'removal_evidence'} or progress['index'] != index or progress['source'] != item['source']:
            raise Error('JOURNAL_INVALID', 'invalid cleanup item progress')
        if progress['location'] not in {'source', 'quarantine', 'purged'} or progress['state'] not in STATES:
            raise Error('JOURNAL_INVALID', 'invalid cleanup item location')
        count = len(item['manifest']['entries'])
        removed = progress['removed']
        if not isinstance(removed, list) or any(type(n) is not int or not 0 <= n < count for n in removed) or len(set(removed)) != len(removed):
            raise Error('JOURNAL_INVALID', 'invalid cleanup removed entries')
        if not isinstance(progress['observations'], dict) or len(progress['observations']) > count:
            raise Error('JOURNAL_INVALID', 'invalid cleanup observations')
        for key, observed in progress['observations'].items():
            if not isinstance(key, str) or not key.isdecimal() or str(int(key)) != key or not 0 <= int(key) < count or not isinstance(observed, dict) or set(observed) - {'mtime_ns', 'ctime_ns'} or any(type(v) is not int or v < 0 for v in observed.values()):
                raise Error('JOURNAL_INVALID', 'invalid cleanup fresh timestamps')
        evidence = progress['removal_evidence']
        if not isinstance(evidence, dict) or set(evidence) != {str(n) for n in removed} or any(v not in {'observed_missing_after_intent', 'syscall_returned_and_missing'} for v in evidence.values()):
            raise Error('JOURNAL_INVALID', 'invalid deletion evidence')
    intent = record['intent']
    if intent is not None:
        if not isinstance(intent, dict) or set(intent) != {'action', 'item_index', 'entry_index', 'expected'} or intent['action'] not in {'prepare_container', 'quarantine', 'restore', 'unlink', 'rmdir'}:
            raise Error('JOURNAL_INVALID', 'invalid cleanup intent')
        i, j = intent['item_index'], intent['entry_index']
        if type(i) is not int or not 0 <= i < len(plan['items']) or type(j) is not int or not 0 <= j < len(plan['items'][i]['manifest']['entries']):
            raise Error('JOURNAL_INVALID', 'cleanup intent index is outside its manifest')
        if intent['action'] != 'prepare_container' and intent['expected'] != _expected(record, i, j):
            raise Error('JOURNAL_INVALID', 'cleanup intent fingerprint mismatch')
        if intent['action'] in {'quarantine', 'restore'} and j != 0 or intent['action'] == 'unlink' and intent['expected']['kind'] != 'file' or intent['action'] == 'rmdir' and intent['expected']['kind'] != 'directory':
            raise Error('JOURNAL_INVALID', 'cleanup intent action mismatch')
    for key, kind in [('restore_plan', 'restore'), ('purge_plan', 'purge')]:
        action = record[key]
        if action is not None:
            validate_plan(profile, action)
            if action['kind'] != kind or action['quarantine_fingerprint'] != plan['fingerprint'] or action['quarantine_operation_id'] != plan['operation_id'] or action['roots'] != plan['roots']:
                raise Error('JOURNAL_INVALID', 'cleanup action plan binding mismatch')
    return record


def expected_manifest(record, item_index, *, remaining=False):
    """Pure metadata projection; fresh ctime is observed, never restored."""
    original = record['quarantine_plan']['items'][item_index]['manifest']
    removed = set(record['items'][item_index]['removed']) if remaining else set()
    entries = [_expected(record, item_index, n) for n in range(len(original['entries'])) if n not in removed]
    return {'entries': entries, 'root_kind': original['root_kind'],
            'file_count': sum(e['kind'] == 'file' for e in entries), 'directory_count': sum(e['kind'] == 'directory' for e in entries),
            'file_bytes': sum(e.get('bytes', 0) for e in entries)}


def request_allows_purge(request):
    """Pure permission check; it never turns a preview into external approval."""
    return (isinstance(request, dict) and 'purge' in request.get('approval', {}).get('actions', [])
            and bool(request.get('items')) and all(item.get('disposition') == 'purge' and item.get('loss', {}).get('accepted') is True for item in request['items']))


def _rename_entry(source_root, source_rel, target_root, target_rel):
    return dc.rename_entry_noreplace(source_root, source_rel, target_root, target_rel)


def _sync(fd):
    # Kept as an explicit boundary for real fsync failure and post-syscall tests.
    os.fsync(fd)


def _op_path(plan):
    return Path(plan['roots']['records']['path']) / ('cleanup-' + plan['operation_id'])


def _private_owner(path):
    info = dc.stat_entry(path, '.')
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise Error('OWNERSHIP_CHANGED', 'cleanup private directory mode changed')
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': 0o700}


def _assert_owner(path, expected):
    if _private_owner(path) != expected:
        raise Error('OWNERSHIP_CHANGED', 'cleanup private directory was replaced')


def _record_name(records, operation):
    return records / ('cleanup-' + operation) / 'journal.json'


def _artifact(profile, value):
    if isinstance(value, dict):
        _sized(value, profile.budgets['max_artifact_bytes'])
        return copy.deepcopy(value)
    return dc.load_artifact(value, profile.budgets['max_artifact_bytes'])


def _control_path(records, journal):
    raw = Path(journal).absolute()
    if '..' in raw.parts or not raw.is_relative_to(records) or raw.name != 'journal.json' or raw.parent.parent != records or not raw.parent.name.startswith('cleanup-') or not _hex(raw.parent.name[8:], 32):
        raise Error('JOURNAL_INVALID', 'cleanup journal is outside its records slot')
    actual = dc.canonical_destination(raw, allow_missing_parents=False)
    if actual != raw:
        raise Error('PATH_ALIAS', 'cleanup journal spelling changed')
    return raw


def _read_controlled(profile, path):
    info = dc.stat_entry(path.parent, path.name)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise Error('JOURNAL_CHANGED', 'cleanup journal must be private and unshared')
    value = dc.load_artifact(path, profile.budgets['max_artifact_bytes'])
    validate_record(profile, value)
    if _identity(info) != (value['record_owner']['device'], value['record_owner']['inode']):
        raise Error('JOURNAL_CHANGED', 'cleanup journal inode was replaced')
    _assert_owner(path.parent, value['record_directory'])
    after = dc.stat_entry(path.parent, path.name)
    if _stable(info) != _stable(after):
        raise Error('JOURNAL_CHANGED', 'cleanup journal changed during load')
    return value, None


def load_record_metadata(profile, journal, records_dir):
    """REC-only ownership check; no candidate, project, or quarantine lookup."""
    records = dc.safe_root(records_dir)
    if str(records) != profile.data['records_dir']:
        raise Error('PROFILE_CONFLICT', 'cleanup records root is not declared')
    supplied = journal if isinstance(journal, dict) else None
    if supplied is not None:
        validate_record(profile, supplied)
        path = _control_path(records, supplied['journal_path'])
    else:
        path = _control_path(records, journal)
    record, _ = _read_controlled(profile, path)
    if supplied is not None and supplied['fingerprint'] != record['fingerprint']:
        raise Error('JOURNAL_CHANGED', 'supplied cleanup journal is stale')
    if record['journal_path'] != str(path):
        raise Error('JOURNAL_INVALID', 'cleanup journal path differs')
    expected_root = record['quarantine_plan']['roots']['records']
    info = dc.stat_entry(records, '.')
    if (info.st_dev, info.st_ino) != (expected_root['device'], expected_root['inode']):
        raise Error('SOURCE_CHANGED', 'cleanup records root was replaced')
    return record


def _load(profile, value, quarantine, records, roots):
    record = load_record_metadata(profile, value, records)
    if record['quarantine_plan']['roots'] != roots:
        raise Error('SOURCE_CHANGED', 'cleanup roots were replaced')
    _policy().validate_request(profile, record['quarantine_plan']['request'])
    return record


def _save(profile, record, *, initial=False):
    """Bind the temporary inode in its own sealed bytes before atomic publish."""
    directory = Path(record['journal_path']).parent
    _assert_owner(directory, record['record_directory'])
    if not initial:
        previous, _ = _read_controlled(profile, Path(record['journal_path']))
        if previous['fingerprint'] != record['fingerprint']:
            raise Error('JOURNAL_CHANGED', 'cleanup journal changed before commit')
    temp = '.cleanup-journal-' + uuid.uuid4().hex + '.tmp'
    with dc.open_dir(directory) as fd:
        source = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        owned = _identity(os.fstat(source))
        try:
            candidate = dict(record)
            candidate['record_owner'] = {'device': owned[0], 'inode': owned[1]}
            sealed = dc.seal(candidate)
            validate_record(profile, sealed)
            total = 0
            for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).iterencode(sealed):
                raw = chunk.encode('ascii')
                total += len(raw)
                if total > profile.budgets['max_artifact_bytes']:
                    raise Error('BUDGET_EXHAUSTED', 'cleanup journal exceeds its byte limit')
                view = memoryview(raw)
                while view:
                    written = os.write(source, view)
                    if written <= 0:
                        raise OSError('short cleanup journal write')
                    view = view[written:]
            os.fchmod(source, 0o600)
            _sync(source)
            if _identity(os.stat(temp, dir_fd=fd, follow_symlinks=False)) != owned:
                raise Error('JOURNAL_CHANGED', 'cleanup journal staging was replaced')
            if initial:
                _rename_entry(directory, temp, directory, 'journal.json')
            else:
                previous, _ = _read_controlled(profile, Path(record['journal_path']))
                if previous['fingerprint'] != record['fingerprint']:
                    raise Error('JOURNAL_CHANGED', 'cleanup journal changed before publication')
                os.replace(temp, 'journal.json', src_dir_fd=fd, dst_dir_fd=fd)
                _sync(fd)
            record['record_owner'] = sealed['record_owner']
            record['fingerprint'] = sealed['fingerprint']
        finally:
            os.close(source)
            try:
                current = os.stat(temp, dir_fd=fd, follow_symlinks=False)
                if _identity(current) == owned and stat.S_ISREG(current.st_mode) and current.st_nlink == 1:
                    os.unlink(temp, dir_fd=fd)
                    _sync(fd)
            except FileNotFoundError:
                pass


def _failure(profile, record, error):
    # Reload the actual published receipt: a journal fsync can fail after rename.
    # Never overwrite an unrecognized artifact or clear its unresolved intent.
    try:
        current, _ = _read_controlled(profile, Path(record['journal_path']))
        record.clear()
        record.update(current)
        irreversible = any(item['removed'] for item in record['items'])
        intent = record['intent']
        if intent and intent['action'] in {'unlink', 'rmdir'}:
            item = record['quarantine_plan']['items'][intent['item_index']]
            entry = item['manifest']['entries'][intent['entry_index']]
            q = Path(record['quarantine_plan']['roots']['quarantine']['path'])
            irreversible = irreversible or not _exists(q, _target(item, entry))
        record['state'] = 'PartiallyPurged' if irreversible else 'NeedsAttention'
        record['last_error'] = {'reason_code': getattr(error, 'reason_code', type(error).__name__),
                                'intent_retained': record['intent'] is not None}
        _save(profile, record)
    except (OSError, ValueError):
        pass


def _new_record(profile, plan, records):
    directory = records / ('cleanup-' + plan['operation_id'])
    with dc.open_dir(records) as fd:
        try:
            os.mkdir(directory.name, 0o700, dir_fd=fd)
        except FileExistsError as error:
            raise Error('RECORD_SLOT_UNPROVEN', 'existing cleanup slot lacks a recognizable journal') from error
        _sync(fd)
    record = {'format': JOURNAL, 'schema_version': 1, 'kind': 'cleanup', 'root': str(profile.root),
              'profile_sha256': profile.sha256, 'config_sha256': dc.digest(profile.config),
              'operation_id': plan['operation_id'], 'journal_path': str(directory / 'journal.json'),
              'quarantine_plan': plan, 'record_directory': _private_owner(directory), 'quarantine_container': None,
              'state': 'Prepared', 'direction': 'quarantine', 'intent': None, 'restore_plan': None, 'purge_plan': None,
              'last_error': None, 'cancelled_purge': None, 'items': [{'index': index, 'source': item['source'], 'location': 'source', 'state': 'Prepared',
                                           'observations': {}, 'removed': [], 'removal_evidence': {}} for index, item in enumerate(plan['items'])]}
    _save(profile, record, initial=True)
    return record


def _q_container(plan):
    return str(Path(plan['items'][0]['quarantine_relative']).parent)


def _container(profile, record, quarantine, *, create=False):
    rel = _q_container(record['quarantine_plan'])
    if record['quarantine_container'] is not None:
        _assert_owner(quarantine / rel, record['quarantine_container'])
    elif create:
        namespace, name = rel.split('/')
        with dc.open_dir(quarantine) as fd:
            try:
                os.mkdir(namespace, 0o700, dir_fd=fd)
                _sync(fd)
            except FileExistsError:
                st = os.stat(namespace, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700:
                    raise Error('OWNERSHIP_CHANGED', 'quarantine namespace is not private')
        record['intent'] = {'action': 'prepare_container', 'item_index': 0, 'entry_index': 0, 'expected': None}
        _save(profile, record)
        with dc.open_dir(quarantine, namespace) as fd:
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError as error:
                raise Error('OWNERSHIP_CHANGED', 'unreceipted quarantine container already exists') from error
            _sync(fd)
        record['quarantine_container'] = _private_owner(quarantine / rel)
        record['intent'] = None
        _save(profile, record)
    elif _exists(quarantine, rel):
        raise Error('OWNERSHIP_CHANGED', 'quarantine container has no ownership receipt')
    else:
        return
    allowed = {Path(item['quarantine_relative']).name for item in record['quarantine_plan']['items']}
    with dc.open_dir(quarantine, rel) as fd:
        with os.scandir(fd) as children:
            for index, entry in enumerate(children):
                if index >= len(allowed) or entry.name not in allowed:
                    raise Error('SOURCE_CHANGED', 'quarantine container contains unknown material')


def _locations(profile, record, quarantine, budget):
    result = []
    _container(profile, record, quarantine)
    for index, (item, progress) in enumerate(zip(record['quarantine_plan']['items'], record['items'])):
        source = _exists(profile.root, item['source'])
        target = _exists(quarantine, item['quarantine_relative'])
        intent = record['intent']
        root_ctime = bool(intent and intent['item_index'] == index and intent['action'] in {'quarantine', 'restore'})
        if source and target:
            raise Error('SOURCE_OCCUPIED', 'original cleanup path is occupied')
        if source:
            entries, _ = _observe_payload(profile, record, index, profile.root, source=True, root_ctime=root_ctime and intent['action'] == 'restore', budget=budget)
            result.append(('source', entries, False))
        elif target:
            entries, pending = _observe_payload(profile, record, index, quarantine, root_ctime=root_ctime and intent['action'] == 'quarantine', budget=budget)
            result.append(('quarantine', entries, pending))
        else:
            entries, pending = _observe_payload(profile, record, index, quarantine, root_ctime=False, budget=budget)
            result.append(('purged', entries, pending))
    return result


# Both spellings are kept public for the reporting integration handshake.
read_record_metadata = load_record_metadata


def _metadata_guard(profile, record, item_index, root, *, source=False):
    item = record['quarantine_plan']['items'][item_index]
    for index, entry in enumerate(item['manifest']['entries']):
        if index in record['items'][item_index]['removed']:
            continue
        rel = _source(item, entry) if source else _target(item, entry)
        info = dc.stat_entry(root, rel)
        expected = _expected(record, item_index, index)
        actual = _stat_fields(info, expected['kind'])
        if expected['kind'] == 'file':
            expected.pop('sha256')
        expected.pop('path')
        if actual != expected:
            raise Error('SOURCE_CHANGED', 'cleanup metadata changed before mutation')


def _ack_move(profile, record, index, entries, target):
    progress = record['items'][index]
    original = record['quarantine_plan']['items'][index]['manifest']['entries']
    progress['observations'] = _observations(entries, original)
    progress['location'] = target
    progress['state'] = 'Quarantined' if target == 'quarantine' else 'Restored'
    record['intent'] = None
    _save(profile, record)


def _move_continue(profile, record, quarantine, records, direction, budget=None, observations=None):
    target = 'quarantine' if direction == 'quarantine' else 'source'
    terminal = 'Quarantined' if target == 'quarantine' else 'Restored'
    budget = budget or dc.HashBudget(profile.budgets)
    observations = observations or _locations(profile, record, quarantine, budget)
    if record['state'] == terminal:
        if all(location == target for location, _, _ in observations):
            return record
        raise Error('SOURCE_CHANGED', 'completed cleanup location changed')
    if record['purge_plan'] is not None or any(item['removed'] for item in record['items']):
        raise Error('PURGE_NOT_RESTORABLE', 'an irreversible cleanup cannot be restored or re-quarantined')
    try:
        _before_write(profile)
        if direction == 'quarantine':
            _forward(profile, record, quarantine, record['quarantine_plan']['material_sha256'])
            _container(profile, record, quarantine, create=True)
        record['direction'] = direction
        record['state'] = 'Quarantining' if direction == 'quarantine' else 'Restoring'
        _save(profile, record)
        for index, (location, entries, _) in enumerate(observations):
            if location == target:
                if record['intent'] is not None and record['intent']['item_index'] == index:
                    _ack_move(profile, record, index, entries, target)
                elif record['items'][index]['location'] != target:
                    raise Error('INTERRUPT_AMBIGUOUS', 'cleanup move lacks matching intent')
                continue
            if location == 'purged':
                raise Error('INTERRUPT_AMBIGUOUS', 'cleanup payload disappeared')
            item = record['quarantine_plan']['items'][index]
            source_root, source_rel = (profile.root, item['source']) if direction == 'quarantine' else (quarantine, item['quarantine_relative'])
            target_root, target_rel = (quarantine, item['quarantine_relative']) if direction == 'quarantine' else (profile.root, item['source'])
            if _exists(target_root, target_rel):
                raise Error('DESTINATION_EXISTS', 'cleanup move destination is occupied')
            if direction == 'quarantine':
                _forward(profile, record, quarantine, record['quarantine_plan']['material_sha256'])
            _metadata_guard(profile, record, index, source_root, source=direction == 'quarantine')
            _sample(profile, source_root, source_rel, quarantine, records)
            budget.check_time()
            record['intent'] = {'action': direction, 'item_index': index, 'entry_index': 0, 'expected': _expected(record, index, 0)}
            _save(profile, record)
            _rename_entry(source_root, source_rel, target_root, target_rel)
            after, _ = _observe_payload(profile, record, index, target_root, source=direction == 'restore', root_ctime=True, budget=budget)
            _ack_move(profile, record, index, after, target)
        record['state'], record['last_error'] = terminal, None
        _save(profile, record)
        return record
    except BaseException as error:
        _failure(profile, record, error)
        raise


def apply(profile, plan, quarantine_root, records_dir, *, approve_plan):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    plan = _artifact(profile, plan)
    validate_plan(profile, plan)
    if plan['kind'] != 'quarantine' or plan['roots'] != roots:
        raise Error('PROFILE_CONFLICT', 'cleanup quarantine plan roots differ')
    _approve(plan, approve_plan)
    with _locks(profile, quarantine, records, roots):
        path = _record_name(records, plan['operation_id'])
        if _exists(records, str(path.parent.relative_to(records))):
            record = _load(profile, path, quarantine, records, roots)
            if record['quarantine_plan']['fingerprint'] != plan['fingerprint']:
                raise Error('JOURNAL_INVALID', 'cleanup slot belongs to another plan')
            if record['restore_plan'] is not None or record['purge_plan'] is not None or record['state'] in {'Restored', 'Purged'}:
                raise Error('PLAN_ALREADY_CONSUMED', 'cleanup reuse requires a fresh quarantine preview')
            return _move_continue(profile, record, quarantine, records, 'quarantine')
        _before_write(profile)
        normalized = _policy().validate_request(profile, plan['request'])
        report = _qualification(profile, normalized)
        if report['material_sha256'] != plan['material_sha256']:
            raise Error('SOURCE_CHANGED', 'cleanup qualification changed after preview')
        # Full content and ctime preflight before even publishing a journal.
        budget, observed = dc.HashBudget(profile.budgets), []
        for item in plan['items']:
            if _exists(quarantine, item['quarantine_relative']):
                raise Error('DESTINATION_EXISTS', 'quarantine destination exists')
            actual = _scan(profile, profile.root, item['source'], item['source'], budget)
            if actual != item['manifest']:
                raise Error('SOURCE_CHANGED', 'cleanup source changed after preview')
            observed.append(('source', {e['path']: e for e in actual['entries']}, False))
        record = _new_record(profile, plan, records)
        return _move_continue(profile, record, quarantine, records, 'quarantine', budget=budget, observations=observed)


def _report(record, status, **extra):
    return dc.seal({'format': REPORT, 'schema_version': 1, 'kind': 'verification', 'root': record['root'],
                    'profile_sha256': record['profile_sha256'], 'operation_id': record['operation_id'],
                    'journal_path': record['journal_path'], 'state': record['state'], 'status': status,
                    'irreversible': record['purge_plan'] is not None, 'physical_release_attribution': 'Unknown',
                    'model_calls': 0, **extra})


def _verify(profile, record, quarantine):
    budget = dc.HashBudget(profile.budgets)
    issues, observed = [], []
    try:
        locations = _locations(profile, record, quarantine, budget)
        for index, (location, entries, pending_missing) in enumerate(locations):
            progress = record['items'][index]
            observed.append({'index': index, 'source': progress['source'], 'location': location,
                             'remaining_files': sum(e['kind'] == 'file' for e in entries.values()),
                             'remaining_bytes': sum(e.get('bytes', 0) for e in entries.values()),
                             'completed_removed_entries': len(progress['removed']),
                             'pending_missing_observed': pending_missing})
            expected = {'Quarantined': 'quarantine', 'Restored': 'source', 'Purged': 'purged'}.get(record['state'])
            if expected is not None and (location != expected or progress['location'] != expected or progress['state'] != record['state']):
                issues.append({'index': index, 'reason_code': 'STATE_MISMATCH'})
        if record['state'] in TERMINAL and record['intent'] is not None:
            issues.append({'reason_code': 'UNCOMMITTED_INTENT'})
        if record['state'] == 'Purged' and any(len(p['removed']) != len(i['manifest']['entries']) for p, i in zip(record['items'], record['quarantine_plan']['items'])):
            issues.append({'reason_code': 'PURGE_INCOMPLETE'})
    except (OSError, ValueError) as error:
        issues.append({'reason_code': getattr(error, 'reason_code', 'READ_UNAVAILABLE')})
    complete = record['state'] in TERMINAL and record['direction'] == {'Quarantined': 'quarantine', 'Restored': 'restore', 'Purged': 'purge'}.get(record['state'])
    if record['state'] == 'Quarantined' and (record['restore_plan'] is not None or record['purge_plan'] is not None):
        complete = False
    status = 'Failed' if issues else 'Passed' if complete else 'Unknown'
    removed = any(p['removed'] for p in record['items'])
    pending_missing = any(item['pending_missing_observed'] for item in observed)
    intact = len(observed) == len(record['items']) and all(item['location'] == 'quarantine' for item in observed)
    restorable = not issues and not removed and not pending_missing and (record['purge_plan'] is None or intact)
    return _report(record, status, items=observed, issues=issues, journal_consistency='Failed' if issues else 'Passed',
                   restore_possible=restorable, irreversible=removed or pending_missing, hash_usage=budget.snapshot())


def verify(profile, journal, quarantine_root, records_dir):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    with _locks(profile, quarantine, records, roots):
        record = _load(profile, journal, quarantine, records, roots)
        return _verify(profile, record, quarantine)


def _action_base(profile, record, kind):
    info = dc.stat_entry(Path(record['journal_path']).parent, 'journal.json')
    return {**_plan_base(profile, record['quarantine_plan']['roots'], kind),
            'quarantine_operation_id': record['operation_id'], 'quarantine_fingerprint': record['quarantine_plan']['fingerprint'],
            'journal_path': record['journal_path'], 'journal_fingerprint': record['fingerprint'],
            'journal_identity': {'device': info.st_dev, 'inode': info.st_ino}}


def _action_binding(profile, plan, record):
    validate_plan(profile, plan)
    original = record['quarantine_plan']
    if plan['quarantine_operation_id'] != original['operation_id'] or plan['quarantine_fingerprint'] != original['fingerprint'] or plan['roots'] != original['roots'] or plan['journal_path'] != record['journal_path']:
        raise Error('PROFILE_CONFLICT', 'cleanup action is not bound to this quarantine')


def _complete_quarantine(profile, record, quarantine):
    """Zero deletions must be proven from every actual entry, not progress alone."""
    if any(progress['removed'] for progress in record['items']):
        return False
    try:
        locations = _locations(profile, record, quarantine, dc.HashBudget(profile.budgets))
    except (OSError, ValueError):
        return False
    return all(location == 'quarantine' and not missing and len(entries) == len(item['manifest']['entries'])
               for (location, entries, missing), item in zip(locations, record['quarantine_plan']['items']))


def restore_preview(profile, journal, quarantine_root, records_dir):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    with _locks(profile, quarantine, records, roots):
        record = _load(profile, journal, quarantine, records, roots)
        checked = _verify(profile, record, quarantine)
        if (record['purge_plan'] is not None or any(p['removed'] for p in record['items'])) and not _complete_quarantine(profile, record, quarantine):
            return _report(record, 'Blocked', reason_code='PURGE_NOT_RESTORABLE', restore_possible=False,
                           remaining=[expected_manifest(record, index, remaining=True) for index in range(len(record['items']))])
        if record['state'] == 'Restored' and checked['status'] == 'Passed':
            return copy.deepcopy(record['restore_plan'])
        if record['restore_plan'] is not None:
            return copy.deepcopy(record['restore_plan'])
        if record['purge_plan'] is not None:
            return dc.seal(_action_base(profile, record, 'restore'))
        if record['state'] != 'Quarantined' or checked['status'] != 'Passed':
            raise Error('CLEANUP_INCOMPLETE', 'complete quarantine recovery before restoring')
        return dc.seal(_action_base(profile, record, 'restore'))


def restore(profile, plan, quarantine_root, records_dir, *, approve_plan):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    plan = _artifact(profile, plan)
    validate_plan(profile, plan)
    if plan['kind'] != 'restore':
        raise Error('ARTIFACT_INVALID', 'restore requires a restore plan')
    _approve(plan, approve_plan)
    with _locks(profile, quarantine, records, roots):
        record = _load(profile, plan['journal_path'], quarantine, records, roots)
        _action_binding(profile, plan, record)
        if record['purge_plan'] is not None and not _complete_quarantine(profile, record, quarantine):
            raise Error('PURGE_NOT_RESTORABLE', 'the full quarantined payload no longer exists unchanged')
        if record['restore_plan'] is not None:
            if record['restore_plan']['fingerprint'] != plan['fingerprint']:
                raise Error('SOURCE_CHANGED', 'another cleanup restore is already active')
        else:
            if record['fingerprint'] != plan['journal_fingerprint'] or record['record_owner'] != plan['journal_identity']:
                raise Error('JOURNAL_CHANGED', 'cleanup restore preview became stale')
            if record['purge_plan'] is not None:
                record['cancelled_purge'] = record['purge_plan']['fingerprint']
                record['purge_plan'] = None
                record['intent'] = None
            record['restore_plan'] = plan
            record['direction'] = 'restore'
            _save(profile, record)
        return _move_continue(profile, record, quarantine, records, 'restore')


def _sample_handles(executable, candidate, timeout, *, directory):
    # Native lsof takes an ordinary file as its final pathname; +D is only for
    # recursive directory sampling. PID/error bytes are bounded, never forwarded.
    argv = [executable, '-nP', '-t'] + (['+D'] if directory else []) + [str(candidate)]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    deadline, total = time.monotonic() + timeout, 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired('lsof', timeout)
                ready = selector.select(remaining)
                if not ready:
                    raise subprocess.TimeoutExpired('lsof', timeout)
                for key, _ in ready:
                    raw = os.read(key.fileobj.fileno(), min(4096, 8193 - total))
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(raw)
                    if key.data == 'stdout' and raw.strip():
                        return process.poll(), True, False
                    if key.data == 'stderr' and raw.strip() or total > 8192:
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


def _purge_order(quarantine_plan):
    order = []
    for item_index, item in enumerate(quarantine_plan['items']):
        entries = item['manifest']['entries']
        indices = sorted(range(len(entries)), key=lambda n: (-len(Path(entries[n]['path']).parts), entries[n]['kind'] == 'directory', entries[n]['path']))
        order.extend([[item_index, index] for index in indices])
    return order


def _purge_authorization(record, approval):
    original = record['quarantine_plan']
    if approval is None:
        if not request_allows_purge(original['request']):
            raise Error('PURGE_APPROVAL_REQUIRED', 'quarantine approval does not permit permanent deletion')
        return {'source': 'original_request', 'quarantine_fingerprint': original['fingerprint'],
                'reference': original['request']['approval']['reference'], 'loss_accepted': True}
    if (not isinstance(approval, dict) or set(approval) != {'quarantine_fingerprint', 'reference', 'loss_accepted'}
            or approval['quarantine_fingerprint'] != original['fingerprint'] or approval['loss_accepted'] is not True
            or not isinstance(approval['reference'], str) or not approval['reference'].strip() or len(approval['reference'].encode('utf-8')) > 4096):
        raise Error('PURGE_APPROVAL_REQUIRED', 'new purge approval must bind the exact quarantined batch and accepted loss')
    return {'source': 'new_approval', **approval}


def _validate_purge(profile, plan, record):
    _action_binding(profile, plan, record)
    if plan['kind'] != 'purge' or plan['order'] != _purge_order(record['quarantine_plan']):
        raise Error('ARTIFACT_INVALID', 'purge order must cover the exact whole quarantine')
    authorization = plan['authorization']
    if not isinstance(authorization, dict) or set(authorization) != {'source', 'reference', 'quarantine_fingerprint', 'loss_accepted'}:
        raise Error('ARTIFACT_INVALID', 'invalid purge authorization')
    if authorization['source'] == 'original_request':
        expected = _purge_authorization(record, None)
    elif authorization['source'] == 'new_approval':
        expected = _purge_authorization(record, {key: authorization[key] for key in ('reference', 'quarantine_fingerprint', 'loss_accepted')})
    else:
        raise Error('ARTIFACT_INVALID', 'unknown purge authorization source')
    if expected != authorization:
        raise Error('ARTIFACT_INVALID', 'purge authorization binding differs')
    dc.validate_seal(plan['qualification'])
    if plan['qualification'].get('status') != 'Passed' or plan['material_sha256'] != plan['qualification'].get('material_sha256') or plan['material_sha256'] != dc.digest(plan['qualification'].get('material')):
        raise Error('ARTIFACT_INVALID', 'purge qualification binding differs')


def _reserve_purge_record(profile, record, plan):
    template = copy.deepcopy(record)
    template['purge_plan'] = plan
    for index, progress in enumerate(template['items']):
        entries = template['quarantine_plan']['items'][index]['manifest']['entries']
        progress['observations'] = {str(n): {'ctime_ns': 9999999999999999999, 'mtime_ns': 9999999999999999999} for n in range(len(entries))}
        progress['removed'] = list(range(len(entries)))
        progress['removal_evidence'] = {str(n): 'observed_missing_after_intent' for n in range(len(entries))}
    _sized(template, profile.budgets['max_artifact_bytes'])
    work = sum(len(item['manifest']['entries']) + sum(len(Path(entry['path']).parts) + 3 for entry in item['manifest']['entries']) for item in record['quarantine_plan']['items'])
    if work > profile.budgets['max_entries']:
        raise Error('BUDGET_EXHAUSTED', 'purge budget cannot cover its deterministic metadata work')


def purge_preview(profile, journal, quarantine_root, records_dir, approval=None):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    with _locks(profile, quarantine, records, roots):
        record = _load(profile, journal, quarantine, records, roots)
        if record['restore_plan'] is not None or record['state'] == 'Restored':
            raise Error('PLAN_ALREADY_CONSUMED', 'restored cleanup requires a new quarantine')
        if record['purge_plan'] is not None:
            _validate_purge(profile, record['purge_plan'], record)
            if _verify(profile, record, quarantine)['status'] == 'Failed':
                raise Error('SOURCE_CHANGED', 'partial purge no longer matches its manifest')
            return copy.deepcopy(record['purge_plan'])
        if record['state'] != 'Quarantined' or _verify(profile, record, quarantine)['status'] != 'Passed':
            raise Error('CLEANUP_INCOMPLETE', 'only completed owned quarantine can be purged')
        authorization = _purge_authorization(record, approval)
        report = _qualification(profile, record['quarantine_plan']['request'], _relocations(record, quarantine))
        if report['material_sha256'] != record['quarantine_plan']['material_sha256']:
            raise Error('SOURCE_CHANGED', 'cleanup retained evidence or consumer set changed')
        for item in record['quarantine_plan']['items']:
            _sample(profile, quarantine, item['quarantine_relative'], quarantine, records)
        plan = dc.seal({**_action_base(profile, record, 'purge'), 'authorization': authorization,
                        'qualification': report, 'material_sha256': report['material_sha256'], 'order': _purge_order(record['quarantine_plan'])})
        _reserve_purge_record(profile, record, plan)
        return plan


def _merge_observations(record, item_index, entries):
    progress = record['items'][item_index]
    original = record['quarantine_plan']['items'][item_index]['manifest']['entries']
    for index, entry in enumerate(original):
        actual = entries.get(entry['path'])
        if actual is None:
            continue
        change = {key: actual[key] for key in ('mtime_ns', 'ctime_ns') if actual[key] != entry[key]}
        if change:
            progress['observations'][str(index)] = change
        else:
            progress['observations'].pop(str(index), None)


def _ack_delete(profile, record, item_index, entry_index, entries, *, returned):
    progress = record['items'][item_index]
    if entry_index in progress['removed']:
        raise Error('JOURNAL_INVALID', 'purge entry was already acknowledged')
    _merge_observations(record, item_index, entries)
    progress['removed'].append(entry_index)
    progress['removal_evidence'][str(entry_index)] = 'syscall_returned_and_missing' if returned else 'observed_missing_after_intent'
    progress['location'] = 'purged' if 0 in progress['removed'] else 'quarantine'
    progress['state'] = 'Purged' if len(progress['removed']) == len(record['quarantine_plan']['items'][item_index]['manifest']['entries']) else 'PartiallyPurged'
    record['intent'] = None
    _save(profile, record)


def _check_delete_ancestors(profile, record, item_index, entry_index, quarantine, indices, budget):
    item = record['quarantine_plan']['items'][item_index]
    entry = item['manifest']['entries'][entry_index]
    names = []
    parent = Path(entry['path']).parent if entry['path'] != '.' else None
    while parent is not None:
        names.append(str(parent))
        if str(parent) == '.':
            break
        parent = parent.parent
    for name in reversed(names):
        index = indices[name]
        expected = _expected(record, item_index, index)
        _charge_meta(budget)
        actual = _stat_fields(dc.stat_entry(quarantine, _target(item, expected)), 'directory')
        expected.pop('path')
        if actual != expected:
            raise Error('SOURCE_CHANGED', 'purge ancestor metadata changed')


def _delete_entry(profile, record, item_index, entry_index, quarantine, indices, budget):
    item = record['quarantine_plan']['items'][item_index]
    entry = _expected(record, item_index, entry_index)
    _check_delete_ancestors(profile, record, item_index, entry_index, quarantine, indices, budget)
    _charge_meta(budget)
    target = _target(item, entry)
    dc.validate_path_spelling(quarantine, target)
    if entry['kind'] == 'file':
        actual = {'path': entry['path'], **_hash_file(quarantine, target, budget)}
    else:
        budget.charge_entry()
        actual = {'path': entry['path'], **_stat_fields(dc.stat_entry(quarantine, target), 'directory')}
    if actual != entry:
        raise Error('SOURCE_CHANGED', 'purge entry fingerprint changed')
    action = 'unlink' if entry['kind'] == 'file' else 'rmdir'
    record['intent'] = {'action': action, 'item_index': item_index, 'entry_index': entry_index, 'expected': entry}
    _save(profile, record)
    with dc.parent_fd(quarantine, target) as (fd, name):
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        expected_meta = {k: v for k, v in entry.items() if k not in {'path', 'sha256'}}
        if _stat_fields(current, entry['kind']) != expected_meta:
            raise Error('SOURCE_CHANGED', 'purge entry changed before its syscall')
        # No portable compare-and-unlink exists. External writers must be paused.
        if action == 'unlink':
            os.unlink(name, dir_fd=fd)
        else:
            os.rmdir(name, dir_fd=fd)
        _sync(fd)
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Error('SOURCE_CHANGED', 'purge entry was recreated after deletion')
        parent_name = str(Path(entry['path']).parent) if entry['path'] != '.' else None
        parent_entries = {}
        if parent_name is not None:
            parent_entries[parent_name] = {'path': parent_name, **_stat_fields(os.fstat(fd), 'directory')}
    _ack_delete(profile, record, item_index, entry_index, parent_entries, returned=True)


def _purge_continue(profile, record, quarantine, records):
    plan = record['purge_plan']
    _validate_purge(profile, plan, record)
    budget = dc.HashBudget(profile.budgets)
    locations = _locations(profile, record, quarantine, budget)
    if record['state'] == 'Purged':
        if _verify(profile, record, quarantine)['status'] != 'Passed':
            raise Error('SOURCE_CHANGED', 'completed purge no longer verifies')
        return record
    try:
        _before_write(profile)
        if any(location == 'source' for location, _, _ in locations):
            raise Error('SOURCE_OCCUPIED', 'purge cannot act on source-project payload')
        intent = record['intent']
        if intent is not None:
            if intent['action'] not in {'unlink', 'rmdir'}:
                raise Error('INTERRUPT_AMBIGUOUS', 'purge cannot consume another action intent')
            index, node = intent['item_index'], intent['entry_index']
            entries, pending_missing = locations[index][1:]
            if pending_missing:
                _ack_delete(profile, record, index, node, entries, returned=False)
            else:
                # The old intent is still pending with the exact original object.
                # Reissuing only this explicitly approved deletion is safe after
                # full remaining-manifest validation; it is not an inferred loss.
                record['intent'] = None
                _save(profile, record)
        _forward(profile, record, quarantine, plan['material_sha256'])
        record['state'], record['direction'] = 'Purging', 'purge'
        _save(profile, record)
        lookups = [{entry['path']: index for index, entry in enumerate(item['manifest']['entries'])} for item in record['quarantine_plan']['items']]
        sampled = set()
        for item_index, entry_index in plan['order']:
            if entry_index in record['items'][item_index]['removed']:
                continue
            item = record['quarantine_plan']['items'][item_index]
            if item_index not in sampled:
                if _exists(profile.root, item['source']):
                    raise Error('SOURCE_OCCUPIED', 'the original cleanup path acquired new material')
                _forward(profile, record, quarantine, plan['material_sha256'])
                _sample(profile, quarantine, item['quarantine_relative'], quarantine, records)
                sampled.add(item_index)
            _delete_entry(profile, record, item_index, entry_index, quarantine, lookups[item_index], budget)
        _container(profile, record, quarantine)
        if any(_exists(quarantine, item['quarantine_relative']) for item in record['quarantine_plan']['items']):
            raise Error('PURGE_INCOMPLETE', 'purge payload still exists')
        record['state'], record['last_error'] = 'Purged', None
        _save(profile, record)
        return record
    except BaseException as error:
        _failure(profile, record, error)
        raise


def purge(profile, plan, quarantine_root, records_dir, *, approve_plan):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    plan = _artifact(profile, plan)
    validate_plan(profile, plan)
    if plan['kind'] != 'purge':
        raise Error('ARTIFACT_INVALID', 'permanent deletion requires its purge plan')
    _approve(plan, approve_plan)
    with _locks(profile, quarantine, records, roots):
        record = _load(profile, plan['journal_path'], quarantine, records, roots)
        _validate_purge(profile, plan, record)
        if record['restore_plan'] is not None:
            raise Error('PLAN_ALREADY_CONSUMED', 'restored payload cannot be purged')
        if record['purge_plan'] is None:
            if record['state'] != 'Quarantined' or record['fingerprint'] != plan['journal_fingerprint'] or record['record_owner'] != plan['journal_identity']:
                raise Error('JOURNAL_CHANGED', 'purge preview is stale')
            _reserve_purge_record(profile, record, plan)
            # Reject already observable new consumers before committing the
            # irreversible direction. The continuation rechecks after this save.
            _forward(profile, record, quarantine, plan['material_sha256'])
            record['purge_plan'], record['direction'] = plan, 'purge'
            _save(profile, record)
        elif record['purge_plan']['fingerprint'] != plan['fingerprint']:
            raise Error('SOURCE_CHANGED', 'another purge is already active')
        return _purge_continue(profile, record, quarantine, records)


def recover(profile, journal, quarantine_root, records_dir, *, approve_plan=None, approve_purge=None):
    quarantine, records, roots = _roots(profile, quarantine_root, records_dir)
    with _locks(profile, quarantine, records, roots):
        record = _load(profile, journal, quarantine, records, roots)
        if record['purge_plan'] is not None:
            if record['state'] == 'Purged':
                if _verify(profile, record, quarantine)['status'] != 'Passed':
                    raise Error('SOURCE_CHANGED', 'purged cleanup no longer verifies')
                return record
            _approve(record['purge_plan'], approve_purge)
            return _purge_continue(profile, record, quarantine, records)
        if record['restore_plan'] is not None:
            if record['state'] == 'Restored':
                if _verify(profile, record, quarantine)['status'] != 'Passed':
                    raise Error('SOURCE_CHANGED', 'restored cleanup no longer verifies')
                return record
            _approve(record['restore_plan'], approve_plan)
            return _move_continue(profile, record, quarantine, records, 'restore')
        if record['state'] == 'Quarantined':
            if _verify(profile, record, quarantine)['status'] != 'Passed':
                raise Error('SOURCE_CHANGED', 'quarantined cleanup no longer verifies')
            return record
        _approve(record['quarantine_plan'], approve_plan)
        return _move_continue(profile, record, quarantine, records, 'quarantine')
