"""Project-only search settings, native rg validation and owned-file recovery.

Plans/journals contain private exact configuration bytes. Callers must expose
only summaries and save these artifacts with the common private writer.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import selectors
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path

from . import changes as c
from . import directory_common as dc
from .jsonc_edit import merge_settings

BEGIN = '# BEGIN FIFAN DIRECTORY SEARCH'
END = '# END FIFAN DIRECTORY SEARCH'
KIND = 'search-config'
CONFIG_LIMIT = 2 * 1024 * 1024


def _fail(code):
    raise dc.DirectoryError(code, code)


def _reason(error, default):
    code = getattr(error, 'reason_code', str(error))
    return code if isinstance(code, str) and 1 < len(code) < 80 and all(ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for ch in code) else default


def _settings(data, targets):
    try:
        return merge_settings(data, targets)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise dc.DirectoryError('CONFIG_CONFLICT', 'settings cannot be merged unambiguously') from exc


def _budget(profile, key, default):
    value = profile.budgets.get(key, default)
    return min(value, default)


def _identity(st):
    return {'device': st.st_dev, 'inode': st.st_ino}


def _same(st, owner):
    return owner is not None and _identity(st) == owner


def _binding(profile):
    st = dc.stat_entry(profile.root, '.')
    identity = (st.st_dev, st.st_ino)
    if profile._root_identity and identity != profile._root_identity:
        _fail('SOURCE_CHANGED')
    return {'root': str(profile.root), 'profile_sha256': profile.sha256,
            'config_sha256': dc.digest(profile.config), 'root_identity': _identity(st)}


def _format(profile, format, operation_id=None):
    return {'format': format, 'schema_version': 1, 'kind': KIND,
            **_binding(profile), 'operation_id': operation_id or uuid.uuid4().hex}


def _check_binding(profile, value, format):
    dc.validate_seal(value)
    if (value.get('format') != format or value.get('schema_version') != 1
            or value.get('kind') != KIND or any(value.get(k) != v for k, v in _binding(profile).items())
            or not isinstance(value.get('operation_id'), str) or len(value['operation_id']) != 32
            or any(x not in '0123456789abcdef' for x in value['operation_id'])):
        _fail('CONFIG_CHANGED')


def _record_limit(profile):
    return _budget(profile, 'max_artifact_bytes', 32 * 1024 * 1024)


def _encoded(data, mode, owner=None):
    return {'base64': base64.b64encode(data).decode('ascii'), 'sha256': hashlib.sha256(data).hexdigest(),
            'bytes': len(data), 'mode': mode, 'owner': owner}


def _decode(item):
    if not isinstance(item, dict) or set(item) != {'base64', 'sha256', 'bytes', 'mode', 'owner'}:
        _fail('BAD_JOURNAL')
    if not isinstance(item['base64'], str) or len(item['base64']) > 4 * ((CONFIG_LIMIT + 2) // 3):
        _fail('BUDGET_EXCEEDED')
    try:
        data = base64.b64decode(item['base64'], validate=True)
    except (ValueError, TypeError) as exc:
        raise dc.DirectoryError('BAD_JOURNAL', 'invalid private configuration record') from exc
    if (len(data) != item['bytes'] or len(data) > CONFIG_LIMIT or hashlib.sha256(data).hexdigest() != item['sha256']
            or type(item['mode']) is not int or not 0 <= item['mode'] <= 0o7777):
        _fail('BAD_JOURNAL')
    owner = item['owner']
    if owner is not None and (not isinstance(owner, dict) or set(owner) != {'device', 'inode'}
                              or any(type(n) is not int or n < 0 for n in owner.values())):
        _fail('BAD_JOURNAL')
    return data


def _validate_observed_spelling(profile, rel):
    try:
        dc.validate_path_spelling(profile.root, rel, allow_missing=True)
        return
    except dc.DirectoryError as error:
        if error.reason_code != 'PATH_ALIAS':
            raise
        alias_error = error
    # Darwin F_GETPATH may return a different valid hard-link name for a file
    # descriptor. Validate the parent normally, then prove this exact basename
    # exists in that pinned directory; inode equality alone never grants a name.
    parent = str(Path(rel).parent)
    dc.validate_path_spelling(profile.root, parent)
    with dc.parent_fd(profile.root, rel) as (fd, name):
        expected = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(expected.st_mode) or expected.st_nlink <= 1:
            raise alias_error
        limit = _budget(profile, 'max_entries', 200000)
        deadline = time.monotonic() + _budget(profile, 'max_seconds', 60)
        visited = 0
        with os.scandir(fd) as entries:
            for entry in entries:
                visited += 1
                if visited > limit or time.monotonic() >= deadline:
                    _fail('BUDGET_EXCEEDED')
                if entry.name != name:
                    continue
                observed = entry.stat(follow_symlinks=False)
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (not stat.S_ISREG(observed.st_mode) or _identity(observed) != _identity(expected)
                        or _identity(current) != _identity(expected)):
                    _fail('SOURCE_CHANGED')
                return
        if time.monotonic() >= deadline:
            _fail('BUDGET_EXCEEDED')
    raise alias_error


def _observe(profile, rel):
    _binding(profile)
    dc.relative(rel)
    if dc.protected(profile, rel):
        _fail('PROTECTED_PATH')
    _validate_observed_spelling(profile, rel)
    try:
        with c._parent(profile.root, rel) as (fd, name):
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                _fail('UNSUPPORTED_ENTRY')
            data = dc.read_file(profile.root, rel, CONFIG_LIMIT)
            after = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode):
                _fail('SOURCE_CHANGED')
            return _encoded(data, stat.S_IMODE(after.st_mode), _identity(after))
    except FileNotFoundError:
        # Missing parent is allowed only after checking every existing ancestor.
        if not c._missing(profile.root, rel):
            _fail('SOURCE_CHANGED')
        return None


def _match(profile, rel, expected, owner=True):
    current = _observe(profile, rel)
    if expected is None:
        if current is not None:
            _fail('TARGET_OCCUPIED')
    elif current is None or any(current[k] != expected[k] for k in ('sha256', 'bytes', 'mode')):
        _fail('SOURCE_CHANGED')
    elif owner and current['owner'] != expected['owner']:
        _fail('OWNERSHIP_CHANGED')
    return current


def _ignore_path(rel):
    return ''.join('\\' + ch if ch in '*?[]{}!# \\' else ch for ch in rel)


def _vscode_path(rel):
    return ''.join({'*': '[*]', '?': '[?]', '[': '[[]', ']': '[]]', '{': '[{]', '}': '[}]'}.get(ch, ch) for ch in rel) + '/**'


def _ignore(data, excludes):
    try:
        text = data.decode('utf-8')
    except UnicodeError as exc:
        raise ValueError('CONFIG_CONFLICT') from exc
    lines = text.splitlines(keepends=True)
    starts, ends, offset = [], [], 0
    for line in lines:
        bare = line.rstrip('\r\n')
        if 'FIFAN DIRECTORY SEARCH' in bare:
            if bare == BEGIN:
                starts.append(offset)
            elif bare == END:
                ends.append(offset + len(line))
            else:
                _fail('CONFIG_CONFLICT')
        offset += len(line)
    if len(starts) > 1 or len(ends) > 1 or bool(starts) != bool(ends) or starts and starts[0] >= ends[0]:
        _fail('CONFIG_CONFLICT')
    outside = text if not starts else text[:starts[0]] + text[ends[0]:]
    # Exact user counter-rules are an explicit conflict, not ours to override.
    for line in outside.splitlines():
        if line.startswith('!'):
            rule = line[1:].lstrip('/').rstrip('/')
            if rule.endswith('/**'):
                rule = rule[:-3]
            if rule in excludes or rule in {_ignore_path(p) for p in excludes}:
                _fail('CONFIG_CONFLICT')
    newline = '\r\n' if '\r\n' in text else '\n'
    block = newline.join([BEGIN] + ['/' + _ignore_path(p) + '/' for p in excludes] + [END, ''])
    if starts:
        return (text[:starts[0]] + block + text[ends[0]:]).encode('utf-8')
    return (text + (newline if text and not text.endswith(('\n', '\r')) else '') + block).encode('utf-8')


def _search(profile, require_directories=False):
    search = profile.data.get('search', {})
    excludes = search.get('exclude', [])
    if (not isinstance(excludes, list) or any(not isinstance(p, str) for p in excludes)
            or len({dc.path_key(p) for p in excludes}) != len(excludes)):
        _fail('CONFIG_CONFLICT')
    for rel in excludes:
        dc.relative(rel)
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in rel):
            _fail('UNSUPPORTED_PATH')
        if dc.protected(profile, rel) or rel == '.vscode' or rel.startswith('.vscode/'):
            _fail('PROTECTED_PATH')
        if require_directories:
            dc.validate_path_spelling(profile.root, rel)
            st = dc.stat_entry(profile.root, rel)
            if not stat.S_ISDIR(st.st_mode):
                _fail('UNSUPPORTED_ENTRY')
    for name in ('vscode', 'watcher_exclude'):
        if type(search.get(name, False)) is not bool:
            _fail('CONFIG_CONFLICT')
    return search, excludes


def _files(profile):
    search, excludes = _search(profile, require_directories=True)
    result = []
    paths = ['.ignore'] + (['.vscode/settings.json'] if search.get('vscode', False) or search.get('watcher_exclude', False) else [])
    for rel in paths:
        before = _observe(profile, rel)
        data = _decode(before) if before else b''
        if rel == '.ignore':
            after = _ignore(data, excludes)
        else:
            targets = {}
            if search.get('vscode', False):
                targets['search.exclude'] = {_vscode_path(p): True for p in excludes}
            if search.get('watcher_exclude', False):
                targets['files.watcherExclude'] = {_vscode_path(p): True for p in excludes}
            after = _settings(data if before else b'{}\n', targets)
        if len(after) > CONFIG_LIMIT:
            _fail('BUDGET_EXCEEDED')
        result.append({'path': rel, 'before': before,
                       'after': _encoded(after, before['mode'] if before else 0o600),
                       'changed': before is None or data != after})
    return result


def search_preview(profile):
    with dc.root_lock(profile.root):
        result = {**_format(profile, 'fifan-directory-plan'), 'status': 'Preview',
                  'files': _files(profile), 'search': copy.deepcopy(profile.data['search']),
                  'native_validation': 'Not run', 'vscode_ui': 'Not run'}
        result = dc.seal(result)
        if len(dc.canonical(result)) > _record_limit(profile) // 2:
            _fail('BUDGET_EXCEEDED')
        return result


def _records(profile, records_dir):
    root = dc.safe_root(records_dir)
    project_root = dc.safe_root(profile.root)
    if dc.roots_overlap(project_root, root):
        _fail('ROOT_OVERLAP')
    archive = profile.data.get('archive', {})
    declared = archive.get('records_dir')
    if declared is not None and root != dc.canonical_destination(declared):
        _fail('ROOT_GRANT_MISMATCH')
    arc = archive.get('archive_root')
    if arc:
        path = dc.canonical_destination(arc)
        if root == path or root in path.parents or path in root.parents:
            _fail('ROOT_OVERLAP')
    return root


def _save(profile, journal, new=False):
    if not new:
        current = dc.load_artifact(Path(journal['journal_path']), _record_limit(profile))
        dc.validate_seal(current)
        if current.get('fingerprint') != journal.get('fingerprint'):
            _fail('JOURNAL_CHANGED')
    sealed = dc.seal(journal)
    dc.write_artifact(Path(journal['journal_path']), sealed, replace=not new, limit=_record_limit(profile))
    journal['fingerprint'] = sealed['fingerprint']


def _critical(profile, paths):
    result = {}
    for rel in profile.data.get('critical_paths', []):
        dc.relative(rel)
        dc.validate_path_spelling(profile.root, rel)
        if dc.protected(profile, rel):
            _fail('PROTECTED_PATH')
        st = dc.stat_entry(profile.root, rel)
        selected = {p for p in paths if p == rel or p.startswith(rel + '/')} if stat.S_ISDIR(st.st_mode) else {rel} & paths
        if not selected:
            _fail('CRITICAL_HIDDEN')
        result[rel] = selected
    return result


def _rg(profile):
    executable = shutil.which('rg')
    if executable is None:
        _fail('ENGINE_UNAVAILABLE')
    try:
        executable = dc.canonical_destination(Path(executable).resolve(strict=True))
    except (OSError, ValueError) as error:
        raise dc.DirectoryError('ENGINE_UNAVAILABLE', 'native search engine unavailable') from error
    # PATH may contain the inspected project, including through a symlink.
    # Selecting a tool is never permission to execute project-owned material.
    if executable.is_relative_to(profile.root):
        _fail('ENGINE_UNAVAILABLE')
    seconds = _budget(profile, 'max_seconds', 60)
    deadline = time.monotonic() + seconds
    try:
        version = subprocess.run([executable, '--version'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=min(seconds, 5), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise dc.DirectoryError('ENGINE_UNAVAILABLE', 'native search engine unavailable') from exc
    if version.returncode or len(version.stdout) > 16384:
        _fail('ENGINE_UNAVAILABLE')
    engine = version.stdout.splitlines()[0].decode('ascii', errors='replace')
    limit = _budget(profile, 'max_entries', 200000)
    byte_limit = _budget(profile, 'max_artifact_bytes', 32 * 1024 * 1024)
    process = subprocess.Popen([executable, '--files', '--no-config', '-0'], cwd=profile.root,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    paths, pending, total, stderr, entries = set(), b'', 0, 0, 0
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail('ENGINE_TIMEOUT')
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > byte_limit:
                    _fail('BUDGET_EXCEEDED')
                if key.fileobj is process.stderr:
                    stderr += len(chunk)
                    continue
                parts = (pending + chunk).split(b'\0')
                pending = parts.pop()
                for raw in parts:
                    entries += 1
                    if entries > limit:
                        _fail('BUDGET_EXCEEDED')
                    rel = os.fsdecode(raw)
                    if rel.startswith('./'):
                        rel = rel[2:]
                    dc.relative(rel)
                    paths.add(rel)
                    if len(paths) > limit:
                        _fail('BUDGET_EXCEEDED')
                if len(pending) > 65536:
                    _fail('BUDGET_EXCEEDED')
        rc = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if pending or stderr or rc not in (0, 1) or rc == 1 and paths:
            _fail('ENGINE_INCOMPLETE')
        return paths, {'status': 'Passed', 'engine': engine, 'argv': ['rg', '--files', '--no-config', '-0'],
                       'scope': '.', 'returncode': rc, 'visible_files': len(paths),
                       'list_sha256': dc.digest(sorted(paths)), 'stream_bytes': total,
                       'limits': {'max_entries': limit, 'max_seconds': seconds, 'max_stream_bytes': byte_limit}}
    except subprocess.TimeoutExpired as exc:
        raise dc.DirectoryError('ENGINE_TIMEOUT', 'native search engine timed out') from exc
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()


def _validation(profile, before, after):
    old, old_summary = before
    new, new_summary = after
    if old_summary['engine'] != new_summary['engine']:
        _fail('ENGINE_CHANGED')
    critical = _critical(profile, old)
    _critical(profile, new)
    if any(not files <= new for files in critical.values()):
        _fail('CRITICAL_HIDDEN')
    excludes = profile.data['search']['exclude']
    excluded = lambda p: any(p == rel or p.startswith(rel + '/') for rel in excludes)
    if any(not excluded(p) for p in old - new) or any(excluded(p) for p in new):
        _fail('SEARCH_SCOPE_MISMATCH')
    return {'status': 'Passed', 'before': old_summary, 'after': new_summary,
            'hidden_files': len(old - new), 'critical_paths': {p: 'Passed' for p in critical},
            'critical_scope': {p: {'visible_files': len(files), 'list_sha256': dc.digest(sorted(files))}
                               for p, files in _critical(profile, new).items()},
            'vscode_ui': 'Not run', 'storage_reduction': 'Not applicable'}


def _validate_files(profile, plan):
    files = plan.get('files')
    expected_paths = ['.ignore'] + (['.vscode/settings.json'] if profile.data['search'].get('vscode') or profile.data['search'].get('watcher_exclude') else [])
    if not isinstance(files, list) or len(files) > 2 or any(not isinstance(f, dict) for f in files) or [f.get('path') for f in files] != expected_paths:
        _fail('BAD_JOURNAL')
    search, excludes = _search(profile)
    for item in files:
        if set(item) != {'path', 'before', 'after', 'changed'} or type(item['changed']) is not bool:
            _fail('BAD_JOURNAL')
        if item['before'] is not None and item['before'].get('owner') is None:
            _fail('BAD_JOURNAL')
        before = _decode(item['before']) if item['before'] is not None else b''
        after = _decode(item['after'])
        expected = (_ignore(before, excludes) if item['path'] == '.ignore' else _settings(before if item['before'] else b'{}\n',
                    {name: {_vscode_path(p): True for p in excludes} for name, enabled in
                     [('search.exclude', search.get('vscode')), ('files.watcherExclude', search.get('watcher_exclude'))] if enabled}))
        mode = item['before']['mode'] if item['before'] is not None else 0o600
        if after != expected or item['after']['mode'] != mode or item['after']['owner'] is not None or item['changed'] != (item['before'] is None or before != after):
            _fail('BAD_JOURNAL')


def _check_plan(profile, plan):
    try:
        _check_binding(profile, plan, 'fifan-directory-plan')
        _validate_files(profile, plan)
        if plan.get('search') != profile.data['search']:
            _fail('CONFIG_CHANGED')
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeError) as exc:
        raise dc.DirectoryError('BAD_JOURNAL', 'invalid search plan structure') from exc


def _load_journal_data(profile, journal):
    if not isinstance(journal, dict):
        journal = dc.load_artifact(journal, _record_limit(profile))
    else:
        journal = copy.deepcopy(journal)
    _check_binding(profile, journal, 'fifan-directory-journal')
    _check_plan(profile, journal['plan'])
    path = dc.canonical_destination(journal['journal_path'], allow_missing_parents=False)
    if path.name != journal['operation_id'] + '.directory.json' or path.parent == profile.root or profile.root in path.parents:
        _fail('BAD_JOURNAL')
    if journal['operation_id'] != journal['plan']['operation_id'] or len(journal['entries']) != len(journal['plan']['files']):
        _fail('BAD_JOURNAL')
    for entry, item in zip(journal['entries'], journal['plan']['files']):
        if (not isinstance(entry, dict) or set(entry) != {'path', 'applied', 'after_owner', 'restored', 'restored_owner'}
                or entry['path'] != item['path'] or type(entry['applied']) is not bool or type(entry['restored']) is not bool):
            _fail('BAD_JOURNAL')
        for key in ('after_owner', 'restored_owner'):
            owner = entry[key]
            if owner is not None and (not isinstance(owner, dict) or set(owner) != {'device', 'inode'} or any(type(x) is not int or x < 0 for x in owner.values())):
                _fail('BAD_JOURNAL')
        if ((entry['applied'] and entry['after_owner'] is None) or (not entry['applied'] and entry['after_owner'] is not None)
                or entry['restored'] and not entry['applied'] or not item['changed'] and entry['applied']
                or (entry['restored'] and item['before'] is not None and entry['restored_owner'] is None)
                or (entry['restored_owner'] is not None and (not entry['restored'] or item['before'] is None))):
            _fail('BAD_JOURNAL')
        if journal['state'] == 'Applied' and (entry['applied'] != item['changed'] or entry['restored']):
            _fail('BAD_JOURNAL')
        if journal['state'] in {'Restored', 'RolledBack', 'Recovered'} and entry['applied'] and not entry['restored']:
            _fail('BAD_JOURNAL')
    if journal['directory_intent'] not in (None, '.vscode') or not isinstance(journal['created_dirs'], list) or len(journal['created_dirs']) > 1:
        _fail('BAD_JOURNAL')
    for directory in journal['created_dirs']:
        if (not isinstance(directory, dict) or set(directory) != {'path', 'owner'} or directory['path'] != '.vscode'
                or '.vscode/settings.json' not in [i['path'] for i in journal['plan']['files']]
                or not isinstance(directory['owner'], dict) or set(directory['owner']) != {'device', 'inode'}
                or any(type(n) is not int or n < 0 for n in directory['owner'].values())):
            _fail('BAD_JOURNAL')
    cleanup = journal.get('directory_cleanup')
    if cleanup is not None:
        if (not isinstance(cleanup, dict) or set(cleanup) != {'path', 'owner', 'phase'}
                or cleanup['phase'] not in {'intent', 'removed', 'retained'}
                or not any(cleanup['path'] == d['path'] and cleanup['owner'] == d['owner'] for d in journal['created_dirs'])
                or any(e['applied'] and not e['restored'] for e in journal['entries'])):
            _fail('BAD_JOURNAL')
    if journal['state'] not in {'Applying', 'Applied', 'Blocked', 'Restoring', 'Restored', 'RolledBack', 'Recovered'}:
        _fail('BAD_JOURNAL')
    return journal


def _load_journal(profile, journal):
    try:
        return _load_journal_data(profile, journal)
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeError) as exc:
        raise dc.DirectoryError('BAD_JOURNAL', 'invalid search journal structure') from exc


def _disk_journal(profile, journal):
    path = Path(journal['journal_path'])
    current = dc.load_artifact(path, _record_limit(profile))
    if current != journal:
        _fail('JOURNAL_CHANGED')


def _owned_expected(item, owner):
    result = copy.deepcopy(item)
    result['owner'] = owner
    return result


def _unlink_owned(profile, rel, expected):
    _match(profile, rel, expected)
    with c._parent(profile.root, rel) as (fd, name):
        if not _same(os.stat(name, dir_fd=fd, follow_symlinks=False), expected['owner']):
            _fail('OWNERSHIP_CHANGED')
        os.unlink(name, dir_fd=fd)
        os.fsync(fd)


def _temp_cleanup(profile, pending, desired):
    temp = pending.get('temp')
    if temp is None:
        return
    observed = _observe(profile, temp)
    if observed is not None:
        if observed['owner'] != pending['owner']:
            _fail('OWNERSHIP_CHANGED')
        expected = _owned_expected(desired, pending['owner'])
        _match(profile, temp, expected)
        _unlink_owned(profile, temp, expected)


def _ensure_parent(profile, journal, rel):
    if rel != '.vscode/settings.json':
        return
    try:
        st = dc.stat_entry(profile.root, '.vscode')
        if not stat.S_ISDIR(st.st_mode):
            _fail('UNSUPPORTED_ENTRY')
        return
    except FileNotFoundError:
        pass
    journal['directory_intent'] = '.vscode'
    _save(profile, journal)
    with c._parent(profile.root, '.vscode') as (fd, name):
        os.mkdir(name, 0o700, dir_fd=fd)
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
    journal['created_dirs'].append({'path': '.vscode', 'owner': _identity(st)})
    journal['directory_intent'] = None
    _save(profile, journal)


def _publish(profile, journal, index, direction):
    item, entry = journal['plan']['files'][index], journal['entries'][index]
    expected = item['before'] if direction == 'apply' else _owned_expected(item['after'], entry['after_owner'])
    desired = item['after'] if direction == 'apply' else item['before']
    _match(profile, item['path'], expected)
    _ensure_parent(profile, journal, item['path'])
    temp = str(Path(item['path']).parent / ('.fifan-search-' + journal['operation_id'] + '-' + str(index) + '-' + direction + '-' + uuid.uuid4().hex + '.tmp'))
    pending = {'index': index, 'direction': direction, 'temp': temp, 'owner': None}
    journal['pending'] = pending
    _save(profile, journal)
    with c._parent(profile.root, temp) as (fd, name):
        f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, desired['mode'], dir_fd=fd)
        try:
            data = _decode(desired)
            view = memoryview(data)
            while view:
                written = os.write(f, view)
                if written <= 0:
                    raise OSError('short configuration write')
                view = view[written:]
            os.fchmod(f, desired['mode'])
            os.fsync(f)
            pending['owner'] = _identity(os.fstat(f))
        finally:
            os.close(f)
        os.fsync(fd)
    _save(profile, journal)
    _match(profile, item['path'], expected)
    _match(profile, temp, _owned_expected(desired, pending['owner']))
    with c._parent(profile.root, item['path']) as (fd, name):
        temp_name = Path(temp).name
        if expected is None:
            os.link(temp_name, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        else:
            # Same final non-cooperating-writer window as changes._atomic.
            os.replace(temp_name, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    _match(profile, item['path'], _owned_expected(desired, pending['owner']))
    if direction == 'apply':
        entry['applied'], entry['after_owner'] = True, pending['owner']
    else:
        entry['restored'], entry['restored_owner'] = True, pending['owner']
    _save(profile, journal)
    _temp_cleanup(profile, pending, desired)
    journal['pending'] = None
    _save(profile, journal)


def _reconcile(profile, journal):
    _reconcile_directory_cleanup(profile, journal)
    if journal['directory_intent'] is not None:
        # A mkdir without persisted ownership is deliberately not guessed ours.
        try:
            dc.stat_entry(profile.root, journal['directory_intent'])
        except FileNotFoundError:
            journal['directory_intent'] = None
            _save(profile, journal)
        else:
            _fail('INTERRUPTED_AMBIGUOUS')
    pending = journal['pending']
    if pending is None:
        return
    index = pending.get('index')
    if type(index) is not int or not 0 <= index < len(journal['entries']):
        _fail('BAD_JOURNAL')
    item, entry = journal['plan']['files'][index], journal['entries'][index]
    direction = pending.get('direction')
    if (set(pending) != {'index', 'direction', 'temp', 'owner'} or direction not in {'apply', 'restore', 'remove'}
            or not item['changed'] or direction in {'restore', 'remove'} and not entry['applied']
            or direction == 'remove' and (item['before'] is not None or pending['temp'] is not None or pending['owner'] != entry['after_owner'])
            or direction == 'restore' and item['before'] is None):
        _fail('BAD_JOURNAL')
    current = _observe(profile, item['path'])
    if direction == 'remove':
        if current is None:
            entry['restored'] = True
        else:
            _match(profile, item['path'], _owned_expected(item['after'], entry['after_owner']))
    else:
        desired = item['after'] if direction == 'apply' else item['before']
        previous = item['before'] if direction == 'apply' else _owned_expected(item['after'], entry['after_owner'])
        if pending.get('owner') is not None and current == _owned_expected(desired, pending['owner']):
            if direction == 'apply':
                entry['applied'], entry['after_owner'] = True, pending['owner']
            else:
                entry['restored'], entry['restored_owner'] = True, pending['owner']
        else:
            _match(profile, item['path'], previous)
        temp = pending.get('temp')
        parent = str(Path(item['path']).parent)
        prefix = '.fifan-search-' + journal['operation_id'] + '-' + str(index) + '-' + direction + '-'
        if (not isinstance(temp, str) or str(Path(temp).parent) != parent
                or not Path(temp).name.startswith(prefix) or not Path(temp).name.endswith('.tmp')
                or len(Path(temp).name) != len(prefix) + 32 + len('.tmp')
                or any(ch not in '0123456789abcdef' for ch in Path(temp).name[len(prefix):-4])):
            _fail('BAD_JOURNAL')
        if pending.get('owner') is None and _observe(profile, temp) is not None:
            _fail('INTERRUPTED_AMBIGUOUS')
        _temp_cleanup(profile, pending, desired)
    journal['pending'] = None
    _save(profile, journal)


def _validate_current(profile, journal):
    if journal['pending'] is not None or journal['directory_intent'] is not None:
        _fail('INTERRUPTED_AMBIGUOUS')
    for item, entry in zip(journal['plan']['files'], journal['entries']):
        if entry['restored']:
            expected = _owned_expected(item['before'], entry['restored_owner']) if item['before'] else None
        elif entry['applied']:
            expected = _owned_expected(item['after'], entry['after_owner'])
        else:
            expected = item['before']
        _match(profile, item['path'], expected)
    for directory in journal['created_dirs']:
        try:
            st = dc.stat_entry(profile.root, directory['path'])
        except FileNotFoundError:
            cleanup = journal.get('directory_cleanup')
            if cleanup is not None and cleanup['path'] == directory['path'] and cleanup['phase'] == 'removed':
                continue
            _fail('OWNERSHIP_CHANGED')
        cleanup = journal.get('directory_cleanup')
        if cleanup is not None and cleanup['path'] == directory['path'] and cleanup['phase'] == 'removed':
            _fail('OWNERSHIP_CHANGED')
        if not stat.S_ISDIR(st.st_mode) or not _same(st, directory['owner']):
            _fail('OWNERSHIP_CHANGED')


def _reconcile_directory_cleanup(profile, journal):
    cleanup = journal.get('directory_cleanup')
    if cleanup is None:
        return
    try:
        st = dc.stat_entry(profile.root, cleanup['path'])
    except FileNotFoundError:
        if cleanup['phase'] not in {'intent', 'removed'}:
            _fail('OWNERSHIP_CHANGED')
        # The persisted intent predates rmdir. A missing directory is a known
        # deletion outcome, never evidence that a newly present inode is ours.
        if cleanup['phase'] != 'removed':
            with c._parent(profile.root, cleanup['path']) as (fd, _):
                os.fsync(fd)
            cleanup['phase'] = 'removed'
            _save(profile, journal)
        return
    if cleanup['phase'] == 'removed' or not stat.S_ISDIR(st.st_mode) or not _same(st, cleanup['owner']):
        _fail('OWNERSHIP_CHANGED')


def _cleanup_dirs(profile, journal):
    retained = []
    for directory in reversed(journal['created_dirs']):
        cleanup = journal.get('directory_cleanup')
        if cleanup is not None and cleanup['path'] == directory['path'] and cleanup['phase'] == 'removed':
            # _validate_current/_reconcile already reject any replacement here.
            continue
        with c._parent(profile.root, directory['path']) as (fd, name):
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode) or not _same(st, directory['owner']):
                _fail('OWNERSHIP_CHANGED')
            journal['directory_cleanup'] = {'path': directory['path'], 'owner': _identity(st), 'phase': 'intent'}
            _save(profile, journal)
            try:
                os.rmdir(name, dir_fd=fd)
            except OSError:
                journal['directory_cleanup']['phase'] = 'retained'
                retained.append(directory['path'])
            else:
                # A failed durability sync is not a failed deletion. Keep the
                # persisted intent so recover can confirm absence and sync it.
                os.fsync(fd)
                journal['directory_cleanup']['phase'] = 'removed'
            _save(profile, journal)
    journal['retained_directories'] = retained


def _restore_steps(profile, journal, terminal):
    _reconcile(profile, journal)
    _validate_current(profile, journal)
    journal['state'] = 'Restoring'
    _save(profile, journal)
    for index in reversed(range(len(journal['entries']))):
        item, entry = journal['plan']['files'][index], journal['entries'][index]
        if not entry['applied'] or entry['restored']:
            continue
        if item['before'] is not None:
            _publish(profile, journal, index, 'restore')
        else:
            expected = _owned_expected(item['after'], entry['after_owner'])
            _match(profile, item['path'], expected)
            journal['pending'] = {'index': index, 'direction': 'remove', 'temp': None, 'owner': entry['after_owner']}
            _save(profile, journal)
            _unlink_owned(profile, item['path'], expected)
            entry['restored'] = True
            journal['pending'] = None
            _save(profile, journal)
    _cleanup_dirs(profile, journal)
    journal['state'], journal['status'] = terminal, 'Passed'
    _save(profile, journal)
    _validate_current(profile, journal)
    return journal


def _verify_native(profile, record):
    current = _rg(profile)
    critical = _critical(profile, current[0])
    if record['state'] == 'Applied':
        critical_scope = {p: {'visible_files': len(files), 'list_sha256': dc.digest(sorted(files))}
                          for p, files in critical.items()}
        if not isinstance(record.get('validation'), dict) or critical_scope != record['validation'].get('critical_scope'):
            _fail('CRITICAL_CHANGED')
        excludes = profile.data['search']['exclude']
        if any(p == d or p.startswith(d + '/') for p in current[0] for d in excludes):
            _fail('SEARCH_SCOPE_MISMATCH')
    return current


def apply(profile, plan, records_dir):
    with dc.root_lock(profile.root):
        records = _records(profile, records_dir)
        _check_plan(profile, plan)
        path = records / (plan['operation_id'] + '.directory.json')
        try:
            existing = dc.load_artifact(path, _record_limit(profile))
        except FileNotFoundError:
            existing = None
        if existing is not None:
            journal = _load_journal(profile, existing)
            if journal['plan'] != plan or journal['state'] != 'Applied':
                _fail('OPERATION_NOT_REPLAYABLE')
            _validate_current(profile, journal)
            _verify_native(profile, journal)
            return journal
        if plan['files'] != _files(profile):
            _fail('SOURCE_CHANGED')
        journal = {**_format(profile, 'fifan-directory-journal', plan['operation_id']),
                   'journal_path': str(path), 'plan': copy.deepcopy(plan),
                   'state': 'Applying', 'status': 'Unknown', 'entries': [
                       {'path': item['path'], 'applied': False, 'after_owner': None,
                        'restored': False, 'restored_owner': None} for item in plan['files']],
                   'pending': None, 'directory_intent': None, 'directory_cleanup': None, 'created_dirs': [],
                   'retained_directories': [], 'baseline': None, 'validation': None, 'reason_code': None}
        _save(profile, journal, new=True)
        try:
            before = _rg(profile)
            critical = _critical(profile, before[0])
            reserve = 8192 + sum(2 * len(dc.canonical(path)) + 400 for path in critical)
            if len(dc.canonical(journal)) + reserve > _record_limit(profile):
                _fail('BUDGET_EXCEEDED')
            journal['baseline'] = before[1]
            _save(profile, journal)
            for index, item in enumerate(plan['files']):
                if item['changed']:
                    _publish(profile, journal, index, 'apply')
            after = _rg(profile)
            journal['validation'] = _validation(profile, before, after)
            _validate_current(profile, journal)
            journal['state'], journal['status'] = 'Applied', 'Passed'
            _save(profile, journal)
            return journal
        except Exception as exc:
            # Original failure is retained even when safe rollback succeeds.
            journal['reason_code'] = _reason(exc, 'SEARCH_VALIDATION_FAILED')
            journal['state'], journal['status'] = 'Blocked', 'Blocked'
            _save(profile, journal)
            try:
                _restore_steps(profile, journal, 'RolledBack')
                journal['status'] = 'Failed' if journal['reason_code'] in {'CRITICAL_HIDDEN', 'SEARCH_SCOPE_MISMATCH', 'ENGINE_CHANGED'} else 'Blocked'
                _save(profile, journal)
            except Exception:
                journal['state'], journal['status'] = 'Blocked', 'Blocked'
                _save(profile, journal)
            return journal


def verify(profile, journal):
    with dc.root_lock(profile.root):
        record = _load_journal(profile, journal)
        _disk_journal(profile, record)
        try:
            _validate_current(profile, record)
            current = _verify_native(profile, record)
            complete = record['state'] in {'Applied', 'Restored', 'Recovered', 'RolledBack'}
            return {**_binding(profile), 'kind': KIND, 'operation_id': record['operation_id'],
                    'journal_path': record['journal_path'], 'state': record['state'],
                    'status': 'Passed' if complete else 'Unknown', 'current_search': current[1], 'vscode_ui': 'Not run'}
        except (ValueError, OSError) as exc:
            return {**_binding(profile), 'kind': KIND, 'operation_id': record['operation_id'],
                    'journal_path': record['journal_path'], 'state': record['state'],
                    'status': 'Blocked', 'reason_code': _reason(exc, 'VERIFICATION_INCOMPLETE')}


def restore_preview(profile, journal):
    with dc.root_lock(profile.root):
        record = _load_journal(profile, journal)
        _disk_journal(profile, record)
        _validate_current(profile, record)
        if record['state'] not in {'Applied', 'Restored', 'RolledBack', 'Recovered'}:
            _fail('INTERRUPTED_AMBIGUOUS')
        return dc.seal({**_format(profile, 'fifan-directory-restore-plan'), 'status': 'Preview',
                        'journal_path': record['journal_path'], 'journal_fingerprint': record['fingerprint'],
                        'source_operation_id': record['operation_id'],
                        'files': [{'path': i['path'], 'action': 'restore_bytes' if i['before'] is not None else 'remove_owned_created_file'} for i in record['plan']['files'] if i['changed']],
                        'terminal_state': record['state']})


def restore(profile, restore_plan, records_dir):
    with dc.root_lock(profile.root):
        records = _records(profile, records_dir)
        _check_binding(profile, restore_plan, 'fifan-directory-restore-plan')
        record = _load_journal(profile, restore_plan['journal_path'])
        expected_files = [{'path': i['path'], 'action': 'restore_bytes' if i['before'] is not None else 'remove_owned_created_file'} for i in record['plan']['files'] if i['changed']]
        if restore_plan.get('files') != expected_files:
            _fail('BAD_JOURNAL')
        if dc.safe_root(Path(record['journal_path']).parent) != records or restore_plan['source_operation_id'] != record['operation_id']:
            _fail('ROOT_GRANT_MISMATCH')
        if record.get('restore_operation_id') == restore_plan['operation_id'] and record['state'] == 'Restored':
            _validate_current(profile, record)
            return record
        if record['fingerprint'] != restore_plan['journal_fingerprint']:
            _fail('JOURNAL_CHANGED')
        _validate_current(profile, record)
        record['restore_operation_id'] = restore_plan['operation_id']
        _save(profile, record)
        return _restore_steps(profile, record, 'Restored')


def recover(profile, journal, records_dir):
    with dc.root_lock(profile.root):
        records = _records(profile, records_dir)
        record = _load_journal(profile, journal)
        _disk_journal(profile, record)
        if dc.safe_root(Path(record['journal_path']).parent) != records:
            _fail('ROOT_GRANT_MISMATCH')
        if record['state'] in {'Applied', 'Restored', 'RolledBack', 'Recovered'}:
            _validate_current(profile, record)
            if record['state'] == 'Applied':
                _verify_native(profile, record)
            return record
        # Recovery finishes a begun restore, or safely rolls back a partial
        # application. It never claims an unvalidated interrupted apply passed.
        return _restore_steps(profile, record, 'Restored' if 'restore_operation_id' in record else 'Recovered')
