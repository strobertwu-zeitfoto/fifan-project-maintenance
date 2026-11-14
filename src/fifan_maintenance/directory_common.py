"""Shared data contracts and descriptor-relative primitives for directory tasks.

Profiles select scope; they do not grant runtime permission to write external
roots. No helper executes project configuration, commands or plugins.
"""
from __future__ import annotations

import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import secrets
import stat
import sys
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .changes import _project_lock
from .diagnostics import DiagnosticError
from .inventory import excluded
from .project import read_bytes, relative_parts, strict_json

MiB = 1024 * 1024
GiB = 1024 * MiB
MAX_PROFILE_BYTES = 256 * 1024
DEFAULT_BUDGETS = {
    'max_entries': 200000, 'max_seconds': 60, 'max_depth': 16,
    'max_output_bytes': 8192, 'max_hash_entries': 20000,
    'max_hash_bytes': 2 * GiB, 'max_hash_file_bytes': 512 * MiB,
    'max_artifact_bytes': 32 * MiB, 'max_reference_bytes': 64 * MiB,
    'max_reference_file_bytes': 4 * MiB, 'max_reference_files': 20000,
}
HARD_BUDGETS = {
    'max_entries': 1000000, 'max_seconds': 300, 'max_depth': 128,
    'max_output_bytes': 30720, 'max_hash_entries': 100000,
    'max_hash_bytes': 64 * GiB, 'max_hash_file_bytes': 4 * GiB,
    'max_artifact_bytes': 128 * MiB, 'max_reference_bytes': 256 * MiB,
    'max_reference_file_bytes': 16 * MiB, 'max_reference_files': 100000,
}
PROFILE_FIELDS = {'schema_version', 'project_root', 'preset', 'scan_roots',
                  'critical_paths', 'reference_sources', 'classifications',
                  'search', 'archive', 'budgets', 'streaming_references', 'reference_batching'}


class DirectoryError(DiagnosticError):
    """Controlled failure: reason_code and integer/hash metadata are safe to show."""


@dataclass
class DirectoryProfile:
    root: Path
    config: dict
    data: dict
    sha256: str
    budgets: dict
    _root_identity: tuple = field(default=(), init=False, repr=False)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise DirectoryError('INVALID_INPUT', 'value must be finite JSON data') from error


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def seal(value, field='fingerprint'):
    if not isinstance(value, dict) or not isinstance(field, str) or not field:
        raise DirectoryError('INVALID_INPUT', 'sealed artifact must be an object')
    result = copy.deepcopy(value)
    result.pop(field, None)
    result[field] = digest(result)
    return result


def validate_seal(value, field='fingerprint'):
    if not isinstance(value, dict) or not isinstance(value.get(field), str):
        raise DirectoryError('ARTIFACT_INVALID', 'artifact seal is missing')
    if value[field] != digest({k: v for k, v in value.items() if k != field}):
        raise DirectoryError('ARTIFACT_INVALID', 'artifact fingerprint mismatch')


def relative(path, allow_dot=False):
    if allow_dot and path == '.':
        return '.'
    try:
        relative_parts(path)
    except (ValueError, TypeError) as error:
        raise DirectoryError('PROTECTED_PATH', 'path must be canonical and relative') from error
    return path


def _key(value):
    return unicodedata.normalize('NFC', unicodedata.normalize('NFC', value).casefold())


def path_key(path):
    """Conservative alias comparison only; never turn this key into an IO path.

    Case-sensitive volumes may distinguish keys that this policy merges. Such
    ambiguity is rejected rather than used to broaden an authorization.
    """
    relative(path, allow_dot=True)
    return _key(path)


def _absolute(path):
    if not isinstance(path, (str, os.PathLike)):
        raise DirectoryError('INVALID_INPUT', 'absolute path required')
    text = os.fspath(path)
    if not isinstance(text, str) or not text or '\x00' in text or '\\' in text:
        raise DirectoryError('INVALID_INPUT', 'invalid absolute path')
    result = Path(text)
    if not result.is_absolute() or any(p in {'.', '..', ''} for p in text.split('/')[1:]) and text != '/':
        raise DirectoryError('PROTECTED_PATH', 'absolute path must be canonical')
    return result


def _identity(info):
    return info.st_dev, info.st_ino


def _stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_directory(path):
    path = _absolute(path)
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise DirectoryError('SAFE_IO_UNAVAILABLE', 'descriptor-relative IO unavailable')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _fd_path(fd):
    # Verified against the local Darwin SDK sys/fcntl.h and sys/syslimits.h:
    # F_GETPATH=50, PATH_MAX=1024. This asks the kernel, not a directory listing.
    if sys.platform != 'darwin':
        raise DirectoryError('SAFE_IO_UNAVAILABLE', 'native canonical FD paths unavailable')
    try:
        raw = fcntl.fcntl(fd, 50, b'\0' * 1024)
    except OSError as error:
        raise DirectoryError('SAFE_IO_UNAVAILABLE', 'native canonical FD path lookup failed') from error
    value = raw.split(b'\0', 1)[0]
    if not value or len(value) >= 1024:
        raise DirectoryError('SAFE_IO_UNAVAILABLE', 'native canonical FD path unavailable')
    return _absolute(os.fsdecode(value))


def canonical_destination(path, allow_missing_parents=True):
    """Canonical existing ancestors and a safe missing suffix, without links.

    Existing final files are resolved by descriptor as well. This neither creates
    a directory nor grants permission to write. Missing final files are allowed;
    missing intermediate directories require allow_missing_parents=True.
    """
    path = _absolute(path)
    if type(allow_missing_parents) is not bool:
        raise DirectoryError('INVALID_INPUT', 'invalid missing-parent policy')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            try:
                before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not last and not allow_missing_parents:
                    raise
                return _fd_path(fd).joinpath(*parts[index:])
            if stat.S_ISLNK(before.st_mode):
                raise DirectoryError('PROTECTED_PATH', 'symlink destinations are not traversed')
            if not stat.S_ISDIR(before.st_mode) and (not last or not stat.S_ISREG(before.st_mode)):
                raise DirectoryError('PROTECTED_PATH', 'destination has a non-directory ancestor or special file')
            child_flags = flags if stat.S_ISDIR(before.st_mode) else os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
            nxt = os.open(part, child_flags, dir_fd=fd)
            if _identity(os.fstat(nxt)) != _identity(before):
                os.close(nxt)
                raise DirectoryError('SOURCE_CHANGED', 'destination changed during canonical lookup')
            os.close(fd)
            fd = nxt
        return _fd_path(fd)
    finally:
        os.close(fd)


def validate_path_spelling(root, rel, *, allow_missing=False):
    """Reject alternate spelling of existing components, preserving real Unicode.

    Missing suffixes may be explicitly allowed for planned destinations. Aliases
    are rejected rather than silently changing a request or its prefix mapping.
    """
    relative(rel, allow_dot=True)
    root = safe_root(root)
    expected = root if rel == '.' else root / rel
    actual = canonical_destination(expected, allow_missing_parents=allow_missing)
    if not allow_missing:
        stat_entry(root, rel)
    if actual != expected:
        raise DirectoryError('PATH_ALIAS', 'path does not use native filesystem spelling')


def safe_root(path):
    path = _absolute(path)
    # Opening every component, rather than resolve(), rejects ancestor symlinks.
    fd = _open_directory(path)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise DirectoryError('PROTECTED_PATH', 'directory required')
        return _fd_path(fd)
    finally:
        os.close(fd)


@contextmanager
def open_dir(root, rel='.'):
    """Yield a pinned directory FD; check root and named directory on exit.

    Callers may stream os.scandir(fd), but own their entry/time/depth budgets.
    Non-cooperating writers are not locked by a descriptor or these checks.
    """
    root = _absolute(root)
    relative(rel, allow_dot=True)
    root_fd = _open_directory(root)
    fd = os.dup(root_fd)
    try:
        if rel != '.':
            for part in rel.split('/'):
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nxt
        root_identity, directory_identity = _identity(os.fstat(root_fd)), _identity(os.fstat(fd))
        yield fd
        # Resolve again through nofollow handles; detached or replaced roots do
        # not become a successful operation against a similarly named tree.
        current = _open_directory(root)
        try:
            if _identity(os.fstat(current)) != root_identity:
                raise DirectoryError('SOURCE_CHANGED', 'root directory was replaced')
            if rel != '.':
                for part in rel.split('/'):
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    os.close(current)
                    current = nxt
            if _identity(os.fstat(current)) != directory_identity:
                raise DirectoryError('SOURCE_CHANGED', 'named directory was replaced')
        finally:
            os.close(current)
    finally:
        os.close(fd)
        os.close(root_fd)


@contextmanager
def parent_fd(root, rel):
    relative(rel)
    parts = rel.split('/')
    with open_dir(root, '/'.join(parts[:-1]) or '.') as fd:
        yield fd, parts[-1]


def fsync_dir(root, rel='.'):
    with open_dir(root, rel) as fd:
        os.fsync(fd)


def stat_entry(root, rel):
    if rel == '.':
        with open_dir(root) as fd:
            return os.fstat(fd)
    with parent_fd(root, rel) as (fd, name):
        return os.stat(name, dir_fd=fd, follow_symlinks=False)


def read_file(root, rel, limit, *, strict_io=False):
    relative(rel)
    if type(strict_io) is not bool:
        raise DirectoryError('INVALID_INPUT', 'invalid strict IO policy')
    if type(limit) is not int or limit < 0:
        raise DirectoryError('INVALID_INPUT', 'invalid file byte limit')
    # Keep the existing stable regular-file reader and its exact FD boundary.
    with open_dir(root):
        if strict_io:
            return read_bytes(Path(root), rel, limit, probe=False)
        return read_bytes(Path(root), rel, limit)


def _artifact_path(path):
    path = _absolute(path)
    if path == Path('/'):
        raise DirectoryError('INVALID_INPUT', 'artifact must be a file')
    return canonical_destination(path)


def _artifact_limit(limit):
    if type(limit) is not int or not 0 < limit <= HARD_BUDGETS['max_artifact_bytes']:
        raise DirectoryError('BUDGET_EXHAUSTED', 'invalid artifact byte limit')


def load_artifact(path, limit=32 * MiB):
    _artifact_limit(limit)
    path = _artifact_path(path)
    try:
        value = strict_json(read_file(path.parent, path.name, limit))
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, DirectoryError):
            raise
        raise DirectoryError('ARTIFACT_INVALID', 'invalid or over-budget JSON artifact') from error
    if not isinstance(value, dict):
        raise DirectoryError('ARTIFACT_INVALID', 'artifact must be a JSON object')
    return value


def write_artifact(path, value, *, replace=False, limit=32 * MiB):
    """Persist private JSON atomically. Parents must already exist safely.

    Default publication uses link(O_EXCL semantics), never exists()+rename.
    replace=True is only for caller-guarded journals under the caller's locks.
    The caller must first validate runtime external write permission.
    """
    _artifact_limit(limit)
    if type(replace) is not bool or not isinstance(value, dict):
        raise DirectoryError('INVALID_INPUT', 'artifact must be an object')
    path = _artifact_path(path)
    with parent_fd(path.parent, path.name) as (fd, name):
        temp = '.fifan-directory-' + secrets.token_hex(16) + '.tmp'
        file_fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        owned = _identity(os.fstat(file_fd))
        try:
            total = 0
            encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
            try:
                for chunk in encoder.iterencode(value):
                    data = chunk.encode('ascii')
                    total += len(data)
                    if total > limit:
                        raise DirectoryError('BUDGET_EXHAUSTED', 'artifact exceeds byte budget', limit=limit, actual=total)
                    view = memoryview(data)
                    while view:
                        written = os.write(file_fd, view)
                        if written <= 0:
                            raise OSError('short artifact write')
                        view = view[written:]
            except (ValueError, TypeError, UnicodeError, RecursionError) as error:
                if isinstance(error, DirectoryError):
                    raise
                raise DirectoryError('INVALID_INPUT', 'artifact must be finite JSON data') from error
            os.fchmod(file_fd, 0o600)
            os.fsync(file_fd)
            if _identity(os.stat(temp, dir_fd=fd, follow_symlinks=False)) != owned:
                raise DirectoryError('SOURCE_CHANGED', 'artifact temporary file was replaced')
            if replace:
                try:
                    current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    current = None
                if current is not None and not stat.S_ISREG(current.st_mode):
                    raise DirectoryError('PROTECTED_PATH', 'artifact destination is not a regular file')
                os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
            else:
                os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                os.unlink(temp, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(file_fd)
            try:
                if _identity(os.stat(temp, dir_fd=fd, follow_symlinks=False)) == owned:
                    os.unlink(temp, dir_fd=fd)
            except FileNotFoundError:
                pass
    return path


def _path_list(value, *, allow_dot=False):
    if not isinstance(value, list):
        raise DirectoryError('INVALID_INPUT', 'expected exact path list')
    for item in value:
        relative(item, allow_dot=allow_dot)
    if len(value) != len({path_key(item) for item in value}):
        raise DirectoryError('INVALID_INPUT', 'duplicate path declaration')
    return list(value)


def _external_declaration(value):
    path = canonical_destination(value)
    try:
        info = stat_entry(path.parent, path.name) if path != Path('/') else stat_entry(path, '.')
    except FileNotFoundError:
        return str(path)
    if not stat.S_ISDIR(info.st_mode):
        raise DirectoryError('PROTECTED_PATH', 'external root must be a directory')
    return str(safe_root(path))


def load_profile(root, config, profile_path_or_dict, *, external_metadata=True):
    root = safe_root(root)
    if type(external_metadata) is not bool:
        raise DirectoryError('INVALID_INPUT', 'external metadata policy must be boolean')
    if not isinstance(config, dict):
        raise DirectoryError('INVALID_INPUT', 'project configuration must be an object')
    if isinstance(profile_path_or_dict, dict):
        if len(canonical(profile_path_or_dict)) > MAX_PROFILE_BYTES:
            raise DirectoryError('BUDGET_EXHAUSTED', 'directory profile exceeds input limit', limit=MAX_PROFILE_BYTES)
        data = copy.deepcopy(profile_path_or_dict)
    else:
        path = _artifact_path(profile_path_or_dict)
        if path.is_relative_to(root):
            raise DirectoryError('PROFILE_CONFLICT', 'directory profile must be outside project')
        data = load_artifact(path, limit=MAX_PROFILE_BYTES)
    if set(data) - PROFILE_FIELDS or type(data.get('schema_version')) is not int or data['schema_version'] != 1:
        raise DirectoryError('INVALID_INPUT', 'unsupported directory profile')
    declared_root = data.get('project_root')
    if (not isinstance(declared_root, str)
            or (canonical_destination(declared_root) if external_metadata else _absolute(declared_root)) != root):
        raise DirectoryError('PROFILE_CONFLICT', 'directory profile project root mismatch')
    if not isinstance(data.get('preset', 'generic'), str) or data.get('preset', 'generic') not in {'generic', 'unity'}:
        raise DirectoryError('INVALID_INPUT', 'unsupported directory preset')
    result = {'schema_version': 1, 'project_root': str(root), 'preset': data.get('preset', 'generic'),
              'scan_roots': _path_list(data.get('scan_roots', ['.']), allow_dot=True),
              'critical_paths': _path_list(data.get('critical_paths', []))}
    if not result['scan_roots']:
        raise DirectoryError('INVALID_INPUT', 'scan_roots cannot be empty')
    references = data.get('reference_sources', [])
    classifications = data.get('classifications', [])
    if not isinstance(references, list) or not isinstance(classifications, list):
        raise DirectoryError('INVALID_INPUT', 'profile declarations must be lists')
    for entries, roles, fields in [(references, {'current', 'historical'}, {'path', 'role'}),
                                    (classifications, {'keep', 'active', 'historical', 'rebuildable', 'unknown'}, {'path', 'role', 'reason'})]:
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != fields or not isinstance(entry.get('role'), str) or entry.get('role') not in roles:
                raise DirectoryError('INVALID_INPUT', 'invalid profile path classification')
            relative(entry['path'])
            if 'reason' in fields and (not isinstance(entry['reason'], str) or not entry['reason'].strip()):
                raise DirectoryError('INVALID_INPUT', 'classification requires an explicit reason')
            if path_key(entry['path']) in seen:
                raise DirectoryError('PROFILE_CONFLICT', 'ambiguous duplicate path classification')
            seen.add(path_key(entry['path']))
    result['reference_sources'], result['classifications'] = references, classifications
    streaming = _path_list(data.get('streaming_references', []))
    if any(not path.lower().endswith(('.log', '.txt')) for path in streaming):
        raise DirectoryError('INVALID_INPUT', 'streaming references must be explicit log/txt files')
    if streaming:
        result['streaming_references'] = streaming
    search = data.get('search', {})
    if not isinstance(search, dict) or set(search) - {'exclude', 'vscode', 'watcher_exclude'}:
        raise DirectoryError('INVALID_INPUT', 'unsupported search profile')
    if any(type(search[key]) is not bool for key in ('vscode', 'watcher_exclude') if key in search):
        raise DirectoryError('INVALID_INPUT', 'search flags must be boolean')
    result['search'] = {'exclude': _path_list(search.get('exclude', [])),
                        'vscode': search.get('vscode', False), 'watcher_exclude': search.get('watcher_exclude', False)}
    archive = data.get('archive', {})
    if not isinstance(archive, dict) or set(archive) - {'archive_root', 'records_dir', 'candidates', 'require_no_open_handles'}:
        raise DirectoryError('INVALID_INPUT', 'unsupported archive profile')
    if type(archive.get('require_no_open_handles', True)) is not bool:
        raise DirectoryError('INVALID_INPUT', 'require_no_open_handles must be boolean')
    result['archive'] = {'candidates': _path_list(archive.get('candidates', [])),
                         'require_no_open_handles': archive.get('require_no_open_handles', True)}
    for key in ('archive_root', 'records_dir'):
        if key in archive:
            result['archive'][key] = (_external_declaration(archive[key]) if external_metadata
                                      else str(_absolute(archive[key])))
    budgets = data.get('budgets', {})
    if not isinstance(budgets, dict) or set(budgets) - set(DEFAULT_BUDGETS):
        raise DirectoryError('INVALID_INPUT', 'unsupported directory budget')
    for key, value in budgets.items():
        lower = 0 if key == 'max_depth' else 1
        if type(value) is not int or not lower <= value <= HARD_BUDGETS[key]:
            raise DirectoryError('BUDGET_EXHAUSTED', 'directory budget outside hard limits', limit=HARD_BUDGETS[key])
    result['budgets'] = {**DEFAULT_BUDGETS, **budgets}
    if 'reference_batching' in data:
        from .reference_batches import validate_options
        result['reference_batching'] = validate_options(data['reference_batching'])
    if len(canonical(result)) > result['budgets']['max_artifact_bytes']:
        raise DirectoryError('BUDGET_EXHAUSTED', 'directory profile exceeds artifact limit')
    profile = DirectoryProfile(root, copy.deepcopy(config), result, digest(result), dict(result['budgets']))
    profile._root_identity = _identity(stat_entry(root, '.'))
    return profile


def protected(profile, rel, *, archive=False):
    relative(rel, allow_dot=True)
    if rel == '.':
        return bool(archive)
    rel = path_key(rel)
    config = {**profile.config, **{key: [_key(pattern) for pattern in profile.config.get(key, [])]
                                 for key in ('exclude', 'protected')}}
    if excluded(rel, config):
        return True
    if archive and any(p.endswith('.meta') for p in rel.split('/')):
        return True
    if archive and profile.data.get('preset') == 'unity' and rel.split('/')[0] in {'assets', 'packages', 'projectsettings'}:
        return True
    return False


def validate_profile_root(profile):
    """An existing path name is not permission to inspect a replaced root."""
    if not isinstance(profile, DirectoryProfile):
        raise DirectoryError('INVALID_INPUT', 'directory profile is required')
    info = stat_entry(profile.root, '.')
    if profile._root_identity and _identity(info) != profile._root_identity:
        raise DirectoryError('SOURCE_CHANGED', 'profile project root was replaced')


@contextmanager
def root_lock(root):
    root = safe_root(root)
    with open_dir(root):
        try:
            with _project_lock(root):
                yield
        except ValueError as error:
            if 'project busy' in str(error).lower():
                raise DirectoryError('PROJECT_BUSY', 'project directory is busy') from error
            raise


def _ancestor_identities(root):
    # No content enumeration: only descriptor-relative parent identities. This
    # also catches native mount/firmlink aliases that a string prefix cannot.
    fd = _open_directory(root)
    identities = []
    try:
        for _ in range(1024):
            current = _identity(os.fstat(fd))
            identities.append(current)
            parent = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            same = _identity(os.fstat(parent)) == current
            os.close(fd)
            fd = parent
            if same:
                return identities
        raise DirectoryError('SAFE_IO_UNAVAILABLE', 'filesystem ancestry exceeds safety limit')
    finally:
        os.close(fd)


def roots_overlap(first, second):
    """Observe real same/ancestor roots without granting any write permission."""
    first_ids = _ancestor_identities(safe_root(first))
    second_ids = _ancestor_identities(safe_root(second))
    return first_ids[0] in second_ids or second_ids[0] in first_ids


def external_roots(profile, archive_root, records_dir):
    declared = profile.data.get('archive', {})
    if archive_root is None or records_dir is None:
        raise DirectoryError('BODY_NOT_AUTHORIZED', 'runtime external roots are required')
    arc, rec = safe_root(archive_root), safe_root(records_dir)
    if (not declared.get('archive_root') or not declared.get('records_dir')
            or canonical_destination(declared['archive_root']) != arc
            or canonical_destination(declared['records_dir']) != rec):
        raise DirectoryError('PROFILE_CONFLICT', 'runtime roots must match profile')
    roots = (safe_root(profile.root), arc, rec)
    identities = [_ancestor_identities(root) for root in roots]
    for i, first in enumerate(roots):
        for j in range(i + 1, len(roots)):
            second = roots[j]
            if identities[i][0] in identities[j] or identities[j][0] in identities[i]:
                raise DirectoryError('PROTECTED_PATH', 'project, archive and records roots must not overlap')
    return arc, rec


class HashBudget:
    """One budget per manifest/hash batch. Failed reads still consume resources."""
    def __init__(self, limits):
        raw = limits.budgets if isinstance(limits, DirectoryProfile) else limits
        if not isinstance(raw, dict) or set(raw) - set(DEFAULT_BUDGETS):
            raise DirectoryError('INVALID_INPUT', 'invalid hash budget')
        for key, value in raw.items():
            if type(value) is not int or not (0 if key == 'max_depth' else 1) <= value <= HARD_BUDGETS[key]:
                raise DirectoryError('BUDGET_EXHAUSTED', 'hash budget outside hard limits')
        self.limits = {**DEFAULT_BUDGETS, **raw}
        self.entries = 0
        self.bytes = 0
        self.started = time.monotonic()

    def check_time(self):
        if time.monotonic() - self.started >= self.limits['max_seconds']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'directory hash time limit exhausted', limit=self.limits['max_seconds'])

    def charge_entry(self):
        self.check_time()
        if self.entries >= self.limits['max_hash_entries']:
            raise DirectoryError('BUDGET_EXHAUSTED', 'directory hash entry limit exhausted', limit=self.limits['max_hash_entries'])
        self.entries += 1

    def charge_bytes(self, size):
        if type(size) is not int or size < 0:
            raise DirectoryError('INVALID_INPUT', 'invalid hash byte charge')
        if size > self.limits['max_hash_bytes'] - self.bytes:
            raise DirectoryError('BUDGET_EXHAUSTED', 'directory hash byte limit exhausted', limit=self.limits['max_hash_bytes'])
        self.bytes += size
        self.check_time()

    def snapshot(self):
        return {'hash_entries': self.entries, 'hash_bytes': self.bytes,
                'elapsed_seconds': round(time.monotonic() - self.started, 6)}


def stream_hash(profile, rel, budget, *, root=None):
    """Hash a stable regular file in bounded blocks; no partial SHA is returned.

    root is only for an archive payload already authorized by external_roots().
    It must match profile.archive.archive_root; runtime grants remain the caller's
    responsibility. Files are charged here; callers charge directory entries.
    """
    if not isinstance(budget, HashBudget):
        raise DirectoryError('INVALID_INPUT', 'HashBudget instance required')
    if any(budget.limits[key] > profile.budgets[key] for key in ('max_hash_entries', 'max_hash_bytes', 'max_hash_file_bytes', 'max_seconds')):
        raise DirectoryError('BUDGET_EXHAUSTED', 'hash budget exceeds profile authorization')
    return _stream_hash(profile, rel, budget, root=root)


def reference_hash_limits(profile):
    """Reference proof IO is independent of candidate manifest hash budgets."""
    limits = dict(profile.budgets)
    limits.update(max_hash_entries=limits['max_reference_files'],
                  max_hash_bytes=limits['max_reference_bytes'],
                  max_hash_file_bytes=limits['max_reference_bytes'])
    return limits


def stream_reference_hash(profile, rel, budget, *, reference_path, root=None):
    relative(reference_path)
    if (protected(profile, reference_path)
            or not any(reference_path == item['path'] or reference_path.startswith(item['path'] + '/')
                       for item in profile.data['reference_sources'])):
        raise DirectoryError('BODY_NOT_AUTHORIZED', 'reference proof is not authorized')
    if root is None or Path(root) == profile.root:
        if rel != reference_path:
            raise DirectoryError('BODY_NOT_AUTHORIZED', 'reference proof path mismatch')
    if not isinstance(budget, HashBudget):
        raise DirectoryError('INVALID_INPUT', 'HashBudget instance required')
    authorized = reference_hash_limits(profile)
    if any(budget.limits[key] > authorized[key] for key in ('max_hash_entries', 'max_hash_bytes', 'max_hash_file_bytes', 'max_seconds')):
        raise DirectoryError('BUDGET_EXHAUSTED', 'reference hash budget exceeds profile authorization')
    file_limit = (profile.budgets['max_reference_bytes'] if reference_path in profile.data.get('streaming_references', [])
                  else profile.budgets['max_reference_file_bytes'])
    return _stream_hash(profile, rel, budget, root=root, file_limit=file_limit)


def _stream_hash(profile, rel, budget, *, root=None, file_limit=None):
    relative(rel)
    if protected(profile, rel):
        raise DirectoryError('PROTECTED_PATH', 'protected content cannot be hashed')
    owner = profile.root if root is None else safe_root(root)
    if owner != profile.root and str(owner) != profile.data.get('archive', {}).get('archive_root'):
        raise DirectoryError('BODY_NOT_AUTHORIZED', 'archive hash root not declared')
    budget.charge_entry()
    with parent_fd(owner, rel) as (fd, name):
        if owner == profile.root and profile._root_identity and _identity(stat_entry(owner, '.')) != profile._root_identity:
            raise DirectoryError('SOURCE_CHANGED', 'profile project root was replaced')
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(source)
            if not stat.S_ISREG(before.st_mode):
                raise DirectoryError('PROTECTED_PATH', 'only regular files can be hashed')
            per_file = budget.limits['max_hash_file_bytes'] if file_limit is None else min(file_limit, budget.limits['max_hash_file_bytes'])
            if before.st_size > per_file or before.st_size > budget.limits['max_hash_bytes'] - budget.bytes:
                raise DirectoryError('BUDGET_EXHAUSTED', 'file exceeds hash byte budget', actual=before.st_size)
            hasher, size = hashlib.sha256(), 0
            while True:
                budget.check_time()
                remaining = min(per_file - size,
                                budget.limits['max_hash_bytes'] - budget.bytes)
                # One extra byte detects concurrent growth. Charge before read so
                # a limit never silently authorizes a read beyond the allowance.
                if remaining == 0:
                    if os.fstat(source).st_size != size:
                        raise DirectoryError('SOURCE_CHANGED', 'file changed during hash')
                    break
                block = os.read(source, min(1024 * 1024, remaining))
                if not block:
                    break
                budget.charge_bytes(len(block))
                size += len(block)
                hasher.update(block)
            after = os.fstat(source)
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if _stable(before) != _stable(after) or _stable(named) != _stable(before) or size != before.st_size:
                raise DirectoryError('SOURCE_CHANGED', 'file changed during hash')
            return {'path': rel, 'kind': 'file', 'bytes': size, 'sha256': hasher.hexdigest(),
                    'device': before.st_dev, 'inode': before.st_ino, 'mode': stat.S_IMODE(before.st_mode),
                    'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns, 'nlink': before.st_nlink}
        finally:
            os.close(source)


def _renameat_noreplace(source_fd, source_name, dest_fd, dest_name):
    # Local macOS SDK sys/stdio.h: renameatx_np(int,const char*,int,const
    # char*,unsigned int), RENAME_EXCL=0x00000004 (Darwin 10.12+).
    if sys.platform != 'darwin':
        raise DirectoryError('RENAME_UNAVAILABLE', 'atomic directory no-replace rename is unavailable')
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, 'renameatx_np', None)
    if function is None:
        raise DirectoryError('RENAME_UNAVAILABLE', 'atomic directory no-replace rename is unavailable')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source_name), dest_fd, os.fsencode(dest_name), 0x4) != 0:
        code = ctypes.get_errno()
        if code in {errno.EEXIST, errno.ENOTEMPTY}:
            raise DirectoryError('DESTINATION_EXISTS', 'directory destination already exists')
        if code == errno.EXDEV:
            raise DirectoryError('CROSS_DEVICE', 'directory move must remain on one filesystem')
        if code in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
            raise DirectoryError('RENAME_UNAVAILABLE', 'atomic directory no-replace rename is unsupported')
        raise OSError(code, os.strerror(code))


def rename_noreplace(source_root, source_rel, dest_root, dest_rel):
    relative(source_rel)
    relative(dest_rel)
    with parent_fd(source_root, source_rel) as (source_fd, source_name):
        with parent_fd(dest_root, dest_rel) as (dest_fd, dest_name):
            source = os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
            if not stat.S_ISDIR(source.st_mode):
                raise DirectoryError('PROTECTED_PATH', 'directory rename requires an ordinary directory')
            if source.st_dev != os.fstat(dest_fd).st_dev:
                raise DirectoryError('CROSS_DEVICE', 'directory move must remain on one filesystem')
            _renameat_noreplace(source_fd, source_name, dest_fd, dest_name)
            written = os.stat(dest_name, dir_fd=dest_fd, follow_symlinks=False)
            if _identity(written) != _identity(source):
                raise DirectoryError('SOURCE_CHANGED', 'directory identity changed during move')
            os.fsync(source_fd)
            os.fsync(dest_fd)


def rename_entry_noreplace(source_root, source_rel, dest_root, dest_rel):
    """Move one ordinary file or directory; the old directory-only API stays fixed.

    The caller must persist its intent first. A failure after the rename (for
    example fsync) is not evidence that the source is still at its old name.
    """
    relative(source_rel)
    relative(dest_rel)
    validate_path_spelling(source_root, source_rel)
    validate_path_spelling(dest_root, dest_rel, allow_missing=True)
    with parent_fd(source_root, source_rel) as (source_fd, source_name):
        with parent_fd(dest_root, dest_rel) as (dest_fd, dest_name):
            before = os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
            regular = stat.S_ISREG(before.st_mode)
            if not (regular or stat.S_ISDIR(before.st_mode)) or regular and before.st_nlink != 1:
                raise DirectoryError('PROTECTED_PATH', 'ordinary unshared entry required')
            if before.st_dev != os.fstat(dest_fd).st_dev:
                raise DirectoryError('CROSS_DEVICE', 'entry move must remain on one filesystem')
            _renameat_noreplace(source_fd, source_name, dest_fd, dest_name)
            written = os.stat(dest_name, dir_fd=dest_fd, follow_symlinks=False)
            stable = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns)
            if stable(written) != stable(before):
                raise DirectoryError('SOURCE_CHANGED', 'entry changed during move')
            os.fsync(source_fd)
            os.fsync(dest_fd)
