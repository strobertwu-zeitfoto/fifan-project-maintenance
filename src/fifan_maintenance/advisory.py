"""Bounded literal preservation and declared-binding audit; no semantic verdict."""
from __future__ import annotations

import hashlib
import re
import stat
import time
from pathlib import Path

from .directory_common import (DirectoryError, canonical, canonical_destination,
                               path_key, read_file, relative, safe_root, seal,
                               stat_entry, validate_path_spelling)
from .inventory import excluded

MAX_REQUEST_BYTES = 256 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FILES = 128
KINDS = {'task_id', 'number', 'negation', 'pending', 'text'}


def _object(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise DirectoryError('INVALID_INPUT', 'invalid audit contract fields')


def _list(value, limit=128):
    if not isinstance(value, list) or len(value) > limit:
        raise DirectoryError('INVALID_INPUT', 'invalid audit list budget')
    return value


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise DirectoryError('INVALID_INPUT', 'lowercase SHA-256 required')


def external_path(root, config, value):
    """Reject aliases and protected locations before opening external material."""
    path = Path(value)
    if not path.is_absolute():
        raise DirectoryError('INVALID_INPUT', 'absolute external path required')
    actual = canonical_destination(path, allow_missing_parents=False)
    if actual != path:
        raise DirectoryError('PATH_ALIAS', 'external spelling differs')
    if actual == root or actual.is_relative_to(root):
        raise DirectoryError('OUTPUT_INSIDE_PROJECT', 'external audit material required')
    if excluded(str(path).lstrip('/'), config):
        raise DirectoryError('PROTECTED_PATH', 'protected audit material')
    try:
        info = stat_entry(path.parent, path.name)
    except FileNotFoundError:
        info = None
    if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise DirectoryError('PROTECTED_PATH', 'ordinary non-aliased external material required')
    return path


def audit(root, config, request):
    """Inspect only explicit file pairs, manifests, recovery files and search sets.

    A fingerprint binds results to these exact bytes, not to undisclosed project
    content. A required fragment is checked literally; no requirement inference,
    proof/receipt regeneration or archive/cleanup action occurs here.
    """
    original_root = str(root)
    root = safe_root(root)
    if str(root) != original_root:
        raise DirectoryError('PATH_ALIAS', 'project spelling differs')
    started = time.monotonic()
    if len(canonical(request)) > MAX_REQUEST_BYTES:
        raise DirectoryError('BUDGET_EXHAUSTED', 'audit request too large')
    _object(request, {'schema_version', 'project_root', 'documents'}, {'bindings', 'search', 'recovery'})
    if type(request['schema_version']) is not int or request['schema_version'] != 1 or request['project_root'] != str(root):
        raise DirectoryError('PROFILE_CONFLICT', 'audit project identity mismatch')
    observed, raw_files, identities = {}, {}, {}
    total = 0
    reserved_reread_bytes = 0
    max_files = min(MAX_FILES, config.get('max_files', MAX_FILES))
    max_file_bytes = min(MAX_FILE_BYTES, config.get('max_file_bytes', MAX_FILE_BYTES))
    max_total_bytes = min(MAX_TOTAL_BYTES, config.get('max_total_bytes', MAX_TOTAL_BYTES))
    max_seconds = min(10, config.get('max_seconds', 10))

    def read(ref):
        nonlocal total, reserved_reread_bytes
        if time.monotonic() - started > max_seconds:
            raise DirectoryError('BUDGET_EXHAUSTED', 'audit time budget exhausted')
        _object(ref, {'path', 'sha256'})
        rel = relative(ref['path'])
        _sha(ref['sha256'])
        if excluded(rel, config):
            raise DirectoryError('PROTECTED_PATH', 'protected audit source')
        if rel not in raw_files:
            if len(raw_files) >= max_files:
                raise DirectoryError('BUDGET_EXHAUSTED', 'too many audit files')
            validate_path_spelling(root, rel)
            info = stat_entry(root, rel)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DirectoryError('PROTECTED_PATH', 'ordinary non-aliased source required')
            key = path_key(rel)
            if key in identities and identities[key] != rel:
                raise DirectoryError('PATH_ALIAS', 'aliased audit selection')
            identities[key] = rel
            # Every distinct source is read again before publication. Reserve
            # that second read now; repeated declarations reuse the cached body.
            available = max_total_bytes - total - reserved_reread_bytes
            data = read_file(root, rel, min(max_file_bytes, available // 2), strict_io=True)
            total += len(data)
            reserved_reread_bytes += len(data)
            raw_files[rel] = data
            observed[rel] = {'path': rel, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        if observed[rel]['sha256'] != ref['sha256']:
            raise DirectoryError('SOURCE_CHANGED', 'audit source SHA mismatch')
        return raw_files[rel]

    documents, blockers, pending = [], [], []
    sources = set()
    requirement_count = 0
    for doc in _list(request['documents'], 64):
        _object(doc, {'baseline', 'candidate', 'requirements'})
        before, after = read(doc['baseline']), read(doc['candidate'])
        try:
            baseline, candidate = before.decode('utf-8'), after.decode('utf-8')
        except UnicodeError as error:
            raise DirectoryError('INVALID_INPUT', 'audit documents must be UTF-8') from error
        source = doc['baseline']['path']
        if source in sources or source == doc['candidate']['path']:
            raise DirectoryError('INVALID_INPUT', 'document mapping must be unique and distinct')
        sources.add(source)
        requirements, ids = [], set()
        for item in _list(doc['requirements'], 256):
            requirement_count += 1
            if requirement_count > 256:
                raise DirectoryError('BUDGET_EXHAUSTED', 'too many audit requirements')
            _object(item, {'id', 'kind', 'text'})
            identifier = item['id']
            if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', identifier) or identifier in ids:
                raise DirectoryError('INVALID_INPUT', 'unique bounded requirement ID required')
            ids.add(identifier)
            text = item['text']
            if item['kind'] not in KINDS or not isinstance(text, str) or not text.strip() or len(text) > 4096:
                raise DirectoryError('INVALID_INPUT', 'bounded literal requirement required')
            def positions(body):
                found = []
                for n, line in enumerate(body.splitlines(), 1):
                    if text in line:
                        found.append(n)
                        if len(found) == 32:
                            break
                return found
            # Single-line literals make locations exact and prevent whitespace
            # normalization from silently weakening a negation or number guard.
            if '\n' in text or '\r' in text:
                raise DirectoryError('INVALID_INPUT', 'requirement must be a single-line literal')
            if time.monotonic() - started > max_seconds:
                raise DirectoryError('BUDGET_EXHAUSTED', 'audit time budget exhausted')
            old_lines, new_lines = positions(baseline), positions(candidate)
            state = 'Passed' if old_lines and new_lines else 'Failed' if old_lines else 'Unknown'
            requirements.append({'id': identifier, 'kind': item['kind'], 'status': state,
                                 'baseline_lines': old_lines, 'candidate_lines': new_lines,
                                 'location_limit_per_document': 32,
                                 'locations_may_be_truncated': len(old_lines) == 32 or len(new_lines) == 32})
            if state != 'Passed':
                blockers.append({'reason_code': 'REQUIRED_TEXT_MISSING' if old_lines else 'BASELINE_REQUIREMENT_UNCONFIRMED',
                                 'path': source, 'requirement_id': identifier})
        if not requirements:
            pending.append({'reason_code': 'NO_REQUIREMENTS_DECLARED', 'path': source})
        documents.append({'baseline': observed[source], 'candidate': observed[doc['candidate']['path']],
                          'changed': before != after, 'byte_delta': len(after) - len(before), 'requirements': requirements})

    bindings = []
    for item in _list(request.get('bindings', [])):
        _object(item, {'file', 'source'})
        read(item['file'])
        if item['source'] not in sources:
            raise DirectoryError('INVALID_INPUT', 'binding source must be declared baseline')
        changed = next(doc['changed'] for doc in documents if doc['baseline']['path'] == item['source'])
        bindings.append({'file': observed[item['file']['path']], 'source': item['source'],
                         'basis': 'user_declared_dependency', 'affected': changed,
                         'status': 'Blocked' if changed else 'Passed', 'regenerated': False})
        if changed:
            blockers.append({'reason_code': 'DECLARED_BINDING_IMPACT', 'path': item['file']['path'], 'source': item['source']})

    search = {'status': 'Unknown', 'recommendation': 'Unknown', 'basis': 'no explicit search scopes'}
    if 'search' in request:
        _object(request['search'], {'before', 'after'})
        scopes = {}
        for side in ('before', 'after'):
            refs = _list(request['search'][side])
            for ref in refs:
                read(ref)
            paths = [ref['path'] for ref in refs]
            if len(paths) != len(set(paths)):
                raise DirectoryError('INVALID_INPUT', 'duplicate search scope path')
            scopes[side] = paths
        reduction = len(scopes['before']) - len(scopes['after'])
        search = {'status': 'Passed', 'basis': 'explicit_current_file_sets_only',
                  'before_count': len(scopes['before']), 'after_count': len(scopes['after']),
                  'declared_scope_reduction': reduction,
                  'recommendation': 'Review' if reduction > 0 else 'NoChange',
                  'effective_search_configuration': 'Unknown', 'archive_benefit': 'Unknown'}

    recovery = []
    for ref in _list(request.get('recovery', [])):
        read(ref)
        recovery.append({**observed[ref['path']], 'execution_status': 'Not run'})
    pending.extend([{'reason_code': 'SEMANTIC_ACCEPTANCE_REQUIRED'},
                    {'reason_code': 'UNDECLARED_BINDINGS_UNKNOWN'}])
    if not recovery:
        pending.append({'reason_code': 'RECOVERY_ENTRY_NOT_DECLARED'})
    if not documents:
        pending.append({'reason_code': 'NO_DOCUMENTS_DECLARED'})
    # Re-read only this bounded set before publication to reject in-flight edits.
    for rel, data in raw_files.items():
        if time.monotonic() - started > max_seconds:
            raise DirectoryError('BUDGET_EXHAUSTED', 'audit time budget exhausted')
        validate_path_spelling(root, rel)
        info = stat_entry(root, rel)
        if info.st_nlink != 1 or info.st_size != len(data):
            raise DirectoryError('SOURCE_CHANGED', 'source identity or size changed')
        if len(data) > max_total_bytes - total:
            raise DirectoryError('BUDGET_EXHAUSTED', 'audit reread budget exhausted')
        current = read_file(root, rel, len(data), strict_io=True)
        total += len(current)
        reserved_reread_bytes -= len(data)
        if current != data:
            raise DirectoryError('SOURCE_CHANGED', 'audit source changed before summary')
    return seal({'schema_version': 1, 'kind': 'maintenance_advisory', 'project_root': str(root),
                 'request_sha256': hashlib.sha256(canonical(request)).hexdigest(),
                 'config_sha256': hashlib.sha256(canonical(config)).hexdigest(),
                 'status': 'Blocked' if blockers else 'Unknown' if not documents or any(not d['requirements'] for d in documents) else 'Passed',
                 'status_scope': 'declared_literal_and_hash_checks_only', 'documents': documents,
                 'bindings': bindings, 'search': search, 'hard_blockers': blockers,
                 'incomplete': pending, 'recovery_entries': recovery,
                 'observed_files': list(observed.values()), 'body_bytes_read': total,
                 'project_writes': 0, 'receipt_regeneration': False,
                 'semantic_acceptance': 'Unknown', 'physical_space_released_bytes': None})
