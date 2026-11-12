"""Metadata-only preview authorization plus request-local physical read budgets.

This module never reads document bodies or changes persistent configuration.
The CLI must validate the original request before prepare/locator/NoChange, then
enter preview_read_scope. Physical readers call authorize_read after fstat and
before reading, exactly once per physical read. A true return requires the caller
to cap its read to that observed size and reject subsequent file growth.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
import math
import hashlib
import json
from pathlib import Path
import re
import stat
import time

_ACTIVE = ContextVar('fifan_preview_read_policy', default=None)
_LIMITS = ('max_files', 'max_file_bytes', 'max_total_bytes', 'max_seconds')


def _fail(code, **metadata):
    from .diagnostics import DiagnosticError
    raise DiagnosticError(code, 'Preview scope or read budget rejected', **metadata)


def _limits(config):
    from .project import DEFAULT_CONFIG
    from .scope import HARD_LIMITS
    task = config.get('_task') or {}
    if not isinstance(task, dict):
        _fail('INVALID_INPUT')
    declared = task.get('budgets', {})
    if not isinstance(declared, dict):
        _fail('INVALID_INPUT')
    result = {}
    for name in _LIMITS:
        values = [config.get(name, DEFAULT_CONFIG[name]), HARD_LIMITS[name]]
        if name in declared:
            values.append(declared[name])
        for value in values:
            if (type(value) not in (int, float) or value <= 0
                    or type(value) is float and not math.isfinite(value)
                    or name != 'max_seconds' and type(value) is not int):
                _fail('INVALID_INPUT')
        result[name] = min(values)
    return result


def _context(root, config):
    from .models import Context
    from .project import project_root
    if not isinstance(config, dict):
        _fail('INVALID_INPUT')
    return Context(project_root(root), {}, deepcopy(config))


def _sources(config):
    task = config.get('_task')
    if task is None:
        return None  # Preserve the legacy explicit-operation project scope.
    sources = task.get('sources') if isinstance(task, dict) else None
    references = task.get('reference_bodies', []) if isinstance(task, dict) else None
    if (not isinstance(sources, list) or any(not isinstance(path, str) or not path for path in sources)
            or not isinstance(references, list) or any(not isinstance(path, str) or not path for path in references)):
        _fail('INVALID_INPUT')
    return set(sources)


def _path(ctx, path, *, operation=False, **metadata):
    from .project import relative_parts
    try:
        relative_parts(path)
        ctx.resolve(path)
    except (OSError, ValueError, TypeError):
        _fail('PROTECTED_PATH', **metadata)
    sources = _sources(ctx.config)
    if (operation and sources is not None and path not in sources) or not ctx.body_allowed(path):
        _fail('BODY_NOT_AUTHORIZED', **metadata)
    return path


def _hash(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[0-9a-fA-F]{64}', value))


def _text(value, nonempty=False):
    if not isinstance(value, str) or nonempty and not value:
        _fail('INVALID_INPUT')
    try:
        return len(value.encode('utf-8'))
    except UnicodeError:
        _fail('INVALID_INPUT')


def _locator_size(locator, operation_index):
    if (not isinstance(locator, dict) or set(locator) != {'sha256', 'start_byte', 'end_byte'} or not _hash(locator['sha256'])
            or type(locator['start_byte']) is not int or type(locator['end_byte']) is not int or not 0 <= locator['start_byte'] < locator['end_byte']):
        _fail('INVALID_INPUT', operation_index=operation_index)
    return locator['end_byte'] - locator['start_byte'], locator['end_byte']


def _request_paths(root, request):
    """Pure schema validation: enumerate every current backend body participant."""
    if not isinstance(request, dict):
        _fail('INVALID_INPUT')
    version = request.get('version')
    if version is None and set(request) == {'operations'}:
        version = 1
    elif type(version) is not int or version not in (2, 3):
        _fail('INVALID_INPUT')
    fields = {'operations'} if version == 1 else {'version', 'operations', 'guards'} | ({'archive_proofs'} if version == 3 else set())
    if set(request) - fields:
        _fail('INVALID_INPUT')
    operations = request.get('operations')
    if not isinstance(operations, list) or not 1 <= len(operations) <= 100:
        _fail('INVALID_INPUT')
    participants, destinations, estimates = [], [], []
    patches_total = 0
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            _fail('INVALID_INPUT', operation_index=index)
        kind = operation.get('kind', operation.get('type'))
        wanted = {'type', 'path', 'old', 'new'} if kind == 'replace' else {'type', 'path', 'destination'} if kind == 'move' else {'kind', 'path', 'destination', 'expected_sha256', 'origin'} if kind == 'snapshot' and version > 1 else {'type', 'path', 'expected_sha256', 'patches'} if kind == 'replace_many' and version == 3 else None
        if kind == 'replace' and 'old_locator' in operation:
            wanted = {'type', 'path', 'old_locator', 'new'}
        if wanted is None or set(operation) != wanted:
            _fail('INVALID_INPUT', operation_index=index)
        participants.append((operation['path'], 'operation', index))
        delta = 0
        locator_ends = []
        if kind == 'replace':
            if 'old_locator' in operation:
                old_size, end = _locator_size(operation['old_locator'], index)
                locator_ends.append(end)
            else:
                old_size = _text(operation['old'], True)
            delta = _text(operation['new']) - old_size
        elif kind in ('move', 'snapshot'):
            destinations.append((operation['destination'], index))
            if kind == 'snapshot':
                origin = operation['origin']
                if (not _hash(operation['expected_sha256']) or not isinstance(origin, dict)
                        or set(origin) != {'reference_base', 'classification_basis'} or not isinstance(origin['classification_basis'], str) or not origin['classification_basis'].strip()):
                    _fail('INVALID_INPUT', operation_index=index)
                if origin['reference_base'] != '.':
                    from .project import relative_parts
                    try:
                        relative_parts(origin['reference_base'])
                    except (ValueError, TypeError):
                        _fail('INVALID_INPUT', operation_index=index)
        else:
            if not _hash(operation['expected_sha256']):
                _fail('INVALID_INPUT', operation_index=index)
            patches = operation['patches']
            if not isinstance(patches, list) or not 1 <= len(patches) <= 1000:
                _fail('INVALID_INPUT', operation_index=index)
            patches_total += len(patches)
            for patch in patches:
                if not isinstance(patch, dict) or set(patch) not in ({'old', 'new'}, {'old_locator', 'new'}):
                    _fail('INVALID_INPUT', operation_index=index)
                new_size = _text(patch['new'])
                if 'old' in patch:
                    old_size = _text(patch['old'], True)
                else:
                    old_size, end = _locator_size(patch['old_locator'], index)
                    locator_ends.append(end)
                delta += new_size - old_size
        estimates.append((operation['path'], delta, index, locator_ends))
    if patches_total > 1000:
        _fail('BUDGET_EXHAUSTED', limit=1000, actual=patches_total)
    guards = request.get('guards', [])
    if not isinstance(guards, list) or len(guards) > 100:
        _fail('INVALID_INPUT')
    for index, guard in enumerate(guards):
        if (not isinstance(guard, dict) or set(guard) - {'kind', 'path', 'value', 'exceptions'} or not {'kind', 'path', 'value'} <= set(guard)
                or guard['kind'] not in ('snippet', 'heading', 'table', 'anchor')):
            _fail('INVALID_INPUT')
        _text(guard['value'], True)
        exceptions = guard.get('exceptions', [])
        if not isinstance(exceptions, list) or len(exceptions) > 100 or guard['kind'] == 'anchor' and exceptions:
            _fail('INVALID_INPUT')
        for exception in exceptions:
            if not isinstance(exception, dict) or set(exception) != {'old', 'new'}:
                _fail('INVALID_INPUT')
            _text(exception['old'], True)
            _text(exception['new'])
        participants.append((guard['path'], 'guard', index))
    proofs = request.get('archive_proofs', [])
    if not isinstance(proofs, list) or len(proofs) > 100:
        _fail('INVALID_INPUT')
    for index, proof in enumerate(proofs):
        fields = {'version', 'root', 'config_sha256', 'allowed_external_roots', 'items', 'proof_sha256'}
        if (not isinstance(proof, dict) or set(proof) != fields or type(proof['version']) is not int or proof['version'] != 1
                or proof['root'] != str(root) or not _hash(proof['config_sha256']) or not _hash(proof['proof_sha256'])
                or not isinstance(proof['items'], list) or not 1 <= len(proof['items']) <= 100 or not isinstance(proof['allowed_external_roots'], list)):
            _fail('INVALID_INPUT')
        if proof['allowed_external_roots']:
            _fail('EXTERNAL_PROOF_NOT_PERSISTABLE')
        try:
            proof_bytes = json.dumps({key: value for key, value in proof.items() if key != 'proof_sha256'}, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()
        except (TypeError, ValueError, RecursionError):
            _fail('INVALID_INPUT')
        if hashlib.sha256(proof_bytes).hexdigest() != proof['proof_sha256']:
            _fail('PROOF_BINDING_MISMATCH')
        for item in proof['items']:
            if (not isinstance(item, dict) or set(item) != {'source', 'archive', 'reference_base_sha256', 'classification_basis_sha256'}
                    or not all(_hash(item[name]) for name in ('reference_base_sha256', 'classification_basis_sha256'))):
                _fail('INVALID_INPUT')
            for side in ('source', 'archive'):
                endpoint = item[side]
                if (not isinstance(endpoint, dict) or set(endpoint) != {'root', 'path', 'selector', 'expected_sha256', 'selected_sha256'}
                        or not _hash(endpoint['expected_sha256']) or not _hash(endpoint['selected_sha256'])):
                    _fail('INVALID_INPUT')
                if endpoint['root'] != str(root):
                    _fail('EXTERNAL_PROOF_NOT_PERSISTABLE')
                selector = endpoint['selector']
                if (not isinstance(selector, dict) or set(selector) != {'kind', 'start_byte', 'end_byte'} or selector['kind'] != 'bytes'
                        or type(selector['start_byte']) is not int or type(selector['end_byte']) is not int or not 0 <= selector['start_byte'] < selector['end_byte']):
                    _fail('INVALID_INPUT')
                participants.append((endpoint['path'], 'proof-' + side, index))
    return participants, destinations, estimates


def _authorized_paths(root, task_config, request):
    started = time.monotonic()
    ctx = _context(root, task_config)
    limits = _limits(ctx.config)
    participants, destinations, estimates = _request_paths(ctx.root, request)
    # Validate all permissions before metadata so an eventual NoChange cannot
    # discard an unauthorized guard or proof participant.
    roles = {}
    for path, role, index in participants:
        if time.monotonic() - started > limits['max_seconds']:
            _fail('BUDGET_EXHAUSTED')
        _path(ctx, path, operation=role == 'operation', operation_index=index)
        roles.setdefault(path, set()).add(role)
    for destination, index in destinations:
        if time.monotonic() - started > limits['max_seconds']:
            _fail('BUDGET_EXHAUSTED')
        from .project import relative_parts
        try:
            relative_parts(destination)
            ctx.resolve(destination)
        except (ValueError, TypeError, OSError):
            _fail('PROTECTED_PATH', operation_index=index)
    if len(roles) > limits['max_files']:
        _fail('BUDGET_EXHAUSTED', limit=limits['max_files'], actual=len(roles))
    return ctx, roles, destinations, estimates, limits, started


def validate_preview_authorization(root, task_config, request):
    """Recheck original participants and destinations without pre-action metadata.

    Used only with an existing journal whose actual post-state is verified by
    its execution backend. Missing moved sources do not revoke the original
    declaration; protected paths and body permissions still apply.
    """
    _, roles, destinations, _, limits, _ = _authorized_paths(root, task_config, request)
    return {'status': 'Passed', 'body_bytes_read': 0, 'file_count': len(roles),
            'destinations': [path for path, _ in destinations], 'limits': limits}


def validate_preview_scope(root, task_config, request):
    """Reject unauthorized/oversized declarations before any document read."""
    ctx, roles, destinations, estimates, limits, started = _authorized_paths(root, task_config, request)
    sizes, total = {}, 0
    for path in sorted(roles):
        if time.monotonic() - started > limits['max_seconds']:
            _fail('BUDGET_EXHAUSTED')
        try:
            info = ctx.metadata(path)
        except (OSError, ValueError):
            _fail('SOURCE_UNAVAILABLE')
        if not stat.S_ISREG(info.st_mode):
            _fail('PROTECTED_PATH')
        if info.st_size > limits['max_file_bytes']:
            _fail('BUDGET_EXHAUSTED', limit=limits['max_file_bytes'], actual=info.st_size)
        total += info.st_size
        if total > limits['max_total_bytes']:
            _fail('BUDGET_EXHAUSTED', limit=limits['max_total_bytes'], actual=total)
        sizes[path] = info.st_size
    for path, delta, index, locator_ends in estimates:
        if any(end > sizes[path] for end in locator_ends):
            _fail('PATCH_RANGE_INVALID', operation_index=index)
        if sizes[path] + delta > limits['max_file_bytes']:
            _fail('BUDGET_EXHAUSTED', operation_index=index, limit=limits['max_file_bytes'], actual=sizes[path] + delta)
    sources = _sources(ctx.config)
    primary = sum(size for path, size in sizes.items() if sources is None or path in sources)
    return {'status': 'Passed', 'body_bytes_read': 0, 'file_count': len(sizes), 'total_bytes': total,
            'primary_bytes': primary, 'reference_bytes': total - primary, 'limits': limits,
            'files': [{'path': path, 'roles': sorted(roles[path]), 'bytes': sizes[path]} for path in sorted(sizes)],
            'destinations': [path for path, _ in destinations], 'metadata_only': True}


class _ReadScope:
    def __init__(self, root, config):
        self.context = _context(root, config)
        self.limits = _limits(self.context.config)
        _sources(self.context.config)
        self.started = time.monotonic()
        self.files = set()
        self.read_bytes = self.primary_bytes = self.reference_bytes = 0


@contextmanager
def preview_read_scope(root, task_config):
    policy = _ReadScope(root, task_config)
    token = _ACTIVE.set(policy)
    try:
        yield policy
    finally:
        _ACTIVE.reset(token)


def authorize_read(root, rel, size):
    """Return true only when this physical read was checked and charged.

    Other roots and calls outside the context return false. Repeated reads of
    the same file each consume bytes; unique-file limits count each path once.
    """
    policy = _ACTIVE.get()
    if policy is None:
        return False
    try:
        actual_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    if actual_root != policy.context.root:
        return False
    if type(size) is not int or size < 0:
        _fail('INVALID_INPUT')
    _path(policy.context, rel)
    if time.monotonic() - policy.started > policy.limits['max_seconds']:
        _fail('BUDGET_EXHAUSTED')
    if size > policy.limits['max_file_bytes'] or policy.read_bytes + size > policy.limits['max_total_bytes']:
        _fail('BUDGET_EXHAUSTED')
    if rel not in policy.files and len(policy.files) >= policy.limits['max_files']:
        _fail('BUDGET_EXHAUSTED')
    policy.files.add(rel)
    policy.read_bytes += size
    sources = _sources(policy.context.config)
    if sources is None or rel in sources:
        policy.primary_bytes += size
    else:
        policy.reference_bytes += size
    return True
