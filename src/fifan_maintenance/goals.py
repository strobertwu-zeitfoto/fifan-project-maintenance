"""Explicit, bounded byte measurements; never a semantic acceptance or cleanup tool."""
from __future__ import annotations

import copy
import hashlib
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import Context
from .project import fingerprint, relative_parts

DOMAINS = ('active', 'current_views', 'reused_archives', 'new_archives', 'external_records')
REQUEST_FIELDS = {'version', 'active', 'views', 'reused_archives', 'new_archives',
                  'external_roots', 'external_records', 'baseline', 'allow_absent'}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _root(value):
    path = Path(value).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_dir():
        raise ValueError('measurement root must be a real directory without symlink ancestors')
    return path.resolve(strict=True)


def _unknown():
    return {'status': 'Unknown', 'bytes': None, 'items': [], 'reason': 'not-declared'}


def _domain(items):
    known = all(x['status'] == 'Passed' for x in items)
    unique = {}
    for item in items:
        if item['status'] == 'Passed':
            key = tuple(item.get('identity', [item['root'], item['path']]))
            if key in unique:
                item['duplicate_of'] = unique[key]['path']
                if (item['sha256'], item['bytes']) != (unique[key]['sha256'], unique[key]['bytes']):
                    known = False
            else:
                unique[key] = item
    return {'status': 'Passed' if known else 'Unknown',
            'bytes': sum(x['bytes'] for x in unique.values()) if known else None,
            'observed_bytes': sum(x['bytes'] for x in unique.values()), 'items': items}


def measure(root, config, request):
    """Read only exact declared files. Missing lists are Unknown; [] is known empty.

    Archive entries may be project-relative strings or {root, path} objects whose
    external root is explicitly in external_roots. Views are inclusive line ranges
    of declared active files. Overlapping views are counted once within their
    domain, and never added to storage. config['_overlay'] means Preview, not Disk.
    allow_absent entries are {role, path, root?}, matching an exact declared file.
    Only authorized descriptor-relative missing metadata yields measured zero;
    presence=Absent is neither a health verdict nor permission to delete files.
    """
    if not isinstance(request, dict) or request.get('version') != 1 or set(request) - REQUEST_FIELDS:
        raise ValueError('unsupported measurement request')
    root = _root(root)
    config = copy.deepcopy(config)
    started, collected = time.monotonic(), _now()
    external = request.get('external_roots', [])
    if not isinstance(external, list) or any(not isinstance(p, str) or not Path(p).is_absolute() for p in external):
        raise ValueError('external roots must be explicitly declared absolute paths')
    allowed = {str(_root(p)) for p in external}
    if str(root) in allowed:
        raise ValueError('external root must be outside project')
    for p in allowed:
        if Path(p).is_relative_to(root) or root.is_relative_to(Path(p)):
            raise ValueError('external roots must not overlap the project')
    config_sha = fingerprint({k: v for k, v in config.items() if k != '_overlay'})
    contexts = {str(root): Context(root, {}, copy.deepcopy(config))}
    for p in allowed:
        cfg = {k: v for k, v in config.items() if k not in {'_overlay', '_task'}}
        contexts[p] = Context(Path(p), {}, cfg)
    cache, data_cache, metrics = {}, {}, {'read_bytes': 0, 'hashed_bytes': 0, 'metadata_files': 0, 'model_usage': 'Unknown'}
    limit_files = config.get('max_files', 20000)
    requested_count = 0

    def location(entry, external_only=False):
        if isinstance(entry, str) and not external_only:
            owner, rel = str(root), entry
        elif isinstance(entry, dict) and set(entry) == {'root', 'path'}:
            owner, rel = entry['root'], entry['path']
            if not isinstance(owner, str) or owner not in allowed:
                raise ValueError('external file root is not authorized')
        else:
            raise ValueError('file needs an exact path and authorized root')
        relative_parts(rel)
        return owner, rel

    absence_permissions = set()
    absence_list = request.get('allow_absent', [])
    if not isinstance(absence_list, list):
        raise ValueError('allow_absent must be a list')
    for permission in absence_list:
        if not isinstance(permission, dict) or set(permission) - {'role', 'root', 'path'} or not {'role', 'path'} <= set(permission):
            raise ValueError('invalid allow_absent entry')
        role = permission['role']
        if role not in {'active', 'reused_archives', 'new_archives', 'external_records'}:
            raise ValueError('allow_absent requires an exact file role')
        target = {'root': permission['root'], 'path': permission['path']} if 'root' in permission else permission['path']
        owner, rel = location(target, role == 'external_records')
        if role == 'active' and owner != str(root):
            raise ValueError('active sources must be project-relative paths')
        entries = request.get(role)
        if not isinstance(entries, list) or (owner, rel) not in [location(e, role == 'external_records') for e in entries]:
            raise ValueError('allow_absent must match a declared file in its role')
        key = (role, owner, rel)
        if key in absence_permissions:
            raise ValueError('duplicate allow_absent permission')
        absence_permissions.add(key)

    def for_role(item, role):
        result = dict(item)
        confirmed = result.pop('_absence_confirmed', False)
        if confirmed and (role, result['root'], result['path']) in absence_permissions:
            result.update(status='Passed', presence='Absent', bytes=0, sha256=None,
                          absence_authorized=True, identity=['absent', result['root'], result['path']])
            result.pop('reason', None)
        return result

    def read(entry, external_only=False, role=None):
        nonlocal requested_count
        owner, rel = location(entry, external_only)
        key = (owner, rel)
        requested_count += 1
        if requested_count > limit_files:
            raise ValueError('measurement file count budget exhausted')
        if key in cache:
            return for_role(cache[key], role)
        item = {'root': owner, 'path': rel, 'location': 'inside' if owner == str(root) else 'outside',
                'source': 'actual-file', 'collected_at': _now(), 'status': 'Unknown', 'presence': 'Unknown', 'bytes': None, 'sha256': None}
        ctx = contexts[owner]
        try:
            if time.monotonic() - started >= config.get('max_seconds', 60):
                raise ValueError('measurement time budget exhausted')
            ctx.resolve(rel)
            if not ctx.body_allowed(rel):
                raise ValueError('reference body outside task scope')
            overlay = ctx.config.get('_overlay', {})
            if rel not in overlay:
                metrics['metadata_files'] += 1
                try:
                    before = ctx.metadata(rel)
                except FileNotFoundError:
                    item['_absence_confirmed'] = True
                    raise
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError('measurement needs regular file')
            remaining = config.get('max_total_bytes', 64 * 1024 * 1024) - metrics['read_bytes']
            ctx.config['max_total_bytes'] = ctx._read_total + remaining
            data = ctx.read_bytes(rel)
            metrics['read_bytes'] += len(data)
            if rel not in overlay:
                after = ctx.metadata(rel)
                fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                if fields(before) != fields(after) or len(data) != after.st_size:
                    raise ValueError('measurement source drifted')
                item['identity'] = [after.st_dev, after.st_ino]
                item['mtime_ns'] = after.st_mtime_ns
            else:
                item['identity'] = ['overlay', owner, rel]
                item['source'] = 'preview-overlay'
            item.update(status='Passed', presence='Present', bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            metrics['hashed_bytes'] += len(data)
            data_cache[key] = data
        except (OSError, ValueError) as error:
            # Do not echo source text or exception strings containing secrets.
            item['reason'] = type(error).__name__
        cache[key] = dict(item)
        return for_role(item, role)

    domains = {name: _unknown() for name in DOMAINS}
    for name in ('active', 'reused_archives', 'new_archives', 'external_records'):
        if name not in request:
            continue
        entries = request[name]
        if not isinstance(entries, list):
            raise ValueError('measurement domains must be exact file lists')
        if name == 'active' and any(not isinstance(entry, str) for entry in entries):
            raise ValueError('active sources must be project-relative paths')
        locations = [location(e, name == 'external_records') for e in entries]
        if len(set(locations)) != len(locations):
            raise ValueError('duplicate measurement path in domain')
        domains[name] = _domain([read(e, name == 'external_records', name) for e in entries])
    if 'views' in request:
        if not isinstance(request['views'], list):
            raise ValueError('views must be a list')
        active = request.get('active', [])
        intervals, views, names = {}, [], set()
        for view in request['views']:
            if not isinstance(view, dict) or set(view) - {'name', 'path', 'start_line', 'end_line', 'kind'}:
                raise ValueError('invalid current view')
            rel = view.get('path')
            if rel not in active or view.get('kind') != 'current' or not isinstance(view.get('name'), str) or not view['name']:
                raise ValueError('current view needs a declared active file and name')
            start, end = view.get('start_line'), view.get('end_line')
            if type(start) is not int or type(end) is not int or start < 1 or end < start:
                raise ValueError('invalid current view range')
            if (rel, view['name']) in names:
                raise ValueError('duplicate current view name')
            names.add((rel, view['name']))
            source = read(rel, role='active')
            item = {**source, 'name': view['name'], 'start_line': start, 'end_line': end}
            if source.get('presence') == 'Absent':
                item.update(status='Unknown', bytes=None, sha256=None, reason='view-source-absent')
            elif source['status'] == 'Passed':
                lines = data_cache[(str(root), rel)].splitlines(keepends=True)
                if end > len(lines):
                    item.update(status='Unknown', bytes=None, sha256=None, reason='view-range-outside-file')
                else:
                    offset = sum(map(len, lines[:start - 1]))
                    data = b''.join(lines[start - 1:end])
                    item.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    metrics['hashed_bytes'] += len(data)
                    intervals.setdefault(tuple(source['identity']), []).append((offset, offset + len(data)))
            views.append(item)
        total = 0
        for ranges in intervals.values():
            stop = 0
            for start, end in sorted(ranges):
                total += max(0, end - max(stop, start))
                stop = max(stop, end)
        known = all(x['status'] == 'Passed' for x in views)
        domains['current_views'] = {'status': 'Passed' if known else 'Unknown', 'bytes': total if known else None,
                                    'observed_bytes': total, 'items': views, 'overlap_policy': 'union-of-byte-ranges'}
    baseline = request.get('baseline', [])
    if not isinstance(baseline, list):
        raise ValueError('baseline must be a list')
    baseline_status = 'Passed'
    baseline_checks = []
    for old in baseline:
        if not isinstance(old, dict) or not {'path', 'sha256', 'bytes', 'collected_at', 'source'} <= set(old):
            raise ValueError('baseline requires path, SHA, bytes, collection time and source')
        owner = old.get('root', str(root))
        item = next((i for d in domains.values() for i in d['items']
                     if i['root'] == owner and i['path'] == old['path'] and i['status'] == 'Passed'), None)
        matched = bool(item and item['status'] == 'Passed' and old['sha256'] == item['sha256'] and old['bytes'] == item['bytes']
                       and isinstance(old['collected_at'], str) and old['collected_at'] and old['source'])
        baseline_checks.append({'root': owner, 'path': old['path'], 'status': 'Passed' if matched else 'Unknown'})
        if not matched:
            baseline_status = 'Unknown'
    storage_items = [i for name in ('active', 'reused_archives', 'new_archives', 'external_records') for i in domains[name]['items']]
    storage = _domain([dict(i) for i in storage_items])
    if any(domains[n]['status'] != 'Passed' for n in ('active', 'reused_archives', 'new_archives', 'external_records')):
        storage.update(status='Unknown', bytes=None)
    storage['scope'] = 'declared files only; logical bytes deduplicated by device/inode; not allocated blocks or whole project'
    metrics['elapsed_seconds'] = round(time.monotonic() - started, 6)
    return {'schema_version': 1, 'contract': 'goals-v1', 'root': str(root), 'config_sha256': config_sha,
            'candidate': 'Preview' if '_overlay' in config else 'Disk', 'collected_at': collected,
            'snapshot': 'per-file collection; not an atomic snapshot', 'domains': domains, 'storage': storage,
            'baseline_status': baseline_status, 'baseline_checks': baseline_checks, 'metrics': metrics,
            'measurement_coverage': {k: v['status'] for k, v in domains.items()}, 'semantic_acceptance': 'Unknown'}


def normalize_measurement(record):
    """Adapt explicit 1.1 metadata without inventing archives, views or timestamps.

    Reports: files[path].size/sha256, restricted to scope.sources if declared.
    Preflight: sources[].bytes; SHA/time remain unknown. Plan/journal: no complete
    byte metadata, therefore Unknown. No backup bodies or source text is emitted.
    """
    if not isinstance(record, dict):
        raise ValueError('measurement record must be an object')
    if record.get('contract') == 'goals-v1':
        result = copy.deepcopy(record)
        domains = result.get('domains')
        if not isinstance(domains, dict):
            raise ValueError('invalid measurement domains')
        for name in DOMAINS:
            domain = domains.get(name)
            if not isinstance(domain, dict) or not isinstance(domain.get('items'), list):
                raise ValueError('invalid measurement domain')
            if domain.get('status') == 'Passed':
                valid = type(domain.get('bytes')) is int and domain['bytes'] >= 0
                for item in domain['items']:
                    if not isinstance(item, dict):
                        raise ValueError('invalid measurement item')
                    sha = item.get('sha256')
                    present = (item.get('presence', 'Present') == 'Present' and isinstance(sha, str) and len(sha) == 64
                               and all(c in '0123456789abcdef' for c in sha))
                    absent = (item.get('presence') == 'Absent' and item.get('absence_authorized') is True
                              and item.get('bytes') == 0 and sha is None
                              and item.get('identity') == ['absent', item.get('root'), item.get('path')])
                    valid = valid and (item.get('status') == 'Passed' and type(item.get('bytes')) is int
                                       and item['bytes'] >= 0 and (present or absent)
                                       and isinstance(item.get('collected_at'), str) and bool(item['collected_at'])
                                       and isinstance(item.get('identity'), list) and bool(item['identity'])
                                       and isinstance(item.get('path'), str) and isinstance(item.get('root'), str))
                if not valid:
                    domain['status'] = 'Unknown'
        result['measurement_coverage'] = {name: domains[name]['status'] for name in DOMAINS}
        if not isinstance(result.get('storage'), dict):
            result['storage'] = _unknown()
        if any(domains[name]['status'] != 'Passed' for name in ('active', 'reused_archives', 'new_archives', 'external_records')):
            result['storage']['status'] = 'Unknown'
        return result
    domains = {name: _unknown() for name in DOMAINS}
    items = []
    source = 'report' if isinstance(record.get('files'), dict) else 'preflight'
    files = record.get('files')
    selected = record.get('scope', {}).get('sources') if isinstance(record.get('scope'), dict) else None
    if isinstance(files, dict):
        paths = selected if isinstance(selected, list) else list(files)
        for path in paths:
            metadata = files.get(path, {})
            size = metadata.get('size') if isinstance(metadata, dict) else None
            items.append({'root': record.get('root'), 'path': path, 'bytes': size if type(size) is int and size >= 0 else None,
                          'sha256': metadata.get('sha256') if isinstance(metadata, dict) else None,
                          'collected_at': None, 'source': source, 'status': 'Unknown'})
    elif isinstance(record.get('sources'), list):
        for item in record['sources']:
            if isinstance(item, dict) and isinstance(item.get('path'), str):
                size = item.get('bytes')
                items.append({'root': record.get('root'), 'path': item['path'], 'bytes': size if type(size) is int and size >= 0 else None,
                              'sha256': None, 'collected_at': None, 'source': source, 'status': 'Unknown'})
    if items:
        domains['active'] = {'status': 'Unknown', 'bytes': sum(i['bytes'] for i in items) if all(i['bytes'] is not None for i in items) else None,
                             'items': items, 'reason': 'legacy-missing-time-or-identity'}
    return {'schema_version': 1, 'contract': 'goals-v1', 'root': record.get('root'), 'config_sha256': record.get('config_sha256'),
            'candidate': record.get('candidate', 'Unknown'), 'domains': domains, 'storage': _unknown(),
            'baseline_status': 'Unknown', 'measurement_coverage': {n: d['status'] for n, d in domains.items()},
            'legacy_source': source if items else 'plan-journal-or-unsupported', 'semantic_acceptance': 'Unknown'}


def evaluate(before, after, goal):
    """Mechanical goal result only. Explicit exceptions are reported, never waived."""
    before, after = normalize_measurement(before), normalize_measurement(after)
    goal = {'kind': goal} if isinstance(goal, str) else goal
    if not isinstance(goal, dict) or set(goal) - {'kind', 'each_file', 'max_after_bytes', 'minimum_reduction_bytes', 'exceptions'} or goal.get('kind') not in {'navigation', 'body-slim', 'storage'}:
        raise ValueError('invalid goal')
    if 'each_file' in goal and type(goal['each_file']) is not bool:
        raise ValueError('each_file must be boolean')
    for name in ('max_after_bytes', 'minimum_reduction_bytes'):
        if name in goal and (type(goal[name]) is not int or goal[name] < 0):
            raise ValueError('goal thresholds must be nonnegative integers')
    exceptions = goal.get('exceptions', [])
    if not isinstance(exceptions, list) or any(not isinstance(e, dict) or set(e) != {'path', 'reason'} or not all(isinstance(e[k], str) and e[k] for k in e) for e in exceptions):
        raise ValueError('exceptions need exact path and explicit reason')
    reasons, rows = [], []
    for key in ('root', 'config_sha256'):
        if not isinstance(before.get(key), str) or not before[key] or before[key] != after.get(key):
            reasons.append('binding-mismatch:' + key)
    if before.get('candidate') != 'Disk' or after.get('candidate') not in {'Disk', 'Preview'}:
        reasons.append('unbound-candidate')
    if before.get('baseline_status') != 'Passed' or after.get('baseline_status') != 'Passed':
        reasons.append('baseline-unverified-or-drifted')
    old_active = before.get('domains', {}).get('active', _unknown())
    new_active = after.get('domains', {}).get('active', _unknown())
    old = {(i.get('root'), i.get('path')): i for i in old_active.get('items', [])}
    new = {(i.get('root'), i.get('path')): i for i in new_active.get('items', [])}
    if set(old) != set(new):
        reasons.append('active-set-mismatch')
    for key in sorted(set(old) | set(new), key=str):
        b, a = old.get(key, {}), new.get(key, {})
        bs, az = b.get('bytes'), a.get('bytes')
        known = type(bs) is int and type(az) is int
        rows.append({'root': key[0], 'path': key[1], 'before_bytes': bs, 'after_bytes': az,
                     'delta_bytes': az - bs if known else None, 'status': 'Passed' if known and az < bs else 'Failed' if known else 'Unknown'})
    kind = goal['kind']
    if kind == 'storage':
        def cohort(record):
            return {(role, item.get('root'), item.get('path'))
                    for role in ('active', 'reused_archives', 'new_archives', 'external_records')
                    for item in record.get('domains', {}).get(role, {}).get('items', [])}
        if cohort(before) != cohort(after):
            reasons.append('storage-cohort-mismatch')
    domain_before = before.get('storage', _unknown()) if kind == 'storage' else old_active
    domain_after = after.get('storage', _unknown()) if kind == 'storage' else new_active
    b, a = domain_before.get('bytes'), domain_after.get('bytes')
    if domain_before.get('status') != 'Passed' or domain_after.get('status') != 'Passed' or type(b) is not int or type(a) is not int:
        reasons.append('incomplete-measurement')
    if kind == 'navigation':
        reasons.append('navigation-requires-semantic-review')
    result = 'Unknown'
    if not reasons:
        tests = [a < b]
        if 'max_after_bytes' in goal:
            tests.append(a <= goal['max_after_bytes'])
        if 'minimum_reduction_bytes' in goal:
            tests.append(b - a >= goal['minimum_reduction_bytes'])
        if goal.get('each_file'):
            tests.append(bool(rows) and all(r['status'] == 'Passed' for r in rows))
        result = 'Passed' if all(tests) else 'Failed'
    deltas = {}
    for name in DOMAINS:
        bd, ad = before.get('domains', {}).get(name, _unknown()), after.get('domains', {}).get(name, _unknown())
        x, y = bd.get('bytes'), ad.get('bytes')
        deltas[name] = {'before_bytes': x, 'after_bytes': y, 'delta_bytes': y - x if type(x) is int and type(y) is int else None,
                        'status': 'Passed' if bd.get('status') == ad.get('status') == 'Passed' else 'Unknown'}
    return {'schema_version': 1, 'contract': 'goal-evaluation-v1',
            'root': before.get('root') if 'binding-mismatch:root' not in reasons else None,
            'config_sha256': before.get('config_sha256') if 'binding-mismatch:config_sha256' not in reasons else None,
            'goal': goal, 'goal_result': result,
            'measurement_coverage': {'before': before.get('measurement_coverage', {}), 'after': after.get('measurement_coverage', {})},
            'candidate': after.get('candidate'), 'files': rows, 'deltas': deltas, 'reasons': reasons,
            'before_bytes': b, 'after_bytes': a, 'reduction_bytes': b - a if type(b) is int and type(a) is int else None,
            'exceptions': exceptions, 'semantic_acceptance': 'Unknown', 'scope': 'declared files only; no automatic deletion'}
