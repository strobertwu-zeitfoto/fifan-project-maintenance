"""Cleanup-only metadata observations and REC-only declaration projections.

Reports never grant payload access. Q and REC must be passed explicitly for live
measurement; history reads only its explicitly selected records root. No body
content, manifest file SHA verification, deletion or old-session interpretation
is performed here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import time

from . import directory_common as dc

FORMAT = 'fifan-cleanup-report'
DOMAINS = ('project_payload', 'quarantine_payload', 'records')
STAGES = {'T0', 'T1', 'T2', 'T3'}
WARNINGS = [
    'These are per-entry metadata observations, not an atomic snapshot or full payload hash verification.',
    'Logical payload removal is not physical disk release; exclusive storage attribution remains Unknown.',
    'Artifacts and journal updates written after observed_at, including the final report, are not measured.',
    'Only the exact request source/Q cohort and the entire explicitly granted REC are included; this is not a whole-project total.',
]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _error(code='ARTIFACT_INVALID'):
    raise dc.DirectoryError(code, 'cleanup reporting binding or metadata rejected')


def _root_id(root):
    info = dc.stat_entry(root, '.')
    if not stat.S_ISDIR(info.st_mode):
        _error('PROTECTED_PATH')
    return {'path': str(root), 'device': info.st_dev, 'inode': info.st_ino}


def _same_root(root, expected):
    actual = _root_id(root)
    if actual != expected:
        _error('SOURCE_CHANGED')


def _within(path, parent):
    path, parent = dc.path_key(path), dc.path_key(parent)
    return parent == '.' or path == parent or path.startswith(parent + '/')


def _exact_paths(paths):
    previous = []
    for path in paths:
        dc.relative(path)
        if any(_within(path, other) or _within(other, path) for other in previous):
            _error('PROFILE_CONFLICT')
        previous.append(path)


class _Budget:
    def __init__(self, profile):
        self.limits = profile.budgets
        self.started = time.monotonic()
        self.work = self.metadata = 0

    def check(self):
        if time.monotonic() - self.started >= self.limits['max_seconds']:
            _error('BUDGET_EXHAUSTED')

    def charge(self):
        self.check()
        if self.work >= self.limits['max_entries']:
            _error('BUDGET_EXHAUSTED')
        self.work += 1


def _metadata_matches(info, entry):
    actual_kind = 'file' if stat.S_ISREG(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'unsupported'
    if entry.get('kind') != actual_kind:
        return False
    for key, actual in (('device', info.st_dev), ('inode', info.st_ino), ('mtime_ns', info.st_mtime_ns), ('ctime_ns', info.st_ctime_ns)):
        if key not in entry or entry[key] != actual:
            return False
    if type(entry.get('mode')) is not int or stat.S_IMODE(entry['mode']) != stat.S_IMODE(info.st_mode):
        return False
    if actual_kind == 'file':
        return entry.get('bytes') == info.st_size and entry.get('nlink') == info.st_nlink
    return actual_kind == 'directory'


def _observe(profile, root, path, budget, root_identity, *, expected=None, protect=None):
    """Observe a file/directory through nofollow FDs. Missing stays unexplained."""
    result = {'path': path, 'exists': None, 'presence': 'Unknown', 'status': 'Unknown', 'bytes': None,
              'observed_bytes': 0, 'observed_files': 0, 'observed_directories': 0, 'unique_inode_bytes': 0,
              'unique_inode_count': 0, 'coverage': {'complete': False, 'count_is_lower_bound': True, 'gaps': []}}
    gaps, gap_count, seen, inodes, snapshots = [], 0, set(), {}, {}
    expected_entries = {entry['path']: entry for entry in expected['entries']} if expected is not None else None
    initial = None
    work_before, metadata_before = budget.work, budget.metadata

    def gap(relative, code):
        nonlocal gap_count
        gap_count += 1
        if len(gaps) < 20:
            gaps.append({'path': relative, 'reason_code': code})

    def visit(relative, depth, charged=False):
        nonlocal initial
        if not charged:
            budget.charge()
        full = path if relative == '.' else relative if path == '.' else path + '/' + relative
        if protect is not None and protect(relative):
            gap(relative, 'PROTECTED_PATH')
            return
        budget.metadata += 1
        try:
            info = dc.stat_entry(root, full)
        except FileNotFoundError:
            if relative == '.':
                result.update(exists=False, presence='Missing')
            else:
                gap(relative, 'SOURCE_CHANGED')
            return
        if relative == '.':
            initial = (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            result.update(exists=True, presence='Present')
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            gap(relative, 'SYMLINK_OR_SPECIAL')
            return
        if relative in seen:
            gap(relative, 'PATH_ALIAS')
            return
        seen.add(relative)
        snapshots[full] = (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if expected_entries is not None and (relative not in expected_entries or not _metadata_matches(info, expected_entries[relative])):
            gap(relative, 'SOURCE_CHANGED')
        if stat.S_ISREG(info.st_mode):
            result['observed_files'] += 1
            result['observed_bytes'] += info.st_size
            key = info.st_dev, info.st_ino
            if key in inodes and inodes[key] != info.st_size:
                gap(relative, 'SOURCE_CHANGED')
            inodes.setdefault(key, info.st_size)
            return
        result['observed_directories'] += 1
        if depth > profile.budgets['max_depth']:
            gap(relative, 'DEPTH_LIMIT')
            return
        with dc.open_dir(root, full) as fd:
            before = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                gap(relative, 'SOURCE_CHANGED')
                return
            with os.scandir(fd) as entries:
                while True:
                    budget.charge()
                    try:
                        entry = next(entries)
                    except StopIteration:
                        break
                    child = entry.name if relative == '.' else relative + '/' + entry.name
                    visit(child, depth + 1, True)
            budget.check()
            after = os.fstat(fd)
            if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                gap(relative, 'SOURCE_CHANGED')

    try:
        budget.charge()
        budget.metadata += 1
        _same_root(root, root_identity)
        dc.validate_path_spelling(root, path, allow_missing=True)
        visit('.', 0)
        budget.charge()
        budget.metadata += 1
        _same_root(root, root_identity)
        if initial is not None:
            budget.metadata += 1
            info = dc.stat_entry(root, path)
            current = (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if current != initial:
                gap('.', 'SOURCE_CHANGED')
        for full, previous in snapshots.items():
            budget.charge()
            budget.metadata += 1
            fresh = dc.stat_entry(root, full)
            if (fresh.st_dev, fresh.st_ino, fresh.st_mode, fresh.st_size, fresh.st_mtime_ns, fresh.st_ctime_ns) != previous:
                gap(full, 'SOURCE_CHANGED')
        if expected_entries is not None and result['exists'] and seen != set(expected_entries):
            gap('.', 'MANIFEST_METADATA_INCOMPLETE')
    except (OSError, ValueError) as error:
        gap('.', getattr(error, 'reason_code', 'METADATA_UNAVAILABLE'))
    complete = gap_count == 0 and result['exists'] is True
    result.update(status='Passed' if complete else 'Unknown', bytes=result['observed_bytes'] if complete else None,
                  unique_inode_count=len(inodes), unique_inode_bytes=sum(inodes.values()))
    result['coverage'] = {'complete': complete, 'physical_metadata_complete': gap_count == 0 and result['exists'] is not None,
                          'count_is_lower_bound': not complete, 'work_entries': budget.work - work_before,
                          'metadata_lookups': budget.metadata - metadata_before, 'gap_count': gap_count,
                          'gaps': gaps, 'gaps_truncated': gap_count > len(gaps)}
    return result


def _authorized_absence(item, explanation):
    if item['exists'] is False and item['coverage']['physical_metadata_complete']:
        item.update(status='Passed', bytes=0, absence_explanation=explanation)
        item['coverage'].update(complete=True, count_is_lower_bound=False)


def _aggregate(root, items):
    complete = bool(items) and all(item['status'] == 'Passed' and item['coverage']['complete'] for item in items)
    return {'root': str(root) if root is not None else None, 'items': items, 'status': 'Passed' if complete else 'Unknown',
            'bytes': sum(item['bytes'] for item in items) if complete else None,
            'observed_bytes': sum(item['observed_bytes'] for item in items),
            'files': sum(item['observed_files'] for item in items) if complete else None,
            'directories': sum(item['observed_directories'] for item in items) if complete else None,
            'coverage': {'complete': complete, 'count_is_lower_bound': not complete}}


def _unmeasured(reason, root=None):
    return {'root': str(root) if root is not None else None, 'items': [], 'status': 'Not run', 'bytes': None,
            'observed_bytes': 0, 'files': None, 'directories': None,
            'coverage': {'complete': False, 'count_is_lower_bound': True, 'reason_code': reason}}


def _terminal_consistent(record):
    if record is None:
        return True  # A RAM preview is an observation baseline, not execution.
    state = record['state']
    if state not in ('Quarantined', 'Restored', 'Purged') or record['intent'] is not None:
        return False
    if record['direction'] != {'Quarantined': 'quarantine', 'Restored': 'restore', 'Purged': 'purge'}[state]:
        return False
    if state == 'Quarantined' and (record['restore_plan'] is not None or record['purge_plan'] is not None):
        return False
    location = {'Quarantined': 'quarantine', 'Restored': 'source', 'Purged': 'purged'}[state]
    for progress, original in zip(record['items'], record['quarantine_plan']['items']):
        if progress['state'] != state or progress['location'] != location:
            return False
        expected_removed = set(range(len(original['manifest']['entries']))) if state == 'Purged' else set()
        if set(progress['removed']) != expected_removed:
            return False
    return True


def _select_plan(profile, request, plan, record):
    from . import cleanup_operations as operations
    selected = record['quarantine_plan'] if record is not None else plan
    if selected is None:
        return None
    operations.validate_plan(profile, selected)
    if selected['kind'] != 'quarantine' or selected['request_sha256'] != dc.digest(request):
        _error('PROFILE_CONFLICT')
    if plan is not None:
        operations.validate_plan(profile, plan)
        if plan['fingerprint'] != selected['fingerprint']:
            _error('PROFILE_CONFLICT')
    return selected


def _bounded(value, limit):
    if len(dc.canonical(value)) + 100 > limit:
        _error('BUDGET_EXHAUSTED')
    return dc.seal(value)


def measure(profile, request, quarantine_root, records_dir, *, plan=None, journal=None, stage=None):
    """Observe exact source/Q positions and the entire explicitly granted REC.

    T0 uses a RAM or pre-existing approved quarantine plan. This function never
    creates a plan, journal, output directory or receipt. An absent source gets
    zero only with an owned, persisted, consistent terminal cleanup journal.
    """
    from . import cleanup_policy as policy
    from . import cleanup_operations as operations
    if stage is not None and stage not in STAGES:
        _error('INVALID_INPUT')
    started_at, budget = _now(), _Budget(profile)
    policy.validate_profile_root(profile)
    if request is None:
        if plan is not None or journal is not None:
            _error('INVALID_INPUT')
        return _unbound_measurement(profile, stage)
    normalized = policy.validate_request(profile, request)
    root_ids = {'project': _root_id(profile.root), 'quarantine': None, 'records': None}
    q = rec = record = None
    if quarantine_root is not None and records_dir is not None:
        q, rec = policy.runtime_roots(profile, quarantine_root, records_dir)
        root_ids.update(quarantine=_root_id(q), records=_root_id(rec))
        if journal is not None:
            # The loader checks the real private REC inode and supplied seal;
            # it does not obtain authority from the journal's Q declaration.
            record = operations.load_record_metadata(profile, journal, rec)
    elif journal is not None:
        _error('BODY_NOT_AUTHORIZED')
    selected = _select_plan(profile, normalized, plan, record)
    if selected is not None and q is not None and selected['roots'] != root_ids:
        _error('SOURCE_CHANGED')
    if record is not None:
        operations.validate_record(profile, record)
    items = selected['items'] if selected is not None else [{'source': item['source'], 'quarantine_relative': None, 'manifest': None} for item in normalized['items']]
    _exact_paths([item['source'] for item in items])
    if selected is not None:
        _exact_paths([item['quarantine_relative'] for item in items])
    cohort = {'roots': root_ids, 'operation_id': selected['operation_id'] if selected else None,
              'items': [{'source': item['source'], 'quarantine_relative': item['quarantine_relative'],
                         'manifest_sha256': dc.digest(item['manifest']) if item['manifest'] is not None else None} for item in items],
              'records_scope': 'entire-explicit-root', 'logical_bytes': 'per-named-regular-file', 'budgets': dict(profile.budgets)}
    source_items, quarantine_items = [], []
    consistent = _terminal_consistent(record)
    for index, item in enumerate(items):
        expected = operations.expected_manifest(record, index, remaining=record['state'] in ('Purging', 'PartiallyPurged', 'Purged', 'NeedsAttention')) if record else item['manifest']
        protect = lambda suffix, source=item['source']: policy.protected(profile, source if suffix == '.' else source + '/' + suffix)
        source = _observe(profile, profile.root, item['source'], budget, root_ids['project'], expected=expected, protect=protect)
        if q is not None and selected is not None:
            quarantined = _observe(profile, q, item['quarantine_relative'], budget, root_ids['quarantine'], expected=expected, protect=protect)
            state = record['state'] if record is not None else None
            if record is None:
                _authorized_absence(quarantined, {'kind': 'FutureQuarantinePosition', 'plan_fingerprint': selected['fingerprint']})
            elif consistent:
                basis = {'operation_id': record['operation_id'], 'journal_fingerprint': record['fingerprint'], 'record_binding': 'owned-persisted-REC', 'actor_attribution': 'Unknown'}
                if state == 'Quarantined' and quarantined['status'] == 'Passed' and quarantined['exists'] is True:
                    _authorized_absence(source, {**basis, 'kind': 'Quarantined'})
                elif state == 'Purged' and quarantined['exists'] is False and quarantined['coverage']['physical_metadata_complete']:
                    _authorized_absence(source, {**basis, 'kind': 'Purged'})
                    _authorized_absence(quarantined, {**basis, 'kind': 'Purged'})
                elif state == 'Restored' and source['status'] == 'Passed' and source['exists'] is True:
                    _authorized_absence(quarantined, {**basis, 'kind': 'RestoredQuarantineMissing'})
                # A returned source after quarantine/purge is not the old cohort,
                # even if its current size happens to equal the old payload size.
                if state in ('Quarantined', 'Purged') and source['exists'] is True:
                    source['status'], source['bytes'] = 'Unknown', None
                    source['coverage']['complete'] = False
                    source['coverage']['gaps'].append({'path': '.', 'reason_code': 'SOURCE_REAPPEARED'})
            quarantine_items.append(quarantined)
        source_items.append(source)
    domains = {'project_payload': _aggregate(profile.root, source_items),
               'quarantine_payload': _aggregate(q, quarantine_items) if quarantine_items else _unmeasured('PLAN_OR_RUNTIME_ROOTS_MISSING', q),
               'records': _unmeasured('RUNTIME_ROOTS_MISSING')}
    if rec is not None:
        records = _observe(profile, rec, '.', budget, root_ids['records'])
        domains['records'] = _aggregate(rec, [records])
    complete = selected is not None and consistent and all(item['status'] == 'Passed' and item['coverage']['complete'] for item in domains.values())
    reasons = []
    if selected is None:
        reasons.append('PLAN_BINDING_MISSING')
    if not consistent:
        reasons.append('EXECUTION_INCOMPLETE_OR_INCONSISTENT')
    if q is None:
        reasons.append('RUNTIME_ROOTS_MISSING')
    value = {'format': FORMAT, 'schema_version': 1, 'kind': 'measurement', 'root': str(profile.root), 'profile_sha256': profile.sha256,
             'config_sha256': dc.digest(profile.config), 'request_sha256': dc.digest(normalized), 'operation_id': cohort['operation_id'],
             'cohort': cohort, 'cohort_sha256': dc.digest(cohort), 'stage': stage,
             'status': 'Passed' if complete else 'Unknown', 'reasons': reasons, 'domains': domains,
             'total_logical_bytes': sum(item['bytes'] for item in domains.values()) if complete else None,
             'observed_total_logical_bytes': sum(item['observed_bytes'] for item in domains.values()), 'total_is_lower_bound': not complete,
             'cleanup_state': record['state'] if record is not None else None,
             'journal_fingerprint': record['fingerprint'] if record is not None else None,
             'plan_fingerprint': selected['fingerprint'] if selected is not None else None,
             'payload_body_bytes_read': 0, 'record_metadata_io': 'owned REC JSON loader' if record is not None else 'Not run',
             'work_entries': budget.work, 'metadata_lookups': budget.metadata, 'elapsed_seconds': round(time.monotonic() - budget.started, 6),
             'started_at': started_at, 'observed_at': _now(), 'post_observation_artifacts_measured': False,
             'storage_release': 'Unknown', 'content_conservation': 'Unknown', 'exclusive_attribution': 'Unknown',
             'physical_release_bytes': None, 'semantic_acceptance': 'Not run', 'warnings': list(WARNINGS)}
    policy.validate_profile_root(profile)
    return _bounded(value, profile.budgets['max_artifact_bytes'])


def _measurement(value):
    dc.validate_seal(value)
    if (value.get('format'), value.get('schema_version'), value.get('kind')) != (FORMAT, 1, 'measurement'):
        _error()
    if value.get('cohort_sha256') != dc.digest(value.get('cohort')):
        _error()
    domains = value.get('domains')
    if not isinstance(domains, dict) or set(domains) != set(DOMAINS):
        _error()
    for item in domains.values():
        if not isinstance(item, dict) or not isinstance(item.get('coverage'), dict):
            _error()
        if item.get('status') == 'Passed' and (type(item.get('bytes')) is not int or item['bytes'] < 0 or not item['coverage'].get('complete')):
            _error()
    return value


def evaluate(before, after, *, stage):
    """Compare the same cohort; Unknown observations never become numeric zero."""
    if stage not in STAGES - {'T0'}:
        _error('INVALID_INPUT')
    before, after = _measurement(before), _measurement(after)
    binding = ('root', 'profile_sha256', 'config_sha256', 'request_sha256', 'operation_id', 'cohort_sha256', 'plan_fingerprint')
    mismatches = [key for key in binding if before.get(key) != after.get(key)]
    if after.get('stage') not in (None, stage):
        mismatches.append('stage')
    if before.get('stage') in STAGES and before['stage'] >= stage:
        mismatches.append('stage_order')
    domains = {}
    for key in DOMAINS:
        left, right = before['domains'][key], after['domains'][key]
        complete = not mismatches and all(item.get('status') == 'Passed' and item['coverage'].get('complete') for item in (left, right))
        domains[key] = {'status': 'Passed' if complete else 'Unknown',
                        'before_bytes': left['bytes'], 'after_bytes': right['bytes'],
                        'delta_bytes': right['bytes'] - left['bytes'] if complete else None}
    complete = not mismatches and all(item['status'] == 'Passed' for item in domains.values())
    payload_complete = not mismatches and all(domains[key]['status'] == 'Passed' for key in DOMAINS[:2])
    reduction = -sum(domains[key]['delta_bytes'] for key in DOMAINS[:2]) if payload_complete else None
    result = {'format': FORMAT, 'schema_version': 1, 'kind': 'evaluation', 'stage': stage,
              'status': 'Passed' if complete else 'Unknown', 'coverage': {'complete': complete},
              'binding_mismatches': mismatches, 'root': after['root'], 'profile_sha256': after['profile_sha256'],
              'config_sha256': after['config_sha256'], 'request_sha256': after['request_sha256'],
              'operation_id': after['operation_id'], 'cohort_sha256': after['cohort_sha256'],
              'before_fingerprint': before['fingerprint'], 'after_fingerprint': after['fingerprint'],
              'domains': domains, 'logical_payload_reduction_bytes': reduction,
              'logical_purged_payload_bytes': reduction if after.get('cleanup_state') == 'Purged' and reduction is not None and reduction >= 0 else None,
              'total_delta_bytes': sum(item['delta_bytes'] for item in domains.values()) if complete else None,
              'physical_release_bytes': None, 'storage_release': 'Unknown', 'exclusive_attribution': 'Unknown',
              'semantic_acceptance': 'Not run', 'post_observation_artifacts_measured': False,
              'warnings': list(WARNINGS)}
    return dc.seal(result)


def history(profile, records_dir, *, max_records=1000, max_bytes=64 * 1024 * 1024):
    """Project declarations from one explicit REC, never opening source or Q.

    Ownership verification refers only to the REC JSON and its private directory.
    Payload presence is deliberately Not run, even for terminal declarations.
    """
    import json
    from . import cleanup_operations as operations
    if type(max_records) is not int or max_records < 1 or max_records > profile.budgets['max_entries']:
        _error('BUDGET_EXHAUSTED')
    if type(max_bytes) is not int or max_bytes < 1 or max_bytes > min(dc.HARD_BUDGETS['max_artifact_bytes'], profile.budgets['max_reference_bytes']):
        _error('BUDGET_EXHAUSTED')
    rec = dc.safe_root(records_dir)
    if dc.canonical_destination(profile.data['records_dir']) != rec:
        _error('PROFILE_CONFLICT')
    identity, budget = _root_id(rec), _Budget(profile)
    records, gaps, used, candidates = [], [], 0, 0
    try:
        with dc.open_dir(rec) as fd:
            with os.scandir(fd) as entries:
                for entry in entries:
                    budget.charge()
                    # Only the cleanup protocol's explicit operation directories.
                    if not entry.name.startswith('cleanup-'):
                        continue
                    name = entry.name
                    if len(name) != 40 or any(c not in '0123456789abcdef' for c in name[8:]):
                        gaps.append({'path': name, 'reason_code': 'JOURNAL_INVALID'})
                        continue
                    candidates += 1
                    if candidates > max_records:
                        _error('BUDGET_EXHAUSTED')
                    rel = name + '/journal.json'
                    try:
                        info = dc.stat_entry(rec, rel)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            _error('PROTECTED_PATH')
                        limit = min(profile.budgets['max_artifact_bytes'], max_bytes - used)
                        if info.st_size > limit:
                            _error('BUDGET_EXHAUSTED')
                        raw = dc.read_file(rec, rel, limit)
                        used += len(raw)
                        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                                           parse_constant=lambda _: _error('JOURNAL_INVALID'))
                        budget.check()
                        if not isinstance(value, dict):
                            _error('JOURNAL_INVALID')
                        if value.get('format') != 'fifan-cleanup-journal':
                            _error('JOURNAL_INVALID')
                        operations.validate_record(profile, value)
                        # Verify owned REC metadata without a second, independently
                        # budgeted body read. Embedded Q/source paths are never opened.
                        owner = value['record_owner']
                        if (info.st_dev, info.st_ino) != (owner['device'], owner['inode']) or stat.S_IMODE(info.st_mode) != 0o600:
                            _error('JOURNAL_CHANGED')
                        directory = dc.stat_entry(rec, name)
                        expected_owner = value['record_directory']
                        if (directory.st_dev, directory.st_ino, stat.S_IMODE(directory.st_mode)) != (expected_owner['device'], expected_owner['inode'], 0o700):
                            _error('OWNERSHIP_CHANGED')
                        fresh = dc.stat_entry(rec, rel)
                        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (fresh.st_dev, fresh.st_ino, fresh.st_size, fresh.st_mtime_ns, fresh.st_ctime_ns):
                            _error('JOURNAL_CHANGED')
                        if value['journal_path'] != str(rec / rel) or value['quarantine_plan']['roots']['records'] != identity:
                            _error('SOURCE_CHANGED')
                        plan = value['quarantine_plan']
                        terminal = _terminal_consistent(value)
                        declared_exists = {'Quarantined': False, 'Purged': False, 'Restored': True}.get(value['state']) if terminal else None
                        items = [{'source': item['source'], 'quarantine_relative': item['quarantine_relative'],
                                  'manifest_file_bytes': item['manifest']['file_bytes'],
                                  'declared_location': progress['location'], 'declared_state': progress['state'],
                                  'declared_source_exists': declared_exists,
                                  'source_exists': None, 'quarantine_exists': None, 'live_verification': 'Not run'}
                                 for item, progress in zip(plan['items'], value['items'])]
                        records.append({'operation_id': value['operation_id'], 'journal_fingerprint': value['fingerprint'],
                                        'request_sha256': plan['request_sha256'], 'state': value['state'],
                                        'terminal_consistent': terminal, 'status': 'Passed' if terminal else 'Unknown', 'items': items,
                                        'ownership_verification': 'Passed', 'live_verification': 'Not run'})
                    except (OSError, ValueError, TypeError, KeyError) as error:
                        gaps.append({'path': rel, 'reason_code': getattr(error, 'reason_code', 'JOURNAL_INVALID')})
                        if getattr(error, 'reason_code', None) == 'BUDGET_EXHAUSTED':
                            break
        _same_root(rec, identity)
    except (OSError, ValueError) as error:
        gaps.append({'path': '.', 'reason_code': getattr(error, 'reason_code', 'METADATA_UNAVAILABLE')})
    records.sort(key=lambda item: item['operation_id'])
    complete = not gaps and all(item['status'] == 'Passed' for item in records)
    return _bounded({'format': FORMAT, 'schema_version': 1, 'kind': 'history', 'root': str(profile.root),
                     'profile_sha256': profile.sha256, 'config_sha256': dc.digest(profile.config),
                     'records_root': identity, 'status': 'Passed' if complete else 'Unknown',
                     'coverage': {'complete': complete, 'count_is_lower_bound': bool(gaps), 'gaps': gaps[:20],
                                  'gap_count': len(gaps)}, 'records': records, 'record_count': len(records),
                     'record_metadata_bytes_read': used, 'payload_body_bytes_read': 0,
                     'live_verification': 'Not run', 'projection': 'declarations only',
                     'observed_at': _now(), 'post_observation_artifacts_measured': False}, profile.budgets['max_artifact_bytes'])


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _error('JOURNAL_INVALID')
        result[key] = value
    return result


def _unbound_measurement(profile, stage):
    """Inspect has no approved request cohort and cannot invent payload totals."""
    roots = {'project': _root_id(profile.root), 'quarantine': None, 'records': None}
    cohort = {'roots': roots, 'operation_id': None, 'items': [], 'records_scope': 'Not run',
              'logical_bytes': 'per-named-regular-file', 'budgets': dict(profile.budgets)}
    return _bounded({'format': FORMAT, 'schema_version': 1, 'kind': 'measurement', 'stage': stage,
                     'root': str(profile.root), 'profile_sha256': profile.sha256, 'config_sha256': dc.digest(profile.config),
                     'request_sha256': None, 'operation_id': None, 'cohort': cohort, 'cohort_sha256': dc.digest(cohort),
                     'status': 'Unknown', 'coverage': {'complete': False, 'reason_codes': ['COHORT_NOT_DECLARED']},
                     'domains': {name: _unmeasured('COHORT_NOT_DECLARED') for name in DOMAINS},
                     'total_logical_bytes': None, 'observed_total_logical_bytes': 0, 'total_is_lower_bound': True,
                     'cleanup_state': None, 'journal_fingerprint': None, 'plan_fingerprint': None,
                     'payload_body_bytes_read': 0, 'observed_at': _now(), 'post_observation_artifacts_measured': False,
                     'physical_release_bytes': None, 'storage_release': 'Unknown', 'content_conservation': 'Unknown',
                     'exclusive_attribution': 'Unknown', 'semantic_acceptance': 'Not run', 'warnings': list(WARNINGS)},
                    profile.budgets['max_artifact_bytes'])
