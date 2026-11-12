"""Read-only three-domain logical footprint observations for directory workflows.

The fixed cohort includes the whole declared records root. This is metadata,
not content conservation, exclusive attribution or a physical-space estimate.
"""
from __future__ import annotations

import os
import stat
import time
from datetime import datetime, timezone

from . import directory_common as dc

DOMAINS = ('project_payload', 'archive_payload', 'records')
WARNINGS = [
    'Per-entry observations are not an atomic snapshot; concurrent external changes cannot be attributed exclusively to this workflow.',
    'Artifacts written after observed_at, including a later measurement receipt, are not included; this is not the final dataset size.',
    'Logical footprint does not prove original-content conservation; use independent manifest verification.',
    'Logical bytes and inode counts do not establish physical space or released storage.',
]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _binding(profile, request, archive_root, records_dir):
    arc, rec = dc.external_roots(profile, archive_root, records_dir)
    if not isinstance(request, dict) or set(request) != {'schema_version', 'batches'} or type(request.get('schema_version')) is not int or request['schema_version'] != 1:
        raise dc.DirectoryError('INVALID_INPUT', 'invalid footprint request')
    roots = {}
    for label, root in (('project', profile.root), ('archive', arc), ('records', rec)):
        info = dc.stat_entry(root, '.')
        roots[label] = {'path': str(root), 'device': info.st_dev, 'inode': info.st_ino}
    expected = getattr(profile, '_root_identity', ())
    if expected and tuple(expected) != (roots['project']['device'], roots['project']['inode']):
        raise dc.DirectoryError('SOURCE_CHANGED', 'profile project root was replaced')
    batches = request['batches']
    if not isinstance(batches, list) or not 1 <= len(batches) <= 100:
        raise dc.DirectoryError('INVALID_INPUT', 'footprint needs 1..100 exact batches')
    selected, sources, destinations = [], [], []
    source_ids, destination_ids = set(), set()
    authorized = {dc.path_key(path) for path in profile.data.get('archive', {}).get('candidates', [])}
    for batch in batches:
        if not isinstance(batch, dict) or not {'source', 'destination'} <= set(batch) or set(batch) - {'source', 'destination', 'closure', 'historical_references', 'known_absent', 'dynamic_reference_resolutions'}:
            raise dc.DirectoryError('INVALID_INPUT', 'invalid footprint batch')
        source, dest = dc.relative(batch['source']), dc.relative(batch['destination'])
        if dc.path_key(source) not in authorized:
            raise dc.DirectoryError('BODY_NOT_AUTHORIZED', 'footprint candidate is not declared')
        for values, path in ((sources, source), (destinations, dest)):
            key = dc.path_key(path)
            if any(key == previous or key.startswith(previous + '/') or previous.startswith(key + '/') for previous in values):
                raise dc.DirectoryError('INVALID_INPUT', 'footprint batch paths overlap')
            values.append(key)
        for owner, path, identities in ((profile.root, source, source_ids), (arc, dest, destination_ids)):
            if dc.protected(profile, path, archive=True):
                continue  # Protection remains an explicit Unknown domain, not missing zero.
            try:
                dc.validate_path_spelling(owner, path, allow_missing=True)
                info = dc.stat_entry(owner, path)
            except dc.DirectoryError as error:
                if error.reason_code == 'PATH_ALIAS':
                    raise
                continue  # The observation itself reports unsafe/unavailable metadata.
            except OSError:
                continue
            identity = (info.st_dev, info.st_ino)
            if identity in identities:
                raise dc.DirectoryError('PATH_ALIAS', 'footprint batches identify the same directory')
            identities.add(identity)
        selected.append({'source': source, 'destination': dest})
    cohort = {'roots': roots, 'batches': sorted(selected, key=lambda b: (b['source'], b['destination'])),
              'records_scope': 'entire-declared-root', 'logical_bytes': 'per-named-regular-file'}
    return arc, rec, cohort


class _Budget:
    def __init__(self, profile):
        self.limits = profile.budgets
        self.started = time.monotonic()
        self.work = self.metadata = 0

    def charge(self):
        if self.work >= self.limits['max_entries'] or time.monotonic() - self.started >= self.limits['max_seconds']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'metadata observation budget exhausted')
        self.work += 1

    def check_time(self):
        if time.monotonic() - self.started >= self.limits['max_seconds']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'metadata observation time exhausted')


def _domain(profile, root, positions, budget, global_inodes, *, archive_protection, expected_identity):
    result = {'root': str(root), 'paths': positions, 'bytes': 0, 'files': 0, 'dirs': 0,
              'absent': [], 'status': 'Passed', 'unique_inode_count': 0, 'unique_inode_bytes': 0}
    local_inodes, gaps = {}, []
    gap_count = 0
    work_before, metadata_before = budget.work, budget.metadata

    def gap(path, code):
        nonlocal gap_count
        result['status'] = 'Unknown'
        gap_count += 1
        if len(gaps) < 20:
            gaps.append({'path': path, 'reason_code': code})

    def visit(path, depth, *, future=False, charged=False):
        if not charged:
            budget.charge()
        if dc.protected(profile, path, archive=archive_protection):
            gap(path, 'PROTECTED_PATH')
            return
        try:
            budget.metadata += 1
            info = dc.stat_entry(root, path)
        except FileNotFoundError:
            # Only a batch's explicitly declared future position can be absent.
            # The fixed records root itself must exist via external_roots().
            if future:
                result['absent'].append(path)
            else:
                gap(path, 'SOURCE_CHANGED')
            return
        except (OSError, dc.DirectoryError):
            gap(path, 'METADATA_UNAVAILABLE')
            return
        if stat.S_ISREG(info.st_mode):
            if future:
                gap(path, 'BATCH_NOT_DIRECTORY')
                return
            result['files'] += 1
            result['bytes'] += info.st_size
            identity = (info.st_dev, info.st_ino)
            prior = global_inodes.get(identity)
            if prior is not None and prior != info.st_size:
                gap(path, 'SOURCE_CHANGED')
            global_inodes.setdefault(identity, info.st_size)
            local_inodes.setdefault(identity, info.st_size)
            return
        if not stat.S_ISDIR(info.st_mode):
            gap(path, 'SYMLINK_OR_SPECIAL')
            return
        result['dirs'] += 1
        if depth > profile.budgets['max_depth']:
            gap(path, 'DEPTH_LIMIT')
            return
        try:
            with dc.open_dir(root, path) as fd:
                before = os.fstat(fd)
                if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                    gap(path, 'SOURCE_CHANGED')
                    return
                with os.scandir(fd) as iterator:
                    while True:
                        budget.charge()  # Includes empty/EOF iterations and exclusions.
                        try:
                            entry = next(iterator)
                        except StopIteration:
                            break
                        child = entry.name if path == '.' else path + '/' + entry.name
                        visit(child, depth + 1, charged=True)
                budget.check_time()
                after = os.fstat(fd)
                if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                    gap(path, 'SOURCE_CHANGED')
        except dc.DirectoryError as error:
            if error.reason_code == 'BUDGET_EXHAUSTED':
                raise
            gap(path, error.reason_code)
        except OSError:
            gap(path, 'DIRECTORY_UNAVAILABLE')

    def check_root():
        budget.charge()
        budget.metadata += 1
        info = dc.stat_entry(root, '.')
        if (info.st_dev, info.st_ino) != expected_identity:
            raise dc.DirectoryError('SOURCE_CHANGED', 'footprint root was replaced')

    root_valid = True
    try:
        check_root()
    except (OSError, dc.DirectoryError) as error:
        gap('.', getattr(error, 'reason_code', 'METADATA_UNAVAILABLE'))
        root_valid = False
    for index, position in enumerate(positions if root_valid else []):
        try:
            visit(position, 0, future=position != '.')
        except dc.DirectoryError as error:
            gap(position, error.reason_code)
            if error.reason_code == 'BUDGET_EXHAUSTED':
                # Retain explicit unobserved roots without inventing their size.
                for pending in positions[index + 1:]:
                    gap(pending, 'NOT_OBSERVED_BUDGET')
                break
    if root_valid:
        try:
            check_root()
        except (OSError, dc.DirectoryError) as error:
            gap('.', getattr(error, 'reason_code', 'METADATA_UNAVAILABLE'))
    complete = result['status'] == 'Passed'
    result['observed_bytes'] = result['bytes']
    result['unique_inode_count'] = len(local_inodes)
    result['unique_inode_bytes'] = sum(local_inodes.values())
    result['presence'] = 'Absent' if complete and len(result['absent']) == len(positions) else 'Present' if complete else 'Unknown'
    result['coverage'] = {'complete': complete, 'count_is_lower_bound': not complete,
                          'work_entries': budget.work - work_before, 'metadata_lookups': budget.metadata - metadata_before,
                          'gap_count': gap_count, 'gaps': gaps, 'gaps_truncated': gap_count > len(gaps)}
    # Numeric bytes always mean the observed lower bound; the status and coverage
    # gate all differences. Unknown is never silently used as a measured zero.
    return result


def measure(profile, request, archive_root, records_dir):
    started_at = _now()
    arc, rec, cohort = _binding(profile, request, archive_root, records_dir)
    budget, global_inodes = _Budget(profile), {}
    domains = {}
    for name, root, positions, protection in (
        ('project_payload', profile.root, [b['source'] for b in cohort['batches']], True),
        ('archive_payload', arc, [b['destination'] for b in cohort['batches']], True),
        ('records', rec, ['.'], False),
    ):
        label = {'project_payload': 'project', 'archive_payload': 'archive', 'records': 'records'}[name]
        identity = cohort['roots'][label]
        domains[name] = _domain(profile, root, positions, budget, global_inodes, archive_protection=protection,
                                expected_identity=(identity['device'], identity['inode']))
    complete = all(d['status'] == 'Passed' for d in domains.values())
    finished_at = _now()
    return {'schema_version': 1, 'format': 'fifan-directory-metrics', 'root': str(profile.root),
            'profile_sha256': profile.sha256, 'cohort_sha256': dc.digest(cohort), 'cohort': cohort,
            'status': 'Passed' if complete else 'Unknown', 'domains': domains,
            'total_logical_bytes': sum(d['bytes'] for d in domains.values()),
            'total_is_lower_bound': not complete, 'unique_inode_count': len(global_inodes),
            'unique_inode_bytes': sum(global_inodes.values()), 'body_bytes_read': 0,
            'metadata_lookups': budget.metadata, 'binding_metadata_lookups': 3, 'work_entries': budget.work,
            'elapsed_seconds': round(time.monotonic() - budget.started, 6),
            'observed_at': finished_at, 'started_at': started_at,
            'storage_release': 'Unknown', 'content_conservation': 'Unknown', 'exclusive_attribution': 'Unknown',
            'warnings': list(WARNINGS)}


def evaluate(before, after):
    """Compare the exact same complete cohort. Deltas never accept content loss."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise dc.DirectoryError('INVALID_INPUT', 'footprint comparison requires objects')
    reasons = []
    for field in ('root', 'profile_sha256', 'cohort_sha256'):
        if not isinstance(before.get(field), str) or not before[field] or before[field] != after.get(field):
            reasons.append('binding-mismatch:' + field)
    for label, measurement in (('before', before), ('after', after)):
        if measurement.get('format') != 'fifan-directory-metrics' or type(measurement.get('schema_version')) is not int or measurement['schema_version'] != 1:
            reasons.append(label + ':unsupported-measurement')
        if not isinstance(measurement.get('observed_at'), str) or not measurement['observed_at']:
            reasons.append(label + ':missing-observation-time')
        domains = measurement.get('domains')
        if not isinstance(domains, dict):
            reasons.append(label + ':incomplete-domains')
            continue
        for name in DOMAINS:
            item = domains.get(name)
            if (not isinstance(item, dict) or item.get('status') != 'Passed'
                    or not isinstance(item.get('coverage'), dict) or item['coverage'].get('complete') is not True
                    or item['coverage'].get('count_is_lower_bound') is not False
                    or any(type(item.get(k)) is not int or item[k] < 0 for k in ('bytes', 'files', 'dirs'))):
                reasons.append(label + ':incomplete-domain:' + name)
        if measurement.get('status') != 'Passed' or measurement.get('total_is_lower_bound') is not False:
            reasons.append(label + ':incomplete-measurement')
        cohort = measurement.get('cohort')
        if not isinstance(cohort, dict) or dc.digest(cohort) != measurement.get('cohort_sha256'):
            reasons.append(label + ':invalid-cohort')
        else:
            roots, batches = cohort.get('roots'), cohort.get('batches')
            if (not isinstance(roots, dict) or not isinstance(batches, list)
                    or not batches or any(not isinstance(b, dict) or set(b) != {'source', 'destination'} for b in batches)
                    or any(not isinstance(roots.get(k), dict) for k in ('project', 'archive', 'records'))):
                reasons.append(label + ':invalid-cohort')
            else:
                expected = {'project_payload': ('project', [b['source'] for b in batches]),
                            'archive_payload': ('archive', [b['destination'] for b in batches]),
                            'records': ('records', ['.'])}
                for name, (root_label, paths) in expected.items():
                    item = domains.get(name, {})
                    if not isinstance(item, dict) or item.get('root') != roots[root_label].get('path') or item.get('paths') != paths:
                        reasons.append(label + ':domain-cohort-mismatch:' + name)
    deltas = {'project_reduction_bytes': None, 'archive_increase_bytes': None,
              'records_increase_bytes': None, 'combined_delta_bytes': None}
    if not reasons:
        old, new = before['domains'], after['domains']
        deltas = {'project_reduction_bytes': old['project_payload']['bytes'] - new['project_payload']['bytes'],
                  'archive_increase_bytes': new['archive_payload']['bytes'] - old['archive_payload']['bytes'],
                  'records_increase_bytes': new['records']['bytes'] - old['records']['bytes'],
                  'combined_delta_bytes': sum(new[n]['bytes'] - old[n]['bytes'] for n in DOMAINS)}
    return {'schema_version': 1, 'format': 'fifan-directory-metrics-evaluation',
            'root': before.get('root') if 'binding-mismatch:root' not in reasons else None,
            'profile_sha256': before.get('profile_sha256') if 'binding-mismatch:profile_sha256' not in reasons else None,
            'cohort_sha256': before.get('cohort_sha256') if 'binding-mismatch:cohort_sha256' not in reasons else None,
            'status': 'Passed' if not reasons else 'Unknown', 'reasons': reasons, **deltas,
            'observed_at': {'before': before.get('observed_at'), 'after': after.get('observed_at')},
            'storage_release': 'Unknown', 'content_conservation': 'Unknown', 'exclusive_attribution': 'Unknown',
            'warnings': list(WARNINGS)}
