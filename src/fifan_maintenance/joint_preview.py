"""Read-only file/navigation + archive projection, never an executable plan.

The only disk state accepted for execution remains a fresh native archive
preview after the independently journalled file apply has completed.
"""
from __future__ import annotations

import hashlib
import posixpath
import stat
from pathlib import Path
from urllib.parse import unquote, urlsplit

from . import changes, directory_archive as archive, directory_common as dc
from . import directory_census as census
from .adapters.markdown import parse

FORMAT = 'fifan-joint-preview'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _authorized(profile, path):
    return any(path == item['path'] or path.startswith(item['path'] + '/')
               for item in profile.data['reference_sources']) and not dc.protected(profile, path)


def _navigation(profile, overlay, request, fingerprints):
    """Check local navigation in the projected final namespace, with bounded IO."""
    issues, checked, observations = [], 0, []
    metadata_entries = 0
    limits = dc.reference_hash_limits(profile)
    budget = dc.HashBudget(limits)
    archive_root = Path(profile.data['archive']['archive_root'])
    cache = {}
    expected = {item['path']: item['sha256'] for item in fingerprints}

    def body(path, *, payload=False):
        if path in cache:
            return cache[path]
        if (not _authorized(profile, path) and not (payload and any(census._within(path, batch['source']) for batch in request['batches']))) or dc.protected(profile, path):
            raise dc.DirectoryError('BODY_NOT_AUTHORIZED')
        if path in overlay:
            raw = overlay[path]
            if raw is None:
                raise FileNotFoundError(path)
            budget.charge_entry()
            if len(raw) > profile.budgets['max_reference_file_bytes']:
                raise dc.DirectoryError('BUDGET_EXHAUSTED')
            budget.charge_bytes(len(raw))
        else:
            budget.charge_entry()
            remaining = limits['max_hash_bytes'] - budget.bytes
            raw = dc.read_file(profile.root, path, min(remaining, profile.budgets['max_reference_file_bytes']))
            budget.charge_bytes(len(raw))
        if path in expected and _sha(raw) != expected[path]:
            raise dc.DirectoryError('SOURCE_CHANGED')
        cache[path] = parse(raw.decode('utf-8'))
        return cache[path]

    def target_location(source, token):
        # Normalize text only. All actual IO uses no-follow descriptor helpers.
        url = urlsplit(token)
        if url.scheme in ('http', 'https', 'mailto', 'tel', 'ftp') or url.netloc:
            raise dc.DirectoryError('EXTERNAL_TARGET_NOT_CHECKED')
        if url.scheme not in ('', 'file') or url.query:
            raise dc.DirectoryError('TARGET_SEMANTICS_UNKNOWN')
        decoded = unquote(url.path)
        if '\x00' in decoded or '\\' in decoded:
            raise dc.DirectoryError('TARGET_SEMANTICS_UNKNOWN')
        absolute = Path(posixpath.normpath(decoded if decoded.startswith('/') else
                        str(profile.root / posixpath.dirname(source)) + '/' + decoded)) if decoded else profile.root / source
        for batch in request['batches']:
            dest = archive_root / batch['destination']
            if absolute == dest or dest in absolute.parents:
                suffix = absolute.relative_to(dest).as_posix()
                mapped = batch['source'] + ('' if suffix == '.' else '/' + suffix)
                return mapped, unquote(url.fragment), True
        if absolute != profile.root and profile.root not in absolute.parents:
            raise dc.DirectoryError('TARGET_OUTSIDE_DECLARED_ROOTS')
        path = absolute.relative_to(profile.root).as_posix()
        dc.relative(path)
        for batch in request['batches']:
            if census._within(path, batch['source']):
                # Native locator contents/anchors are generated only by apply.
                raise dc.DirectoryError('FINAL_TARGET_REMOVED')
        return path, unquote(url.fragment), False

    for item in fingerprints:
        source = item['path']
        if item['role'] != 'current' or not source.lower().endswith(('.md', '.markdown', '.html', '.htm')) or overlay.get(source, b'') is None:
            continue
        try:
            doc = body(source)
            if doc.unsupported:
                issues.append({'path': source, 'reason_code': 'NAVIGATION_SYNTAX_UNKNOWN', 'status': 'Unknown'})
            for link in doc.links:
                budget.check_time()
                try:
                    target, anchor, archived = target_location(source, link.target)
                    if metadata_entries >= profile.budgets['max_entries']:
                        raise dc.DirectoryError('BUDGET_EXHAUSTED')
                    metadata_entries += 1
                    if dc.protected(profile, target, archive=archived):
                        raise dc.DirectoryError('PROTECTED_PATH')
                    if target in overlay and not archived:
                        if overlay[target] is None:
                            raise FileNotFoundError(target)
                        is_dir = False
                    else:
                        dc.validate_path_spelling(profile.root, target)
                        info = dc.stat_entry(profile.root, target)
                        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                            raise dc.DirectoryError('TARGET_NOT_REGULAR')
                        is_dir = stat.S_ISDIR(info.st_mode)
                    if anchor:
                        if is_dir or not target.lower().endswith(('.md', '.markdown', '.html', '.htm')):
                            raise dc.DirectoryError('ANCHOR_FORMAT_UNKNOWN')
                        if profile.config.get('links', {}).get('anchor_style', 'github') != 'github':
                            raise dc.DirectoryError('ANCHOR_STYLE_UNKNOWN')
                        if anchor not in body(target, payload=archived).anchors:
                            raise dc.DirectoryError('FINAL_ANCHOR_MISSING')
                    checked += 1
                    observations.append({'path': source, 'line': link.line, 'mapped_target': target,
                                         'location': 'future_archive' if archived else 'project'})
                except (OSError, ValueError, UnicodeError) as error:
                    reason = getattr(error, 'reason_code', 'FINAL_TARGET_MISSING' if isinstance(error, FileNotFoundError) else 'NAVIGATION_UNAVAILABLE')
                    status = 'Blocked' if reason in ('FINAL_TARGET_MISSING', 'FINAL_TARGET_REMOVED', 'FINAL_ANCHOR_MISSING') else 'Unknown'
                    issues.append({'path': source, 'line': link.line, 'reason_code': reason, 'status': status})
                if len(dc.canonical(issues)) + len(dc.canonical(observations)) > profile.budgets['max_artifact_bytes'] // 2:
                    raise dc.DirectoryError('BUDGET_EXHAUSTED')
        except (OSError, ValueError, UnicodeError) as error:
            issues.append({'path': source, 'reason_code': getattr(error, 'reason_code', 'NAVIGATION_UNAVAILABLE'), 'status': 'Unknown'})
    return {'checked': checked, 'issues': issues, 'targets': observations, 'hash_usage': budget.snapshot(), 'metadata_entries': metadata_entries}


def preview(profile, file_plan, archive_request, archive_root, records_dir):
    dc.validate_profile_root(profile)
    if dc.digest(profile.data) != profile.sha256 or profile.budgets != profile.data['budgets']:
        raise dc.DirectoryError('PROFILE_CONFLICT')
    overlay = changes.overlay(profile.root, file_plan, profile.config)
    archive_root, records_root = dc.external_roots(profile, archive_root, records_dir)
    batches = archive._request(profile, archive_request)
    # File plans may only change explicitly granted reference material. In
    # particular they cannot modify payloads and silently change their proof.
    unsupported = []
    for path in overlay:
        if not _authorized(profile, path):
            raise dc.DirectoryError('BODY_NOT_AUTHORIZED', 'joint candidate is outside declared reference sources')
        if any(census._within(path, batch['source']) for batch in batches):
            raise dc.DirectoryError('MULTIPLE_WRITES', 'file changes overlap an archive payload')
        try:
            dc.validate_path_spelling(profile.root, path)
            info = dc.stat_entry(profile.root, path)
            if not stat.S_ISREG(info.st_mode):
                raise dc.DirectoryError('REFERENCE_NOT_REGULAR')
        except FileNotFoundError:
            unsupported.append({'path': path, 'reason_code': 'NEW_REFERENCE_PROJECTION_UNSUPPORTED', 'status': 'Unknown'})
    # The shared scanner charges original reads and candidate bytes, and never
    # accepts this overlay through the native archive-preview/apply API.
    projected = census.impact(profile, archive_request, reference_overlay={k: v for k, v in overlay.items() if k not in {i['path'] for i in unsupported}})
    fingerprints = projected['batches'][0]['reference_fingerprints'] if projected['batches'] else []
    navigation = _navigation(profile, overlay, archive_request, fingerprints)
    navigation['issues'].extend(unsupported)
    manifest_budget, manifests = dc.HashBudget(profile.budgets), []
    for batch in batches:
        if archive._exists(archive_root, batch['destination']):
            raise dc.DirectoryError('DESTINATION_EXISTS')
        manifests.append({'source': batch['source'], 'destination': batch['destination'],
                          'manifest_sha256': dc.digest(archive._manifest(profile, profile.root, batch['source'], batch['source'], manifest_budget))})
    issues = navigation['issues']
    status = 'Blocked' if projected['status'] == 'Blocked' or any(i['status'] == 'Blocked' for i in issues) else 'Unknown' if projected['status'] != 'Passed' or issues else 'Preview'
    binding = {'project_root': str(profile.root), 'profile_sha256': profile.sha256,
               'config_sha256': dc.digest(profile.config), 'file_plan_sha256': dc.digest(file_plan),
               'archive_request_sha256': dc.digest(archive_request),
               'overlay_sha256': dc.digest({path: None if raw is None else _sha(raw) for path, raw in sorted(overlay.items())}),
               'impact_material_sha256': projected['material_sha256'], 'manifests': manifests,
               'roots': archive._root_records(profile, archive_root, records_root)}
    value = {'format': FORMAT, 'schema_version': 1, 'kind': 'joint-preview', 'status': status,
             'binding': binding, 'projected_impact': projected, 'navigation': navigation,
             'manifest_hash_usage': manifest_budget.snapshot(), 'executable': False,
             'execution_order': ['Validate this candidate against unchanged inputs.',
                                 'Apply the original file plan with native file apply; retain its journal.',
                                 'Create a fresh native directory archive-preview from actual post-file state.',
                                 'Review that fresh plan, then native directory apply; retain its journal.'],
             'recovery_steps': ['If file apply fails: use its native verify/recover journal; do not archive.',
                                'If fresh archive-preview blocks: keep payload in place; recover file journal if rolling back.',
                                'If directory apply interrupts: native directory verify/recover with its real journal.',
                                'For rollback after archive: native directory restore-preview/restore first, then file recover.'],
             'limitations': ['Projection is not native archive eligibility or an executable plan.',
                             'New reference files are Unknown; refresh native preview after actual file apply.',
                             'External consumers and semantic acceptance remain unverified.'],
             'body_bytes_sent': 0, 'semantic_acceptance': 'Not run'}
    dc.validate_profile_root(profile)
    if len(dc.canonical(value)) + 100 > profile.budgets['max_artifact_bytes']:
        raise dc.DirectoryError('BUDGET_EXHAUSTED')
    return dc.seal(value)


def validate_candidate(profile, candidate, file_plan, archive_request, archive_root, records_dir):
    """Reject stale projection evidence; this function never applies anything."""
    dc.validate_seal(candidate)
    if candidate.get('format') != FORMAT or candidate.get('kind') != 'joint-preview' or candidate.get('executable') is not False:
        raise dc.DirectoryError('ARTIFACT_INVALID')
    fresh = preview(profile, file_plan, archive_request, archive_root, records_dir)
    if candidate['binding'] != fresh['binding'] or candidate['status'] != fresh['status'] or candidate['navigation']['targets'] != fresh['navigation']['targets'] or candidate['navigation']['issues'] != fresh['navigation']['issues']:
        raise dc.DirectoryError('SOURCE_CHANGED', 'joint preview inputs or final navigation changed')
    return fresh
