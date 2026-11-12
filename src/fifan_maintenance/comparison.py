"""Stable multiset report comparison, with explicit binding/coverage gates."""
from __future__ import annotations

from collections import defaultdict
import fnmatch
import hashlib
import json
import posixpath
from urllib.parse import unquote, urlsplit, urlunsplit

BINDINGS = ('schema_version', 'tool_version', 'root', 'config_sha256', 'mode', 'checks', 'scope', 'views', 'budgets')
MAX_FINDINGS = 10000
MAX_INPUT_BYTES = 16 * 1024 * 1024
VOLATILE = {'line', 'line_precision', 'line_number', 'column', 'count', 'total', 'size', 'age_days', 'threshold', 'threshold_days'}


def _canonical(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _target(finding):
    evidence = finding.get('evidence', {})
    source = finding.get('path', '')
    anchor = evidence.get('anchor')
    if 'normalized_target' in evidence:
        target = evidence['normalized_target']
        if not isinstance(target, str):
            raise ValueError('invalid normalized target')
        if target and not urlsplit(target).scheme:
            target = posixpath.normpath(target)
        return target, anchor or ''
    value = evidence.get('target', '')
    if not isinstance(value, str):
        raise ValueError('invalid target')
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, '')), unquote(parsed.fragment) if anchor is None else anchor
    path = unquote(parsed.path)
    target = posixpath.normpath(posixpath.join(posixpath.dirname(source), path)) if path else source if value else ''
    return target, unquote(parsed.fragment) if anchor is None else anchor


def _stable_evidence(value):
    if isinstance(value, dict):
        return {key: _stable_evidence(child) for key, child in value.items() if key not in VOLATILE}
    if isinstance(value, list):
        return [_stable_evidence(child) for child in value]
    return value


def _binding_shape(report):
    if any(not isinstance(report.get(name), str) or not report[name] for name in ('root', 'config_sha256', 'tool_version', 'mode')):
        return False
    if type(report.get('schema_version')) is not int or report['schema_version'] < 1:
        return False
    if not isinstance(report.get('checks'), list) or any(not isinstance(check, str) for check in report['checks']):
        return False
    if not isinstance(report.get('scope'), dict) or not isinstance(report.get('views'), list) or not isinstance(report.get('budgets'), dict):
        return False
    for name in ('sources', 'reference_bodies', 'historical_roots'):
        values = report['scope'].get(name)
        if values is not None and (not isinstance(values, list) or any(not isinstance(value, str) for value in values)):
            return False
    patterns = report.get('historical_sources', [])
    return isinstance(patterns, list) and all(isinstance(pattern, str) for pattern in patterns)


def issue_identity(finding):
    if not isinstance(finding, dict) or not isinstance(finding.get('evidence', {}), dict):
        raise ValueError('invalid finding')
    for name in ('check', 'code', 'path', 'status', 'severity'):
        if name not in finding or not isinstance(finding[name], str):
            raise ValueError('invalid finding identity')
    target, anchor = _target(finding)
    if not isinstance(anchor, str) or any('[limited]' in value or value.endswith('…') for value in (target, anchor)):
        raise ValueError('truncated or invalid target identity')
    identity = {key: finding.get(key, '') for key in ('check', 'code', 'status', 'severity')}
    identity.update(source=posixpath.normpath(finding.get('path') or '.'), target=target, anchor=anchor)
    evidence = finding.get('evidence', {})
    if finding.get('check') == 'links':
        identity['kind'] = evidence.get('kind', '')
    else:
        identity['evidence'] = _stable_evidence({key: value for key, value in evidence.items() if key not in {'target', 'normalized_target', 'resolved_target', 'anchor'}})
    return hashlib.sha256(_canonical(identity).encode('utf-8')).hexdigest()


def _coverage(report):
    reasons = []
    findings = report.get('findings')
    if not isinstance(findings, list):
        return ['invalid-findings']
    if report.get('findings_truncated') or report.get('output_truncated') or report.get('truncated'):
        reasons.append('truncated-findings')
    if type(report.get('finding_total')) is not int or report['finding_total'] != len(findings):
        reasons.append('finding-total-mismatch')
    coverage = report.get('coverage')
    if not isinstance(coverage, list) or not coverage:
        reasons.append('missing-coverage')
    else:
        covered = set()
        for item in coverage:
            if not isinstance(item, dict):
                reasons.append('invalid-coverage')
                continue
            if not isinstance(item.get('check'), str):
                reasons.append('invalid-coverage-check')
                continue
            covered.add(item['check'])
            if item.get('status') not in ('Passed', 'Failed') or item.get('generation_limited'):
                reasons.append('incomplete-check:' + str(item.get('check')))
        for check in report.get('checks', []):
            if check not in covered:
                reasons.append('missing-check:' + str(check))
    if any(not isinstance(item, dict) or item.get('status') not in ('Passed', 'Failed') for item in findings):
        reasons.append('uncertain-findings')
    historical = report.get('historical_metadata')
    if historical is not None and (not isinstance(historical, dict) or historical.get('status') != 'Passed'):
        reasons.append('historical-metadata-incomplete')
    elif report.get('scope', {}).get('historical_roots') and historical is None:
        reasons.append('historical-metadata-missing')
    return reasons


def _changed_files(before, after):
    old, new = before.get('files'), after.get('files')
    if not isinstance(old, dict) or not isinstance(new, dict):
        return None
    return sum(old.get(path) != new.get(path) for path in old.keys() | new.keys())


def _group_counts(items, report):
    if items is None:
        return None
    counts = {'current': 0, 'historical': 0, 'unclassified': 0}
    patterns = report.get('historical_sources', [])
    roots = report.get('scope', {}).get('historical_roots', [])
    for item in items:
        path = item.get('path', '')
        if not path:
            group = 'unclassified'
        elif any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns) or any(path == root or path.startswith(root.rstrip('/') + '/') for root in roots):
            group = 'historical'
        else:
            group = 'current'
        counts[group] += 1
    return counts


def _anchors(before, after):
    missing_both = 'anchors' not in before and 'anchors' not in after
    old, new = before.get('anchors'), after.get('anchors')
    if (not isinstance(old, dict) or not isinstance(new, dict)
            or any(not isinstance(path, str) or not isinstance(values, list) or any(not isinstance(value, str) for value in values)
                   for mapping in (old, new) if isinstance(mapping, dict) for path, values in mapping.items())):
        return {'status': 'Unknown', 'lost': None, 'added': None, 'legacy_missing_both': missing_both}
    if old.keys() != new.keys():
        return {'status': 'Unknown', 'lost': None, 'added': None, 'legacy_missing_both': False}
    lost, added = [], []
    for path in sorted(old):
        lost.extend({'source': path, 'anchor': anchor} for anchor in sorted(set(old[path]) - set(new[path])))
        added.extend({'source': path, 'anchor': anchor} for anchor in sorted(set(new[path]) - set(old[path])))
    return {'status': 'Passed', 'lost': lost, 'added': added, 'legacy_missing_both': False}


def _compare_global(before, after):
    """Lists classify each occurrence; line shifts do not change identity.

    Incomplete matched reports show provisional observed deltas. Resolved is
    withheld, and no_new_issues remains None, whenever coverage is incomplete.
    """
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError('reports must be objects')
    result = {'schema_version': 1, 'status': 'Unknown', 'compatible': False, 'complete': False,
              'new': None, 'existing': None, 'resolved': None, 'counts': None,
              'changed_files': _changed_files(before, after), 'no_new_issues': None,
              'semantic_acceptance': 'Not run'}
    reasons = []
    for name in BINDINGS:
        if name not in before or name not in after:
            reasons.append('missing-binding:' + name)
        elif before[name] != after[name]:
            reasons.append('binding-mismatch:' + name)
    if reasons:
        return {**result, 'reasons': reasons}
    if not _binding_shape(before) or not _binding_shape(after):
        return {**result, 'reasons': ['invalid-report-bindings']}
    if before.get('anchor_encoding') != after.get('anchor_encoding'):
        return {**result, 'reasons': ['binding-mismatch:anchor_encoding']}
    if before.get('historical_sources', []) != after.get('historical_sources', []):
        return {**result, 'reasons': ['binding-mismatch:historical_sources']}
    result['compatible'] = True
    old, new = before.get('findings'), after.get('findings')
    if not isinstance(old, list) or not isinstance(new, list):
        return {**result, 'reasons': ['invalid-findings']}
    if len(old) + len(new) > MAX_FINDINGS:
        return {**result, 'reasons': ['comparison-count-budget']}
    try:
        if len(_canonical([old, new]).encode('utf-8')) > MAX_INPUT_BYTES:
            return {**result, 'reasons': ['comparison-byte-budget']}
        old_buckets, new_buckets = defaultdict(list), defaultdict(list)
        for item in old:
            old_buckets[issue_identity(item)].append(item)
        for item in new:
            new_buckets[issue_identity(item)].append(item)
    except (ValueError, TypeError, RecursionError):
        return {**result, 'reasons': ['invalid-finding-identity']}
    reasons = ['before:' + reason for reason in _coverage(before)] + ['after:' + reason for reason in _coverage(after)]
    added, existing, resolved = [], [], []
    for identity in sorted(old_buckets.keys() | new_buckets.keys()):
        previous, current = old_buckets[identity], new_buckets[identity]
        shared = min(len(previous), len(current))
        existing.extend(current[:shared])
        added.extend(current[shared:])
        resolved.extend(previous[shared:])
    anchor_comparison = _anchors(before, after)
    if anchor_comparison['status'] == 'Unknown' and not anchor_comparison['legacy_missing_both']:
        reasons.append('anchor-coverage-incomplete')
    lost_anchors, added_anchors = anchor_comparison['lost'], anchor_comparison['added']
    complete = not reasons
    counts = {'new': len(added), 'existing': len(existing), 'resolved': len(resolved)}
    if not anchor_comparison['legacy_missing_both']:
        counts.update(lost_anchors=len(lost_anchors) if lost_anchors is not None else None, added_anchors=len(added_anchors) if added_anchors is not None else None)
    return {**result, 'status': ('Failed' if lost_anchors or any(item.get('status') == 'Failed' for item in added) else 'Passed') if complete else 'Unknown', 'complete': complete,
            'classification': 'definitive' if complete else 'provisional-observations', 'reasons': reasons,
            'new': added, 'existing': existing, 'resolved': resolved if complete else None,
            'counts': counts if complete else None,
            'anchor_comparison': anchor_comparison, 'lost_anchors': lost_anchors, 'added_anchors': added_anchors,
            'group_counts': {'new': _group_counts(added, after), 'existing': _group_counts(existing, after), 'resolved': _group_counts(resolved, before) if complete else None},
            'grouping_basis': 'explicit historical declarations; current means not declared historical',
            'observed_counts': {'new': len(added), 'existing': len(existing)},
            'no_new_issues': not added and not lost_anchors if complete else None}


def _domain_compare(before, after, name, global_result):
    result = {'status': 'Unknown', 'complete': False, 'new': None, 'existing': None, 'resolved': None, 'no_new_issues': None, 'reasons': []}
    if not global_result['compatible']:
        return {**result, 'reasons': ['GLOBAL_BINDING_MISMATCH']}
    if not isinstance(global_result.get('observed_counts'), dict):
        return {**result, 'reasons': ['GLOBAL_INDEX_UNAVAILABLE']}
    old_domain = before.get('coverage_domains', {}).get(name)
    new_domain = after.get('coverage_domains', {}).get(name)
    if not isinstance(old_domain, dict) or not isinstance(new_domain, dict):
        return {**result, 'reasons': ['DOMAIN_EVIDENCE_MISSING']}
    reasons = []
    for label, report, domain in [('before', before, old_domain), ('after', after, new_domain)]:
        if domain.get('complete') is not True or domain.get('status') not in ('Passed', 'Failed'):
            reasons.append(label + ':DOMAIN_INCOMPLETE')
        if report.get('findings_truncated') or report.get('output_truncated') or report.get('finding_total') != len(report.get('findings', [])):
            reasons.append(label + ':FINDING_INDEX_INCOMPLETE')
    if old_domain.get('scope') != new_domain.get('scope'):
        reasons.append('DOMAIN_SCOPE_MISMATCH')
    try:
        def selected(report):
            values = []
            for finding in report.get('findings', []):
                tagged = finding.get('evidence', {}).get('coverage_domains', [])
                if name in tagged or name == 'document_hints' and finding.get('check') == 'documents':
                    values.append(finding)
            return values
        old_items, new_items = selected(before), selected(after)
        if any(item.get('status') not in ('Passed', 'Failed') for item in old_items + new_items):
            reasons.append('UNCERTAIN_DOMAIN_FINDINGS')
        previous, current = defaultdict(list), defaultdict(list)
        for item in old_items:
            previous[issue_identity(item)].append(item)
        for item in new_items:
            current[issue_identity(item)].append(item)
        added, existing, resolved = [], [], []
        for identity in sorted(previous.keys() | current.keys()):
            old, new = previous[identity], current[identity]
            common = min(len(old), len(new))
            existing.extend(new[:common])
            added.extend(new[common:])
            resolved.extend(old[common:])
        lost = global_result.get('lost_anchors') if name == 'local_anchors' else []
        if name == 'local_anchors' and lost is None:
            reasons.append('ANCHOR_INDEX_INCOMPLETE')
        complete = not reasons
        return {**result, 'status': ('Failed' if lost or any(item.get('status') == 'Failed' for item in added) else 'Passed') if complete else 'Unknown', 'complete': complete, 'new': added, 'existing': existing, 'resolved': resolved if complete else None, 'counts': {'new': len(added), 'existing': len(existing), 'resolved': len(resolved)} if complete else None, 'observed_counts': {'new': len(added), 'existing': len(existing)}, 'lost_anchors': lost, 'no_new_issues': not added and not lost if complete else None, 'reasons': reasons, 'before_coverage': old_domain, 'after_coverage': new_domain}
    except (TypeError, ValueError, KeyError):
        return {**result, 'reasons': ['INVALID_DOMAIN_FINDINGS']}


def compare_reports(before, after):
    result = _compare_global(before, after)
    names = {'local_targets', 'local_anchors', 'external', 'document_hints', 'historical_metadata', 'archive_coverage'}
    result['domain_contract_version'] = 1
    result['domains'] = {name: _domain_compare(before, after, name, result) for name in sorted(names)}
    return result
