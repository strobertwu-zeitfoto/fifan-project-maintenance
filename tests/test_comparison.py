from __future__ import annotations

from copy import deepcopy

import pytest

from fifan_maintenance.comparison import compare_reports, issue_identity


def finding(line=1, target='target.md', status='Failed', code='missing-target'):
    return {'check': 'links', 'code': code, 'path': 'docs/source.md', 'line': line, 'status': status,
            'severity': 'warning', 'message': 'broken', 'evidence': {'target': target, 'line_precision': 'token-block'}}


def report(findings):
    return {'schema_version': 1, 'tool_version': '1.1.0', 'root': '/fixture/project', 'config_sha256': 'a' * 64,
            'mode': 'check', 'checks': ['links'], 'scope': {'sources': ['docs/source.md'], 'reference_bodies': [], 'historical_roots': []},
            'views': [], 'budgets': {'max_file_bytes': 10000}, 'findings': findings, 'finding_total': len(findings),
            'findings_truncated': False, 'coverage': [{'check': 'links', 'status': 'Passed', 'total': len(findings)}],
            'files': {'docs/source.md': {'sha256': 'a', 'size': 10}}}


def test_multiset_line_shifts_and_normalized_targets():
    before = report([finding(1, '../target%20file.md'), finding(2, '../target%20file.md')])
    after = report([finding(50, '../target file.md')])
    result = compare_reports(before, after)
    assert result['status'] == 'Passed'
    assert result['counts'] == {'new': 0, 'existing': 1, 'resolved': 1}
    assert result['existing'][0]['line'] == 50
    assert result['no_new_issues'] is True
    assert issue_identity(finding(1)) == issue_identity(finding(90))


def test_new_anchor_status_and_repeat_occurrences():
    before = report([finding(target='a.md#old')])
    after = report([finding(target='a.md#new'), finding(target='a.md#new'), finding(code='missing-anchor')])
    result = compare_reports(before, after)
    assert result['counts'] == {'new': 3, 'existing': 0, 'resolved': 1}
    assert result['no_new_issues'] is False


@pytest.mark.parametrize('key', ['root', 'config_sha256', 'tool_version', 'schema_version', 'mode', 'checks', 'scope', 'views', 'budgets'])
def test_binding_mismatch_refuses_complete_comparison(key):
    before, after = report([]), report([])
    after[key] = 'different'
    result = compare_reports(before, after)
    assert result['status'] == 'Unknown'
    assert result['compatible'] is False
    assert result['resolved'] is None and result['no_new_issues'] is None
    assert 'binding-mismatch:' + key in result['reasons']


@pytest.mark.parametrize('gap', ['truncated', 'generation', 'unknown', 'total', 'missing-check', 'missing-binding'])
def test_coverage_gaps_never_claim_no_new_or_resolution(gap):
    before, after = report([finding()]), report([])
    if gap == 'truncated':
        before['findings_truncated'] = True
    elif gap == 'generation':
        after['coverage'][0]['generation_limited'] = True
    elif gap == 'unknown':
        after['coverage'][0]['status'] = 'Not run'
    elif gap == 'total':
        before['finding_total'] = 2
    elif gap == 'missing-check':
        after['coverage'] = []
    else:
        del after['views']
    result = compare_reports(before, after)
    assert result['status'] == 'Unknown'
    assert not result['complete']
    assert result['resolved'] is None and result['counts'] is None and result['no_new_issues'] is None


def test_legacy_binding_unknown_and_changed_files_available():
    before, after = report([]), report([])
    before.pop('scope')
    after['files']['docs/source.md']['sha256'] = 'new'
    result = compare_reports(before, after)
    assert result['changed_files'] == 1
    assert result['status'] == 'Unknown'


def test_comparison_internal_budget_and_bad_findings():
    before, after = report([]), report([])
    after['findings'] = [finding()] * 10001
    after['finding_total'] = 10001
    assert compare_reports(before, after)['reasons'] == ['comparison-count-budget']
    after = report([{'evidence': []}])
    assert compare_reports(before, after)['reasons'] == ['invalid-finding-identity']


def test_missing_files_metadata_is_unknown_not_zero():
    before, after = report([]), report([])
    del before['files']
    assert compare_reports(before, after)['changed_files'] is None


def test_explicit_historical_grouping_and_metadata_coverage():
    current = finding()
    historical = {**finding(), 'path': 'old/source.md'}
    unclassified = {**finding(), 'path': ''}
    before, after = report([]), report([current, historical, unclassified])
    for item in (before, after):
        item['historical_sources'] = ['old/**']
        item['historical_metadata'] = {'status': 'Passed'}
    result = compare_reports(before, after)
    assert result['status'] == 'Failed'
    assert result['group_counts']['new'] == {'current': 1, 'historical': 1, 'unclassified': 1}
    after['historical_metadata']['status'] = 'Unknown'
    result = compare_reports(before, after)
    assert result['status'] == 'Unknown'
    assert result['resolved'] is None and result['no_new_issues'] is None


def test_historical_roots_are_explicit_no_directory_name_heuristics():
    before, after = report([]), report([{**finding(), 'path': 'archive/a.md'}, {**finding(), 'path': 'declared/a.md'}])
    for item in (before, after):
        item['scope']['historical_roots'] = ['declared']
        item['historical_metadata'] = {'status': 'Passed'}
    result = compare_reports(before, after)
    assert result['group_counts']['new'] == {'current': 1, 'historical': 1, 'unclassified': 0}


def test_unreferenced_lost_anchors_are_problems_but_added_titles_are_not():
    before, after = report([]), report([])
    before['anchors'] = {'docs/source.md': ['retained', 'lost', 'lost']}
    after['anchors'] = {'docs/source.md': ['retained', 'added']}
    result = compare_reports(before, after)
    assert result['status'] == 'Failed'
    assert result['lost_anchors'] == [{'source': 'docs/source.md', 'anchor': 'lost'}]
    assert result['added_anchors'] == [{'source': 'docs/source.md', 'anchor': 'added'}]
    assert result['counts']['lost_anchors'] == 1
    assert result['no_new_issues'] is False
    before['anchors'] = {'docs/source.md': ['retained']}
    assert compare_reports(before, after)['no_new_issues'] is True


def test_missing_anchor_observations_cannot_claim_no_anchor_loss():
    before, after = report([]), report([])
    legacy = compare_reports(before, after)
    assert legacy['status'] == 'Passed'
    assert legacy['anchor_comparison']['status'] == 'Unknown'
    before['anchors'] = {'docs/source.md': ['a']}
    result = compare_reports(before, after)
    assert result['status'] == 'Unknown' and result['lost_anchors'] is None
    after['anchors'] = {}
    assert compare_reports(before, after)['status'] == 'Unknown'


def test_nested_line_metadata_does_not_change_issue_identity():
    before = {'check': 'configs', 'code': 'bad', 'path': 'a.json', 'line': 1, 'status': 'Failed', 'severity': 'warning', 'evidence': {'location': {'line': 1, 'key': 'a'}}}
    after = deepcopy(before)
    after['evidence']['location']['line'] = 99
    assert issue_identity(before) == issue_identity(after)


def test_malformed_matched_bindings_and_unknown_findings_are_not_complete():
    before, after = report([]), report([])
    before['root'] = after['root'] = None
    assert compare_reports(before, after)['status'] == 'Unknown'
    before, after = report([]), report([finding(status='Unknown')])
    assert compare_reports(before, after)['status'] == 'Unknown'
    before, after = report([]), report([])
    after['coverage'][0]['check'] = []
    assert compare_reports(before, after)['status'] == 'Unknown'


def test_anchor_encoding_mismatch_is_not_comparable():
    before, after = report([]), report([])
    before['anchors'] = after['anchors'] = {'docs/source.md': []}
    before['anchor_encoding'] = 'sha256'
    assert compare_reports(before, after)['status'] == 'Unknown'
