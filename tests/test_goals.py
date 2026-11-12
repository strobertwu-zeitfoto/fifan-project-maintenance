from __future__ import annotations

import base64
import copy
import hashlib
import os

import pytest

from fifan_maintenance.goals import evaluate, measure, normalize_measurement
from fifan_maintenance.project import load_config
from fifan_maintenance.scope import task_config


def request(**kwargs):
    return {'version': 1, 'active': ['a.md', 'b.md'], 'views': [],
            'reused_archives': [], 'new_archives': [], 'external_records': [], **kwargs}


def fixture(tmp_path):
    (tmp_path / 'a.md').write_bytes(b'1234567890\r\nline2\r\n')
    (tmp_path / 'b.md').write_bytes(b'1234567890')
    return load_config(tmp_path)


def test_navigation_growth_does_not_claim_slim_or_semantic_acceptance(tmp_path):
    config = fixture(tmp_path)
    before = measure(tmp_path, config, request())
    (tmp_path / 'a.md').write_bytes(b'Navigation\n' + (tmp_path / 'a.md').read_bytes())
    after = measure(tmp_path, config, request())
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Failed'
    result = evaluate(before, after, 'navigation')
    assert result['goal_result'] == result['semantic_acceptance'] == 'Unknown'
    assert result['files'][0]['delta_bytes'] == len(b'Navigation\n')


def test_total_reduction_each_file_and_explicit_thresholds(tmp_path):
    config = fixture(tmp_path)
    before = measure(tmp_path, config, request())
    (tmp_path / 'a.md').write_bytes(b'a')
    (tmp_path / 'b.md').write_bytes(b'12345678901')
    after = measure(tmp_path, config, request())
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Passed'
    result = evaluate(before, after, {'kind': 'body-slim', 'each_file': True,
                                   'exceptions': [{'path': 'b.md', 'reason': 'necessary contract growth'}]})
    assert result['goal_result'] == 'Failed' and result['exceptions']
    assert evaluate(before, after, {'kind': 'body-slim', 'max_after_bytes': 11})['goal_result'] == 'Failed'
    assert evaluate(before, after, {'kind': 'body-slim', 'max_after_bytes': 12})['goal_result'] == 'Passed'
    assert evaluate(before, after, {'kind': 'body-slim', 'minimum_reduction_bytes': 999})['goal_result'] == 'Failed'


def test_archive_growth_not_conflated_with_body_reduction(tmp_path):
    config = fixture(tmp_path)
    declared = request(new_archives=['archive.md'], allow_absent=[{'role': 'new_archives', 'path': 'archive.md'}])
    before = measure(tmp_path, config, declared)
    (tmp_path / 'a.md').write_bytes(b'a')
    (tmp_path / 'archive.md').write_bytes(b'recovery' * 20)
    after = measure(tmp_path, config, declared)
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Passed'
    assert evaluate(before, after, 'storage')['goal_result'] == 'Failed'
    assert after['domains']['new_archives']['bytes'] == 160
    assert (tmp_path / 'archive.md').exists()


def test_views_count_raw_crlf_bytes_union_without_double_storage(tmp_path):
    config = fixture(tmp_path)
    views = [{'name': 'first', 'path': 'a.md', 'kind': 'current', 'start_line': 1, 'end_line': 1},
             {'name': 'both', 'path': 'a.md', 'kind': 'current', 'start_line': 1, 'end_line': 2}]
    result = measure(tmp_path, config, request(views=views, reused_archives=['a.md']))
    assert result['domains']['current_views']['bytes'] == 19
    assert [v['bytes'] for v in result['domains']['current_views']['items']] == [12, 19]
    assert result['storage']['bytes'] == 29
    assert result['metrics']['read_bytes'] == 29
    assert result['metrics']['hashed_bytes'] == 29 + 12 + 19


def test_hardlinks_count_once_across_domains(tmp_path):
    config = fixture(tmp_path)
    os.link(tmp_path / 'a.md', tmp_path / 'archive.md')
    result = measure(tmp_path, config, request(reused_archives=['archive.md']))
    assert result['storage']['bytes'] == 29
    assert result['domains']['reused_archives']['items'][0]['bytes'] == 19
    assert result['storage']['items'][2]['duplicate_of'] == 'a.md'


def test_explicit_external_record_root_secure_read_and_location(tmp_path):
    root, outside = tmp_path / 'project', tmp_path / 'records'
    root.mkdir()
    outside.mkdir()
    config = fixture(root)
    (outside / 'journal.json').write_bytes(b'{}')
    entry = {'root': str(outside), 'path': 'journal.json'}
    with pytest.raises(ValueError, match='not authorized'):
        measure(root, config, request(external_records=[entry]))
    result = measure(root, config, request(external_roots=[str(outside)], external_records=[entry]))
    assert result['domains']['external_records']['bytes'] == 2
    assert result['domains']['external_records']['items'][0]['location'] == 'outside'
    (outside / 'link.json').symlink_to(outside / 'journal.json')
    result = measure(root, config, request(external_roots=[str(outside)], external_records=[{**entry, 'path': 'link.json'}]))
    assert result['domains']['external_records']['status'] == 'Unknown'
    with pytest.raises(ValueError):
        measure(root, config, request(external_roots=[str(tmp_path)], external_records=[]))


def test_missing_unreadable_or_undeclared_never_becomes_zero(tmp_path):
    config = fixture(tmp_path)
    result = measure(tmp_path, config, {'version': 1, 'active': ['missing.md']})
    assert result['domains']['active']['bytes'] is None
    assert result['domains']['new_archives']['bytes'] is None
    assert result['storage']['bytes'] is None
    assert evaluate(result, result, 'storage')['goal_result'] == 'Unknown'
    explicit = measure(tmp_path, config, request(active=[]))
    assert explicit['domains']['active']['bytes'] == 0
    assert explicit['storage']['bytes'] == 0


def test_drifted_baseline_reports_unknown_but_recollects_actual(tmp_path):
    config = fixture(tmp_path)
    before = measure(tmp_path, config, request())
    original = before['domains']['active']['items'][0]
    baseline = {key: original[key] for key in ('root', 'path', 'bytes', 'sha256', 'collected_at', 'source')}
    same = measure(tmp_path, config, request(baseline=[baseline]))
    assert same['baseline_status'] == 'Passed'
    (tmp_path / 'a.md').write_bytes(b'a')
    after = measure(tmp_path, config, request(baseline=[baseline]))
    assert after['domains']['active']['items'][0]['bytes'] == 1
    assert after['baseline_status'] == 'Unknown'
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Unknown'
    refreshed = measure(tmp_path, config, request())
    assert evaluate(before, refreshed, 'body-slim')['goal_result'] == 'Passed'


def test_overlay_preview_bound_to_same_config_and_not_disk(tmp_path):
    config = fixture(tmp_path)
    before = measure(tmp_path, config, request())
    overlay = {**config, '_overlay': {'a.md': base64.b64encode(b'a').decode()}}
    after = measure(tmp_path, overlay, request())
    result = evaluate(before, after, 'body-slim')
    assert result['goal_result'] == 'Passed'
    assert result['candidate'] == 'Preview'
    assert after['config_sha256'] == before['config_sha256']
    assert (tmp_path / 'a.md').read_bytes() != b'a'
    assert evaluate(after, before, 'body-slim')['goal_result'] == 'Unknown'


def test_metadata_drift_during_read_is_unknown(tmp_path, monkeypatch):
    config = fixture(tmp_path)
    from fifan_maintenance.models import Context
    original = Context.read_bytes
    def changing(ctx, rel):
        data = original(ctx, rel)
        if rel == 'a.md':
            (tmp_path / rel).write_bytes(b'drift')
        return data
    monkeypatch.setattr(Context, 'read_bytes', changing)
    result = measure(tmp_path, config, request())
    assert result['domains']['active']['status'] == 'Unknown'
    assert result['domains']['active']['items'][0]['bytes'] is None


def test_respects_scope_protection_budget_and_no_symlink_root(tmp_path):
    config = fixture(tmp_path)
    (tmp_path / 'secret.md').write_bytes(b'NEVER RETURN BODY')
    selected = task_config(tmp_path, config, files=['a.md'])
    result = measure(tmp_path, selected, request(active=['a.md'], reused_archives=['secret.md']))
    assert result['domains']['reused_archives']['status'] == 'Unknown'
    assert 'NEVER RETURN BODY' not in str(result)
    result = measure(tmp_path, {**config, 'max_total_bytes': 20}, request())
    assert result['domains']['active']['bytes'] is None
    (tmp_path / 'link').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        measure(tmp_path / 'link', config, request())
    result = measure(tmp_path, config, request(active=['.env']))
    assert result['domains']['active']['status'] == 'Unknown'


def test_changed_project_or_active_set_unknown(tmp_path):
    config = fixture(tmp_path)
    before = measure(tmp_path, config, request())
    after = copy.deepcopy(before)
    after['root'] = '/another-project'
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Unknown'
    after = measure(tmp_path, config, request(active=['a.md']))
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Unknown'


def test_legacy_explicit_sizes_kept_but_missing_domains_and_time_unknown():
    report = {'schema_version': 1, 'root': '/fixture', 'candidate': 'Disk',
              'scope': {'sources': ['a.md']}, 'files': {'a.md': {'size': 90, 'sha256': 'a' * 64}, 'other': {'size': 123}}}
    adapted = normalize_measurement(report)
    assert adapted['domains']['active']['bytes'] == 90
    assert len(adapted['domains']['active']['items']) == 1
    assert adapted['domains']['external_records']['bytes'] is None
    assert evaluate(report, report, 'body-slim')['goal_result'] == 'Unknown'
    preflight = normalize_measurement({'root': '/fixture', 'sources': [{'path': 'a.md', 'bytes': 55}]})
    assert preflight['domains']['active']['bytes'] == 55
    assert preflight['domains']['active']['items'][0]['sha256'] is None
    for legacy in ({'root': '/fixture', 'estimated_primary_bytes': 22}, {'version': 2, 'operations': []}, {'version': 1, 'plan': {}, 'backups': []}):
        assert normalize_measurement(legacy)['domains']['active']['bytes'] is None


@pytest.mark.parametrize('goal', [{'kind': 'bad'}, {'kind': 'body-slim', 'each_file': 'yes'},
                                  {'kind': 'storage', 'max_after_bytes': True},
                                  {'kind': 'body-slim', 'minimum_reduction_bytes': -1},
                                  {'kind': 'body-slim', 'exceptions': ['waived']}])
def test_invalid_goal_is_rejected(tmp_path, goal):
    before = measure(tmp_path, fixture(tmp_path), request())
    with pytest.raises(ValueError):
        evaluate(before, before, goal)


@pytest.mark.parametrize('bad', [{'version': 2}, {'version': 1, 'active': ['../escape']},
                                 {'version': 1, 'active': ['a.md', 'a.md']},
                                 {'version': 1, 'views': [{'path': 'a.md'}]},
                                 {'version': 1, 'baseline': [{'path': 'a.md'}]}])
def test_invalid_measurement_rejected(tmp_path, bad):
    with pytest.raises(ValueError):
        measure(tmp_path, fixture(tmp_path), bad)


def test_missing_native_item_provenance_cannot_claim_goal_pass(tmp_path):
    config = fixture(tmp_path)
    before = measure(tmp_path, config, request())
    (tmp_path / 'a.md').write_bytes(b'a')
    after = measure(tmp_path, config, request())
    del before['domains']['active']['items'][0]['sha256']
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Unknown'
    assert evaluate(before, after, 'storage')['goal_result'] == 'Unknown'


def test_bad_view_range_remains_unknown_and_no_file_write(tmp_path):
    config = fixture(tmp_path)
    result = measure(tmp_path, config, request(views=[{'name': 'outside', 'path': 'a.md', 'kind': 'current', 'start_line': 1, 'end_line': 300}]))
    assert result['domains']['current_views']['bytes'] is None
    assert (tmp_path / 'a.md').read_bytes() == b'1234567890\r\nline2\r\n'


def test_active_sources_cannot_be_external_even_with_authorized_record_root(tmp_path):
    project, records = tmp_path / 'project', tmp_path / 'records'
    project.mkdir()
    records.mkdir()
    (records / 'a.md').write_bytes(b'a')
    with pytest.raises(ValueError, match='active sources'):
        measure(project, load_config(project), {'version': 1, 'external_roots': [str(records)],
                                              'active': [{'root': str(records), 'path': 'a.md'}]})


def test_storage_cannot_claim_reduction_by_dropping_archive_declaration(tmp_path):
    config = fixture(tmp_path)
    (tmp_path / 'archive.md').write_bytes(b'A' * 1000)
    before = measure(tmp_path, config, request(reused_archives=['archive.md']))
    after = measure(tmp_path, config, request())
    result = evaluate(before, after, 'storage')
    assert result['goal_result'] == 'Unknown'
    assert 'storage-cohort-mismatch' in result['reasons']
    assert (tmp_path / 'archive.md').stat().st_size == 1000


def test_explicit_absent_file_measures_zero_then_real_new_file_growth(tmp_path):
    config = fixture(tmp_path)
    declared = request(new_archives=['new.md'], allow_absent=[{'role': 'new_archives', 'path': 'new.md'}])
    before = measure(tmp_path, config, declared)
    absent = before['domains']['new_archives']['items'][0]
    assert absent['presence'] == 'Absent' and absent['bytes'] == 0 and absent['sha256'] is None
    assert absent['absence_authorized'] is True
    assert absent['identity'] == ['absent', str(tmp_path), 'new.md']
    assert before['storage']['bytes'] == 29
    assert normalize_measurement(before)['storage']['status'] == 'Passed'
    (tmp_path / 'new.md').write_bytes(b'large archive' * 30)
    (tmp_path / 'a.md').write_bytes(b'a')
    after = measure(tmp_path, config, declared)
    assert evaluate(before, after, 'body-slim')['goal_result'] == 'Passed'
    result = evaluate(before, after, 'storage')
    assert result['goal_result'] == 'Failed'
    assert result['root'] == str(tmp_path) and result['config_sha256'] == before['config_sha256']
    assert after['domains']['new_archives']['items'][0]['presence'] == 'Present'


def test_same_cohort_new_archive_can_still_allow_actual_storage_reduction(tmp_path):
    config = fixture(tmp_path)
    declared = request(new_archives=['new.md'], allow_absent=[{'role': 'new_archives', 'path': 'new.md'}])
    before = measure(tmp_path, config, declared)
    (tmp_path / 'a.md').write_bytes(b'a')
    (tmp_path / 'new.md').write_bytes(b'b')
    after = measure(tmp_path, config, declared)
    assert evaluate(before, after, 'storage')['goal_result'] == 'Passed'


def test_storage_role_change_is_cohort_mismatch(tmp_path):
    config = fixture(tmp_path)
    (tmp_path / 'archive.md').write_bytes(b'archive')
    before = measure(tmp_path, config, request(reused_archives=['archive.md']))
    (tmp_path / 'a.md').write_bytes(b'a')
    after = measure(tmp_path, config, request(new_archives=['archive.md']))
    result = evaluate(before, after, 'storage')
    assert result['goal_result'] == 'Unknown'
    assert 'storage-cohort-mismatch' in result['reasons']


def test_explicit_external_absence_new_record_growth(tmp_path):
    project, outside = tmp_path / 'p', tmp_path / 'records'
    project.mkdir()
    outside.mkdir()
    config = fixture(project)
    entry = {'root': str(outside), 'path': 'new-journal.json'}
    declared = request(external_roots=[str(outside)], external_records=[entry],
                       allow_absent=[{'role': 'external_records', **entry}])
    before = measure(project, config, declared)
    assert before['domains']['external_records']['bytes'] == 0
    (outside / 'new-journal.json').write_bytes(b'new journal')
    after = measure(project, config, declared)
    assert evaluate(before, after, 'storage')['goal_result'] == 'Failed'
    assert before['domains']['external_records']['items'][0]['location'] == 'outside'


def test_absent_does_not_bypass_protection_scope_or_metadata_failure(tmp_path, monkeypatch):
    config = fixture(tmp_path)
    for rel in ('.env', 'Library/missing.md'):
        declared = request(new_archives=[rel], allow_absent=[{'role': 'new_archives', 'path': rel}])
        item = measure(tmp_path, config, declared)['domains']['new_archives']['items'][0]
        assert item['status'] == 'Unknown' and item['bytes'] is None
    scoped = task_config(tmp_path, config, files=['a.md'])
    declared = request(active=['a.md'], new_archives=['unauthorized.md'],
                       allow_absent=[{'role': 'new_archives', 'path': 'unauthorized.md'}])
    assert measure(tmp_path, scoped, declared)['domains']['new_archives']['bytes'] is None
    from fifan_maintenance.models import Context
    original = Context.metadata
    def denied(ctx, rel):
        if rel == 'new.md':
            raise PermissionError('deny')
        return original(ctx, rel)
    monkeypatch.setattr(Context, 'metadata', denied)
    declared = request(new_archives=['new.md'], allow_absent=[{'role': 'new_archives', 'path': 'new.md'}])
    assert measure(tmp_path, config, declared)['domains']['new_archives']['bytes'] is None


def test_disappearance_after_metadata_is_not_confirmed_absence(tmp_path, monkeypatch):
    config = fixture(tmp_path)
    from fifan_maintenance.models import Context
    original = Context.read_bytes
    def disappeared(ctx, rel):
        if rel == 'a.md':
            raise FileNotFoundError(rel)
        return original(ctx, rel)
    monkeypatch.setattr(Context, 'read_bytes', disappeared)
    result = measure(tmp_path, config, request(allow_absent=[{'role': 'active', 'path': 'a.md'}]))
    item = result['domains']['active']['items'][0]
    assert item['bytes'] is None and item['presence'] == 'Unknown'


def test_absence_permission_is_role_specific_and_legacy_not_promoted(tmp_path):
    config = fixture(tmp_path)
    declared = request(new_archives=['new.md'], reused_archives=['new.md'],
                       allow_absent=[{'role': 'new_archives', 'path': 'new.md'}])
    result = measure(tmp_path, config, declared)
    assert result['domains']['new_archives']['bytes'] == 0
    assert result['domains']['reused_archives']['bytes'] is None
    forged = copy.deepcopy(result)
    item = forged['domains']['new_archives']['items'][0]
    item.pop('absence_authorized')
    assert normalize_measurement(forged)['domains']['new_archives']['status'] == 'Unknown'
    legacy = normalize_measurement({'root': str(tmp_path), 'sources': [{'path': 'new.md', 'bytes': 0}]})
    assert legacy['domains']['active']['status'] == 'Unknown'
    assert legacy['domains']['active']['items'][0]['sha256'] is None


@pytest.mark.parametrize('permission', [
    {'role': 'views', 'path': 'new.md'}, {'role': 'new_archives', 'path': '../escape'},
    {'role': 'new_archives', 'path': 'not-declared.md'},
    {'role': 'external_records', 'path': 'new.md'},
    {'role': 'new_archives', 'path': 'new.md', 'root': '/not-authorized'},
])
def test_invalid_absence_permission_rejected(tmp_path, permission):
    config = fixture(tmp_path)
    with pytest.raises(ValueError):
        measure(tmp_path, config, request(new_archives=['new.md'], allow_absent=[permission]))


def test_absent_native_baseline_remains_verified_without_inventing_hash(tmp_path):
    config = fixture(tmp_path)
    declared = request(new_archives=['new.md'], allow_absent=[{'role': 'new_archives', 'path': 'new.md'}])
    before = measure(tmp_path, config, declared)
    absent = before['domains']['new_archives']['items'][0]
    baseline = {key: absent[key] for key in ('root', 'path', 'bytes', 'sha256', 'collected_at', 'source')}
    after = measure(tmp_path, config, {**declared, 'baseline': [baseline]})
    assert after['baseline_status'] == 'Passed'
    assert evaluate(before, after, 'storage')['goal_result'] == 'Failed'
