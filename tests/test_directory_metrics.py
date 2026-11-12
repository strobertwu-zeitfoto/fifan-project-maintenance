from __future__ import annotations

import copy
import os
import sys

import pytest

from fifan_maintenance import directory_common as common
from fifan_maintenance import directory_metrics as metrics
from fifan_maintenance.project import load_config


def fixture(tmp_path, *, budgets=None, candidates=None, preset='generic'):
    project, archive, records = (tmp_path / name for name in ('project', 'archive', 'records'))
    for root in (project, archive, records):
        root.mkdir(exist_ok=True)
    (project / 'history').mkdir(exist_ok=True)
    (project / 'history' / 'original').write_bytes(b'original payload' * 100)
    profile = common.load_profile(project, load_config(project), {
        'schema_version': 1, 'project_root': str(project), 'preset': preset,
        'archive': {'archive_root': str(archive), 'records_dir': str(records),
                    'candidates': ['history'] if candidates is None else candidates},
        'budgets': {} if budgets is None else budgets,
    })
    request = {'schema_version': 1, 'batches': [{'source': 'history', 'destination': 'batch'}]}
    return profile, request, archive, records


def test_three_domains_are_metadata_only_and_future_archive_is_measured_absent(tmp_path, monkeypatch):
    profile, request, archive, records = fixture(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError('body read is not allowed')
    monkeypatch.setattr(common, 'read_file', forbidden)
    monkeypatch.setattr(common, 'stream_hash', forbidden)
    result = metrics.measure(profile, request, archive, records)
    assert result['status'] == 'Passed'
    assert result['domains']['project_payload']['bytes'] == 1600
    assert result['domains']['archive_payload']['bytes'] == 0
    assert result['domains']['archive_payload']['presence'] == 'Absent'
    assert result['domains']['archive_payload']['absent'] == ['batch']
    assert result['domains']['records']['paths'] == ['.']
    assert result['domains']['records']['bytes'] == 0
    assert result['total_logical_bytes'] == 1600
    assert result['body_bytes_read'] == 0 and result['metadata_lookups'] > 0
    assert result['storage_release'] == result['content_conservation'] == 'Unknown'


def test_dynamic_resolution_field_preserves_existing_metadata_cohort(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    before = metrics.measure(profile, request, archive, records)
    request['batches'][0]['dynamic_reference_resolutions'] = []
    after = metrics.measure(profile, request, archive, records)
    assert before['cohort_sha256'] == after['cohort_sha256']
    assert before['cohort'] == after['cohort']
    assert metrics.evaluate(before, after)['project_reduction_bytes'] == 0
    assert after['body_bytes_read'] == 0


@pytest.mark.skipif(sys.platform != 'darwin', reason='real same-volume no-replace directory rename is Darwin-specific')
def test_real_move_counts_locator_and_entire_records_growth(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    (records / 'preexisting.json').write_bytes(b'existing data')
    before = metrics.measure(profile, request, archive, records)
    common.rename_noreplace(profile.root, 'history', archive, 'batch')
    (profile.root / 'history').mkdir()
    (profile.root / 'history' / 'ARCHIVED.md').write_bytes(b'Archive locator')
    (records / 'journal.json').write_bytes(b'journal' * 10)
    (records / 'preexisting.json').write_bytes(b'existing data plus concurrent external growth')
    after = metrics.measure(profile, request, archive, records)
    result = metrics.evaluate(before, after)
    assert result['status'] == 'Passed'
    assert result['project_reduction_bytes'] == 1600 - len(b'Archive locator')
    assert result['archive_increase_bytes'] == 1600
    expected_records = len(b'journal' * 10) + len(b'existing data plus concurrent external growth') - len(b'existing data')
    assert result['records_increase_bytes'] == expected_records
    assert result['combined_delta_bytes'] == len(b'Archive locator') + expected_records
    assert result['exclusive_attribution'] == result['content_conservation'] == 'Unknown'
    assert any('concurrent external' in warning for warning in result['warnings'])
    assert any('after observed_at' in warning for warning in result['warnings'])
    assert (archive / 'batch' / 'original').read_bytes() == b'original payload' * 100


def test_source_future_position_can_be_absent_without_counting_missing_subtree_errors_as_zero(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    os.rename(profile.root / 'history', profile.root / 'not-in-cohort')
    result = metrics.measure(profile, request, archive, records)
    assert result['domains']['project_payload']['presence'] == 'Absent'
    assert result['domains']['project_payload']['bytes'] == 0
    assert result['status'] == 'Passed'
    assert result['total_logical_bytes'] == 0


def test_protected_symlink_and_special_items_make_lower_bound_unknown(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    (profile.root / 'history' / '.env').write_bytes(b'secret')
    (profile.root / 'history' / 'link').symlink_to(profile.root / 'history' / 'original')
    os.mkfifo(profile.root / 'history' / 'fifo')
    result = metrics.measure(profile, request, archive, records)
    domain = result['domains']['project_payload']
    assert domain['status'] == 'Unknown'
    assert domain['bytes'] == 1600
    assert domain['coverage']['count_is_lower_bound'] is True
    assert domain['absent'] == []
    assert metrics.evaluate(result, result)['combined_delta_bytes'] is None
    assert metrics.evaluate(result, result)['status'] == 'Unknown'


def test_protected_declared_batch_is_not_absent_zero(tmp_path):
    profile, request, archive, records = fixture(tmp_path, candidates=['history', 'Library/missing'])
    request['batches'] = [{'source': 'Library/missing', 'destination': 'batch'}]
    result = metrics.measure(profile, request, archive, records)
    domain = result['domains']['project_payload']
    assert domain['status'] == 'Unknown' and domain['presence'] == 'Unknown'
    assert domain['absent'] == []
    assert domain['coverage']['gaps'][0]['reason_code'] == 'PROTECTED_PATH'


def test_permission_failure_never_becomes_absent(tmp_path, monkeypatch):
    profile, request, archive, records = fixture(tmp_path)
    original = common.stat_entry
    def denied(root, rel):
        if root == archive and rel == 'batch':
            raise PermissionError('denied')
        return original(root, rel)
    monkeypatch.setattr(common, 'stat_entry', denied)
    result = metrics.measure(profile, request, archive, records)
    assert result['domains']['archive_payload']['status'] == 'Unknown'
    assert result['domains']['archive_payload']['presence'] == 'Unknown'
    assert result['domains']['archive_payload']['absent'] == []


def test_missing_intermediate_directory_confirmed_but_parent_link_is_not_absent(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    request['batches'][0]['destination'] = 'namespace/batch'
    result = metrics.measure(profile, request, archive, records)
    assert result['domains']['archive_payload']['absent'] == ['namespace/batch']
    (archive / 'namespace').symlink_to(profile.root, target_is_directory=True)
    result = metrics.measure(profile, request, archive, records)
    assert result['domains']['archive_payload']['status'] == 'Unknown'
    assert result['domains']['archive_payload']['absent'] == []


def test_entry_budget_is_global_lower_bound_and_workflow_can_continue(tmp_path):
    profile, request, archive, records = fixture(tmp_path, budgets={'max_entries': 3})
    result = metrics.measure(profile, request, archive, records)
    assert result['status'] == 'Unknown' and result['total_is_lower_bound'] is True
    assert result['work_entries'] <= 3
    assert all(d['coverage']['complete'] is False for d in result['domains'].values())
    assert all(d['presence'] == 'Unknown' for d in result['domains'].values())
    # Incomplete measurement is data, not an exception aborting the next stage.
    (records / 'independent-step.json').write_bytes(b'independent operation can continue')
    assert (records / 'independent-step.json').exists()
    assert metrics.evaluate(result, result)['project_reduction_bytes'] is None


def test_depth_limit_preserves_observed_lower_bound(tmp_path):
    profile, request, archive, records = fixture(tmp_path, budgets={'max_depth': 0})
    (profile.root / 'history' / 'deep').mkdir()
    (profile.root / 'history' / 'deep' / 'hidden').write_bytes(b'not observed')
    result = metrics.measure(profile, request, archive, records)
    domain = result['domains']['project_payload']
    assert domain['bytes'] == 1600
    assert domain['status'] == 'Unknown'
    assert any(g['reason_code'] == 'DEPTH_LIMIT' for g in domain['coverage']['gaps'])
    assert result['domains']['records']['status'] == 'Passed'


def test_time_limit_returns_unknown_not_fake_zero(tmp_path, monkeypatch):
    profile, request, archive, records = fixture(tmp_path, budgets={'max_seconds': 1})
    original = metrics.time.monotonic
    start = original()
    calls = []
    def clock():
        calls.append(1)
        return start if len(calls) == 1 else start + 2
    monkeypatch.setattr(metrics.time, 'monotonic', clock)
    result = metrics.measure(profile, request, archive, records)
    assert result['status'] == 'Unknown'
    assert metrics.evaluate(result, result)['combined_delta_bytes'] is None


@pytest.mark.parametrize('change', ['source', 'destination', 'records', 'profile'])
def test_cohort_and_profile_mismatch_cannot_show_savings(tmp_path, change):
    profile, request, archive, records = fixture(tmp_path, candidates=['history', 'another'])
    before = metrics.measure(profile, request, archive, records)
    revised = copy.deepcopy(request)
    if change == 'source':
        revised['batches'][0]['source'] = 'another'
    elif change == 'destination':
        revised['batches'][0]['destination'] = 'other'
    elif change == 'records':
        records.rename(tmp_path / 'old-records')
        records.mkdir()
    else:
        profile.sha256 = 'f' * 64
    after = metrics.measure(profile, revised, archive, records)
    result = metrics.evaluate(before, after)
    assert result['status'] == 'Unknown'
    assert result['combined_delta_bytes'] is None
    assert any('binding-mismatch:' in reason for reason in result['reasons'])


@pytest.mark.parametrize('batches', [
    [{'source': 'unauthorized', 'destination': 'one'}],
    [{'source': 'history', 'destination': '../outside'}],
    [{'source': 'history', 'destination': 'same'}, {'source': 'history', 'destination': 'different'}],
    [{'source': 'history', 'destination': 'a'}, {'source': 'history/sub', 'destination': 'b'}],
    [{'source': 'history', 'destination': 'a'}, {'source': 'another', 'destination': 'a/nested'}],
])
def test_unauthorized_or_overlapping_batches_rejected(tmp_path, batches):
    profile, request, archive, records = fixture(tmp_path, candidates=['history', 'history/sub', 'another'])
    request['batches'] = batches
    with pytest.raises(common.DirectoryError):
        metrics.measure(profile, request, archive, records)


def test_runtime_external_grant_is_required_and_root_overlap_rejected(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    with pytest.raises(common.DirectoryError):
        metrics.measure(profile, request, None, records)
    with pytest.raises(common.DirectoryError):
        metrics.measure(profile, request, records, archive)
    profile.data['archive']['records_dir'] = str(profile.root)
    with pytest.raises(common.DirectoryError):
        metrics.measure(profile, request, archive, profile.root)


def test_hardlinks_are_logical_names_without_claiming_physical_release(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    os.link(profile.root / 'history' / 'original', profile.root / 'history' / 'alias')
    result = metrics.measure(profile, request, archive, records)
    domain = result['domains']['project_payload']
    assert domain['bytes'] == 3200 and domain['files'] == 2
    assert domain['unique_inode_bytes'] == 1600 and domain['unique_inode_count'] == 1
    assert result['storage_release'] == 'Unknown'


def test_later_measurement_receipt_is_explicitly_not_in_snapshot(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    before = metrics.measure(profile, request, archive, records)
    (records / 'journal').write_bytes(b'journal')
    after = metrics.measure(profile, request, archive, records)
    result = metrics.evaluate(before, after)
    common.write_artifact(records / 'later-result.json', result)
    assert result['records_increase_bytes'] == len(b'journal')
    assert (records / 'later-result.json').stat().st_size > result['records_increase_bytes']
    assert any('later measurement receipt' in warning for warning in result['warnings'])


def test_invalid_incomplete_or_tampered_measurement_returns_unknown(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    before = metrics.measure(profile, request, archive, records)
    for mutate in (
        lambda value: value['domains'].pop('records'),
        lambda value: value['domains']['records'].update(bytes=None),
        lambda value: value['domains']['records']['coverage'].update(complete=False),
        lambda value: value['cohort']['roots']['records'].update(inode=999),
    ):
        after = copy.deepcopy(before)
        mutate(after)
        result = metrics.evaluate(before, after)
        assert result['status'] == 'Unknown' and result['combined_delta_bytes'] is None


def test_absent_root_replacement_during_measurement_is_unknown(tmp_path, monkeypatch):
    profile, request, archive, records = fixture(tmp_path)
    original = common.stat_entry
    replaced = []
    def change(root, rel):
        if root == archive and rel == 'batch' and not replaced:
            archive.rename(tmp_path / 'old-archive')
            archive.mkdir()
            replaced.append(True)
        return original(root, rel)
    monkeypatch.setattr(common, 'stat_entry', change)
    result = metrics.measure(profile, request, archive, records)
    assert result['domains']['archive_payload']['status'] == 'Unknown'
    assert any(g['reason_code'] == 'SOURCE_CHANGED' for g in result['domains']['archive_payload']['coverage']['gaps'])
    assert metrics.evaluate(result, result)['archive_increase_bytes'] is None


def test_child_disappears_during_traversal_is_gap_not_declared_absence(tmp_path, monkeypatch):
    profile, request, archive, records = fixture(tmp_path)
    original = common.stat_entry
    def disappeared(root, rel):
        if root == profile.root and rel == 'history/original':
            raise FileNotFoundError(rel)
        return original(root, rel)
    monkeypatch.setattr(common, 'stat_entry', disappeared)
    result = metrics.measure(profile, request, archive, records)
    domain = result['domains']['project_payload']
    assert domain['status'] == 'Unknown' and domain['absent'] == []
    assert any(g['reason_code'] == 'SOURCE_CHANGED' for g in domain['coverage']['gaps'])


def test_evaluate_cannot_silently_change_records_domain_scope(tmp_path):
    profile, request, archive, records = fixture(tmp_path)
    before = metrics.measure(profile, request, archive, records)
    after = copy.deepcopy(before)
    after['domains']['records']['paths'] = ['new-files-only']
    result = metrics.evaluate(before, after)
    assert result['status'] == 'Unknown' and result['records_increase_bytes'] is None
    assert 'after:domain-cohort-mismatch:records' in result['reasons']
    after = copy.deepcopy(before)
    del after['observed_at']
    assert metrics.evaluate(before, after)['status'] == 'Unknown'


def test_metrics_rejects_case_and_unicode_alias_batch_double_count(tmp_path):
    import unicodedata
    profile, request, archive, records = fixture(tmp_path, candidates=['history', 'another', 'Résumé'])
    (profile.root / 'another').mkdir()
    (profile.root / 'Résumé').mkdir()
    for batches in (
        [{'source': 'history', 'destination': 'One'}, {'source': 'HISTORY', 'destination': 'Two'}],
        [{'source': 'history', 'destination': 'One'}, {'source': 'another', 'destination': 'ONE/sub'}],
        [{'source': 'Résumé', 'destination': 'One'}, {'source': unicodedata.normalize('NFD', 'RÉSUMÉ'), 'destination': 'Two'}],
    ):
        with pytest.raises(common.DirectoryError):
            metrics.measure(profile, {'schema_version': 1, 'batches': batches}, archive, records)
    alias_request = {'schema_version': 1, 'batches': [{'source': 'HISTORY', 'destination': 'batch'}]}
    with pytest.raises(common.DirectoryError) as error:
        metrics.measure(profile, alias_request, archive, records)
    assert error.value.reason_code == 'PATH_ALIAS'
    valid = {'schema_version': 1, 'batches': [{'source': 'Résumé', 'destination': '未来归档'}]}
    assert metrics.measure(profile, valid, archive, records)['status'] == 'Passed'
