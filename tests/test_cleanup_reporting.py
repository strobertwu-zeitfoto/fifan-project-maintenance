from __future__ import annotations

import copy
import hashlib
import os

import pytest

from fifan_maintenance import cleanup_reporting as report
from fifan_maintenance import cleanup_operations as ops
from fifan_maintenance import cleanup_policy as policy
from fifan_maintenance import directory_common as dc
from fifan_maintenance.project import load_config


@pytest.fixture
def case(tmp_path):
    root, q, rec = [tmp_path / name for name in ('project', 'q', 'rec')]
    for path in (root, q, rec):
        path.mkdir()
    (root / 'logs').mkdir()
    (root / 'logs/old.log').write_bytes(b'closed\r\n\x00secret-payload')
    (root / 'closed.md').write_bytes(b'closed evidence')
    (root / 'current.md').write_bytes(b'Current retained entry')
    data = {'schema_version': 1, 'project_root': str(root), 'scan_roots': ['logs'],
            'candidates': [{'path': 'logs/old.log', 'kind': 'completed_log'}],
            'current': ['current.md'],
            'reference_sources': [{'path': 'closed.md', 'role': 'historical'}, {'path': 'current.md', 'role': 'current'}],
            'quarantine_root': str(q), 'records_dir': str(rec), 'require_no_open_handles': False}
    profile = policy.load_profile(root, load_config(root), data)
    request = {'schema_version': 1, 'approval': {'reference': 'synthetic approval', 'actions': ['quarantine', 'purge']},
               'items': [{'source': 'logs/old.log', 'kind': 'completed_log', 'reason': 'completed fixture',
                          'disposition': 'purge', 'closure': {'decision': 'closed', 'reason': 'closed fixture',
                          'evidence': [{'path': 'closed.md', 'sha256': hashlib.sha256(b'closed evidence').hexdigest()}]},
                          'loss': {'accepted': True, 'rebuildable': 'Unknown', 'unique_evidence': False, 'description': 'synthetic original loss'},
                          'retained': []}]}
    plan = ops.preview(profile, request, q, rec)
    return profile, request, q, rec, plan


def observe(case, **kwargs):
    profile, request, q, rec, plan = case
    return report.measure(profile, request, q, rec, plan=plan, **kwargs)


def test_t0_quarantine_purge_actual_domains(case):
    profile, request, q, rec, plan = case
    t0 = observe(case, stage='T0')
    assert t0['status'] == 'Passed'
    size = t0['domains']['project_payload']['bytes']
    assert size > 0 and t0['domains']['quarantine_payload']['bytes'] == 0
    assert t0['domains']['records']['bytes'] == 0
    journal = ops.apply(profile, plan, q, rec, approve_plan=plan['fingerprint'])
    t1 = observe(case, journal=journal, stage='T1')
    assert t1['status'] == 'Passed'
    assert t1['domains']['project_payload']['bytes'] == 0
    assert t1['domains']['quarantine_payload']['bytes'] == size
    compared = report.evaluate(t0, t1, stage='T1')
    assert compared['logical_payload_reduction_bytes'] == 0
    assert compared['domains']['records']['delta_bytes'] > 0
    purge = ops.purge_preview(profile, journal, q, rec)
    purged = ops.purge(profile, purge, q, rec, approve_plan=purge['fingerprint'])
    t2 = observe(case, journal=purged, stage='T2')
    assert t2['status'] == 'Passed'
    result = report.evaluate(t0, t2, stage='T2')
    assert result['logical_purged_payload_bytes'] == size
    assert result['physical_release_bytes'] is None
    assert b'secret-payload' not in dc.canonical(t2)


def test_restore_same_cohort_and_missing_is_not_zero(case):
    profile, request, q, rec, plan = case
    t0 = observe(case, stage='T0')
    journal = ops.apply(profile, plan, q, rec, approve_plan=plan['fingerprint'])
    unbound = observe(case)
    assert unbound['domains']['project_payload']['bytes'] is None
    restore = ops.restore_preview(profile, journal, q, rec)
    restored = ops.restore(profile, restore, q, rec, approve_plan=restore['fingerprint'])
    t3 = observe(case, journal=restored, stage='T3')
    assert t3['status'] == 'Passed'
    assert report.evaluate(t0, t3, stage='T3')['logical_payload_reduction_bytes'] == 0


def test_no_runtime_grant_does_not_read_external_roots(case, monkeypatch):
    profile, request, q, rec, plan = case
    original = dc.stat_entry
    def spy(root, rel):
        assert root == profile.root
        return original(root, rel)
    monkeypatch.setattr(dc, 'stat_entry', spy)
    result = report.measure(profile, request, None, None)
    assert result['status'] == 'Unknown'
    assert result['domains']['quarantine_payload']['status'] == 'Not run'
    assert result['total_logical_bytes'] is None


def test_metadata_only_and_records_include_hidden(case, monkeypatch):
    profile, request, q, rec, plan = case
    (rec / '.hidden').write_bytes(b'accounted')
    def forbidden(*args, **kwargs):
        raise AssertionError('body read')
    monkeypatch.setattr(dc, 'read_file', forbidden)
    monkeypatch.setattr(dc, 'stream_hash', forbidden)
    result = observe(case)
    assert result['status'] == 'Passed'
    assert result['domains']['records']['bytes'] == len(b'accounted')


def test_metadata_drift_and_symlink_not_zero(case):
    profile, request, q, rec, plan = case
    (profile.root / 'logs/old.log').write_bytes(b'changed')
    result = observe(case)
    assert result['domains']['project_payload']['bytes'] is None
    assert result['status'] == 'Unknown'
    (rec / '.link').symlink_to(profile.root / 'closed.md')
    assert observe(case)['domains']['records']['bytes'] is None


def test_budget_unknown_and_cohort_drift(case):
    first = observe(case, stage='T0')
    profile = case[0]
    data = copy.deepcopy(profile.data)
    data['budgets']['max_entries'] = 2
    limited = policy.load_profile(profile.root, profile.config, data)
    unknown = report.measure(limited, case[1], case[2], case[3], stage='T1')
    assert unknown['status'] == 'Unknown'
    assert unknown['total_logical_bytes'] is None
    drift = copy.deepcopy(first)
    drift['operation_id'] = 'different'
    drift = dc.seal(drift)
    compared = report.evaluate(first, drift, stage='T1')
    assert compared['status'] == 'Unknown'
    assert compared['logical_payload_reduction_bytes'] is None


def test_history_rec_only_live_unknown_and_budget(case, monkeypatch):
    profile, request, q, rec, plan = case
    journal = ops.apply(profile, plan, q, rec, approve_plan=plan['fingerprint'])
    original = dc.stat_entry
    def spy(root, rel):
        assert str(root).startswith(str(rec))
        return original(root, rel)
    monkeypatch.setattr(dc, 'stat_entry', spy)
    result = report.history(profile, rec)
    assert result['status'] == 'Passed'
    assert result['record_count'] == 1
    assert result['records'][0]['state'] == 'Quarantined'
    assert result['records'][0]['items'][0]['source_exists'] is None
    assert result['records'][0]['items'][0]['declared_source_exists'] is False
    assert result['live_verification'] == 'Not run'
    assert report.history(profile, rec, max_bytes=1)['status'] == 'Unknown'


def test_unowned_record_replacement_is_unknown(case):
    profile, request, q, rec, plan = case
    journal = ops.apply(profile, plan, q, rec, approve_plan=plan['fingerprint'])
    path = rec / ('cleanup-' + plan['operation_id']) / 'journal.json'
    raw = path.read_bytes()
    path.unlink()
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    assert report.history(profile, rec)['status'] == 'Unknown'
    with pytest.raises(dc.DirectoryError):
        observe(case, journal=journal)


def test_inspect_no_request_cannot_invent_cohort(case, monkeypatch):
    profile = case[0]
    original = dc.stat_entry
    def spy(root, rel):
        assert root == profile.root and rel in ('.', '.fifan-maintenance.json')
        return original(root, rel)
    monkeypatch.setattr(dc, 'stat_entry', spy)
    result = report.measure(profile, None, case[2], case[3], stage='T0')
    assert result['status'] == 'Unknown'
    assert result['request_sha256'] is None
    assert all(item['bytes'] is None for item in result['domains'].values())


def test_entire_rec_nested_hidden_and_depth_limit(case):
    profile, request, q, rec, plan = case
    (rec / '.hidden/deep').mkdir(parents=True)
    (rec / '.hidden/deep/file').write_bytes(b'account all records')
    result = observe(case)
    assert result['domains']['records']['bytes'] == len(b'account all records')
    data = copy.deepcopy(profile.data)
    data['budgets']['max_depth'] = 1
    limited = policy.load_profile(profile.root, profile.config, data)
    result = report.measure(limited, request, q, rec)
    assert result['domains']['records']['bytes'] is None
    assert result['domains']['records']['observed_bytes'] == 0


def test_history_bad_arrays_symlink_and_unrelated_records(case):
    profile, request, q, rec, plan = case
    (rec / 'ordinary-report.json').write_bytes(b'unrelated old session')
    directory = rec / ('cleanup-' + 'a' * 32)
    directory.mkdir(mode=0o700)
    (directory / 'journal.json').write_bytes(b'[]')
    os.chmod(directory / 'journal.json', 0o600)
    result = report.history(profile, rec)
    assert result['status'] == 'Unknown' and result['record_count'] == 0
    (directory / 'journal.json').unlink()
    (directory / 'journal.json').symlink_to(profile.root / 'closed.md')
    assert report.history(profile, rec)['status'] == 'Unknown'


def test_root_alias_and_wrong_record_root_rejected(case):
    profile, request, q, rec, plan = case
    alias = q.parent / 'alias'
    alias.symlink_to(q, target_is_directory=True)
    with pytest.raises((dc.DirectoryError, OSError)):
        report.measure(profile, request, alias, rec, plan=plan)
    with pytest.raises(dc.DirectoryError):
        report.history(profile, q)


def test_measure_detects_file_growth_during_rec_scan(case, monkeypatch):
    profile, request, q, rec, plan = case
    target = rec / '.account'
    target.write_bytes(b'old')
    original = dc.stat_entry
    calls = 0
    def changed(root, rel):
        nonlocal calls
        if root == rec and rel == '.account':
            calls += 1
            if calls == 2:
                target.write_bytes(b'grown after first stat')
        return original(root, rel)
    monkeypatch.setattr(dc, 'stat_entry', changed)
    result = observe(case)
    assert result['domains']['records']['bytes'] is None
    assert result['domains']['records']['coverage']['count_is_lower_bound']


def test_evaluate_rejects_unsealed_and_format(case):
    first = observe(case)
    bad = copy.deepcopy(first)
    bad['total_logical_bytes'] = 0
    with pytest.raises(dc.DirectoryError):
        report.evaluate(first, bad, stage='T1')
    bad = dc.seal(dict(first, format='fifan-directory-report'))
    with pytest.raises(dc.DirectoryError):
        report.evaluate(first, bad, stage='T1')


@pytest.mark.parametrize('direction', ['restore', 'purge'])
def test_action_plan_persisted_before_payload_change_is_not_terminal(case, tmp_path, direction):
    import subprocess
    import sys
    from pathlib import Path
    profile, request, q, rec, plan = case
    journal = ops.apply(profile, plan, q, rec, approve_plan=plan['fingerprint'])
    action = getattr(ops, direction + '_preview')(profile, journal, q, rec)
    dc.write_artifact(tmp_path / 'profile.json', profile.data)
    dc.write_artifact(tmp_path / 'action.json', action)
    code = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from fifan_maintenance import cleanup_policy as policy, cleanup_operations as ops, directory_common as dc
from fifan_maintenance.project import load_config
base=Path(sys.argv[2]); direction=sys.argv[3]
p=policy.load_profile(base/'project', load_config(base/'project'), base/'profile.json')
action=dc.load_artifact(base/'action.json'); original=ops._save
def save(profile, record, **kwargs):
    result=original(profile, record, **kwargs)
    if record['direction']==direction and record['state']=='Quarantined' and record[direction+'_plan'] is not None:
        os._exit(83)
    return result
ops._save=save
getattr(ops,direction)(p,action,base/'q',base/'rec',approve_plan=action['fingerprint'])
'''
    child = subprocess.run([sys.executable, '-B', '-c', code, str(Path(ops.__file__).parents[1]),
                            str(tmp_path), direction], capture_output=True, timeout=20)
    assert child.returncode == 83, child.stderr
    pending = dc.load_artifact(journal['journal_path'])
    assert ops.verify(profile, pending, q, rec)['status'] == 'Unknown'
    history = report.history(profile, rec)
    assert history['status'] == 'Unknown'
    assert history['records'][0]['terminal_consistent'] is False
    assert observe(case, journal=pending, stage='T1')['status'] == 'Unknown'
    finished = ops.recover(profile, pending, q, rec, **{
        'approve_purge' if direction == 'purge' else 'approve_plan': action['fingerprint']})
    expected = {'restore': 'Restored', 'purge': 'Purged'}[direction]
    assert finished['state'] == expected
    assert ops.verify(profile, finished, q, rec)['status'] == 'Passed'
    assert report.history(profile, rec)['status'] == 'Passed'
    assert observe(case, journal=finished, stage='T3')['status'] == 'Passed'
