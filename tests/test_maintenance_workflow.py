from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from fifan_maintenance import cleanup_operations as ops
from fifan_maintenance import cleanup_policy as policy
from fifan_maintenance import cleanup_reporting as reporting
from fifan_maintenance import directory_common as dc
from fifan_maintenance import maintenance_workflow as mw
from fifan_maintenance.project import load_config


@pytest.fixture
def case(tmp_path):
    root, quarantine, records = [tmp_path / name for name in ('project', 'quarantine', 'records')]
    for path in (root, quarantine, records):
        path.mkdir()
    (root / 'current').mkdir()
    (root / 'current/entry.md').write_text('# Current\nRetain this exact current contract.\n')
    (root / 'old.log').write_bytes(b'closed fixture process log\n')
    evidence = b'Explicit approved closed fixture, not the only record.\n'
    (root / 'closed.md').write_bytes(evidence)
    profile = policy.load_profile(root, load_config(root), {
        'schema_version': 1, 'project_root': str(root), 'scan_roots': ['.'],
        'current': ['current'], 'candidates': [{'path': 'old.log', 'kind': 'completed_log'}],
        'reference_sources': [{'path': 'current', 'role': 'current'}, {'path': 'closed.md', 'role': 'historical'}],
        'quarantine_root': str(quarantine), 'records_dir': str(records), 'require_no_open_handles': False})
    request = {'schema_version': 1, 'approval': {'reference': 'explicit synthetic fixture approval', 'actions': ['quarantine', 'purge']},
        'items': [{'source': 'old.log', 'kind': 'completed_log', 'reason': 'Approved closed disposable fixture log',
                   'closure': {'decision': 'closed', 'reason': 'Closed fixture', 'evidence': [{'path': 'closed.md', 'sha256': hashlib.sha256(evidence).hexdigest()}]},
                   'loss': {'accepted': True, 'rebuildable': False, 'unique_evidence': False, 'description': 'Approved loss of this exact process log'},
                   'retained': [], 'disposition': 'purge'}]}
    return profile, request, quarantine, records


def read_receipt(result):
    value = dc.load_artifact(result['workflow_path'])
    dc.validate_seal(value)
    return value


def execute(case, mode='quarantine', after=None, **kwargs):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    return mw.workflow(profile, mode=mode, request=request, plan=plan, approve_plan=plan['fingerprint'],
                       Q=quarantine, records_dir=records, after=after, **kwargs)


def task_profile(case, tmp_path):
    path = tmp_path / 'task-profile.json'
    dc.write_artifact(path, {'schema_version': 1, 'sources': ['current/entry.md'], 'checks': ['documents']})
    return {'kind': 'task-check', 'profile': str(path)}


def test_default_inspect_does_not_read_payload_or_enter_cleanup(case, monkeypatch):
    profile, _, quarantine, records = case
    before = (profile.root / 'old.log').read_bytes()
    def forbidden(*args, **kwargs):
        pytest.fail('default inspect must not invoke an execution engine')
    monkeypatch.setattr(ops, 'apply', forbidden)
    monkeypatch.setattr(ops, 'purge', forbidden)
    result = mw.workflow(profile, records_dir=records)
    assert result['completion'] == 'inspect_only'
    assert (profile.root / 'old.log').read_bytes() == before
    assert not list(quarantine.iterdir())
    receipt = read_receipt(result)
    assert receipt['cleanup'] == {}
    assert receipt['measurement_data']['T0']['stage'] == 'T0'
    assert receipt['after_action']['status'] == 'Not run'


def test_quarantine_measures_before_records_and_rebuilds_retained_baseline(case):
    profile, _, quarantine, records = case
    result = execute(case)
    assert result['status'] == 'Passed', result
    assert result['cleanup_state'] == 'Quarantined'
    assert not (profile.root / 'old.log').exists()
    receipt = read_receipt(result)
    assert receipt['format'] == mw.FORMAT
    assert {item['stage'] for item in receipt['measurements']} == {'T0', 'T1'}
    baseline = dc.load_artifact(receipt['baseline_path'])
    assert baseline['status'] == 'Passed'
    assert baseline['material']['current_paths'] == ['current/entry.md']
    assert Path(result['cleanup_journal']).is_file()
    assert Path(result['workflow_path']).parent.stat().st_mode & 0o777 == 0o700


def test_purge_without_original_full_permission_has_zero_payload_side_effects(case):
    profile, request, quarantine, records = case
    request = copy.deepcopy(request)
    request['approval']['actions'] = ['quarantine']
    request['items'][0]['disposition'] = 'quarantine'
    plan = ops.preview(profile, request, quarantine, records)
    result = mw.workflow(profile, mode='purge', request=request, plan=plan,
                         approve_plan=plan['fingerprint'], Q=quarantine, records_dir=records)
    assert result['status'] == 'Blocked' and result['reason_code'] == 'APPROVAL_REQUIRED'
    assert (profile.root / 'old.log').read_bytes() == b'closed fixture process log\n'
    assert not list(quarantine.iterdir())
    assert not list(records.glob('cleanup-*'))


def test_exact_authorization_can_quarantine_then_purge(case):
    result = execute(case, mode='purge')
    assert result['status'] == 'Passed', result
    assert result['cleanup_state'] == 'Purged'
    receipt = read_receipt(result)
    assert {item['stage'] for item in receipt['measurements']} == {'T0', 'T1', 'T2'}
    assert 'purge_plan_path' in receipt['cleanup']
    assert not (case[0].root / 'old.log').exists()


def test_explicit_after_check_uses_post_cleanup_baseline(case, tmp_path, monkeypatch):
    profile, _, _, _ = case
    after = task_profile(case, tmp_path)
    original = policy.rebaseline
    old_sha = hashlib.sha256((profile.root / 'current/entry.md').read_bytes()).hexdigest()
    calls = []
    def baseline(profile, request=None, **kwargs):
        assert not (profile.root / 'old.log').exists()
        (profile.root / 'current/entry.md').write_text('# Current\nNew current fixture after cleanup.\n')
        value = original(profile, request, **kwargs)
        calls.append(value)
        return value
    monkeypatch.setattr(policy, 'rebaseline', baseline)
    result = execute(case, after=after)
    assert result['status'] == 'Passed', result
    assert result['after_action']['status'] == 'Passed'
    assert result['after_action']['write_performed'] is False
    assert calls and calls[0]['material']['reference_fingerprints']
    current_sha = next(f['sha256'] for f in calls[0]['material']['reference_fingerprints'] if f['path'] == 'current/entry.md')
    assert current_sha != old_sha
    after_check = dc.load_artifact(result['after_action']['artifact'])
    assert after_check['files']['current/entry.md']['sha256'] == current_sha
    receipt = read_receipt(result)
    assert [m['stage'] for m in receipt['measurements']] == ['T0', 'T1', 'T3']
    assert receipt['measurement_note'].startswith('Final receipt/report writes')


def test_wrong_after_archive_runtime_grant_is_rejected_before_cleanup(case, tmp_path):
    profile, request, quarantine, records = case
    directory_profile = tmp_path / 'directory.json'
    dc.write_artifact(directory_profile, {'schema_version': 1, 'project_root': str(profile.root)})
    after = {'kind': 'directory-archive', 'profile': str(directory_profile), 'archive_root': str(tmp_path / 'ungranted')}
    plan = ops.preview(profile, request, quarantine, records)
    with pytest.raises(ValueError) as error:
        mw.workflow(profile, mode='quarantine', request=request, plan=plan, approve_plan=plan['fingerprint'],
                    Q=quarantine, records_dir=records, after=after)
    assert error.value.reason_code == 'EXTERNAL_ROOT_NOT_AUTHORIZED'
    assert (profile.root / 'old.log').exists()
    assert not list(records.iterdir())


def test_wrapper_only_calls_existing_launcher(monkeypatch):
    import importlib.util
    script = Path(__file__).resolve().parents[1] / 'tools/run_project_maintenance.py'
    spec = importlib.util.spec_from_file_location('maintenance_wrapper', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(sys, 'argv', [str(script), '--project', 'fixture', '--records-dir', 'records'])
    monkeypatch.setattr(module.subprocess, 'call', lambda argv: calls.append(argv) or 7)
    assert module.main() == 7
    assert calls == [[str(script.parents[1] / 'bin/fifan-maintain'), 'maintenance', 'workflow', '--project', 'fixture', '--records-dir', 'records']]


def test_small_cleanup_plan_api_handshake(case):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    assert plan['format'] == 'fifan-cleanup-plan'
    assert plan['kind'] == 'quarantine'
    assert plan['request']['approval']['actions'] == ['quarantine', 'purge']
    assert plan['qualification']['status'] == 'Passed'
    assert plan['items'][0]['source'] == 'old.log'
    assert not list(records.iterdir())
    assert not list(quarantine.iterdir())


def test_resume_after_transient_after_error_has_no_stale_error(case, tmp_path, monkeypatch):
    profile, request, quarantine, records = case
    after = task_profile(case, tmp_path)
    original = mw._after_readonly
    calls = []
    def fail_once(run, effective):
        if not calls:
            calls.append(True)
            raise dc.DirectoryError('INJECTED_AFTER_FAILURE')
        return original(run, effective)
    monkeypatch.setattr(mw, '_after_readonly', fail_once)
    plan = ops.preview(profile, request, quarantine, records)
    first = mw.workflow(profile, mode='quarantine', request=request, plan=plan, approve_plan=plan['fingerprint'],
                        Q=quarantine, records_dir=records, after=after)
    assert first['status'] == 'Blocked' and first['cleanup_state'] == 'Quarantined'
    def no_new_preview(*args, **kwargs):
        pytest.fail('resume must not create a new cleanup operation')
    monkeypatch.setattr(ops, 'preview', no_new_preview)
    final = mw.workflow(profile, mode='quarantine', request=request, approve_plan=plan['fingerprint'],
                        Q=quarantine, records_dir=records, after=after, resume=first['workflow_path'])
    assert final['status'] == 'Passed', final
    assert 'reason_code' not in final and 'next_action' not in final
    assert len(list(records.glob('cleanup-*'))) == 1
    assert final['cleanup_journal'] == first['cleanup_journal']
    assert read_receipt(final)['previous_attempts'][0]['reason_code'] == 'INJECTED_AFTER_FAILURE'


def test_initial_engine_journal_failure_keeps_exact_original_plan(case, monkeypatch):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    original = ops._save
    injected = []
    def fail_initial(profile, record, *, initial=False):
        if initial and not injected:
            injected.append(record['journal_path'])
            raise OSError('injected initial engine journal save failure')
        return original(profile, record, initial=initial)
    monkeypatch.setattr(ops, '_save', fail_initial)
    first = mw.workflow(profile, mode='quarantine', request=request, plan=plan, approve_plan=plan['fingerprint'],
                        Q=quarantine, records_dir=records)
    assert injected and first['status'] == 'Blocked'
    assert (profile.root / 'old.log').exists()
    receipt = read_receipt(first)
    assert receipt['cleanup']['operation_id'] == plan['operation_id']
    assert receipt['cleanup']['journal_path'] == injected[0]
    def no_new_preview(*args, **kwargs):
        pytest.fail('failure retries must not manufacture a new plan')
    monkeypatch.setattr(ops, 'preview', no_new_preview)
    final = mw.workflow(profile, mode='quarantine', request=request, approve_plan=plan['fingerprint'],
                        Q=quarantine, records_dir=records, resume=first['workflow_path'])
    assert read_receipt(final)['cleanup']['operation_id'] == plan['operation_id']
    assert len(list(records.glob('cleanup-*'))) <= 1
    assert final['status'] in {'Passed', 'Blocked'}  # Ambiguous owner may safely block.
    if final['status'] == 'Passed':
        assert final['cleanup_state'] == 'Quarantined'
        assert not (profile.root / 'old.log').exists()


def test_resume_rejects_missing_runtime_approval(case):
    profile, request, quarantine, records = case
    first = execute(case)
    before = Path(first['cleanup_journal']).read_bytes()
    with pytest.raises(ValueError) as error:
        mw.workflow(profile, mode='quarantine', request=request, Q=quarantine, records_dir=records,
                    resume=first['workflow_path'])
    assert error.value.reason_code == 'APPROVAL_REQUIRED'
    assert Path(first['cleanup_journal']).read_bytes() == before


def test_after_without_own_approval_only_checks_existing_exact_profile(case, tmp_path):
    from fifan_maintenance import changes
    profile, _, _, _ = case
    task = tmp_path / 'task.json'
    dc.write_artifact(task, {'schema_version': 1, 'sources': ['current/entry.md'], 'checks': ['documents']})
    original = (profile.root / 'current/entry.md').read_bytes()
    file_plan = changes.preview(profile.root, {'operations': [{'type': 'replace', 'path': 'current/entry.md',
                                'old': 'Retain this exact current contract.', 'new': 'Explicit new contract.'}]}, profile.config)
    path = tmp_path / 'file-plan.json'
    dc.write_artifact(path, file_plan)
    after = {'kind': 'file-plan', 'profile': str(task), 'plan': str(path)}
    result = execute(case, after=after)
    assert result['status'] == 'Passed', result
    assert result['after_action']['write_performed'] is False
    assert (profile.root / 'current/entry.md').read_bytes() == original


def test_real_process_exit_after_quarantine_move_resumes_same_operation(case, tmp_path):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    profile_path, request_path, plan_path = [tmp_path / name for name in ('profile.json', 'request.json', 'plan.json')]
    for path, value in ((profile_path, profile.data), (request_path, request), (plan_path, plan)):
        dc.write_artifact(path, value)
    code = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from fifan_maintenance import cleanup_policy as p
from fifan_maintenance import directory_common as dc
from fifan_maintenance import maintenance_workflow as mw
from fifan_maintenance.project import load_config
profile=p.load_profile(sys.argv[2],load_config(Path(sys.argv[2])),sys.argv[3])
request=dc.load_artifact(sys.argv[4]);plan=dc.load_artifact(sys.argv[5])
original=dc.rename_entry_noreplace
def moved(source_root,source,destination_root,destination):
    result=original(source_root,source,destination_root,destination)
    if str(source_root)==str(profile.root):
        os._exit(79)
    return result
dc.rename_entry_noreplace=moved
mw.workflow(profile,mode='quarantine',request=request,plan=plan,approve_plan=plan['fingerprint'],Q=sys.argv[6],records_dir=sys.argv[7])
'''
    child = subprocess.run([sys.executable, '-B', '-c', code, str(Path(mw.__file__).parents[1]), str(profile.root),
                            str(profile_path), str(request_path), str(plan_path), str(quarantine), str(records)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    assert child.returncode == 79, child.stderr.decode(errors='replace')
    receipts = list(records.glob('maintenance-*/workflow.json'))
    assert len(receipts) == 1
    assert not (profile.root / 'old.log').exists()
    before = dc.load_artifact(receipts[0])
    assert before['cleanup']['operation_id'] == plan['operation_id']
    result = mw.workflow(profile, mode='quarantine', request=request, approve_plan=plan['fingerprint'],
                         Q=quarantine, records_dir=records, resume=receipts[0])
    assert result['status'] == 'Passed', result
    assert result['cleanup_state'] == 'Quarantined'
    assert len(list(records.glob('cleanup-*'))) == 1


def test_global_protected_unknown_keeps_independent_cleanup_result(case):
    profile, _, _, _ = case
    (profile.root / '.git').mkdir()
    (profile.root / '.env').write_text('password=SYNTHETIC_DO_NOT_OUTPUT')
    result = execute(case)
    assert result['status'] == 'Unknown', result
    assert result['cleanup_state'] == 'Quarantined' and result['cleanup_status'] == 'Passed'
    assert result['inspection_status'] == result['global_coverage_status'] == 'Unknown'
    assert result['global_no_dependencies'] == 'Unknown'
    assert not (profile.root / 'old.log').exists()
    assert 'SYNTHETIC_DO_NOT_OUTPUT' not in json.dumps(result)


def test_completed_resume_is_readonly_for_workflow_and_engine_records(case):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    first = mw.workflow(profile, mode='quarantine', request=request, plan=plan,
                        approve_plan=plan['fingerprint'], Q=quarantine, records_dir=records)
    assert first['status'] == 'Passed', first
    before = {p.relative_to(records): (p.read_bytes(), p.stat().st_ino) for p in records.rglob('*') if p.is_file()}
    again = mw.workflow(profile, mode='quarantine', request=request, approve_plan=plan['fingerprint'],
                        Q=quarantine, records_dir=records, resume=first['workflow_path'])
    assert again['status'] == 'Passed' and again['live_verification'] == 'Passed'
    assert {p.relative_to(records): (p.read_bytes(), p.stat().st_ino) for p in records.rglob('*') if p.is_file()} == before


def test_same_effective_config_new_file_stops_dependent_after_action(case, tmp_path, monkeypatch):
    after = task_profile(case, tmp_path)
    original = policy.rebaseline
    def changed(profile, request=None, **kwargs):
        value = original(profile, request, **kwargs)
        # {} has the same effective DEFAULT_CONFIG but is a new physical input.
        (profile.root / '.fifan-maintenance.json').write_text('{}')
        return value
    monkeypatch.setattr(policy, 'rebaseline', changed)
    entered = []
    monkeypatch.setattr(mw, '_after_readonly', lambda *args: entered.append(True))
    result = execute(case, after=after)
    assert result['status'] == 'Blocked' and result['reason_code'] == 'SOURCE_CHANGED'
    assert result['cleanup_state'] == 'Quarantined'
    assert entered == []


def test_existing_precise_file_plan_requires_and_uses_own_approval(case, tmp_path):
    from fifan_maintenance import changes
    profile, _, _, _ = case
    task = tmp_path / 'approved-task.json'
    dc.write_artifact(task, {'schema_version': 1, 'sources': ['current/entry.md'], 'checks': ['documents']})
    plan = changes.preview(profile.root, {'operations': [{'type': 'replace', 'path': 'current/entry.md',
                             'old': 'Retain this exact current contract.', 'new': 'Explicitly approved revised fixture contract.'}]}, profile.config)
    path = tmp_path / 'approved-file-plan.json'
    dc.write_artifact(path, plan)
    after = {'kind': 'file-plan', 'profile': str(task), 'plan': str(path), 'approve_plan': plan['operation_id']}
    result = execute(case, after=after)
    assert result['status'] == 'Passed', result
    assert result['after_action']['write_performed'] is True
    assert result['after_action']['check_status'] == 'Passed'
    assert 'Explicitly approved revised fixture contract.' in (profile.root / 'current/entry.md').read_text()
    record = dc.load_artifact(result['after_action']['journal_path'])
    assert changes.verify(profile.root, record, profile.config)['status'] == 'Passed'
    metrics = result['after_metrics']
    body = metrics['body']
    assert body['status'] == 'Passed'
    expected = (profile.root / 'current/entry.md').read_bytes()
    assert body['after_bytes'] == len(expected)
    assert body['files'][0]['after_sha256'] == hashlib.sha256(expected).hexdigest()
    assert body['before_bytes'] == len(b'# Current\nRetain this exact current contract.\n')
    assert body['reduction_bytes'] == body['before_bytes'] - body['after_bytes']
    assert metrics['archive']['status'] == metrics['search']['status'] == 'Not run'
    artifact = dc.load_artifact(metrics['artifact'])
    dc.validate_seal(artifact)
    assert artifact['kind'] == 'after-metrics'
    assert 'backups' not in json.dumps(artifact)


def test_file_move_and_snapshot_are_not_reported_as_body_reduction(case, tmp_path):
    from fifan_maintenance import changes
    profile, _, _, _ = case
    (profile.root / 'notes').mkdir()
    (profile.root / 'notes/original.md').write_bytes(b'original retained note')
    (profile.root / 'notes/move.md').write_bytes(b'move only, preserve body')
    plan = changes.preview(profile.root, {'version': 2, 'guards': [], 'operations': [
        {'kind': 'snapshot', 'path': 'notes/original.md', 'destination': 'notes/copy.md',
         'expected_sha256': hashlib.sha256(b'original retained note').hexdigest(),
         'origin': {'reference_base': '.', 'classification_basis': 'explicit synthetic preserved original'}},
        {'type': 'move', 'path': 'notes/move.md', 'destination': 'notes/moved.md'}]}, profile.config)
    task = tmp_path / 'move-task.json'
    dc.write_artifact(task, {'schema_version': 1, 'sources': ['notes/original.md', 'notes/move.md',
                      'notes/copy.md', 'notes/moved.md']})
    path = tmp_path / 'move-plan.json'
    dc.write_artifact(path, plan)
    result = execute(case, after={'kind': 'file-plan', 'profile': str(task), 'plan': str(path),
                                  'approve_plan': plan['operation_id']})
    assert result['after_action']['mechanical_status'] == 'Passed', result
    body = result['after_metrics']['body']
    assert body['status'] == 'Not run'
    assert body['reduction_bytes'] is None and body['before_bytes'] is None
    assert body['files'] == []
    assert {item['kind'] for item in body['other_operations']} == {'snapshot', 'move'}
    assert {item['destination'] for item in body['other_operations']} == {'notes/copy.md', 'notes/moved.md'}
    assert (profile.root / 'notes/original.md').read_bytes() == (profile.root / 'notes/copy.md').read_bytes()


def test_after_directory_readonly_does_not_probe_profile_external_declarations(case, tmp_path, monkeypatch):
    profile, _, _, records = case
    path = tmp_path / 'ungranted-directory.json'
    dc.write_artifact(path, {'schema_version': 1, 'project_root': str(profile.root), 'scan_roots': ['current'],
                            'archive': {'archive_root': '/UNGRANTED/ARC', 'records_dir': '/UNGRANTED/REC'}})
    original = dc.canonical_destination
    def no_ungranted(value, *args, **kwargs):
        if str(value).startswith('/UNGRANTED'):
            pytest.fail('a data-only declaration was used as an external read grant')
        return original(value, *args, **kwargs)
    monkeypatch.setattr(dc, 'canonical_destination', no_ungranted)
    result = mw.workflow(profile, records_dir=records, after={'kind': 'directory-inspect', 'profile': str(path)})
    assert result['status'] == 'Passed', result
    assert result['after_action']['write_performed'] is False


def test_approved_after_search_arc_requires_outer_grant_before_cleanup(case, tmp_path):
    from fifan_maintenance import search_view
    profile, request, quarantine, records = case
    (profile.root / 'retained-history').mkdir()
    (profile.root / 'retained-history/kept.md').write_text('retain original')
    arc = tmp_path / 'after-archive'
    arc.mkdir()
    data = {'schema_version': 1, 'project_root': str(profile.root), 'critical_paths': ['current/entry.md'],
            'search': {'exclude': ['retained-history']},
            'archive': {'archive_root': str(arc), 'records_dir': str(records)}}
    path = tmp_path / 'directory-search.json'
    dc.write_artifact(path, data)
    directory = dc.load_profile(profile.root, profile.config, data)
    search_plan = search_view.search_preview(directory)
    plan_path = tmp_path / 'search-plan.json'
    dc.write_artifact(plan_path, search_plan)
    after = {'kind': 'directory-search', 'profile': str(path), 'plan': str(plan_path), 'approve_plan': search_plan['fingerprint']}
    cleanup_plan = ops.preview(profile, request, quarantine, records)
    with pytest.raises(ValueError) as error:
        mw.workflow(profile, mode='quarantine', request=request, plan=cleanup_plan, approve_plan=cleanup_plan['fingerprint'],
                    Q=quarantine, records_dir=records, after=after)
    assert error.value.reason_code == 'EXTERNAL_ROOT_NOT_AUTHORIZED'
    assert (profile.root / 'old.log').exists()
    result = mw.workflow(profile, mode='quarantine', request=request, plan=cleanup_plan, approve_plan=cleanup_plan['fingerprint'],
                         Q=quarantine, records_dir=records, after=after, after_archive_root=arc)
    assert result['status'] == 'Passed', result
    assert result['after_action']['write_performed'] is True
    assert (profile.root / '.ignore').is_file()
    metrics = result['after_action']['metrics']['search']
    journal = dc.load_artifact(result['after_action']['journal_path'])
    assert metrics['before'] == journal['validation']['before']
    assert metrics['after'] == journal['validation']['after']
    assert metrics['hidden_files'] == 1
    assert metrics['current']['list_sha256'] == metrics['after']['list_sha256']
    assert metrics['critical_paths']['current/entry.md'] == 'Passed'
    assert 'after cleanup' in metrics['measurement_span']


def test_after_file_checks_report_actual_failure_without_undoing_approved_edit(case, tmp_path):
    from fifan_maintenance import changes
    profile, _, _, _ = case
    task = tmp_path / 'links-task.json'
    dc.write_artifact(task, {'schema_version': 1, 'sources': ['current/entry.md'], 'checks': ['links']})
    plan = changes.preview(profile.root, {'operations': [{'type': 'replace', 'path': 'current/entry.md',
                             'old': 'Retain this exact current contract.', 'new': '[New broken fixture link](missing.md)'}]}, profile.config)
    path = tmp_path / 'links-file-plan.json'
    dc.write_artifact(path, plan)
    result = execute(case, after={'kind': 'file-plan', 'profile': str(task), 'plan': str(path), 'approve_plan': plan['operation_id']})
    assert result['status'] == 'Failed', result
    assert result['cleanup_state'] == 'Quarantined'
    assert result['after_action']['mechanical_status'] == 'Passed'
    assert result['after_action']['check_status'] == 'Failed'
    assert '[New broken fixture link](missing.md)' in (profile.root / 'current/entry.md').read_text()


def test_real_process_exit_after_purge_unlink_resumes_only_original_approved_direction(case, tmp_path):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    profile_path, request_path, plan_path = [tmp_path / name for name in ('purge-profile.json', 'purge-request.json', 'purge-plan.json')]
    for path, value in ((profile_path, profile.data), (request_path, request), (plan_path, plan)):
        dc.write_artifact(path, value)
    code = r'''
import os, sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from fifan_maintenance import cleanup_policy as p
from fifan_maintenance import directory_common as dc
from fifan_maintenance import maintenance_workflow as mw
from fifan_maintenance.project import load_config
profile=p.load_profile(sys.argv[2],load_config(Path(sys.argv[2])),sys.argv[3])
request=dc.load_artifact(sys.argv[4]);plan=dc.load_artifact(sys.argv[5])
original=os.unlink
def removed(name,*args,**kwargs):
    result=original(name,*args,**kwargs)
    if name=='payload-0000':
        os._exit(81)
    return result
os.unlink=removed
mw.workflow(profile,mode='purge',request=request,plan=plan,approve_plan=plan['fingerprint'],Q=sys.argv[6],records_dir=sys.argv[7])
'''
    child = subprocess.run([sys.executable, '-B', '-c', code, str(Path(mw.__file__).parents[1]), str(profile.root),
                            str(profile_path), str(request_path), str(plan_path), str(quarantine), str(records)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    assert child.returncode == 81, child.stderr.decode(errors='replace')
    receipts = list(records.glob('maintenance-*/workflow.json'))
    assert len(receipts) == 1
    value = dc.load_artifact(receipts[0])
    assert value['cleanup']['intent'] == 'purge'
    assert 'purge_plan_path' in value['cleanup']
    assert not (profile.root / 'old.log').exists()
    result = mw.workflow(profile, mode='purge', request=request, approve_plan=plan['fingerprint'],
                         Q=quarantine, records_dir=records, resume=receipts[0])
    assert result['status'] == 'Passed', result
    assert result['cleanup_state'] == 'Purged'
    assert len(list(records.glob('cleanup-*'))) == 1


def test_preexisting_plan_storage_is_in_t0_without_backfilling_preview_cost(case):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    path = records / 'preexisting-plan.json'
    dc.write_artifact(path, plan)
    size = path.stat().st_size
    result = mw.workflow(profile, mode='quarantine', request=request, plan=path, approve_plan=plan['fingerprint'],
                         Q=quarantine, records_dir=records)
    assert result['status'] == 'Passed', result
    assert result['preexisting_plan']['origin'] == 'existing-file'
    assert result['preexisting_plan']['path'] == str(path)
    assert 'earlier preview costs' in result['measurement_span']
    assert read_receipt(result)['measurement_data']['T0']['domains']['records']['bytes'] >= size


@pytest.mark.parametrize('measurement_case', ['normal', 'budget', 'missing-before-resume'])
def test_after_archive_uses_only_explicit_granted_root_and_existing_approved_plan(case, tmp_path, monkeypatch, measurement_case):
    from fifan_maintenance import directory_archive
    profile, _, _, records = case
    source = profile.root / 'retained-history'
    source.mkdir()
    (source / 'retained.txt').write_text('approved retained archival payload')
    arc = tmp_path / 'explicit-archive'
    arc.mkdir()
    data = {'schema_version': 1, 'project_root': str(profile.root), 'critical_paths': ['current/entry.md'],
            'reference_sources': [{'path': 'current', 'role': 'current'}, {'path': 'closed.md', 'role': 'historical'}],
            'classifications': [{'path': 'retained-history', 'role': 'historical', 'reason': 'explicit closed fixture'}],
            'archive': {'archive_root': str(arc), 'records_dir': str(records), 'candidates': ['retained-history'],
                        'require_no_open_handles': False}}
    path = tmp_path / 'after-archive-profile.json'
    dc.write_artifact(path, data)
    directory = dc.load_profile(profile.root, profile.config, data)
    request = {'schema_version': 1, 'batches': [{'source': 'retained-history', 'destination': 'closed/history',
        'closure': {'decision': 'closed', 'reason': 'approved fixture', 'evidence': [{'path': 'closed.md',
                    'sha256': hashlib.sha256((profile.root / 'closed.md').read_bytes()).hexdigest()}]}}]}
    plan = directory_archive.archive_preview(directory, request, arc, records)
    plan_path = tmp_path / 'after-archive-plan.json'
    dc.write_artifact(plan_path, plan)
    after = {'kind': 'directory-archive', 'profile': str(path), 'request': request, 'plan': str(plan_path),
             'approve_plan': plan['fingerprint'], 'archive_root': str(arc)}
    original_apply = directory_archive.apply
    calls = []
    def apply_once(*args, **kwargs):
        calls.append('apply')
        value = original_apply(*args, **kwargs)
        if measurement_case == 'missing-before-resume':
            raise OSError('simulated interruption after engine commit')
        return value
    monkeypatch.setattr(directory_archive, 'apply', apply_once)
    if measurement_case == 'budget':
        from fifan_maintenance import directory_metrics
        original_measure = directory_metrics.measure
        observations = []
        def exhausted_after(*args, **kwargs):
            observations.append('measure')
            if len(observations) == 2:
                raise dc.DirectoryError('BUDGET_EXHAUSTED', 'fixture budget')
            return original_measure(*args, **kwargs)
        monkeypatch.setattr(directory_metrics, 'measure', exhausted_after)
    result = execute(case, after=after, after_archive_root=arc)
    if measurement_case == 'missing-before-resume':
        assert result['state'] == 'NeedsAttention'
        receipt = read_receipt(result)
        # Model an earlier receipt without measurements, retaining the actual
        # approved action and committed engine journal. Never infer an orphan
        # observation's role from filenames or timestamps.
        receipt['after_progress'].pop('archive_before_path')
        receipt['after_progress'].pop('archive_before_sha256')
        dc.write_artifact(result['workflow_path'], dc.seal(receipt), replace=True)
        result = mw.workflow(profile, mode='quarantine', Q=case[2], records_dir=records,
                             approve_plan=receipt['approved_plan_fingerprint'], resume=result['workflow_path'],
                             after=after, after_archive_root=arc)
    assert result['status'] == ('Passed' if measurement_case == 'normal' else 'Unknown'), result
    assert calls == ['apply']
    metrics = result['after_metrics']['archive']
    if measurement_case == 'normal':
        assert metrics['status'] == 'Passed'
        assert metrics['archive_increase_bytes'] == len(b'approved retained archival payload')
        before = dc.load_artifact(metrics['before_artifact'])
        observed = dc.load_artifact(metrics['after_artifact'])
        assert before['cohort_sha256'] == observed['cohort_sha256']
        assert before['domains']['archive_payload']['bytes'] == 0
        assert observed['domains']['archive_payload']['bytes'] == len(b'approved retained archival payload')
    else:
        assert metrics['status'] == 'Unknown'
        assert metrics.get('archive_increase_bytes') is None
        if measurement_case == 'missing-before-resume':
            assert metrics['reason_code'] == 'AFTER_BASELINE_MISSING'
            assert metrics['before_artifact'] is None
        else:
            assert dc.load_artifact(metrics['after_artifact'])['reason_code'] == 'BUDGET_EXHAUSTED'
    assert 'do not add' in metrics['records_overlap']
    dc.validate_seal(dc.load_artifact(result['after_metrics']['artifact']))
    assert result['after_action']['write_performed'] is True
    assert (arc / 'closed/history/retained.txt').read_text() == 'approved retained archival payload'
    assert (source / 'ARCHIVED.md').is_file()


def test_after_search_without_own_write_approval_previews_without_arc_probe(case, tmp_path, monkeypatch):
    from fifan_maintenance import search_view
    profile, _, _, _ = case
    (profile.root / 'retained-history').mkdir()
    path = tmp_path / 'readonly-search.json'
    dc.write_artifact(path, {'schema_version': 1, 'project_root': str(profile.root),
        'search': {'exclude': ['retained-history']},
        'archive': {'archive_root': '/UNGRANTED/ARC', 'records_dir': '/UNGRANTED/REC'}})
    original = dc.canonical_destination
    def no_arc(value, *args, **kwargs):
        if str(value).startswith('/UNGRANTED'):
            pytest.fail('readonly search probed a profile-declared ARC/REC')
        return original(value, *args, **kwargs)
    monkeypatch.setattr(dc, 'canonical_destination', no_arc)
    monkeypatch.setattr(search_view, '_records', lambda *a: pytest.fail('readonly preview entered write-root validation'))
    after = {'kind': 'directory-search', 'profile': str(path)}
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    result = mw.workflow(profile, mode='quarantine', request=request, plan=plan, approve_plan=plan['fingerprint'],
                         Q=quarantine, records_dir=records, after=after)
    assert result['cleanup_state'] == 'Quarantined'
    assert result['after_action']['status'] == 'Preview'
    assert result['after_metrics']['search']['status'] == 'Not run'
    assert result['after_action']['write_performed'] is False
    assert not (profile.root / '.ignore').exists()
    files = {p.relative_to(records): p.read_bytes() for p in records.rglob('*') if p.is_file()}
    resumed = mw.workflow(profile, mode='quarantine', request=request, approve_plan=plan['fingerprint'],
                          Q=quarantine, records_dir=records, after=after, resume=result['workflow_path'])
    assert resumed['status'] == 'Unknown' and resumed['live_verification'] == 'Passed'
    assert {p.relative_to(records): p.read_bytes() for p in records.rglob('*') if p.is_file()} == files


def test_real_exit_after_persisted_purge_direction_resumes_with_runtime_approval(case, tmp_path):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    profile_path, request_path, plan_path = [tmp_path / name for name in ('direction-profile.json', 'direction-request.json', 'direction-plan.json')]
    for path, value in ((profile_path, profile.data), (request_path, request), (plan_path, plan)):
        dc.write_artifact(path, value)
    code = r'''
import os, sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from fifan_maintenance import cleanup_policy as p
from fifan_maintenance import cleanup_operations as ops
from fifan_maintenance import directory_common as dc
from fifan_maintenance import maintenance_workflow as mw
from fifan_maintenance.project import load_config
profile=p.load_profile(sys.argv[2],load_config(Path(sys.argv[2])),sys.argv[3])
request=dc.load_artifact(sys.argv[4]);plan=dc.load_artifact(sys.argv[5])
original=ops._save
def committed(profile,record,*,initial=False):
    result=original(profile,record,initial=initial)
    if record['direction']=='purge' and record['state']=='Quarantined' and record['purge_plan'] is not None:
        os._exit(84)
    return result
ops._save=committed
mw.workflow(profile,mode='purge',request=request,plan=plan,approve_plan=plan['fingerprint'],Q=sys.argv[6],records_dir=sys.argv[7])
'''
    child = subprocess.run([sys.executable, '-B', '-c', code, str(Path(mw.__file__).parents[1]), str(profile.root),
                            str(profile_path), str(request_path), str(plan_path), str(quarantine), str(records)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    assert child.returncode == 84, child.stderr.decode(errors='replace')
    receipts = list(records.glob('maintenance-*/workflow.json'))
    assert len(receipts) == 1
    before = dc.load_artifact(receipts[0])
    journal_path = Path(before['cleanup']['journal_path'])
    journal = dc.load_artifact(journal_path)
    assert journal['state'] == 'Quarantined' and journal['direction'] == 'purge'
    assert journal['purge_plan'] is not None and journal['intent'] is None
    assert ops.verify(profile, journal, quarantine, records)['status'] == 'Unknown'
    assert {m['stage'] for m in before['measurements']} == {'T0', 'T1'}
    assert 'baseline_path' not in before  # No dependent work preceded deletion.
    payload = quarantine / journal['quarantine_plan']['items'][0]['quarantine_relative']
    payload_before, journal_before = payload.read_bytes(), journal_path.read_bytes()
    with pytest.raises(ValueError) as error:
        mw.workflow(profile, mode='purge', request=request, Q=quarantine, records_dir=records, resume=receipts[0])
    assert error.value.reason_code == 'APPROVAL_REQUIRED'
    wrong = mw.workflow(profile, mode='purge', request=request, approve_plan='0' * 64,
                        Q=quarantine, records_dir=records, resume=receipts[0])
    assert wrong['status'] == 'Blocked' and wrong['reason_code'] == 'APPROVAL_REQUIRED'
    assert payload.read_bytes() == payload_before and journal_path.read_bytes() == journal_before
    result = mw.workflow(profile, mode='purge', request=request, approve_plan=plan['fingerprint'],
                         Q=quarantine, records_dir=records, resume=receipts[0])
    assert result['status'] == 'Passed', result
    assert result['cleanup_state'] == 'Purged' and result['cleanup_status'] == 'Passed'
    assert not payload.exists() and not (profile.root / 'old.log').exists()
    assert len(list(records.glob('cleanup-*'))) == 1
    after = read_receipt(result)
    assert after['cleanup']['operation_id'] == plan['operation_id'] == before['cleanup']['operation_id']
    assert after['cleanup']['purge_plan_path'] == before['cleanup']['purge_plan_path']
    assert {m['stage'] for m in after['measurements']} == {'T0', 'T1', 'T2'}
    assert 'reason_code' not in result


@pytest.mark.parametrize('followup', ['resume', 'drift', 'mismatched-journal', 'unauthorized-destination'])
def test_real_exit_after_file_move_preserves_authorization_and_resumes(case, tmp_path, followup, monkeypatch):
    from fifan_maintenance import changes
    profile, request, q, rec = case
    (profile.root / 'notes').mkdir()
    source, destination = profile.root / 'notes/move.md', profile.root / 'notes/moved.md'
    source.write_bytes(b'preserved move payload')
    file_plan = changes.preview(profile.root, {'operations': [
        {'type': 'move', 'path': 'notes/move.md', 'destination': 'notes/moved.md'}]}, profile.config)
    task = tmp_path / 'task.json'
    dc.write_artifact(task, {'schema_version': 1, 'sources': ['notes/move.md', 'notes/moved.md']})
    dc.write_artifact(tmp_path / 'file-plan.json', file_plan)
    after = {'kind': 'file-plan', 'profile': str(task), 'plan': str(tmp_path / 'file-plan.json'),
             'approve_plan': file_plan['operation_id']}
    plan = ops.preview(profile, request, q, rec)
    for name, value in [('profile', profile.data), ('request', request), ('plan', plan), ('after', after)]:
        dc.write_artifact(tmp_path / (name + '.json'), value)
    code = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from fifan_maintenance import cleanup_policy as policy, maintenance_workflow as mw, directory_common as dc, changes
from fifan_maintenance.project import load_config
base=Path(sys.argv[2]); p=policy.load_profile(base/'project',load_config(base/'project'),base/'profile.json')
original=changes.apply
def committed(*args, **kwargs):
    original(*args, **kwargs)
    os._exit(86)
changes.apply=committed
plan=dc.load_artifact(base/'plan.json')
mw.workflow(p,mode='quarantine',request=dc.load_artifact(base/'request.json'),plan=plan,
 approve_plan=plan['fingerprint'],Q=base/'quarantine',records_dir=base/'records',after=dc.load_artifact(base/'after.json'))
'''
    child = subprocess.run([sys.executable, '-B', '-c', code, str(Path(mw.__file__).parents[1]), str(tmp_path)],
                           capture_output=True, timeout=20)
    assert child.returncode == 86, child.stderr
    receipt = next(rec.glob('maintenance-*/workflow.json'))
    assert not source.exists() and destination.read_bytes() == b'preserved move payload'
    moved_inode = destination.stat().st_ino
    if followup == 'drift':
        destination.write_bytes(b'user later changed destination')
    elif followup == 'mismatched-journal':
        journal_path = rec / (file_plan['operation_id'] + '.json')
        journal = dc.load_artifact(journal_path)
        journal['plan']['operations'][0]['destination'] = 'notes/other.md'
        # A same-shaped journal from another plan must not be accepted even if sealed.
        journal['plan']['operation_id'] = changes._digest({k: v for k, v in journal['plan'].items() if k != 'operation_id'})
        changes._save(journal_path, journal)
    elif followup == 'unauthorized-destination':
        # Keep the receipt and task profile identical; change the physical path
        # into a forbidden alias after commit, before any backend body read.
        destination.unlink()
        destination.symlink_to(profile.root / 'current/entry.md')
    def forbidden(*args, **kwargs):
        pytest.fail('a committed move must never be applied again')
    monkeypatch.setattr(changes, 'apply', forbidden)
    if followup == 'unauthorized-destination':
        with pytest.raises(ValueError, match='symlink'):
            mw.workflow(profile, mode='quarantine', request=request, approve_plan=plan['fingerprint'],
                        Q=q, records_dir=rec, resume=receipt, after=after)
        return
    result = mw.workflow(profile, mode='quarantine', request=request, approve_plan=plan['fingerprint'],
                         Q=q, records_dir=rec, resume=receipt, after=after)
    if followup != 'resume':
        assert result['status'] in ('Blocked', 'Failed'), result
        assert result['state'] != 'Completed'
        return
    assert result['status'] == 'Passed', result
    again = mw.workflow(profile, mode='quarantine', approve_plan=plan['fingerprint'],
                        Q=q, records_dir=rec, resume=receipt, after=after)
    assert again['status'] == 'Passed', again
    assert destination.stat().st_ino == moved_inode
    assert destination.read_bytes() == b'preserved move payload' and not source.exists()
