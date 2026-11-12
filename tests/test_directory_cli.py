from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from fifan_maintenance.cli import main
from fifan_maintenance.directory_common import load_artifact


@pytest.fixture
def case(tmp_path):
    root, archive, records = [tmp_path / name for name in ('project', 'archive', 'records')]
    for directory in (root, archive, records):
        directory.mkdir()
    (root / 'src').mkdir()
    (root / 'src/main.py').write_text('value = 1\n')
    (root / 'README.md').write_text('# Current\n')
    (root / 'history/a').mkdir(parents=True)
    (root / 'history/a/old.txt').write_bytes(b'original history\r\n')
    (root / 'closed.md').write_text('Historical closure evidence.\n')
    data = {'schema_version': 1, 'project_root': str(root), 'scan_roots': ['.'],
        'critical_paths': ['README.md', 'src'],
        'reference_sources': [{'path': 'closed.md', 'role': 'historical'},
                              {'path': 'README.md', 'role': 'current'},
                              {'path': 'src', 'role': 'current'}],
        'classifications': [{'path': 'history/a', 'role': 'historical', 'reason': 'closed fixture'}],
        'search': {'exclude': ['history'], 'vscode': True},
        'archive': {'archive_root': str(archive), 'records_dir': str(records),
                    'candidates': ['history/a'], 'require_no_open_handles': False}}
    profile = tmp_path / 'profile.json'
    profile.write_text(json.dumps(data))
    return root, archive, records, profile


def call(case, capsys, action, *args):
    root, archive, records, profile = case
    code = main(['directory', action, '--project', str(root), '--profile', str(profile), *map(str, args)])
    captured = capsys.readouterr()
    body = json.loads(captured.err if code == 2 and captured.err else captured.out)
    return code, body


@pytest.mark.parametrize('output_kind', ['plan', 'output'])
def test_preview_outputs_cannot_write_project(case, capsys, monkeypatch, output_kind):
    root, _, records, _ = case
    from fifan_maintenance import search_view
    def forbidden(*args, **kwargs):
        raise AssertionError('preview read before output preflight')
    monkeypatch.setattr(search_view, 'search_preview', forbidden)
    arguments = ['--plan', records / 'plan.json']
    if output_kind == 'plan':
        arguments = ['--plan', root / 'private-plan.json']
    else:
        arguments.extend(['--output', root / 'public-report.json'])
    code, body = call(case, capsys, 'search-preview', *arguments)
    assert code == 2 and body['reason_code'] == 'OUTPUT_INSIDE_PROJECT'
    assert body['project_writes'] == 0
    assert not (root / 'private-plan.json').exists()
    assert not (records / 'plan.json').exists()


def test_real_cli_search_preserves_private_backup_and_restores(case, capsys):
    root, _, records, _ = case
    (root / '.vscode').mkdir()
    original = b'{\r\n // preserve comment\r\n "privateValue": "api_token=cli-private-dont-print",\r\n}\r\n'
    (root / '.vscode/settings.json').write_bytes(original)
    code, body = call(case, capsys, 'search-preview', '--plan', records / 'plan.json')
    assert code == 0 and body['status'] == 'Preview'
    assert 'cli-private-dont-print' not in json.dumps(body)
    plan = load_artifact(records / 'plan.json')
    assert plan['kind'] == 'search-config'
    code, body = call(case, capsys, 'apply', '--plan', records / 'plan.json', '--records-dir', records)
    assert code == 0 and body['state'] == 'Applied'
    journal = Path(body['journal_path'])
    assert 'cli-private-dont-print' not in json.dumps(body)
    code, checked = call(case, capsys, 'verify', '--journal', journal)
    assert code == 0 and checked['status'] == 'Passed'
    code, _ = call(case, capsys, 'restore-preview', '--journal', journal, '--plan', records / 'restore.json')
    assert code == 0
    code, result = call(case, capsys, 'restore', '--plan', records / 'restore.json', '--records-dir', records)
    assert code == 0 and result['state'] == 'Restored'
    assert (root / '.vscode/settings.json').read_bytes() == original
    assert not (root / '.ignore').exists()


def test_workflow_default_inspect_does_not_modify_project(case, capsys):
    root, _, records, _ = case
    before = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob('*') if p.is_file()}
    code, result = call(case, capsys, 'workflow', '--records-dir', records)
    assert code == 0 and result['state'] == 'Inspected'
    assert load_artifact(result['workflow_path'])['phase'] == 'inspect'
    after = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in root.rglob('*') if p.is_file()}
    assert before == after


def test_official_thin_wrapper_defaults_to_inspect(case):
    root, _, records, profile = case
    tool = Path(__file__).resolve().parents[1] / 'tools/run_directory_maintenance.py'
    import sys
    process = subprocess.run([sys.executable, '-B', str(tool), '--project', str(root),
        '--profile', str(profile), '--records-dir', str(records)], capture_output=True, text=True)
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)['state'] == 'Inspected'
    assert not (root / '.ignore').exists()


def test_archive_workflow_pilots_rearchives_resumes_and_restores(case, capsys):
    root, archive, records, _ = case
    payload = (root / 'history/a/old.txt').read_bytes()
    request = records / 'request.json'
    request.write_text(json.dumps({'schema_version': 1, 'batches': [{
        'source': 'history/a', 'destination': 'project-history/a',
        'closure': {'decision': 'closed', 'reason': 'synthetic batch complete',
                    'evidence': [{'path': 'closed.md', 'sha256': hashlib.sha256((root / 'closed.md').read_bytes()).hexdigest()}]}}]}))
    code, result = call(case, capsys, 'workflow', '--phase', 'archive', '--request', request,
        '--archive-root', archive, '--records-dir', records)
    assert code == 0 and result['status'] == 'Passed', result
    workflow = result['workflow_path']
    receipt = load_artifact(workflow)
    assert receipt['batches'][0]['pilot_done'] is True
    assert (archive / 'project-history/a/old.txt').read_bytes() == payload
    assert (root / 'history/a/ARCHIVED.md').is_file()
    assert result['metrics']['combined_delta_bytes'] > 0
    assert result['metrics']['storage_release'] == 'Unknown'
    code, again = call(case, capsys, 'workflow', '--phase', 'archive', '--resume', workflow,
        '--archive-root', archive, '--records-dir', records)
    assert code == 0 and again['state'] == 'Completed', again
    code, restored = call(case, capsys, 'workflow', '--phase', 'restore', '--resume', workflow,
        '--archive-root', archive, '--records-dir', records)
    assert code == 0 and restored['state'] == 'Restored', restored
    assert (root / 'history/a/old.txt').read_bytes() == payload
    assert not (root / 'history/a/ARCHIVED.md').exists()
    assert not (archive / 'project-history/a').exists()


def _workflow_archive_request(case, *, second=False):
    root, archive, records, profile_path = case
    data = json.loads(profile_path.read_text())
    sources = ['history/a']
    if second:
        (root / 'history/b/empty').mkdir(parents=True)
        (root / 'history/b/second.bin').write_bytes(b'\x00\xff second batch')
        data['archive']['candidates'].append('history/b')
        data['classifications'].append({'path': 'history/b', 'role': 'historical', 'reason': 'second closed fixture'})
        profile_path.write_text(json.dumps(data))
        sources.append('history/b')
    evidence = hashlib.sha256((root / 'closed.md').read_bytes()).hexdigest()
    request = records / 'workflow-request.json'
    request.write_text(json.dumps({'schema_version': 1, 'batches': [
        {'source': source, 'destination': 'project-history/' + source.split('/')[-1],
         'closure': {'decision': 'closed', 'reason': 'fixture approved closed batch',
                     'evidence': [{'path': 'closed.md', 'sha256': evidence}]}}
        for source in sources]}))
    return request


def test_workflow_real_exit_after_pilot_checkpoint_resumes_two_batches(case, capsys):
    import os
    import sys
    root, archive, records, profile = case
    request = _workflow_archive_request(case, second=True)
    script = '''
import os,sys
from fifan_maintenance.directory_common import load_profile,load_artifact
from fifan_maintenance.project import load_config
from fifan_maintenance import directory_workflow as wf
root,profile_path,request_path,archive,records=sys.argv[1:]
from pathlib import Path
root=Path(root)
profile=load_profile(root,load_config(root),profile_path)
original=wf._Run.checkpoint
def killed(self):
    original(self)
    if self.value.get('batches') and self.value['batches'][0].get('pilot_done') and self.value['batches'][0].get('stage')=='New':
        os._exit(75)
wf._Run.checkpoint=killed
wf.workflow(profile,phase='archive',request=load_artifact(request_path),archive_root=archive,records_dir=records)
'''
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
    result = subprocess.run([sys.executable, '-B', '-c', script, str(root), str(profile), str(request), str(archive), str(records)],
                            env=env, capture_output=True, timeout=45)
    assert result.returncode == 75, result.stderr.decode()
    workflow_path = next(records.glob('workflow-*/workflow.json'))
    interrupted = load_artifact(workflow_path)
    assert interrupted['batches'][0]['pilot_done'] is True
    assert (root / 'history/a/old.txt').read_bytes() == b'original history\r\n'
    assert (root / 'history/b/second.bin').read_bytes() == b'\x00\xff second batch'
    code, resumed = call(case, capsys, 'workflow', '--phase', 'archive', '--resume', workflow_path,
                         '--archive-root', archive, '--records-dir', records)
    assert code == 0 and resumed['state'] == 'Completed', resumed
    receipt = load_artifact(workflow_path)
    assert [batch['stage'] for batch in receipt['batches']] == ['Archived', 'Archived']
    assert (archive / 'project-history/a/old.txt').read_bytes() == b'original history\r\n'
    assert (archive / 'project-history/b/second.bin').read_bytes() == b'\x00\xff second batch'


def test_workflow_pending_plan_retry_preserves_operation_and_clears_old_error(case, capsys, monkeypatch):
    root, archive, records, _ = case
    from fifan_maintenance import directory_archive as engine
    request = _workflow_archive_request(case)
    original = engine.archive_preview
    def source_configuration_changes(*args, **kwargs):
        plan = original(*args, **kwargs)
        (root / '.fifan-maintenance.json').write_text(json.dumps({'max_files': 123}))
        return plan
    monkeypatch.setattr(engine, 'archive_preview', source_configuration_changes)
    code, blocked = call(case, capsys, 'workflow', '--phase', 'archive', '--request', request,
                         '--archive-root', archive, '--records-dir', records)
    assert code == 2 and blocked['reason_code'] == 'SOURCE_CHANGED'
    workflow_path = Path(blocked['workflow_path'])
    receipt = load_artifact(workflow_path)
    pending = receipt['batches'][0]
    pending_journal = Path(pending['journal_path'])
    pending_plan = load_artifact(pending['plan_path'])
    assert not pending_journal.exists()
    assert (root / 'history/a/old.txt').exists()
    assert not list(archive.iterdir())
    (root / '.fifan-maintenance.json').unlink()
    monkeypatch.setattr(engine, 'archive_preview', original)
    code, completed = call(case, capsys, 'workflow', '--phase', 'archive', '--resume', workflow_path,
                           '--archive-root', archive, '--records-dir', records)
    assert code == 0 and completed['status'] == 'Passed', completed
    assert completed['last_action'] == 'archive'
    assert completed['completion'] == 'all_archived'
    assert 'reason_code' not in completed and 'next_action' not in completed
    receipt = load_artifact(workflow_path)
    assert receipt['batches'][0]['pilot_journal_path'] == str(pending_journal)
    assert load_artifact(pending_journal)['state'] == 'Restored'
    assert load_artifact(pending_journal)['plan']['fingerprint'] == pending_plan['fingerprint']
    assert any(step.get('reason_code') == 'SOURCE_CHANGED' for step in receipt['steps'])
    assert 'reason_code' not in receipt and 'next_action' not in receipt


def test_workflow_two_batch_restore_remeasures_current_payload_not_archive_metrics(case, capsys):
    root, archive, records, _ = case
    request = _workflow_archive_request(case, second=True)
    before = {str(path.relative_to(root)): (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_mode & 0o7777)
              for base in ['history/a', 'history/b'] for path in (root / base).rglob('*') if path.is_file()}
    code, archived = call(case, capsys, 'workflow', '--phase', 'archive', '--request', request,
                          '--archive-root', archive, '--records-dir', records)
    assert code == 0 and archived['state'] == 'Completed', archived
    workflow_path = Path(archived['workflow_path'])
    prior = load_artifact(workflow_path)
    assert len(prior['batches']) == 2 and all(batch['stage'] == 'Archived' for batch in prior['batches'])
    assert prior['batches'][0]['pilot_done'] is True
    assert prior['batches'][0]['pilot_journal_path'] != prior['batches'][0]['journal_path']
    assert load_artifact(prior['batches'][0]['pilot_journal_path'])['state'] == 'Restored'
    archived_delta = prior['metrics']['archive_increase_bytes']
    assert archived_delta == sum(len(item[0]) for item in before.values())
    code, restored = call(case, capsys, 'workflow', '--phase', 'restore', '--resume', workflow_path,
                          '--archive-root', archive, '--records-dir', records)
    assert code == 0 and restored['state'] == 'Restored', restored
    assert restored['phase'] == 'archive'  # origin phase remains provenance.
    assert restored['last_action'] == 'restore'
    assert restored['completion'] == 'all_recovered'
    assert restored['metrics']['project_reduction_bytes'] == 0
    assert restored['metrics']['archive_increase_bytes'] == 0
    assert restored['metrics']['storage_release'] == 'Unknown'
    final = load_artifact(workflow_path)
    saved_archive_metrics = load_artifact(final['archive_metrics_artifact'])
    assert saved_archive_metrics['archive_increase_bytes'] == archived_delta
    assert final['metrics']['archive_increase_bytes'] == 0
    assert all(batch['stage'] == 'Restored' for batch in final['batches'])
    for rel, expected in before.items():
        target = root / rel
        assert (target.read_bytes(), target.stat().st_ino, target.stat().st_mtime_ns, target.stat().st_mode & 0o7777) == expected
    assert not (archive / 'project-history/a').exists()
    assert not (archive / 'project-history/b').exists()
    code, again = call(case, capsys, 'workflow', '--phase', 'restore', '--resume', workflow_path,
                       '--archive-root', archive, '--records-dir', records)
    assert code == 0 and again['state'] == 'Restored', again
    assert again['metrics']['archive_increase_bytes'] == 0
    assert load_artifact(workflow_path)['archive_metrics_artifact'] == final['archive_metrics_artifact']


def test_search_workflow_pending_plan_resume_and_restore(case, capsys, monkeypatch):
    from fifan_maintenance import search_view
    from fifan_maintenance.directory_common import DirectoryError
    root, _, records, _ = case
    original = search_view.apply
    def stopped_before_journal(*args, **kwargs):
        raise DirectoryError('SYNTHETIC_PREWRITE_FAILURE')
    monkeypatch.setattr(search_view, 'apply', stopped_before_journal)
    code, blocked = call(case, capsys, 'workflow', '--phase', 'search', '--records-dir', records)
    assert code == 2 and blocked['reason_code'] == 'SYNTHETIC_PREWRITE_FAILURE'
    workflow_path = Path(blocked['workflow_path'])
    pending = load_artifact(workflow_path)
    planned_journal = pending['search_journal']
    planned_operation = load_artifact(pending['search_plan'])['operation_id']
    assert not Path(planned_journal).exists()
    assert not (root / '.ignore').exists()
    monkeypatch.setattr(search_view, 'apply', original)
    code, resumed = call(case, capsys, 'workflow', '--phase', 'search', '--resume', workflow_path, '--records-dir', records)
    assert code == 0 and resumed['completion'] == 'search_applied', resumed
    receipt = load_artifact(workflow_path)
    assert receipt['search_journal'] == planned_journal
    assert load_artifact(planned_journal)['operation_id'] == planned_operation
    assert 'reason_code' not in resumed and 'next_action' not in resumed
    code, restored = call(case, capsys, 'workflow', '--phase', 'restore', '--resume', workflow_path, '--records-dir', records)
    assert code == 0 and restored['state'] == 'Restored', restored
    assert restored['last_action'] == 'restore'
    assert not (root / '.ignore').exists()
    assert not (root / '.vscode/settings.json').exists()


def test_workflow_resume_rejects_ungranted_record_namespace_before_loading(case, monkeypatch):
    from fifan_maintenance import directory_workflow as wf
    from fifan_maintenance.directory_common import DirectoryError, load_profile
    from fifan_maintenance.project import load_config
    root, _, records, profile_path = case
    profile = load_profile(root, load_config(root), profile_path)
    inspected = []
    def forbidden(path, *args, **kwargs):
        inspected.append(str(path))
        pytest.fail('ungranted artifact opened')
    monkeypatch.setattr(wf, 'load_artifact', forbidden)
    for location in (root / 'workflow.json', records / '..' / 'project' / 'workflow.json'):
        with pytest.raises(DirectoryError):
            wf.workflow(profile, phase='search', records_dir=records, resume=location)
    assert inspected == []
    assert not list(records.iterdir())
    assert not (root / '.ignore').exists()


def test_workflow_records_project_alias_is_rejected_before_receipt_creation(case):
    from fifan_maintenance import directory_workflow as wf
    from fifan_maintenance.directory_common import DirectoryError, load_profile
    from fifan_maintenance.project import load_config
    root, _, records, profile_path = case
    alias = root.with_name(root.name.upper())
    if not alias.exists() or alias.stat().st_ino != root.stat().st_ino:
        pytest.skip('host filesystem has no matching case alias')
    profile = load_profile(root, load_config(root), profile_path)
    with pytest.raises(DirectoryError):
        wf.workflow(profile, phase='inspect', records_dir=alias)
    assert not list(records.iterdir())
    assert not list(root.glob('workflow-*'))


def test_workflow_resume_records_prefix_alias_is_conservatively_blocked(case, capsys):
    from fifan_maintenance import directory_workflow as wf
    from fifan_maintenance.directory_common import DirectoryError, load_profile
    from fifan_maintenance.project import load_config
    root, _, records, profile_path = case
    code, created = call(case, capsys, 'workflow', '--phase', 'search', '--records-dir', records)
    assert code == 0
    workflow_path = Path(created['workflow_path'])
    before = workflow_path.read_bytes()
    aliased_records = records.with_name(records.name.upper())
    if not aliased_records.exists() or aliased_records.stat().st_ino != records.stat().st_ino:
        pytest.skip('host filesystem has no matching case alias')
    aliased_resume = aliased_records / workflow_path.relative_to(records)
    profile = load_profile(root, load_config(root), profile_path)
    with pytest.raises(DirectoryError):
        wf.workflow(profile, phase='search', records_dir=records, resume=aliased_resume)
    assert workflow_path.read_bytes() == before
    # Explicit runtime records aliases are canonicalized safely when the
    # workflow itself is addressed by its returned canonical path.
    completed = wf.workflow(profile, phase='search', records_dir=aliased_records, resume=workflow_path)
    assert completed['state'] == 'Completed' and completed['last_action'] == 'search'


@pytest.mark.parametrize('destination', ['journal', 'payload', 'workflow', 'journal-case'])
def test_directory_output_cannot_overwrite_private_runtime(case, capsys, destination):
    root, archive, records, _ = case
    request_path = _workflow_archive_request(case)
    request = json.loads(request_path.read_text())
    plan_path = records / 'plan.json'
    code, _ = call(case, capsys, 'archive-preview', '--request', request_path,
                   '--plan', plan_path, '--archive-root', archive, '--records-dir', records)
    assert code == 0
    plan = load_artifact(plan_path)
    targets = {'journal': records / (plan['operation_id'] + '.directory.json'),
               'journal-case': records / (plan['operation_id'] + '.DIRECTORY.JSON'),
               'payload': archive / request['batches'][0]['destination'] / 'old.txt',
               'workflow': records / 'workflow-future/workflow.json'}
    before = {str(p.relative_to(records)): p.read_bytes() for p in records.rglob('*') if p.is_file()}
    code, result = call(case, capsys, 'apply', '--plan', plan_path,
                        '--archive-root', archive, '--records-dir', records, '--output', targets[destination])
    assert code == 2 and result['reason_code'] == 'OUTPUT_INPUT_CONFLICT'
    assert (root / 'history/a/old.txt').read_bytes() == b'original history\r\n'
    assert not any(archive.iterdir())
    assert before == {str(p.relative_to(records)): p.read_bytes() for p in records.rglob('*') if p.is_file()}


def test_directory_public_report_can_still_use_records_root(case, capsys):
    _, _, records, _ = case
    output = records / 'workflow-public-report.json'
    code, result = call(case, capsys, 'census', '--output', output)
    assert code == 0
    assert output.is_file()
    assert json.loads(output.read_text())['file_count'] > 0
