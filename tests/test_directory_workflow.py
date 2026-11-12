"""Directory workflow regressions use real engines and persisted receipts."""
import copy
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from fifan_maintenance import directory_archive as archive_engine
from fifan_maintenance import directory_census as census
from fifan_maintenance import directory_common as dc
from fifan_maintenance import directory_workflow as workflow
from fifan_maintenance.project import load_config


@pytest.fixture
def case(tmp_path):
    root, archive, records = [tmp_path / name for name in ('project', 'archive', 'records')]
    for path in (root, archive, records):
        path.mkdir()
    (root / 'history').mkdir()
    (root / 'history/old.bin').write_bytes(b'original\x00\xff\r\n')
    (root / 'README.md').write_text('# Current\n')
    (root / 'closure.md').write_text('Closed synthetic evidence\n')
    data = {'schema_version': 1, 'project_root': str(root), 'scan_roots': ['.'],
            'critical_paths': ['README.md'],
            'reference_sources': [{'path': 'closure.md', 'role': 'historical'},
                                  {'path': 'README.md', 'role': 'current'}],
            'classifications': [{'path': 'history', 'role': 'historical', 'reason': 'closed fixture'}],
            'search': {'exclude': ['history'], 'vscode': True},
            'archive': {'archive_root': str(archive), 'records_dir': str(records),
                        'candidates': ['history'], 'require_no_open_handles': False}}
    profile = dc.load_profile(root, load_config(root), data)
    request = {'schema_version': 1, 'batches': [{'source': 'history', 'destination': 'batch',
        'closure': {'decision': 'closed', 'reason': 'synthetic closed batch', 'evidence': [
            {'path': 'closure.md', 'sha256': hashlib.sha256((root / 'closure.md').read_bytes()).hexdigest()}]}}]}
    return profile, request, archive, records


@pytest.mark.parametrize('dynamic', [False, True])
def test_dynamic_resolution_workflow_pilot_restore_and_rearchive(case, dynamic):
    profile, request, archive, records = case
    request['batches'][0]['dynamic_reference_resolutions'] = []
    if dynamic:
        (profile.root / 'consumer.py').write_text('value = f"diagnostic {name}"\n')
        data = copy.deepcopy(profile.data)
        data['reference_sources'].append({'path': 'consumer.py', 'role': 'current'})
        profile = dc.load_profile(profile.root, profile.config, data)
        unknown = next(x for x in census.impact(profile, request)['batches'][0]['unknowns']
                       if x['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN')
        resolution = {k: v for k, v in unknown.items() if k != 'reason_code'}
        resolution.update(source='history', reason='Reviewed display-only diagnostic expression',
                          evidence=copy.deepcopy(request['batches'][0]['closure']['evidence']))
        request['batches'][0]['dynamic_reference_resolutions'] = [resolution]
    result = workflow.workflow(profile, phase='archive', request=request, archive_root=archive, records_dir=records)
    assert result['status'] == 'Passed', result
    receipt = dc.load_artifact(result['workflow_path'])
    item = receipt['batches'][0]
    assert item['pilot_done'] and item['pilot_journal_path'] != item['journal_path']
    assert dc.load_artifact(item['pilot_journal_path'])['state'] == 'Restored'
    assert (archive / 'batch/old.bin').read_bytes() == b'original\x00\xff\r\n'
    restored = workflow.workflow(profile, phase='restore', resume=result['workflow_path'], archive_root=archive, records_dir=records)
    assert restored['status'] == 'Passed' and restored['state'] == 'Restored'
    assert (profile.root / 'history/old.bin').read_bytes() == b'original\x00\xff\r\n'
    assert not (archive / 'batch').exists()
    rearchived = workflow.workflow(profile, phase='archive', request=request, archive_root=archive, records_dir=records)
    assert rearchived['status'] == 'Passed', rearchived
    assert rearchived['workflow_path'] != result['workflow_path']
    if dynamic:
        request['batches'][0]['dynamic_reference_resolutions'][0]['sha256'] = '0' * 64
        # Return to the original location before testing rejected authorization.
        assert workflow.workflow(profile, phase='restore', resume=rearchived['workflow_path'],
                                 archive_root=archive, records_dir=records)['status'] == 'Passed'
        rejected = workflow.workflow(profile, phase='archive', request=request, archive_root=archive, records_dir=records)
        assert rejected['status'] == 'Blocked'
        assert (profile.root / 'history/old.bin').read_bytes() == b'original\x00\xff\r\n'
        assert not (archive / 'batch').exists()


@pytest.mark.parametrize('window', ['before', 'after'])
@pytest.mark.parametrize('user_edit', [False, True])
def test_search_restore_real_exit_resumes_same_receipt(case, tmp_path, window, user_edit):
    profile, _, _, records = case
    (profile.root / '.vscode').mkdir()
    original_settings = b'{\n "editor.tabSize": 2\n}\n'
    (profile.root / '.vscode/settings.json').write_bytes(original_settings)
    (profile.root / '.ignore').write_bytes(b'# user rules\n')
    initial = workflow.workflow(profile, phase='search', records_dir=records)
    assert initial['status'] == 'Passed', initial
    profile_path = tmp_path / 'profile.json'
    dc.write_artifact(profile_path, profile.data)
    code = r'''
import os, sys
from pathlib import Path
from fifan_maintenance import directory_common as dc, directory_workflow as wf, search_view as s
from fifan_maintenance.project import load_config
profile = dc.load_profile(sys.argv[1], load_config(Path(sys.argv[1])), sys.argv[2])
publish = s._publish
def interrupted(profile, journal, index, direction):
    if direction == 'restore' and sys.argv[5] == 'before':
        os._exit(84)
    result = publish(profile, journal, index, direction)
    if direction == 'restore':
        os._exit(84)
    return result
s._publish = interrupted
wf.workflow(profile, phase='restore', records_dir=sys.argv[3], resume=sys.argv[4])
'''
    child = subprocess.run([sys.executable, '-B', '-c', code, str(profile.root), str(profile_path),
                            str(records), initial['workflow_path'], window], capture_output=True, timeout=20)
    assert child.returncode == 84, child.stderr.decode(errors='replace')
    receipt = dc.load_artifact(initial['workflow_path'])
    journal_path = Path(receipt['search_journal'])
    interrupted = dc.load_artifact(journal_path)
    assert interrupted['state'] == 'Restoring'
    target = profile.root / interrupted['plan']['files'][-1]['path']
    if user_edit:
        target.write_bytes(b'user changes after crash\n')
    result = workflow.workflow(profile, phase='restore', records_dir=records, resume=initial['workflow_path'])
    if user_edit:
        assert result['status'] == 'Blocked'
        assert target.read_bytes() == b'user changes after crash\n'
        assert dc.load_artifact(journal_path)['state'] == 'Restoring'
    else:
        assert result['status'] == 'Passed' and result['state'] == 'Restored', result
        restored_journal = journal_path.read_bytes()
        for _ in range(2):
            again = workflow.workflow(profile, phase='restore', records_dir=records, resume=initial['workflow_path'])
            assert again['status'] == 'Passed' and again['state'] == 'Restored'
            assert journal_path.read_bytes() == restored_journal
        assert dc.load_artifact(journal_path)['operation_id'] == interrupted['operation_id']
        assert (profile.root / '.vscode/settings.json').read_bytes() == original_settings
        assert (profile.root / '.ignore').read_bytes() == b'# user rules\n'
    assert (profile.root / 'history/old.bin').read_bytes() == b'original\x00\xff\r\n'


@pytest.mark.parametrize('batch_count', [1, 2])
def test_archive_verification_count_retains_pilot_and_final_cross_batch_checks(case, monkeypatch, batch_count):
    profile, request, archive, records = case
    if batch_count == 2:
        (profile.root / 'history2').mkdir()
        (profile.root / 'history2/other.bin').write_bytes(b'second payload')
        data = copy.deepcopy(profile.data)
        data['archive']['candidates'].append('history2')
        data['classifications'].append({'path': 'history2', 'role': 'historical', 'reason': 'closed fixture'})
        profile = dc.load_profile(profile.root, profile.config, data)
        batch = copy.deepcopy(request['batches'][0])
        batch.update(source='history2', destination='batch2')
        request['batches'].append(batch)
    calls = []
    original = archive_engine.verify
    def counted(profile, journal, archive):
        result = original(profile, journal, archive)
        calls.append((journal['operation_id'], result['state'], result['status']))
        return result
    monkeypatch.setattr(archive_engine, 'verify', counted)
    result = workflow.workflow(profile, phase='archive', request=request, archive_root=archive, records_dir=records)
    assert result['status'] == 'Passed', result
    receipt = dc.load_artifact(result['workflow_path'])
    batch = receipt['batches'][0]
    pilot = dc.load_artifact(batch['pilot_journal_path'])['operation_id']
    final = dc.load_artifact(batch['journal_path'])['operation_id']
    expected = [(pilot, 'Archived', 'Passed'), (pilot, 'Restored', 'Passed'), (final, 'Archived', 'Passed')]
    if batch_count == 2:
        second = dc.load_artifact(receipt['batches'][1]['journal_path'])['operation_id']
        expected += [(second, 'Archived', 'Passed')]
    expected += [(final, 'Archived', 'Passed')]
    if batch_count == 2:
        expected += [(second, 'Archived', 'Passed')]
    assert calls == expected
    assert (archive / 'batch/old.bin').read_bytes() == b'original\x00\xff\r\n'
    assert workflow.workflow(profile, phase='restore', resume=result['workflow_path'],
                             archive_root=archive, records_dir=records)['status'] == 'Passed'


def test_final_archive_check_still_rejects_payload_change_after_immediate_verify(case, monkeypatch):
    profile, request, archive, records = case
    original = workflow._new_archive
    def changed_after_verify(run, batch, item, purpose):
        journal = original(run, batch, item, purpose)
        if purpose == 'FinalApplying':
            (archive / 'batch/old.bin').write_bytes(b'external change after verified apply')
        return journal
    monkeypatch.setattr(workflow, '_new_archive', changed_after_verify)
    result = workflow.workflow(profile, phase='archive', request=request, archive_root=archive, records_dir=records)
    assert result['status'] == 'Blocked' and result['completion'] == 'incomplete'
    assert (archive / 'batch/old.bin').read_bytes() == b'external change after verified apply'
