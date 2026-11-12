from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

import pytest

from fifan_maintenance import directory_archive as da
from fifan_maintenance import directory_common as dc
from fifan_maintenance.project import load_config


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def fixture(tmp_path):
    project, archive, records = [tmp_path / name for name in ('project', 'archive', 'records')]
    for root in (project, archive, records):
        root.mkdir()
    (project / 'evidence/run-1/empty').mkdir(parents=True)
    (project / 'evidence/run-1/中文 file.txt').write_bytes('original\r\n保留\r\n'.encode())
    (project / 'evidence/run-1/raw.bin').write_bytes(b'\x00\xff\x80')
    os.chmod(project / 'evidence/run-1/中文 file.txt', 0o640)
    os.utime(project / 'evidence/run-1/中文 file.txt', ns=(1650000000123456789, 1650000000123456789))
    (project / 'current.md').write_text('Current entry remains here\n')
    evidence = b'Explicit closed fixture decision\n'
    (project / 'closure.md').write_bytes(evidence)
    data = {'schema_version': 1, 'project_root': str(project), 'scan_roots': ['.'],
            'critical_paths': ['current.md'], 'reference_sources': [{'path': 'closure.md', 'role': 'historical'}, {'path': 'current.md', 'role': 'current'}],
            'classifications': [{'path': 'evidence/run-1', 'role': 'historical', 'reason': 'Explicit closed fixture'}],
            'archive': {'archive_root': str(archive), 'records_dir': str(records), 'candidates': ['evidence/run-1'], 'require_no_open_handles': False}}
    profile = dc.load_profile(project, load_config(project), data)
    request = {'schema_version': 1, 'batches': [{'source': 'evidence/run-1', 'destination': 'fixture/run-1',
               'closure': {'decision': 'closed', 'reason': 'Explicit closed fixture', 'evidence': [{'path': 'closure.md', 'sha256': sha(evidence)}]},
               'known_absent': [{'path': 'previously-missing.lock', 'reason': 'Known missing before this operation'}]}]}
    return profile, request, archive, records


def file_snapshot(root):
    result = {}
    for path in root.rglob('*'):
        rel = path.relative_to(root).as_posix()
        info = path.stat()
        result[rel] = {'mode': info.st_mode & 0o7777, 'mtime_ns': info.st_mtime_ns, 'device': info.st_dev, 'inode': info.st_ino,
                       'sha256': sha(path.read_bytes()) if path.is_file() else None}
    return result


def test_archive_restore_manifest_identity_and_rearchive(fixture):
    profile, request, archive, records = fixture
    source = profile.root / 'evidence/run-1'
    before = file_snapshot(source)
    source_info = source.stat()
    plan = da.archive_preview(profile, request, archive, records)
    assert plan['format'] == da.PLAN
    assert not list(records.iterdir())
    record = da.apply(profile, plan, archive, records)
    assert record['state'] == 'Archived'
    assert (archive / 'fixture/run-1').stat().st_ino == source_info.st_ino
    assert file_snapshot(archive / 'fixture/run-1') == before
    assert list(source.iterdir()) == [source / 'ARCHIVED.md']
    assert 'not the original payload' in (source / 'ARCHIVED.md').read_text()
    checked = da.verify(profile, record, archive)
    assert checked['status'] == 'Passed', checked
    located = da.locate(profile, record, 'evidence/run-1/中文 file.txt', archive)
    assert located['resolution'] == 'ArchivedResolved'
    assert located['original_path_status'] == 'Missing'
    assert located['scripts_replayable_at_original'] is False
    assert da.apply(profile, plan, archive, records)['fingerprint'] == record['fingerprint']
    restore_plan = da.restore_preview(profile, record, archive)
    restored = da.restore(profile, restore_plan, archive, records)
    assert restored['state'] == 'Restored'
    assert file_snapshot(source) == before
    assert source.stat().st_ino == source_info.st_ino
    assert not (source / 'ARCHIVED.md').exists()
    assert not (archive / 'fixture/run-1').exists()
    assert da.verify(profile, restored, archive)['status'] == 'Passed'
    assert da.restore(profile, restore_plan, archive, records)['fingerprint'] == restored['fingerprint']
    assert da.recover(profile, restored, archive, records)['state'] == 'Restored'
    assert da.locate(profile, restored, 'evidence/run-1/raw.bin', archive)['resolution'] == 'Restored'
    with pytest.raises(dc.DirectoryError) as failure:
        da.apply(profile, plan, archive, records)
    assert failure.value.reason_code == 'PLAN_ALREADY_RESTORED'
    fresh = da.archive_preview(profile, request, archive, records)
    assert fresh['operation_id'] != plan['operation_id']
    assert da.apply(profile, fresh, archive, records)['state'] == 'Archived'
    assert (records / (record['operation_id'] + '.directory.json')).stat().st_mode & 0o777 == 0o600


def test_target_collision_is_never_overwritten(fixture):
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    target = archive / 'fixture/run-1'
    target.mkdir(parents=True)
    (target / 'other.txt').write_text('other work')
    with pytest.raises(dc.DirectoryError) as failure:
        da.apply(profile, plan, archive, records)
    assert failure.value.reason_code == 'DESTINATION_EXISTS'
    assert (profile.root / 'evidence/run-1/raw.bin').read_bytes() == b'\x00\xff\x80'
    assert (target / 'other.txt').read_text() == 'other work'
    assert not list(records.iterdir())


@pytest.mark.parametrize('phase', ['before_payload', 'after_payload', 'after_locator'])
def test_archive_interrupted_rename_resumes_only_missing_steps(fixture, monkeypatch, phase):
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    calls = []
    def interrupted(source_root, source, target_root, target):
        calls.append((source_root, source, target_root, target))
        if phase == 'before_payload' and len(calls) == 1:
            raise KeyboardInterrupt()
        original(source_root, source, target_root, target)
        if phase == 'after_payload' and len(calls) == 1 or phase == 'after_locator' and len(calls) == 2:
            raise KeyboardInterrupt()
    monkeypatch.setattr(dc, 'rename_noreplace', interrupted)
    with pytest.raises(KeyboardInterrupt):
        da.apply(profile, plan, archive, records)
    journal_path = records / (plan['operation_id'] + '.directory.json')
    partial = dc.load_artifact(journal_path)
    assert partial['state'] == 'Archiving'
    assert da.verify(profile, partial, archive)['status'] == 'Unknown'
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    recovered = da.recover(profile, journal_path, archive, records)
    assert recovered['state'] == 'Archived'
    assert da.verify(profile, recovered, archive)['status'] == 'Passed'
    assert (archive / 'fixture/run-1/raw.bin').read_bytes() == b'\x00\xff\x80'


@pytest.mark.parametrize('phase', ['before_locator', 'after_locator', 'after_payload'])
def test_restore_interrupted_rename_resumes_only_missing_steps(fixture, monkeypatch, phase):
    profile, request, archive, records = fixture
    archived = da.apply(profile, da.archive_preview(profile, request, archive, records), archive, records)
    plan = da.restore_preview(profile, archived, archive)
    original = dc.rename_noreplace
    calls = []
    def interrupted(source_root, source, target_root, target):
        calls.append((source_root, source, target_root, target))
        if phase == 'before_locator' and len(calls) == 1:
            raise KeyboardInterrupt()
        original(source_root, source, target_root, target)
        if phase == 'after_locator' and len(calls) == 1 or phase == 'after_payload' and len(calls) == 2:
            raise KeyboardInterrupt()
    monkeypatch.setattr(dc, 'rename_noreplace', interrupted)
    with pytest.raises(KeyboardInterrupt):
        da.restore(profile, plan, archive, records)
    journal_path = Path(archived['journal_path'])
    partial = dc.load_artifact(journal_path)
    assert partial['state'] == 'Restoring'
    assert da.verify(profile, partial, archive)['status'] == 'Unknown'
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    recovered = da.recover(profile, journal_path, archive, records)
    assert recovered['state'] == 'Restored'
    assert da.verify(profile, recovered, archive)['status'] == 'Passed'
    assert (profile.root / 'evidence/run-1/raw.bin').read_bytes() == b'\x00\xff\x80'


@pytest.mark.parametrize('change', ['archive_edit', 'archive_new_inode', 'locator_edit', 'locator_new_inode', 'source_new_work'])
def test_restore_refuses_later_work_and_changed_ownership(fixture, change):
    profile, request, archive, records = fixture
    record = da.apply(profile, da.archive_preview(profile, request, archive, records), archive, records)
    source = profile.root / 'evidence/run-1'
    if change == 'archive_edit':
        (archive / 'fixture/run-1/raw.bin').write_bytes(b'new work')
    elif change == 'archive_new_inode':
        target = archive / 'fixture/run-1/raw.bin'
        info, data = target.stat(), target.read_bytes()
        other = records / 'replacement.bin'
        other.write_bytes(data)
        os.chmod(other, info.st_mode & 0o7777)
        os.utime(other, ns=(info.st_atime_ns, info.st_mtime_ns))
        os.replace(other, target)
    elif change == 'locator_edit':
        (source / 'ARCHIVED.md').write_text('new user explanation')
    elif change == 'locator_new_inode':
        target = source / 'ARCHIVED.md'
        info, data = target.stat(), target.read_bytes()
        other = records / 'replacement-locator.md'
        other.write_bytes(data)
        os.chmod(other, info.st_mode & 0o7777)
        os.utime(other, ns=(info.st_atime_ns, info.st_mtime_ns))
        os.replace(other, target)
    else:
        (source / 'other.txt').write_text('new user work')
    assert da.verify(profile, record, archive)['status'] == 'Failed'
    with pytest.raises((dc.DirectoryError, OSError)):
        da.restore_preview(profile, record, archive)
    assert (archive / 'fixture/run-1').is_dir()
    assert source.is_dir()
    if change == 'source_new_work':
        assert (source / 'other.txt').read_text() == 'new user work'


def test_archive_source_drift_and_closure_drift_do_not_move(fixture):
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    (profile.root / 'closure.md').write_text('Changed closure evidence')
    with pytest.raises(dc.DirectoryError):
        da.apply(profile, plan, archive, records)
    assert not list(archive.iterdir())
    assert not list(records.iterdir())


@pytest.mark.parametrize('kind', ['hardlink', 'symlink', 'fifo', 'meta'])
def test_unsupported_payload_entries_never_move(fixture, kind):
    profile, request, archive, records = fixture
    source = profile.root / 'evidence/run-1'
    if kind == 'hardlink':
        os.link(source / 'raw.bin', source / 'shared.bin')
    elif kind == 'symlink':
        (source / 'outside').symlink_to(profile.root / 'current.md')
    elif kind == 'fifo':
        os.mkfifo(source / 'pipe')
    else:
        (source / 'thing.meta').write_text('must preserve')
    with pytest.raises((dc.DirectoryError, OSError)):
        da.archive_preview(profile, request, archive, records)
    assert source.is_dir()
    assert not list(archive.iterdir())
    assert not list(records.iterdir())


def test_project_lock_conflict_preserves_source(fixture):
    profile, request, archive, records = fixture
    with dc.root_lock(profile.root):
        with pytest.raises(dc.DirectoryError) as failure:
            da.archive_preview(profile, request, archive, records)
    assert failure.value.reason_code == 'PROJECT_BUSY'
    assert not list(archive.iterdir())


def test_open_handle_gate_and_unavailable_gate(fixture, monkeypatch):
    from types import SimpleNamespace
    profile, request, archive, records = fixture
    strict = copy.deepcopy(profile.data)
    strict['archive']['require_no_open_handles'] = True
    profile = dc.load_profile(profile.root, profile.config, strict)
    import sys
    monkeypatch.setattr(da.shutil, 'which', lambda name: sys.executable)
    monkeypatch.setattr(da, '_sample_lsof', lambda *a, **kw: (0, True, False))
    with pytest.raises(dc.DirectoryError) as failure:
        da.archive_preview(profile, request, archive, records)
    assert failure.value.reason_code == 'OPEN_HANDLES'
    monkeypatch.setattr(da.shutil, 'which', lambda name: None)
    with pytest.raises(dc.DirectoryError) as failure:
        da.archive_preview(profile, request, archive, records)
    assert failure.value.reason_code == 'OPEN_HANDLES_CHECK_UNAVAILABLE'


def test_archive_atomic_target_insertion_race_preserves_both(fixture, monkeypatch):
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    def raced(source_root, source, target_root, target):
        if source_root == profile.root and target_root == archive:
            (target_root / target).mkdir()
            (target_root / target / 'other.txt').write_text('another writer')
        return original(source_root, source, target_root, target)
    monkeypatch.setattr(dc, 'rename_noreplace', raced)
    with pytest.raises(dc.DirectoryError) as failure:
        da.apply(profile, plan, archive, records)
    assert failure.value.reason_code == 'DESTINATION_EXISTS' 
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert (archive / 'fixture/run-1/other.txt').read_text() == 'another writer'
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    journal = records / (plan['operation_id'] + '.directory.json')
    with pytest.raises(dc.DirectoryError):
        da.recover(profile, journal, archive, records)
    assert (archive / 'fixture/run-1/other.txt').read_text() == 'another writer'


@pytest.mark.parametrize('mode', ['archive', 'restore'])
def test_real_process_exit_after_payload_rename_is_recoverable(fixture, tmp_path, mode):
    import json
    import subprocess
    import sys
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    journal_path = records / (plan['operation_id'] + '.directory.json')
    if mode == 'restore':
        archived = da.apply(profile, plan, archive, records)
        action_plan = da.restore_preview(profile, archived, archive)
    else:
        action_plan = plan
    packet = tmp_path / 'process-input.json'
    packet.write_text(json.dumps({'root': str(profile.root), 'config': profile.config, 'profile': profile.data,
                                  'plan': action_plan, 'archive': str(archive), 'records': str(records)}))
    script = '''
import json,os,sys
from pathlib import Path
from fifan_maintenance import directory_common as dc, directory_archive as da
p=json.loads(Path(sys.argv[1]).read_text())
profile=dc.load_profile(Path(p['root']),p['config'],p['profile'])
original=dc.rename_noreplace
def killed(source_root,source,target_root,target):
    original(source_root,source,target_root,target)
    if (sys.argv[2]=='archive' and target_root==Path(p['archive'])) or (sys.argv[2]=='restore' and source_root==Path(p['archive'])):
        os._exit(73)
dc.rename_noreplace=killed
if sys.argv[2]=='archive':
    da.apply(profile,p['plan'],Path(p['archive']),Path(p['records']))
else:
    da.restore(profile,p['plan'],Path(p['archive']),Path(p['records']))
'''
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(Path(da.__file__).resolve().parents[1]))
    result = subprocess.run([sys.executable, '-B', '-c', script, str(packet), mode], env=env, capture_output=True, timeout=30)
    assert result.returncode == 73, result.stderr.decode()
    interrupted = dc.load_artifact(journal_path)
    assert interrupted['progress'][0]['state'] == ('MoveIntent' if mode == 'archive' else 'RestorePayloadIntent')
    recovered = da.recover(profile, journal_path, archive, records)
    assert recovered['state'] == ('Archived' if mode == 'archive' else 'Restored')
    assert da.verify(profile, recovered, archive)['status'] == 'Passed'


def test_records_failure_precedes_any_payload_move(fixture, monkeypatch):
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    def no_space(*args, **kwargs):
        raise OSError('simulated records volume full')
    monkeypatch.setattr(dc, 'write_artifact', no_space)
    with pytest.raises(OSError):
        da.apply(profile, plan, archive, records)
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert not list(archive.iterdir())


def test_modified_plan_or_journal_is_rejected(fixture):
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    changed = copy.deepcopy(plan)
    changed['batches'][0]['destination'] = '../outside'
    with pytest.raises(dc.DirectoryError):
        da.apply(profile, changed, archive, records)
    changed = dc.seal(changed)
    with pytest.raises(dc.DirectoryError):
        da.apply(profile, changed, archive, records)
    record = da.apply(profile, plan, archive, records)
    changed = copy.deepcopy(record)
    changed['progress'][0]['locator']['stage'] = '../not-ours'
    dc.write_artifact(Path(record['journal_path']), dc.seal(changed), replace=True)
    with pytest.raises(dc.DirectoryError):
        da.recover(profile, Path(record['journal_path']), archive, records)
    assert (archive / 'fixture/run-1/raw.bin').exists()


def test_missing_locator_can_restore_without_deleting_unknown_material(fixture):
    profile, request, archive, records = fixture
    record = da.apply(profile, da.archive_preview(profile, request, archive, records), archive, records)
    locator = profile.root / 'evidence/run-1'
    retained_elsewhere = profile.root / 'user-retained-locator'
    os.rename(locator, retained_elsewhere)
    assert da.verify(profile, record, archive)['status'] == 'Failed'
    plan = da.restore_preview(profile, record, archive)
    assert plan['batches'][0]['locator_action'] == 'Absent'
    restored = da.restore(profile, plan, archive, records)
    assert restored['state'] == 'Restored'
    assert (retained_elsewhere / 'ARCHIVED.md').exists()


def test_runtime_roots_are_mandatory_and_must_match(fixture, tmp_path):
    profile, request, archive, records = fixture
    other = tmp_path / 'other-archive'
    other.mkdir()
    for arc, rec in [(None, records), (archive, None), (other, records), (profile.root, records)]:
        with pytest.raises(dc.DirectoryError):
            da.archive_preview(profile, request, arc, rec)
    assert not list(archive.iterdir())


def test_manifest_and_artifact_budgets_fail_before_moving(fixture):
    profile, request, archive, records = fixture
    for limits in [{'max_hash_entries': 3}, {'max_hash_bytes': 10}, {'max_artifact_bytes': 4096}]:
        data = copy.deepcopy(profile.data)
        data['budgets'].update(limits)
        limited = dc.load_profile(profile.root, profile.config, data)
        with pytest.raises(dc.DirectoryError) as failure:
            da.archive_preview(limited, request, archive, records)
        assert failure.value.reason_code == 'BUDGET_EXHAUSTED'
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert not list(archive.iterdir())


def test_real_open_file_handle_is_observed(fixture):
    profile, request, archive, records = fixture
    if da.shutil.which('lsof') is None:
        pytest.skip('host lsof is unavailable; strict unavailable rejection covered separately')
    with (profile.root / 'evidence/run-1/raw.bin').open('rb'):
        with pytest.raises(dc.DirectoryError) as failure:
            da.archive_preview(profile, request, archive, records)
    assert failure.value.reason_code == 'OPEN_HANDLES'
    assert not list(archive.iterdir())


def test_payload_changed_after_atomic_move_is_preserved_for_attention(fixture, monkeypatch):
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    def raced(source_root, source, target_root, target):
        original(source_root, source, target_root, target)
        if target_root == archive:
            (archive / target / 'new-user-data.txt').write_text('external new data')
    monkeypatch.setattr(dc, 'rename_noreplace', raced)
    with pytest.raises(dc.DirectoryError) as failure:
        da.apply(profile, plan, archive, records)
    assert failure.value.reason_code == 'SOURCE_CHANGED'
    assert not (profile.root / 'evidence/run-1').exists()
    assert (archive / 'fixture/run-1/new-user-data.txt').read_text() == 'external new data'
    assert (archive / 'fixture/run-1/raw.bin').read_bytes() == b'\x00\xff\x80'
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    with pytest.raises(dc.DirectoryError):
        da.recover(profile, records / (plan['operation_id'] + '.directory.json'), archive, records)


def test_unreceipted_locator_staging_is_retained_and_not_adopted(fixture, tmp_path):
    import json
    import subprocess
    import sys
    profile, request, archive, records = fixture
    plan = da.archive_preview(profile, request, archive, records)
    packet = tmp_path / 'process-staging.json'
    packet.write_text(json.dumps({'root': str(profile.root), 'config': profile.config, 'profile': profile.data,
                                  'plan': plan, 'archive': str(archive), 'records': str(records)}))
    script = '''
import json,os,sys
from pathlib import Path
from fifan_maintenance import directory_common as dc, directory_archive as da
p=json.loads(Path(sys.argv[1]).read_text())
profile=dc.load_profile(Path(p['root']),p['config'],p['profile'])
original=da._save
def killed(record,profile,**kwargs):
    if record['progress'][0]['state']=='LocatorPrepared':
        os._exit(74)
    return original(record,profile,**kwargs)
da._save=killed
da.apply(profile,p['plan'],Path(p['archive']),Path(p['records']))
'''
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(Path(da.__file__).resolve().parents[1]))
    result = subprocess.run([sys.executable, '-B', '-c', script, str(packet)], env=env, capture_output=True, timeout=30)
    assert result.returncode == 74, result.stderr.decode()
    journal_path = records / (plan['operation_id'] + '.directory.json')
    before = dc.load_artifact(journal_path)
    assert before['progress'][0]['locator'] is None
    orphan = before['progress'][0]['staging_intent']
    orphan_inode = (records / orphan).stat().st_ino
    recovered = da.recover(profile, journal_path, archive, records)
    assert recovered['state'] == 'Archived'
    assert orphan in recovered['progress'][0]['retained_unknown_staging']
    assert recovered['progress'][0]['locator']['stage'] != orphan
    assert (records / orphan).stat().st_ino == orphan_inode
    assert (records / orphan / 'ARCHIVED.md').exists()
    assert da.verify(profile, recovered, archive)['status'] == 'Passed'


def two_source_fixture(fixture):
    profile, request, archive, records = fixture
    (profile.root / 'evidence/run-2').mkdir()
    (profile.root / 'evidence/run-2/preserved.txt').write_text('second payload')
    data = copy.deepcopy(profile.data)
    data['archive']['candidates'].append('evidence/run-2')
    data['classifications'].append({'path': 'evidence/run-2', 'role': 'historical', 'reason': 'Explicit second closed fixture'})
    profile = dc.load_profile(profile.root, profile.config, data)
    request = copy.deepcopy(request)
    request['batches'].append({**copy.deepcopy(request['batches'][0]), 'source': 'evidence/run-2', 'destination': 'fixture/run-2'})
    return profile, request, archive, records


def test_apfs_source_case_aliases_are_blocked_before_moving(fixture):
    profile, request, archive, records = fixture
    original = profile.root / 'evidence/run-1'
    alias = profile.root / 'EVIDENCE/RUN-1'
    if not alias.exists() or alias.stat().st_ino != original.stat().st_ino:
        pytest.skip('host filesystem does not expose this case alias')
    request = copy.deepcopy(request)
    request['batches'].append({**copy.deepcopy(request['batches'][0]), 'source': 'EVIDENCE/RUN-1', 'destination': 'fixture/other-target'})
    with pytest.raises(dc.DirectoryError):
        da.archive_preview(profile, request, archive, records)
    assert (original / 'raw.bin').exists()
    assert not list(archive.iterdir())
    assert not list(records.iterdir())


@pytest.mark.parametrize('destinations', [('fixture/foo', 'fixture/FOO'), ('fixture/foo', 'fixture/FOO/child'), ('fixture/caf\u00e9', 'fixture/cafe\u0301')])
def test_target_case_and_unicode_aliases_or_ancestors_are_blocked(fixture, destinations):
    profile, request, archive, records = two_source_fixture(fixture)
    for batch, target in zip(request['batches'], destinations):
        batch['destination'] = target
    with pytest.raises(dc.DirectoryError) as failure:
        da.archive_preview(profile, request, archive, records)
    assert failure.value.reason_code == 'MULTIPLE_WRITES'
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert (profile.root / 'evidence/run-2/preserved.txt').exists()
    assert not list(archive.iterdir())
    assert not list(records.iterdir())


def test_apfs_external_root_case_alias_cannot_authorize_project_as_archive(fixture):
    profile, request, archive, records = fixture
    alias = profile.root.with_name(profile.root.name.upper())
    if not alias.exists() or alias.stat().st_ino != profile.root.stat().st_ino:
        pytest.skip('host filesystem does not expose this case alias')
    data = copy.deepcopy(profile.data)
    data['archive']['archive_root'] = str(alias)
    with pytest.raises(dc.DirectoryError):
        aliased_profile = dc.load_profile(profile.root, profile.config, data)
        da.archive_preview(aliased_profile, request, alias, records)
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert not list(archive.iterdir())
    assert not list(records.iterdir())


def test_apfs_protected_git_case_alias_is_not_archivable(fixture):
    profile, request, archive, records = fixture
    (profile.root / '.git/objects').mkdir(parents=True)
    (profile.root / '.git/objects/private.txt').write_text('protected fixture')
    alias = profile.root / '.GIT'
    if not alias.exists():
        pytest.skip('host filesystem does not expose this case alias')
    data = copy.deepcopy(profile.data)
    data['archive']['candidates'] = ['.GIT']
    data['classifications'] = [{'path': '.GIT', 'role': 'historical', 'reason': 'Cannot override protection'}]
    with pytest.raises(dc.DirectoryError):
        aliased_profile = dc.load_profile(profile.root, profile.config, data)
        request = copy.deepcopy(request)
        request['batches'][0]['source'] = '.GIT'
        da.archive_preview(aliased_profile, request, archive, records)
    assert (profile.root / '.git/objects/private.txt').read_text() == 'protected fixture'
    assert not list(archive.iterdir())
    assert not list(records.iterdir())


def test_apfs_unicode_source_alias_is_blocked_before_moving(fixture):
    profile, request, archive, records = fixture
    created = profile.root / 'evidence/Caf\u00e9'
    created.mkdir()
    (created / 'preserved.bin').write_bytes(b'original unicode payload')
    decomposed = profile.root / 'evidence/Cafe\u0301'
    if not decomposed.exists() or decomposed.stat().st_ino != created.stat().st_ino:
        pytest.skip('host filesystem does not expose this Unicode normalization alias')
    actual_name = next(path.name for path in (profile.root / 'evidence').iterdir() if dc.path_key(path.name) == dc.path_key('Caf\u00e9'))
    actual = 'evidence/' + actual_name
    alias = 'evidence/Cafe\u0301' if actual_name != 'Cafe\u0301' else 'evidence/Caf\u00e9'
    data = copy.deepcopy(profile.data)
    data['archive']['candidates'] = [actual]
    data['classifications'] = [{'path': actual, 'role': 'historical', 'reason': 'Explicit unicode fixture'}]
    profile = dc.load_profile(profile.root, profile.config, data)
    request = copy.deepcopy(request)
    request['batches'][0]['source'] = alias
    with pytest.raises(dc.DirectoryError) as failure:
        da.archive_preview(profile, request, archive, records)
    assert failure.value.reason_code == 'PATH_ALIAS'
    assert (created / 'preserved.bin').read_bytes() == b'original unicode payload'
    assert not list(archive.iterdir())
    assert not list(records.iterdir())


def test_existing_archive_parent_case_alias_is_blocked(fixture):
    profile, request, archive, records = fixture
    (archive / 'fixture').mkdir()
    (archive / 'fixture/other.txt').write_text('existing archive namespace')
    request = copy.deepcopy(request)
    request['batches'][0]['destination'] = 'FIXTURE/run-1'
    with pytest.raises(dc.DirectoryError) as failure:
        da.archive_preview(profile, request, archive, records)
    assert failure.value.reason_code == 'PATH_ALIAS'
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert (archive / 'fixture/other.txt').read_text() == 'existing archive namespace'
    assert not list(records.iterdir())


def test_locate_case_alias_maps_only_unique_recorded_path(fixture):
    profile, request, archive, records = fixture
    record = da.apply(profile, da.archive_preview(profile, request, archive, records), archive, records)
    located = da.locate(profile, record, 'EVIDENCE/RUN-1/RAW.BIN', archive)
    assert located['archive_path'] == str(archive / 'fixture/run-1/raw.bin')
    assert located['resolution'] == 'ArchivedResolved'
    with pytest.raises(dc.DirectoryError):
        da.locate(profile, record, 'EVIDENCE/RUN-1-OTHER/RAW.BIN', archive)
    with pytest.raises(dc.DirectoryError):
        da.locate(profile, record, 'EVIDENCE/RUN-1/../current.md', archive)
    assert (archive / 'fixture/run-1/raw.bin').read_bytes() == b'\x00\xff\x80'


def test_pending_archive_recovery_rejects_new_current_reference_file(fixture, monkeypatch):
    profile, request, archive, records = fixture
    (profile.root / 'scripts').mkdir()
    (profile.root / 'scripts/existing.sh').write_text('printf ready\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'scripts', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    def before_first_move(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(dc, 'rename_noreplace', before_first_move)
    with pytest.raises(KeyboardInterrupt):
        da.apply(profile, plan, archive, records)
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    (profile.root / 'scripts/new-consumer.sh').write_text('cat evidence/run-1/raw.bin\n')
    with pytest.raises(dc.DirectoryError):
        da.recover(profile, records / (plan['operation_id'] + '.directory.json'), archive, records)
    assert (profile.root / 'evidence/run-1/raw.bin').read_bytes() == b'\x00\xff\x80'
    assert not (archive / 'fixture/run-1').exists()


@pytest.mark.parametrize('entrypoint,contents', [('apply', 'cat evidence/run-1/raw.bin\n'), ('recover', 'printf harmless\n'), ('recover', 'cat "${DYNAMIC_ROOT}/payload"\n')])
def test_pending_current_membership_drift_is_conservatively_blocked(fixture, monkeypatch, entrypoint, contents):
    profile, request, archive, records = fixture
    (profile.root / 'scripts').mkdir()
    (profile.root / 'scripts/existing.sh').write_text('printf ready\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'scripts', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    monkeypatch.setattr(dc, 'rename_noreplace', lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        da.apply(profile, plan, archive, records)
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    novel = profile.root / 'scripts/new.sh'
    novel.write_text(contents)
    with pytest.raises(dc.DirectoryError) as failure:
        if entrypoint == 'apply':
            da.apply(profile, plan, archive, records)
        else:
            da.recover(profile, records / (plan['operation_id'] + '.directory.json'), archive, records)
    assert failure.value.reason_code == 'SOURCE_CHANGED'
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert not (archive / 'fixture/run-1').exists()
    assert novel.read_text() == contents


def test_new_current_reference_does_not_block_safe_restoration(fixture):
    profile, request, archive, records = fixture
    (profile.root / 'scripts').mkdir()
    (profile.root / 'scripts/existing.sh').write_text('printf ready\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'scripts', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    archived = da.apply(profile, da.archive_preview(profile, request, archive, records), archive, records)
    novel = profile.root / 'scripts/new-consumer.sh'
    novel.write_text('cat evidence/run-1/raw.bin\n')
    plan = da.restore_preview(profile, archived, archive)
    restored = da.restore(profile, plan, archive, records)
    assert restored['state'] == 'Restored'
    assert da.verify(profile, restored, archive)['status'] == 'Passed'
    assert (profile.root / 'evidence/run-1/raw.bin').read_bytes() == b'\x00\xff\x80'
    assert novel.read_text() == 'cat evidence/run-1/raw.bin\n'


def test_new_current_empty_directories_consume_enumeration_budget(fixture, monkeypatch):
    profile, request, archive, records = fixture
    (profile.root / 'scripts').mkdir()
    (profile.root / 'scripts/existing.sh').write_text('printf ready\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'scripts', 'role': 'current'})
    data['budgets']['max_entries'] = 30
    profile = dc.load_profile(profile.root, profile.config, data)
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    monkeypatch.setattr(dc, 'rename_noreplace', lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        da.apply(profile, plan, archive, records)
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    for number in range(50):
        (profile.root / ('scripts/empty-%d' % number)).mkdir()
    with pytest.raises(dc.DirectoryError) as failure:
        da.recover(profile, records / (plan['operation_id'] + '.directory.json'), archive, records)
    assert failure.value.reason_code == 'BUDGET_EXHAUSTED'
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert not (archive / 'fixture/run-1').exists()


@pytest.mark.parametrize('add_consumer', [False, True])
def test_pending_second_batch_reenumerates_current_scope_with_moved_history_mapping(fixture, monkeypatch, add_consumer):
    profile, request, archive, records = two_source_fixture(fixture)
    (profile.root / 'scripts').mkdir()
    (profile.root / 'scripts/existing.sh').write_text('printf ready\n')
    internal = profile.root / 'evidence/run-1/internal-proof.md'
    internal.write_text('Internal closed original\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].extend([{'path': 'scripts', 'role': 'current'}, {'path': 'evidence', 'role': 'historical'}])
    profile = dc.load_profile(profile.root, profile.config, data)
    histories = [{'path': path.relative_to(profile.root).as_posix(), 'sha256': sha(path.read_bytes()),
                  'reason': 'Explicit retained closed artifact'} for path in (profile.root / 'evidence').rglob('*') if path.is_file()]
    request = copy.deepcopy(request)
    for batch in request['batches']:
        batch['historical_references'] = histories
        batch['closure']['evidence'].append({'path': 'evidence/run-1/internal-proof.md', 'sha256': sha(internal.read_bytes())})
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    once = []
    def after_first_payload(*args):
        original(*args)
        if args[0] == profile.root and args[2] == archive and not once:
            once.append(True)
            raise KeyboardInterrupt()
    monkeypatch.setattr(dc, 'rename_noreplace', after_first_payload)
    with pytest.raises(KeyboardInterrupt):
        da.apply(profile, plan, archive, records)
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    assert (archive / 'fixture/run-1/internal-proof.md').is_file()
    if add_consumer:
        (profile.root / 'scripts/new-consumer.sh').write_text('cat evidence/run-2/preserved.txt\n')
    journal_path = records / (plan['operation_id'] + '.directory.json')
    if add_consumer:
        with pytest.raises(dc.DirectoryError) as failure:
            da.recover(profile, journal_path, archive, records)
        assert failure.value.reason_code == 'SOURCE_CHANGED'
        assert (profile.root / 'evidence/run-2/preserved.txt').read_text() == 'second payload'
        assert not (archive / 'fixture/run-2').exists()
    else:
        recovered = da.recover(profile, journal_path, archive, records)
        assert recovered['state'] == 'Archived'
        assert da.verify(profile, recovered, archive)['status'] == 'Passed'
        assert (archive / 'fixture/run-2/preserved.txt').read_text() == 'second payload'


def test_current_parent_wins_over_historical_child_when_reference_set_changes(fixture, monkeypatch):
    profile, request, archive, records = fixture
    (profile.root / 'scripts/legacy').mkdir(parents=True)
    (profile.root / 'scripts/existing.sh').write_text('printf ready\n')
    (profile.root / 'scripts/legacy/existing.md').write_text('Known prior source\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].extend([{'path': 'scripts', 'role': 'current'}, {'path': 'scripts/legacy', 'role': 'historical'}])
    profile = dc.load_profile(profile.root, profile.config, data)
    plan = da.archive_preview(profile, request, archive, records)
    original = dc.rename_noreplace
    monkeypatch.setattr(dc, 'rename_noreplace', lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        da.apply(profile, plan, archive, records)
    monkeypatch.setattr(dc, 'rename_noreplace', original)
    (profile.root / 'scripts/legacy/new-consumer.sh').write_text('cat evidence/run-1/raw.bin\n')
    with pytest.raises(dc.DirectoryError) as failure:
        da.recover(profile, records / (plan['operation_id'] + '.directory.json'), archive, records)
    assert failure.value.reason_code == 'SOURCE_CHANGED'
    assert (profile.root / 'evidence/run-1/raw.bin').exists()
    assert not (archive / 'fixture/run-1').exists()


@pytest.mark.parametrize('position', ['project', 'archive'])
def test_path_selected_lsof_inside_material_is_never_executed(fixture, monkeypatch, position):
    profile, request, archive, records = fixture
    fake = profile.root / 'evidence/run-1/lsof'
    fake.write_text('#!/bin/sh\nexit 0\n')
    fake.chmod(0o755)
    record = None
    if position == 'archive':
        record = da.apply(profile, da.archive_preview(profile, request, archive, records), archive, records)
        fake = archive / 'fixture/run-1/lsof'
    monkeypatch.setenv('PATH', str(fake.parent) + os.pathsep + os.environ.get('PATH', ''))
    sampled = []
    def forbidden(*args):
        sampled.append(args)
        pytest.fail('inspected material was selected for execution')
    monkeypatch.setattr(da, '_sample_lsof', forbidden)
    with pytest.raises(dc.DirectoryError) as failure:
        if record is None:
            da.archive_preview(profile, request, archive, records)
        else:
            da.restore_preview(profile, record, archive)
    assert failure.value.reason_code == 'PROTECTED_PATH'
    assert sampled == []
    assert fake.read_text() == '#!/bin/sh\nexit 0\n'
    if position == 'project':
        assert (profile.root / 'evidence/run-1/raw.bin').exists()
        assert not (archive / 'fixture/run-1').exists()
    else:
        assert (archive / 'fixture/run-1/raw.bin').exists()
        assert (profile.root / 'evidence/run-1/ARCHIVED.md').exists()


def test_external_lsof_symlink_is_resolved_before_sampling(fixture, monkeypatch, tmp_path):
    profile, _, _, _ = fixture
    external = tmp_path / 'external-tools'
    external.mkdir()
    target = external / 'real-tool'
    target.write_text('#!/bin/sh\nexit 1\n')
    target.chmod(0o755)
    (external / 'lsof').symlink_to(target)
    monkeypatch.setenv('PATH', str(external) + os.pathsep + os.environ.get('PATH', ''))
    sampled = []
    def sampled_without_execution(*args):
        sampled.append(args)
        return 1, False, False
    monkeypatch.setattr(da, '_sample_lsof', sampled_without_execution)
    result = da._open_handles(profile, profile.root, 'evidence/run-1')
    assert result['status'] == 'ClearSample'
    assert sampled[0][0] == str(dc.canonical_destination(target))


def test_streaming_large_log_and_resolved_dynamic_archive_restore(fixture, monkeypatch):
    from fifan_maintenance import directory_census as ci
    profile, request, archive, records = fixture
    data = copy.deepcopy(profile.data)
    log = profile.root / 'Editor.log'
    # Above the old hard per-file cap, with a multibyte character across blocks.
    block = ('ordinary log 保留 ' + 'x' * 110 + '\n').encode()
    log.write_bytes(block * (17 * dc.MiB // len(block) + 1))
    code = profile.root / 'consumer.py'
    code.write_text(''.join('print(f"diagnostic {index}")\n' for _ in range(25)))
    data['streaming_references'] = ['Editor.log']
    data['reference_sources'] += [{'path': 'Editor.log', 'role': 'historical'}, {'path': 'consumer.py', 'role': 'current'}]
    data['budgets']['max_seconds'] = 300
    profile = dc.load_profile(profile.root, profile.config, data)
    original_read = dc.read_file
    def bounded_read(root, path, limit):
        assert path != 'Editor.log', 'large text must not use whole-file read'
        return original_read(root, path, limit)
    monkeypatch.setattr(dc, 'read_file', bounded_read)
    report = ci.impact(profile, request)
    dynamic = [x for x in report['batches'][0]['unknowns'] if x['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN']
    assert len(dynamic) == 25  # No hidden twenty-item truncation.
    assert report['coverage']['reference_bytes_read'] == sum((profile.root / x['path']).stat().st_size for x in data['reference_sources'])
    request['batches'][0]['dynamic_reference_resolutions'] = [{k: v for k, v in x.items() if k != 'reason_code'} | {
        'source': request['batches'][0]['source'],
        'reason': 'Reviewed display-only diagnostic expression, unrelated to this batch',
        'evidence': request['batches'][0]['closure']['evidence']} for x in dynamic]
    plan = da.archive_preview(profile, request, archive, records)
    record = da.apply(profile, plan, archive, records)
    assert da.verify(profile, record, archive)['status'] == 'Passed'
    restored = da.restore(profile, da.restore_preview(profile, record, archive), archive, records)
    assert da.verify(profile, restored, archive)['status'] == 'Passed'
    code.write_text(code.read_text() + '\n')
    assert da.verify(profile, restored, archive)['status'] == 'Failed'


@pytest.mark.parametrize('failure', ['wrong_sha', 'wrong_line', 'wrong_expression', 'evidence', 'fixed_path', 'new_line', 'wrong_candidate'])
def test_dynamic_resolution_cannot_hide_changes_or_fixed_consumers(fixture, failure):
    from fifan_maintenance import directory_census as ci
    profile, request, archive, records = fixture
    code = profile.root / 'consumer.py'
    code.write_text('value = f"folder/{name}"\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'consumer.py', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    item = next(x for x in ci.impact(profile, request)['batches'][0]['unknowns'] if x['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN')
    resolution = {k: v for k,v in item.items() if k != 'reason_code'}
    resolution.update(source=request['batches'][0]['source'], reason='Reviewed unrelated path family', evidence=copy.deepcopy(request['batches'][0]['closure']['evidence']))
    request['batches'][0]['dynamic_reference_resolutions'] = [resolution]
    if failure == 'wrong_sha': resolution['sha256'] = '0' * 64
    elif failure == 'wrong_line': resolution['line'] += 1
    elif failure == 'wrong_expression': resolution['expression_sha256'] = '0' * 64
    elif failure == 'evidence': resolution['evidence'][0]['sha256'] = '0' * 64
    elif failure == 'wrong_candidate':
        request['batches'][0]['source'] = 'evidence/other'
    elif failure == 'new_line': code.write_text('\n' + code.read_text())
    elif failure == 'fixed_path':
        code.write_text(code.read_text() + 'path = "evidence/run-1/raw.bin"\n')
        resolution['sha256'] = sha(code.read_bytes())
    if failure == 'wrong_candidate':
        with pytest.raises(dc.DirectoryError, match='resolution candidate mismatch'):
            ci.impact(profile, request)
        return
    result = ci.impact(profile, request)
    assert not result['batches'][0]['eligible']
    if failure == 'fixed_path': assert result['batches'][0]['current_dependencies']


@pytest.mark.parametrize('payload,reason', [(b'x' * (1024 * 1024 + 1), 'REFERENCE_LINE_TOO_LONG'),
                                           (b'ok\n\xff\n', 'REFERENCE_ENCODING_UNKNOWN'),
                                           (b'ok\n\x00\n', 'REFERENCE_BINARY_UNKNOWN')])
def test_streaming_incomplete_text_stays_unknown(fixture, payload, reason):
    from fifan_maintenance import directory_census as ci
    profile, request, _, _ = fixture
    (profile.root / 'Editor.log').write_bytes(payload)
    data = copy.deepcopy(profile.data)
    data['streaming_references'] = ['Editor.log']
    data['reference_sources'].append({'path': 'Editor.log', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    result = ci.impact(profile, request)
    assert not result['batches'][0]['eligible']
    assert reason in {x['reason_code'] for x in result['coverage']['failed_files']}
    assert result['coverage']['reference_bytes_read'] >= min(len(payload), 65536)


def test_identical_expressions_on_one_line_require_distinct_columns(fixture):
    from fifan_maintenance import directory_census as ci
    profile, request, _, _ = fixture
    code = profile.root / 'consumer.cs'
    code.write_text('var a = Path.Combine(x, y); var b = Path.Combine(z, w);\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'consumer.cs', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    unknowns = ci.impact(profile, request)['batches'][0]['unknowns']
    dynamic = [x for x in unknowns if x['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN']
    assert len(dynamic) == 2 and dynamic[0]['expression_sha256'] == dynamic[1]['expression_sha256']
    assert dynamic[0]['column'] != dynamic[1]['column']
    resolution = {k:v for k,v in dynamic[0].items() if k != 'reason_code'}
    resolution.update(source=request['batches'][0]['source'], reason='First expression reviewed', evidence=request['batches'][0]['closure']['evidence'])
    request['batches'][0]['dynamic_reference_resolutions'] = [resolution]
    result = ci.impact(profile, request)
    remaining = result['batches'][0]['unknowns']
    assert remaining == [dynamic[1]] and not result['batches'][0]['eligible']


@pytest.mark.parametrize('case', ['total_budget', 'mutation', 'symlink', 'empty'])
def test_streaming_budget_stability_and_path_guards(fixture, monkeypatch, case):
    from fifan_maintenance import directory_census as ci
    profile, request, _, _ = fixture
    log = profile.root / 'Editor.log'
    log.write_bytes(b'ordinary log\n' * 10000 if case != 'empty' else b'')
    data = copy.deepcopy(profile.data)
    data['streaming_references'] = ['Editor.log']
    data['reference_sources'].append({'path': 'Editor.log', 'role': 'current'})
    if case == 'total_budget': data['budgets']['max_reference_bytes'] = 65536
    if case == 'symlink':
        log.unlink()
        log.symlink_to(profile.root / 'closure.md')
    if case == 'mutation':
        original_read = os.read
        changed = []
        def changing_read(fd, limit):
            block = original_read(fd, limit)
            if block.startswith(b'ordinary log') and not changed:
                changed.append(True)
                with log.open('ab') as out: out.write(b'later edit\n')
            return block
        monkeypatch.setattr(os, 'read', changing_read)
    profile = dc.load_profile(profile.root, profile.config, data)
    result = ci.impact(profile, request)
    assert result['batches'][0]['eligible'] is (case == 'empty')
    if case == 'total_budget':
        assert result['coverage']['reference_bytes_read'] < 65536
    if case == 'mutation':
        assert 'SOURCE_CHANGED' in {item['reason_code'] for item in result['coverage']['failed_files']}


@pytest.mark.parametrize('line', [
    'a=f"{x}"; b=f"{y}"\n',
    "a=f'{x}'; b=f'{y}'\n",
    'a=Path("x")/"leaf"; b=Path("y")/"leaf"\n',
])
def test_separate_fstrings_and_path_operators_require_individual_reviews(fixture, line):
    from fifan_maintenance import directory_census as ci
    profile, request, _, _ = fixture
    (profile.root / 'consumer.py').write_text(line)
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'consumer.py', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    dynamic = ci.impact(profile, request)['batches'][0]['unknowns']
    assert len(dynamic) == 2
    assert dynamic[0]['column'] < dynamic[1]['column']
    resolution = {k:v for k,v in dynamic[0].items() if k != 'reason_code'}
    resolution.update(source=request['batches'][0]['source'], reason='Only first expression reviewed', evidence=request['batches'][0]['closure']['evidence'])
    request['batches'][0]['dynamic_reference_resolutions'] = [resolution]
    checked = ci.impact(profile, request)
    assert checked['batches'][0]['unknowns'] == [dynamic[1]]
    assert not checked['batches'][0]['eligible']


def test_reference_proofs_use_independent_file_byte_and_entry_budgets(fixture):
    profile, request, archive, records = fixture
    data = copy.deepcopy(profile.data)
    data['budgets'].update(max_hash_file_bytes=dc.MiB, max_hash_bytes=dc.MiB, max_hash_entries=16)
    (profile.root / 'large.log').write_bytes(b'ordinary diagnostic\n' * (5 * dc.MiB // 20 + 1))
    data['streaming_references'] = ['large.log']
    data['reference_sources'].append({'path': 'large.log', 'role': 'current'})
    for index in range(20):
        name = 'proof-%02d.txt' % index
        (profile.root / name).write_text('Additional unchanged current proof\n')
        data['reference_sources'].append({'path': name, 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    plan = da.archive_preview(profile, request, archive, records)
    record = da.apply(profile, plan, archive, records)
    assert record['state'] == 'Archived'
    assert da.verify(profile, record, archive)['status'] == 'Passed'
    assert da.recover(profile, record, archive, records)['state'] == 'Archived'
    restored = da.restore(profile, da.restore_preview(profile, record, archive), archive, records)
    assert restored['state'] == 'Restored'
    assert da.verify(profile, restored, archive)['status'] == 'Passed'
    assert da.recover(profile, restored, archive, records)['state'] == 'Restored'
    # The independent reference path must not widen ordinary payload hashing.
    with pytest.raises(dc.DirectoryError) as failure:
        dc.stream_hash(profile, 'large.log', dc.HashBudget(profile))
    assert failure.value.reason_code == 'BUDGET_EXHAUSTED'


@pytest.mark.parametrize('prefix', ['f', 'F', 'fr', 'fR', 'Fr', 'FR', 'rf', 'rF', 'Rf', 'RF'])
@pytest.mark.parametrize('quote', ["'", '"', "'''", '"""'])
def test_all_formatted_prefixes_quotes_and_cases_are_independent_unknowns(fixture, prefix, quote):
    from fifan_maintenance import directory_census as ci
    profile, request, _, _ = fixture
    # Single-line cases reproduce raw interpolated paths; triple-quoted cases
    # deliberately omit braces to preserve uncertain multiline forms as Unknown.
    body = '{root}/{name}' if len(quote) == 1 else 'raw\nmultiline diagnostic'
    line = 'a=f"{x}"; b=' + prefix + quote + body + quote + '\n'
    (profile.root / 'consumer.py').write_text(line)
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'consumer.py', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    dynamic = ci.impact(profile, request)['batches'][0]['unknowns']
    assert len(dynamic) == 2
    assert dynamic[0]['line'] == dynamic[1]['line'] == 1
    assert dynamic[1]['column'] == line.index('b=') + 3
    assert dynamic[1]['expression_sha256'] == sha((prefix + quote).encode())
    resolution = {k:v for k,v in dynamic[0].items() if k != 'reason_code'}
    resolution.update(source=request['batches'][0]['source'], reason='Only first expression reviewed', evidence=request['batches'][0]['closure']['evidence'])
    request['batches'][0]['dynamic_reference_resolutions'] = [resolution]
    checked = ci.impact(profile, request)
    assert checked['batches'][0]['unknowns'] == [dynamic[1]]
    assert not checked['batches'][0]['eligible']


@pytest.mark.parametrize('prefix', ['', 'r', 'R'])
def test_plain_and_raw_unformatted_strings_do_not_add_formatted_unknowns(fixture, prefix):
    from fifan_maintenance import directory_census as ci
    profile, request, _, _ = fixture
    (profile.root / 'consumer.py').write_text('value=' + prefix + '"ordinary diagnostic"\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'consumer.py', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    checked = ci.impact(profile, request)
    assert checked['batches'][0]['unknowns'] == []
    assert checked['batches'][0]['eligible']
