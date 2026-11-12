from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from fifan_maintenance import cleanup_operations as ops
from fifan_maintenance import cleanup_policy as policy
from fifan_maintenance import directory_common as dc
from fifan_maintenance.project import load_config


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def case(tmp_path):
    root, quarantine, records = [tmp_path / value for value in ('project', 'quarantine', 'records')]
    for path in (root, quarantine, records):
        path.mkdir()
    (root / 'logs').mkdir()
    (root / 'logs/old.log').write_bytes('old closed process\r\n原始\r\n'.encode())
    (root / 'exports/old/empty').mkdir(parents=True)
    (root / 'exports/old/raw.bin').write_bytes(b'\x00\xff\x80')
    (root / 'exports/old/notes.txt').write_bytes(b'original package\r\n')
    (root / 'current.md').write_text('Current retained entry\n')
    proof = b'Explicit completed synthetic batch\n'
    (root / 'closed.md').write_bytes(proof)
    os.chmod(root / 'logs/old.log', 0o640)
    os.utime(root / 'logs/old.log', ns=(1650000000123456789, 1650000000123456789))
    data = {'schema_version': 1, 'project_root': str(root), 'scan_roots': ['logs', 'exports'],
            'current': ['current.md'], 'reference_sources': [{'path': 'current.md', 'role': 'current'}, {'path': 'closed.md', 'role': 'historical'}],
            'candidates': [{'path': 'logs/old.log', 'kind': 'completed_log'}, {'path': 'exports/old', 'kind': 'disposable_output'}],
            'quarantine_root': str(quarantine), 'records_dir': str(records), 'require_no_open_handles': True}
    profile = policy.load_profile(root, load_config(root), data)
    request = {'schema_version': 1, 'approval': {'reference': 'explicit synthetic quarantine and purge approval', 'actions': ['quarantine', 'purge']},
               'items': [{'source': path, 'kind': kind, 'disposition': 'purge', 'reason': 'closed exact fixture',
                          'closure': {'decision': 'closed', 'reason': 'completed fixture', 'evidence': [{'path': 'closed.md', 'sha256': sha(proof)}]},
                          'loss': {'accepted': True, 'rebuildable': 'Unknown', 'unique_evidence': False, 'description': 'lose the original synthetic snapshot'},
                          'retained': []} for path, kind in [('logs/old.log', 'completed_log'), ('exports/old', 'disposable_output')]]}
    return profile, request, quarantine, records


def snapshot(path):
    paths = [path] + (list(path.rglob('*')) if path.is_dir() else [])
    return {'.' if item == path else item.relative_to(path).as_posix():
            {'identity': (item.stat().st_dev, item.stat().st_ino), 'mode': item.stat().st_mode & 0o7777,
             'mtime_ns': item.stat().st_mtime_ns, 'sha256': sha(item.read_bytes()) if item.is_file() else None}
            for item in paths}


def test_strict_file_and_directory_quarantine_restore_same_inodes(case):
    profile, request, quarantine, records = case
    before = {item['source']: snapshot(profile.root / item['source']) for item in request['items']}
    plan = ops.preview(profile, request, quarantine, records)
    assert plan['kind'] == 'quarantine'
    assert not list(records.iterdir()) and not list(quarantine.iterdir())
    journal = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    assert journal['state'] == 'Quarantined'
    assert ops.verify(profile, journal, quarantine, records)['status'] == 'Passed'
    for item in plan['items']:
        assert not (profile.root / item['source']).exists()
        assert snapshot(quarantine / item['quarantine_relative']) == before[item['source']]
    restored_plan = ops.restore_preview(profile, journal, quarantine, records)
    restored = ops.restore(profile, restored_plan, quarantine, records, approve_plan=restored_plan['fingerprint'])
    assert restored['state'] == 'Restored'
    assert ops.verify(profile, restored, quarantine, records)['status'] == 'Passed'
    for source, original in before.items():
        assert snapshot(profile.root / source) == original
    assert ops.load_record_metadata(profile, restored, records)['fingerprint'] == restored['fingerprint']
    assert Path(restored['journal_path']).stat().st_mode & 0o777 == 0o600
    assert Path(restored['journal_path']).parent.stat().st_mode & 0o777 == 0o700


def test_strict_native_file_open_handle_is_blocked(case):
    profile, request, quarantine, records = case
    with (profile.root / 'logs/old.log').open('rb'):
        with pytest.raises(dc.DirectoryError) as error:
            ops.preview(profile, request, quarantine, records)
    assert error.value.reason_code == 'OPEN_HANDLES'
    assert not list(quarantine.iterdir()) and not list(records.iterdir())


def test_quarantine_restore_repreview_then_purge_is_irreversible_and_idempotent(case):
    profile, request, quarantine, records = case
    first = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, first, quarantine, records, approve_plan=first['fingerprint'])
    restore_plan = ops.restore_preview(profile, held, quarantine, records)
    ops.restore(profile, restore_plan, quarantine, records, approve_plan=restore_plan['fingerprint'])
    second = ops.preview(profile, request, quarantine, records)
    assert second['operation_id'] != first['operation_id']
    held = ops.apply(profile, second, quarantine, records, approve_plan=second['fingerprint'])
    purge_plan = ops.purge_preview(profile, held, quarantine, records)
    purged = ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
    assert purged['state'] == 'Purged'
    assert all(len(p['removed']) == len(i['manifest']['entries']) for p, i in zip(purged['items'], second['items']))
    assert ops.verify(profile, purged, quarantine, records)['status'] == 'Passed'
    assert all(not (quarantine / item['quarantine_relative']).exists() and not (profile.root / item['source']).exists() for item in second['items'])
    assert ops.restore_preview(profile, purged, quarantine, records)['status'] == 'Blocked'
    assert ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])['fingerprint'] == purged['fingerprint']
    assert ops.recover(profile, purged, quarantine, records)['fingerprint'] == purged['fingerprint']


def test_wrong_approval_has_no_payload_or_record_effect(case):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    with pytest.raises(dc.DirectoryError) as error:
        ops.apply(profile, plan, quarantine, records, approve_plan='0' * 64)
    assert error.value.reason_code == 'APPROVAL_REQUIRED'
    assert not list(records.iterdir()) and not list(quarantine.iterdir())
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    purge_plan = ops.purge_preview(profile, held, quarantine, records)
    before = Path(held['journal_path']).read_bytes()
    with pytest.raises(dc.DirectoryError):
        ops.purge(profile, purge_plan, quarantine, records, approve_plan=plan['fingerprint'])
    assert Path(held['journal_path']).read_bytes() == before
    assert all((quarantine / item['quarantine_relative']).exists() for item in plan['items'])


def test_quarantine_only_requires_a_new_exact_purge_loss_approval(case):
    profile, request, quarantine, records = case
    request = copy.deepcopy(request)
    request['approval']['actions'] = ['quarantine']
    for item in request['items']:
        item['disposition'] = 'quarantine'
        item['loss']['accepted'] = False
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    assert not ops.request_allows_purge(plan['request'])
    with pytest.raises(dc.DirectoryError) as error:
        ops.purge_preview(profile, held, quarantine, records)
    assert error.value.reason_code == 'PURGE_APPROVAL_REQUIRED'
    approval = {'quarantine_fingerprint': plan['fingerprint'], 'reference': 'explicit later irreversible approval', 'loss_accepted': True}
    purge_plan = ops.purge_preview(profile, held, quarantine, records, approval=approval)
    assert purge_plan['authorization']['source'] == 'new_approval'
    purged = ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
    assert purged['state'] == 'Purged'


def child_exit_after_syscall(action, stage, root):
    """A real process death cannot run the engine's exception cleanup."""
    pid = os.fork()
    if pid == 0:
        try:
            if stage in {'quarantine', 'restore'}:
                original = ops._rename_entry
                def renamed(sr, sp, dr, dp):
                    original(sr, sp, dr, dp)
                    if (stage == 'quarantine' and Path(sr) == root or
                            stage == 'restore' and Path(dr) == root):
                        os._exit(73)
                ops._rename_entry = renamed
            else:
                original = getattr(os, stage)
                def removed(name, *args, **kwargs):
                    original(name, *args, **kwargs)
                    if str(name) == ('payload-0000' if stage == 'unlink' else 'empty'):
                        os._exit(73)
                setattr(os, stage, removed)
            action()
        except BaseException:
            os._exit(91)
        os._exit(92)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 73


@pytest.mark.parametrize('stage', ['quarantine', 'restore', 'unlink', 'rmdir'])
def test_real_process_exit_after_payload_syscall_reconciles_only_durable_intent(case, stage):
    profile, request, quarantine, records = case
    original = {i['source']: snapshot(profile.root / i['source']) for i in request['items']}
    plan = ops.preview(profile, request, quarantine, records)
    journal_path = records / ('cleanup-' + plan['operation_id']) / 'journal.json'
    if stage == 'quarantine':
        action = lambda: ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
        approval = {'approve_plan': plan['fingerprint']}
    else:
        held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
        if stage == 'restore':
            next_plan = ops.restore_preview(profile, held, quarantine, records)
            action = lambda: ops.restore(profile, next_plan, quarantine, records, approve_plan=next_plan['fingerprint'])
            approval = {'approve_plan': next_plan['fingerprint']}
        else:
            next_plan = ops.purge_preview(profile, held, quarantine, records)
            action = lambda: ops.purge(profile, next_plan, quarantine, records, approve_plan=next_plan['fingerprint'])
            approval = {'approve_purge': next_plan['fingerprint']}
    child_exit_after_syscall(action, stage, profile.root)
    pending = ops.load_record_metadata(profile, journal_path, records)
    assert pending['intent']['action'] == stage
    assert ops.verify(profile, pending, quarantine, records)['status'] == 'Unknown'
    with pytest.raises(dc.DirectoryError) as error:
        ops.recover(profile, pending, quarantine, records)
    assert error.value.reason_code == 'APPROVAL_REQUIRED'
    if stage in {'unlink', 'rmdir'}:
        check = ops.verify(profile, pending, quarantine, records)
        assert not check['restore_possible'] and check['irreversible']
        assert ops.restore_preview(profile, pending, quarantine, records)['status'] == 'Blocked'
    completed = ops.recover(profile, pending, quarantine, records, **approval)
    assert completed['state'] == {'quarantine': 'Quarantined', 'restore': 'Restored', 'unlink': 'Purged', 'rmdir': 'Purged'}[stage]
    assert completed['last_error'] is None and completed['intent'] is None
    assert ops.verify(profile, completed, quarantine, records)['status'] == 'Passed'
    if stage == 'restore':
        assert {source: snapshot(profile.root / source) for source in original} == original
    if stage in {'unlink', 'rmdir'}:
        assert any('observed_missing_after_intent' in p['removal_evidence'].values() for p in completed['items'])


@pytest.mark.parametrize('failure', ['intent_save', 'delete_sync', 'rmdir_sync', 'receipt_save', 'rename_sync'])
def test_save_and_sync_failure_keep_last_durable_intent_and_recover(case, monkeypatch, failure):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    flags = {'fired': False, 'deleted': False}
    if failure == 'rename_sync':
        original_sync = os.fsync
        parent_inode = (profile.root / 'logs').stat().st_ino
        def sync(fd):
            if os.fstat(fd).st_ino == parent_inode and not flags['fired'] and not (profile.root / 'logs/old.log').exists():
                flags['fired'] = True
                raise OSError('injected actual fsync failure after rename')
            original_sync(fd)
        monkeypatch.setattr(os, 'fsync', sync)
        action = lambda: ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
        approval = {'approve_plan': plan['fingerprint']}
    else:
        held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
        purge_plan = ops.purge_preview(profile, held, quarantine, records)
        if failure in {'delete_sync', 'rmdir_sync'}:
            syscall = 'unlink' if failure == 'delete_sync' else 'rmdir'
            original_unlink, original_sync = getattr(os, syscall), ops._sync
            def unlink(name, *args, **kwargs):
                original_unlink(name, *args, **kwargs)
                if str(name) == ('payload-0000' if syscall == 'unlink' else 'empty'):
                    flags['deleted'] = True
            def sync(fd):
                if flags['deleted'] and not flags['fired']:
                    flags['fired'] = True
                    raise OSError('injected fsync failure after unlink')
                original_sync(fd)
            monkeypatch.setattr(os, syscall, unlink)
            monkeypatch.setattr(ops, '_sync', sync)
        else:
            original_save = ops._save
            def save(p, record, **kwargs):
                pending = record['intent'] and record['intent']['action'] == 'unlink'
                receipt = record['intent'] is None and any(i['removed'] for i in record['items'])
                if not flags['fired'] and (pending if failure == 'intent_save' else receipt):
                    flags['fired'] = True
                    raise OSError('injected journal failure')
                return original_save(p, record, **kwargs)
            monkeypatch.setattr(ops, '_save', save)
        action = lambda: ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
        approval = {'approve_purge': purge_plan['fingerprint']}
    with pytest.raises(OSError):
        action()
    assert flags['fired']
    path = records / ('cleanup-' + plan['operation_id']) / 'journal.json'
    pending = ops.load_record_metadata(profile, path, records)
    assert ops.verify(profile, pending, quarantine, records)['status'] == 'Unknown'
    if failure == 'intent_save':
        assert pending['intent'] is None
        assert all((quarantine / item['quarantine_relative']).exists() for item in plan['items'])
    elif failure != 'rename_sync':
        assert pending['state'] == 'PartiallyPurged'
        assert pending['intent']['action'] == ('rmdir' if failure == 'rmdir_sync' else 'unlink')
        assert not (quarantine / plan['items'][0]['quarantine_relative']).exists()
    completed = ops.recover(profile, pending, quarantine, records, **approval)
    assert completed['state'] == ('Quarantined' if failure == 'rename_sync' else 'Purged')
    assert completed['last_error'] is None
    assert ops.verify(profile, completed, quarantine, records)['status'] == 'Passed'


@pytest.mark.parametrize('mutation', ['same_bytes_new_inode', 'modified_payload', 'new_current_reference', 'journal_new_inode', 'restore_occupied'])
def test_post_quarantine_changes_refuse_forward_writes_without_overwriting(case, mutation):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    target = quarantine / plan['items'][0]['quarantine_relative']
    if mutation == 'same_bytes_new_inode':
        replacement = target.parent / 'replacement'
        replacement.write_bytes(target.read_bytes())
        os.chmod(replacement, target.stat().st_mode & 0o7777)
        os.utime(replacement, ns=(target.stat().st_atime_ns, target.stat().st_mtime_ns))
        replacement.replace(target)
    elif mutation == 'modified_payload':
        target.write_bytes(b'new user content')
    elif mutation == 'new_current_reference':
        (profile.root / 'current.md').write_text('Read logs/old.log for current execution\n')
    elif mutation == 'journal_new_inode':
        journal = Path(held['journal_path'])
        replacement = journal.parent / 'replacement'
        replacement.write_bytes(journal.read_bytes())
        os.chmod(replacement, 0o600)
        replacement.replace(journal)
    else:
        (profile.root / 'logs/old.log').write_bytes(b'new occupant')
    with pytest.raises(dc.DirectoryError):
        ops.purge_preview(profile, held, quarantine, records)
    assert target.exists() and (quarantine / plan['items'][1]['quarantine_relative']).is_dir()
    if mutation == 'new_current_reference':
        # Undoing the move repairs a new consumer; it must not use forward eligibility.
        restore_plan = ops.restore_preview(profile, held, quarantine, records)
        restored = ops.restore(profile, restore_plan, quarantine, records, approve_plan=restore_plan['fingerprint'])
        assert restored['state'] == 'Restored'
    elif mutation == 'restore_occupied':
        with pytest.raises(dc.DirectoryError):
            ops.restore_preview(profile, held, quarantine, records)
        assert (profile.root / 'logs/old.log').read_bytes() == b'new occupant'


def test_move_intent_does_not_excuse_source_ctime_changes_before_rename(case, monkeypatch):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    original = ops._rename_entry
    def interrupted(sr, sp, dr, dp):
        if Path(sr) == profile.root:
            raise OSError('injected interruption before source rename')
        return original(sr, sp, dr, dp)
    monkeypatch.setattr(ops, '_rename_entry', interrupted)
    with pytest.raises(OSError):
        ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    source = profile.root / request['items'][0]['source']
    before = source.stat()
    os.chmod(source, 0o600)
    os.chmod(source, before.st_mode & 0o7777)
    assert source.stat().st_ctime_ns != before.st_ctime_ns
    monkeypatch.setattr(ops, '_rename_entry', original)
    with pytest.raises(dc.DirectoryError) as error:
        ops.recover(profile, records / ('cleanup-' + plan['operation_id']) / 'journal.json', quarantine, records, approve_plan=plan['fingerprint'])
    assert error.value.reason_code == 'SOURCE_CHANGED'
    assert source.exists()
    assert not (quarantine / plan['items'][0]['quarantine_relative']).exists()


@pytest.mark.parametrize('mutation', ['symlink', 'hardlink', 'fifo', 'protected_meta', 'alias', 'source_after_preview', 'budget'])
def test_unsafe_sources_are_rejected_before_payload_or_record_writes(case, monkeypatch, mutation):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    source = profile.root / 'logs/old.log'
    if mutation == 'symlink':
        source.unlink()
        source.symlink_to(profile.root / 'current.md')
    elif mutation == 'hardlink':
        os.link(source, profile.root / 'hard-copy.log')
    elif mutation == 'fifo':
        os.mkfifo(profile.root / 'exports/old/pipe')
    elif mutation == 'protected_meta':
        (profile.root / 'exports/old/item.meta').write_bytes(b'preserve metadata')
    elif mutation == 'alias':
        request = copy.deepcopy(request)
        request['items'][0]['source'] = 'logs/OLD.log'
    elif mutation == 'budget':
        data = copy.deepcopy(profile.data)
        data['budgets']['max_hash_bytes'] = 1
        profile = policy.load_profile(profile.root, profile.config, data)
    if mutation == 'source_after_preview':
        plan = ops.preview(profile, request, quarantine, records)
        source.write_bytes(b'new data after approval')
        action = lambda: ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    else:
        action = lambda: ops.preview(profile, request, quarantine, records)
    with pytest.raises((dc.DirectoryError, OSError)):
        action()
    assert source.exists() and (profile.root / 'exports/old').is_dir()
    assert not list(records.iterdir()) and not list(quarantine.iterdir())


def test_plan_tampering_and_target_occupancy_do_not_authorize_writes(case, monkeypatch):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    forged = copy.deepcopy(plan)
    forged['items'][0]['quarantine_relative'] = 'outside-payload'
    forged = dc.seal(forged)
    with pytest.raises(dc.DirectoryError):
        ops.apply(profile, forged, quarantine, records, approve_plan=forged['fingerprint'])
    assert not list(records.iterdir()) and not list(quarantine.iterdir())
    target = quarantine / plan['items'][0]['quarantine_relative']
    target.parent.mkdir(parents=True)
    target.write_bytes(b'existing foreign data')
    with pytest.raises(dc.DirectoryError):
        ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    assert target.read_bytes() == b'existing foreign data'
    assert not list(records.iterdir())


def test_tool_lock_refuses_overlapping_apply_and_recover(case):
    profile, request, quarantine, records = case
    plan = ops.preview(profile, request, quarantine, records)
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            with dc.root_lock(profile.root):
                os.write(ready_w, b'1')
                os.read(release_r, 1)
        finally:
            os._exit(0)
    try:
        assert os.read(ready_r, 1) == b'1'
        with pytest.raises(ValueError):
            ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
        with pytest.raises(ValueError):
            ops.recover(profile, records / ('cleanup-' + plan['operation_id']) / 'journal.json', quarantine, records, approve_plan=plan['fingerprint'])
        assert not list(records.iterdir()) and not list(quarantine.iterdir())
    finally:
        os.write(release_w, b'1')
        os.waitpid(pid, 0)
        for fd in (ready_r, ready_w, release_r, release_w):
            os.close(fd)


def test_inspected_fake_lsof_is_never_executed_even_when_sampling_optional(case, monkeypatch):
    profile, request, quarantine, records = case
    data = copy.deepcopy(profile.data)
    data['require_no_open_handles'] = False
    profile = policy.load_profile(profile.root, profile.config, data)
    fake = profile.root / 'lsof'
    fake.write_text('#!/bin/sh\nexit 0\n')
    fake.chmod(0o755)
    monkeypatch.setattr(ops.shutil, 'which', lambda _: str(fake))
    monkeypatch.setattr(ops, '_sample_handles', lambda *a, **k: pytest.fail('inspected executable was invoked'))
    with pytest.raises(dc.DirectoryError) as error:
        ops.preview(profile, request, quarantine, records)
    assert error.value.reason_code == 'PROTECTED_PATH'
    assert not list(records.iterdir()) and not list(quarantine.iterdir())


def test_old_build_bundle_code_files_keep_proof_and_postmove_revalidation(case, monkeypatch):
    profile, request, quarantine, records = case
    (profile.root / 'exports/old/runtime.js').write_bytes(b'closed bundled javascript')
    (profile.root / 'builds/current').mkdir(parents=True)
    (profile.root / 'builds/current/app.bin').write_bytes(b'retained runnable is not executed')
    build = {'platform': 'synthetic', 'branch': 'main', 'configuration': 'release', 'purpose': 'comparison'}
    data = copy.deepcopy(profile.data)
    data['candidates'] = [{'path': 'exports/old', 'kind': 'old_build'}]
    data['keep'] = [{'path': 'builds/current', 'reason': 'retained exact fixture build', 'build': build,
                     'evidence': request['items'][0]['closure']['evidence']}]
    profile = policy.load_profile(profile.root, profile.config, data)
    request = copy.deepcopy(request)
    request['items'] = [request['items'][1]]
    request['items'][0].update(kind='old_build', build=build, retained=['builds/current'])
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    restored_plan = ops.restore_preview(profile, held, quarantine, records)
    ops.restore(profile, restored_plan, quarantine, records, approve_plan=restored_plan['fingerprint'])
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    purge_plan = ops.purge_preview(profile, held, quarantine, records)
    purged = ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
    assert ops.verify(profile, purged, quarantine, records)['status'] == 'Passed'
    assert (profile.root / 'builds/current/app.bin').read_bytes() == b'retained runnable is not executed'


def test_initial_journal_failure_never_moves_and_unowned_slot_is_not_recreated(case, monkeypatch):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    original_save = ops._save
    def save(p, record, **kwargs):
        if kwargs.get('initial'):
            raise OSError('initial journal cannot be persisted')
        return original_save(p, record, **kwargs)
    monkeypatch.setattr(ops, '_save', save)
    with pytest.raises(OSError):
        ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    monkeypatch.setattr(ops, '_save', original_save)
    slot = records / ('cleanup-' + plan['operation_id'])
    assert slot.is_dir() and not list(slot.iterdir())
    with pytest.raises((dc.DirectoryError, OSError)):
        ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    assert len(list(records.iterdir())) == 1 and not list(quarantine.iterdir())
    assert all((profile.root / i['source']).exists() for i in request['items'])


def test_unrecorded_missing_payload_never_becomes_purged(case, monkeypatch):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    (quarantine / plan['items'][0]['quarantine_relative']).unlink()
    assert ops.verify(profile, held, quarantine, records)['status'] == 'Failed'
    with pytest.raises(dc.DirectoryError):
        ops.purge_preview(profile, held, quarantine, records)
    with pytest.raises(dc.DirectoryError):
        ops.recover(profile, held, quarantine, records)
    assert (quarantine / plan['items'][1]['quarantine_relative']).is_dir()


def test_new_current_consumer_after_purge_preview_blocks_delete_but_allows_restore(case, monkeypatch):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    purge_plan = ops.purge_preview(profile, held, quarantine, records)
    (profile.root / 'current.md').write_text('new current logs/old.log consumer\n')
    with pytest.raises(dc.DirectoryError):
        ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
    pending = ops.load_record_metadata(profile, held['journal_path'], records)
    assert all(not i['removed'] for i in pending['items'])
    assert all((quarantine / i['quarantine_relative']).exists() for i in plan['items'])
    assert pending['purge_plan'] is None
    restore_plan = ops.restore_preview(profile, pending, quarantine, records)
    restored = ops.restore(profile, restore_plan, quarantine, records, approve_plan=restore_plan['fingerprint'])
    assert restored['state'] == 'Restored'


def test_record_metadata_loader_does_not_probe_project_or_quarantine(case, monkeypatch):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    original_stat = dc.stat_entry
    def only_records(root, rel):
        assert Path(root) != profile.root and Path(root) != quarantine
        return original_stat(root, rel)
    monkeypatch.setattr(dc, 'stat_entry', only_records)
    assert ops.load_record_metadata(profile, held, records)['fingerprint'] == held['fingerprint']


@pytest.mark.parametrize('interruption', ['forward_gate', 'before_unlink'])
def test_persisted_purge_without_any_actual_delete_can_be_explicitly_cancelled_to_restore(case, monkeypatch, interruption):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    purge_plan = ops.purge_preview(profile, held, quarantine, records)
    real_forward = ops._forward
    def drift_after_persist(p, record, q, material):
        if record['purge_plan'] is not None:
            (profile.root / 'current.md').write_text('new current logs/old.log consumer\n')
        return real_forward(p, record, q, material)
    if interruption == 'forward_gate':
        monkeypatch.setattr(ops, '_forward', drift_after_persist)
    else:
        original_unlink = os.unlink
        def before_unlink(name, *args, **kwargs):
            if str(name) == 'payload-0000':
                (profile.root / 'current.md').write_text('new current logs/old.log consumer\n')
                raise OSError('interrupted with durable unlink intent before syscall')
            return original_unlink(name, *args, **kwargs)
        monkeypatch.setattr(os, 'unlink', before_unlink)
    with pytest.raises((dc.DirectoryError, OSError)):
        ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
    pending = ops.load_record_metadata(profile, held['journal_path'], records)
    assert pending['purge_plan'] is not None and not any(i['removed'] for i in pending['items'])
    checked = ops.verify(profile, pending, quarantine, records)
    assert checked['status'] == 'Unknown' and checked['restore_possible'] and not checked['irreversible']
    restore_plan = ops.restore_preview(profile, pending, quarantine, records)
    assert restore_plan['kind'] == 'restore'
    with pytest.raises(dc.DirectoryError):
        ops.restore(profile, restore_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
    if interruption == 'before_unlink':
        child_exit_after_syscall(lambda: ops.restore(profile, restore_plan, quarantine, records, approve_plan=restore_plan['fingerprint']), 'restore', profile.root)
        restoring = ops.load_record_metadata(profile, pending['journal_path'], records)
        assert restoring['purge_plan'] is None and restoring['cancelled_purge'] == purge_plan['fingerprint']
        restored = ops.recover(profile, restoring, quarantine, records, approve_plan=restore_plan['fingerprint'])
    else:
        restored = ops.restore(profile, restore_plan, quarantine, records, approve_plan=restore_plan['fingerprint'])
    assert restored['state'] == 'Restored' and restored['purge_plan'] is None
    assert restored['cancelled_purge'] == purge_plan['fingerprint']
    assert ops.verify(profile, restored, quarantine, records)['status'] == 'Passed'
    with pytest.raises(dc.DirectoryError) as error:
        ops.purge(profile, purge_plan, quarantine, records, approve_plan=purge_plan['fingerprint'])
    assert error.value.reason_code == 'PLAN_ALREADY_CONSUMED'
    assert ops.recover(profile, restored, quarantine, records)['state'] == 'Restored'


@pytest.mark.parametrize('scope', ['quarantine', 'records', 'project'])
@pytest.mark.parametrize('window', ['before_lock', 'opened_fd'])
def test_root_replacement_during_lock_acquisition_stops_before_any_write(case, monkeypatch, scope, window):
    from contextlib import contextmanager
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    selected = {'quarantine': quarantine, 'records': records, 'project': profile.root}[scope]
    retired = selected.with_name(selected.name + '-retired')
    before = {i['source']: snapshot(profile.root / i['source']) for i in request['items']}
    fired = [False]
    def replace():
        assert not fired[0]
        selected.rename(retired)
        selected.mkdir()
        assert selected.stat().st_ino != retired.stat().st_ino
        fired[0] = True
    if window == 'before_lock':
        original_locks = ops._locks
        @contextmanager
        def locks(*args, **kwargs):
            replace()
            with original_locks(*args, **kwargs):
                yield
        monkeypatch.setattr(ops, '_locks', locks)
    else:
        original_open, original_locks = dc.open_dir, ops._locks
        in_locks = [False]
        @contextmanager
        def locks(*args, **kwargs):
            in_locks[0] = True
            try:
                with original_locks(*args, **kwargs):
                    yield
            finally:
                in_locks[0] = False
        @contextmanager
        def opened(root, rel='.'):
            with original_open(root, rel) as fd:
                if in_locks[0] and Path(root) == selected and rel == '.' and not fired[0]:
                    replace()
                yield fd
        monkeypatch.setattr(ops, '_locks', locks)
        monkeypatch.setattr(dc, 'open_dir', opened)
    with pytest.raises(dc.DirectoryError) as error:
        ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    assert error.value.reason_code == 'SOURCE_CHANGED'
    assert fired[0]
    actual_project = retired if scope == 'project' else profile.root
    assert {source: snapshot(actual_project / source) for source in before} == before
    # Neither the retired original nor the new empty external root received a
    # payload/journal. Root replacement is not a syscall-sized write race.
    assert not list(quarantine.iterdir()) and not list(records.iterdir())
    if scope != 'project':
        assert not list(retired.iterdir())


@pytest.mark.parametrize('entrypoint', ['restore', 'purge', 'recover'])
@pytest.mark.parametrize('scope', ['quarantine', 'records', 'project'])
def test_mutating_actions_reject_replaced_root_before_loading_or_writing(case, monkeypatch, entrypoint, scope):
    from contextlib import contextmanager
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    held = ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    if entrypoint == 'restore':
        action_plan = ops.restore_preview(profile, held, quarantine, records)
        action = lambda: ops.restore(profile, action_plan, quarantine, records, approve_plan=action_plan['fingerprint'])
    elif entrypoint == 'purge':
        action_plan = ops.purge_preview(profile, held, quarantine, records)
        action = lambda: ops.purge(profile, action_plan, quarantine, records, approve_plan=action_plan['fingerprint'])
    else:
        action = lambda: ops.recover(profile, held, quarantine, records)
    paths = {'project': profile.root, 'quarantine': quarantine, 'records': records}
    before = {label: snapshot(root) for label, root in paths.items()}
    selected = paths[scope]
    retired = selected.with_name(selected.name + '-retired')
    original_locks = ops._locks
    @contextmanager
    def locks(*args, **kwargs):
        selected.rename(retired)
        selected.mkdir()
        with original_locks(*args, **kwargs):
            yield
    monkeypatch.setattr(ops, '_locks', locks)
    with pytest.raises(dc.DirectoryError) as error:
        action()
    assert error.value.reason_code == 'SOURCE_CHANGED'
    assert not list(selected.iterdir())
    for label, original in before.items():
        assert snapshot(retired if label == scope else paths[label]) == original


def test_cleanup_held_fd_lock_also_blocks_legacy_maintenance_lock(case):
    profile, request, quarantine, records = case
    _, _, roots = ops._roots(profile, quarantine, records)
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            with ops._locks(profile, quarantine, records, roots):
                os.write(ready_w, b'1')
                os.read(release_r, 1)
        finally:
            os._exit(0)
    try:
        assert os.read(ready_r, 1) == b'1'
        with pytest.raises(dc.DirectoryError) as error:
            with dc.root_lock(profile.root):
                pytest.fail('legacy lock must conflict with the cleanup FD lock')
        assert error.value.reason_code == 'PROJECT_BUSY'
    finally:
        os.write(release_w, b'1')
        os.waitpid(pid, 0)
        for fd in (ready_r, ready_w, release_r, release_w):
            os.close(fd)


def test_cleanup_lock_unavailable_fails_closed_before_payload_reads_or_writes(case, monkeypatch):
    profile, request, quarantine, records = case
    monkeypatch.setattr(ops, '_sample', lambda *args: {'status': 'ClearSample', 'guarantee': 'sampling_only'})
    plan = ops.preview(profile, request, quarantine, records)
    def unavailable(*args):
        raise OSError('unsupported directory flock')
    monkeypatch.setattr(ops.fcntl, 'flock', unavailable)
    with pytest.raises(dc.DirectoryError) as error:
        ops.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    assert error.value.reason_code == 'SAFE_IO_UNAVAILABLE'
    assert not list(records.iterdir()) and not list(quarantine.iterdir())
    assert all((profile.root / item['source']).exists() for item in request['items'])
