import os

import pytest

from fifan_maintenance import directory_common as dc


@pytest.mark.parametrize('directory', [False, True])
def test_entry_move_preserves_identity_and_old_directory_contract(tmp_path, directory):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    path = source / 'payload'
    if directory:
        path.mkdir()
        (path / 'content').write_bytes(b'original')
    else:
        path.write_bytes(b'original')
        with pytest.raises(dc.DirectoryError):
            dc.rename_noreplace(source, 'payload', target, 'payload')
        assert path.read_bytes() == b'original'
    before = path.stat()
    dc.rename_entry_noreplace(source, 'payload', target, 'payload')
    assert not path.exists()
    after = (target / 'payload').stat()
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns) == (before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns)
    assert (target / 'payload' / 'content' if directory else target / 'payload').read_bytes() == b'original'


def test_entry_move_native_exclusion_wins_destination_race(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    (source / 'payload').write_bytes(b'original')
    native = dc._renameat_noreplace
    def competing_file(source_fd, source_name, target_fd, target_name):
        (target / 'payload').write_bytes(b'foreign')
        return native(source_fd, source_name, target_fd, target_name)
    monkeypatch.setattr(dc, '_renameat_noreplace', competing_file)
    with pytest.raises(dc.DirectoryError) as error:
        dc.rename_entry_noreplace(source, 'payload', target, 'payload')
    assert error.value.reason_code == 'DESTINATION_EXISTS'
    assert (source / 'payload').read_bytes() == b'original'
    assert (target / 'payload').read_bytes() == b'foreign'


def test_entry_move_shared_file_rejected_without_moving_either_name(tmp_path):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    (source / 'payload').write_bytes(b'original')
    os.link(source / 'payload', source / 'second-name')
    with pytest.raises(dc.DirectoryError):
        dc.rename_entry_noreplace(source, 'payload', target, 'payload')
    assert (source / 'payload').read_bytes() == (source / 'second-name').read_bytes() == b'original'
    assert list(target.iterdir()) == []


def test_entry_move_sync_failure_reports_real_postrename_state(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    (source / 'payload').write_bytes(b'original')
    def failed_sync(fd):
        raise OSError('injected durability failure')
    monkeypatch.setattr(dc.os, 'fsync', failed_sync)
    with pytest.raises(OSError):
        dc.rename_entry_noreplace(source, 'payload', target, 'payload')
    assert not (source / 'payload').exists()
    assert (target / 'payload').read_bytes() == b'original'


def test_directory_profile_can_leave_ungranted_declarations_unprobed(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    declared = tmp_path / 'ungranted'
    data = {'schema_version': 1, 'project_root': str(project),
            'archive': {'archive_root': str(declared / 'archive'),
                        'records_dir': str(declared / 'records')}}
    original = dc.canonical_destination
    def forbidden(path, *args, **kwargs):
        if Path(path).is_relative_to(declared):
            raise AssertionError('ungranted profile declaration was accessed')
        return original(path, *args, **kwargs)
    from pathlib import Path
    monkeypatch.setattr(dc, 'canonical_destination', forbidden)
    profile = dc.load_profile(project, {}, data, external_metadata=False)
    assert profile.data['archive']['archive_root'] == str(declared / 'archive')
    assert not declared.exists()
    data['project_root'] = str(declared / 'other-project')
    with pytest.raises(dc.DirectoryError) as error:
        dc.load_profile(project, {}, data, external_metadata=False)
    assert error.value.reason_code == 'PROFILE_CONFLICT'


def test_unprobed_directory_profile_keeps_native_old_data_and_fingerprint(tmp_path):
    project, archive, records = [tmp_path / part for part in ('project', 'archive', 'records')]
    for path in (project, archive, records):
        path.mkdir()
    data = {'schema_version': 1, 'project_root': str(project),
            'archive': {'archive_root': str(archive), 'records_dir': str(records)}}
    legacy = dc.load_profile(project, {}, data)
    unprobed = dc.load_profile(project, {}, data, external_metadata=False)
    assert legacy.data == unprobed.data
    assert legacy.sha256 == unprobed.sha256
