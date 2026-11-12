from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import stat
import sys

import pytest

from fifan_maintenance import directory_common as common
from fifan_maintenance.project import load_config


def make_profile(tmp_path, **extra):
    project = tmp_path / 'project'
    project.mkdir(exist_ok=True)
    data = {'schema_version': 1, 'project_root': str(project), **extra}
    return common.load_profile(project, load_config(project), data)


def test_profile_defaults_are_independent_of_old_project_config(tmp_path):
    profile = make_profile(tmp_path)
    original = load_config(profile.root)
    assert profile.config == original
    assert 'scan_roots' not in original
    assert profile.data['scan_roots'] == ['.']
    assert profile.data['preset'] == 'generic'
    assert profile.data['search'] == {'exclude': [], 'vscode': False, 'watcher_exclude': False}
    assert profile.data['archive'] == {'candidates': [], 'require_no_open_handles': True}
    assert profile.sha256 == common.digest(profile.data)
    assert profile.budgets == common.DEFAULT_BUDGETS
    assert common.canonical({'x': '中', 'a': 1}) == b'{"a":1,"x":"\\u4e2d"}'
    profile.config['exclude'].append('one')
    assert original['exclude'] == []


def test_profile_file_is_external_fd_strict_json(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    raw = {'schema_version': 1, 'project_root': str(project), 'scan_roots': ['src']}
    external = tmp_path / 'profile.json'
    external.write_text(json.dumps(raw))
    assert common.load_profile(project, load_config(project), external).data['scan_roots'] == ['src']
    (project / 'profile.json').write_text(json.dumps(raw))
    with pytest.raises(common.DirectoryError, match='outside project'):
        common.load_profile(project, load_config(project), project / 'profile.json')
    external.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(common.DirectoryError) as error:
        common.load_profile(project, load_config(project), external)
    assert error.value.reason_code == 'ARTIFACT_INVALID'
    external.write_text('{"x":NaN}')
    with pytest.raises(common.DirectoryError):
        common.load_artifact(external)
    external.write_text('[]')
    with pytest.raises(common.DirectoryError):
        common.load_artifact(external)


@pytest.mark.parametrize('extra', [
    {'unknown': 1}, {'schema_version': True}, {'preset': 'custom'},
    {'project_root': '/wrong'}, {'scan_roots': []}, {'scan_roots': ['x', 'x']},
    {'scan_roots': ['../x']}, {'critical_paths': ['x/./y']}, {'search': {'command': 'run'}},
    {'search': {'vscode': 1}}, {'search': {'exclude': ['.']}},
    {'archive': {'candidates': ['.']}}, {'archive': {'records_dir': 'relative'}},
    {'archive': {'require_no_open_handles': 'yes'}},
    {'reference_sources': [{'path': 'a', 'role': 'unknown'}]},
    {'reference_sources': [{'path': 'a', 'role': 'current'}, {'path': 'a', 'role': 'historical'}]},
    {'classifications': [{'path': 'a', 'role': 'keep', 'reason': ''}]},
    {'classifications': [{'path': 'a', 'role': 'keep', 'reason': 'x', 'extra': 1}]},
    {'budgets': {'extra': 1}}, {'budgets': {'max_seconds': True}},
    {'budgets': {'max_entries': 1000001}}, {'budgets': {'max_hash_bytes': 64 * common.GiB + 1}},
    {'budgets': {'max_hash_file_bytes': 4 * common.GiB + 1}},
    {'budgets': {'max_artifact_bytes': 128 * common.MiB + 1}},
])
def test_invalid_profiles_are_rejected(tmp_path, extra):
    with pytest.raises(common.DirectoryError):
        make_profile(tmp_path, **extra)


def test_protection_reuses_project_contract_and_unity_archive_guards(tmp_path):
    profile = make_profile(tmp_path, preset='unity')
    for path in ('.git/config', '.env', '.env.local', 'Library/cache', '.venv/inside'):
        assert common.protected(profile, path)
    for path in ('Assets/hero.png', 'Packages/manifest.json', 'ProjectSettings/ProjectVersion.txt', 'file.meta'):
        assert common.protected(profile, path, archive=True)
    assert not common.protected(profile, 'Assets/hero.png')
    assert not common.protected(profile, 'docs/archive')
    assert common.protected(profile, '.', archive=True)
    profile.config['exclude'] = ['private/**']
    assert common.protected(profile, 'private/document')


def test_relative_and_safe_root_reject_links_and_ambiguity(tmp_path):
    profile = make_profile(tmp_path)
    assert common.relative('.', allow_dot=True) == '.'
    for path in ('.', '..', '/abs', 'a/../b', 'a//b', 'a\\b', 'a\x00b', ''):
        with pytest.raises(common.DirectoryError):
            common.relative(path)
    link = tmp_path / 'linked'
    link.symlink_to(profile.root, target_is_directory=True)
    with pytest.raises((OSError, common.DirectoryError)):
        common.safe_root(link)
    (profile.root / 'sub').mkdir()
    with pytest.raises((OSError, common.DirectoryError)):
        common.safe_root(link / 'sub')
    with pytest.raises(common.DirectoryError):
        common.safe_root(str(profile.root) + '/../project')


def test_seal_is_copy_and_detects_tampering_without_echoing_material():
    original = {'secret': 'DO NOT ECHO', 'fingerprint': 'old'}
    sealed = common.seal(original)
    assert original['fingerprint'] == 'old'
    common.validate_seal(sealed)
    sealed['secret'] = 'changed'
    with pytest.raises(common.DirectoryError) as error:
        common.validate_seal(sealed)
    assert error.value.reason_code == 'ARTIFACT_INVALID'
    assert 'DO NOT ECHO' not in str(error.value)
    custom = common.seal({'a': 1}, 'sha')
    common.validate_seal(custom, 'sha')
    with pytest.raises(common.DirectoryError):
        common.canonical({'x': float('inf')})


def test_artifact_noclobber_replace_private_mode_and_budget(tmp_path):
    path = tmp_path / 'report.json'
    assert common.write_artifact(path, {'a': '中'}) == path
    assert common.load_artifact(path) == {'a': '中'}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        common.write_artifact(path, {'a': 2})
    assert common.load_artifact(path) == {'a': '中'}
    common.write_artifact(path, {'a': 3}, replace=True)
    assert common.load_artifact(path) == {'a': 3}
    with pytest.raises(common.DirectoryError) as error:
        common.write_artifact(tmp_path / 'large.json', {'big': 'x' * 100}, limit=20)
    assert error.value.reason_code == 'BUDGET_EXHAUSTED'
    assert not (tmp_path / 'large.json').exists()
    assert not list(tmp_path.glob('.fifan-directory-*.tmp'))
    with pytest.raises(common.DirectoryError):
        common.load_artifact(path, limit=2)
    with pytest.raises(common.DirectoryError):
        common.write_artifact(path, {'a': float('nan')}, replace=True)
    assert common.load_artifact(path) == {'a': 3}


def test_artifact_rejects_link_parent_and_link_target_preserves_original(tmp_path):
    actual = tmp_path / 'actual'
    actual.mkdir()
    link = tmp_path / 'linked'
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises((OSError, common.DirectoryError)):
        common.write_artifact(link / 'report.json', {'x': 1})
    (actual / 'original').write_bytes(b'original')
    (actual / 'link.json').symlink_to(actual / 'original')
    with pytest.raises((OSError, common.DirectoryError)):
        common.load_artifact(actual / 'link.json')
    with pytest.raises(common.DirectoryError):
        common.write_artifact(actual / 'link.json', {'x': 1}, replace=True)
    assert (actual / 'original').read_bytes() == b'original'


def test_external_roots_require_runtime_grants_and_nonoverlap(tmp_path):
    arc, rec = tmp_path / 'archive', tmp_path / 'records'
    arc.mkdir()
    rec.mkdir()
    profile = make_profile(tmp_path, archive={'archive_root': str(arc), 'records_dir': str(rec)})
    with pytest.raises(common.DirectoryError):
        common.external_roots(profile, None, rec)
    assert common.external_roots(profile, arc, rec) == (arc, rec)
    with pytest.raises(common.DirectoryError):
        common.external_roots(profile, rec, arc)
    nested = profile.root / 'records'
    nested.mkdir()
    nested_profile = make_profile(tmp_path, archive={'archive_root': str(arc), 'records_dir': str(nested)})
    with pytest.raises(common.DirectoryError):
        common.external_roots(nested_profile, arc, nested)
    arc_child = arc / 'records'
    arc_child.mkdir()
    overlap = make_profile(tmp_path, archive={'archive_root': str(arc), 'records_dir': str(arc_child)})
    with pytest.raises(common.DirectoryError):
        common.external_roots(overlap, arc, arc_child)


def test_fd_directory_and_file_helpers_do_not_follow_links(tmp_path):
    profile = make_profile(tmp_path)
    (profile.root / 'dir').mkdir()
    (profile.root / 'dir' / 'a').write_bytes(b'payload')
    (profile.root / 'link').symlink_to(profile.root / 'dir', target_is_directory=True)
    assert stat.S_ISLNK(common.stat_entry(profile.root, 'link').st_mode)
    with pytest.raises(OSError):
        with common.open_dir(profile.root, 'link'):
            pass
    with common.open_dir(profile.root, 'dir') as fd:
        assert [entry.name for entry in os.scandir(fd)] == ['a']
    assert common.read_file(profile.root, 'dir/a', 7) == b'payload'
    with pytest.raises(ValueError):
        common.read_file(profile.root, 'dir/a', 6)
    with pytest.raises(FileNotFoundError):
        common.stat_entry(profile.root, 'missing')
    with pytest.raises(OSError):
        common.read_file(profile.root, 'link/a', 99)


def test_open_dir_replaced_root_is_detected(tmp_path):
    profile = make_profile(tmp_path)
    with pytest.raises(common.DirectoryError) as error:
        with common.open_dir(profile.root):
            profile.root.rename(tmp_path / 'old-project')
            profile.root.mkdir()
    assert error.value.reason_code == 'SOURCE_CHANGED'


def test_hash_is_streaming_complete_and_preserves_shared_budget(tmp_path, monkeypatch):
    profile = make_profile(tmp_path)
    content = (b'large-payload' * 100000) + b'last'
    (profile.root / 'large').write_bytes(content)
    budget = common.HashBudget(profile.budgets)
    calls = []
    original = common.os.read
    def bounded_read(fd, size):
        calls.append(size)
        assert size <= 1024 * 1024
        return original(fd, size)
    monkeypatch.setattr(common.os, 'read', bounded_read)
    result = common.stream_hash(profile, 'large', budget)
    assert result['sha256'] == hashlib.sha256(content).hexdigest()
    assert result['bytes'] == len(content)
    assert result['device'] == (profile.root / 'large').stat().st_dev
    assert result['inode'] == (profile.root / 'large').stat().st_ino
    assert calls and len(calls) > 1
    assert budget.snapshot()['hash_bytes'] == len(content)
    assert budget.entries == 1
    common.stream_hash(profile, 'large', budget)
    assert budget.bytes == 2 * len(content) and budget.entries == 2


def test_hash_rejects_protected_special_links_and_replaced_profile_root(tmp_path):
    profile = make_profile(tmp_path)
    (profile.root / '.env').write_bytes(b'secret')
    (profile.root / 'ordinary').write_bytes(b'normal')
    (profile.root / 'link').symlink_to(profile.root / 'ordinary')
    os.mkfifo(profile.root / 'fifo')
    for rel in ('.env', 'link', 'fifo'):
        with pytest.raises((OSError, common.DirectoryError)):
            common.stream_hash(profile, rel, common.HashBudget(profile))
    profile.root.rename(tmp_path / 'original')
    profile.root.mkdir()
    (profile.root / 'ordinary').write_bytes(b'normal')
    with pytest.raises(common.DirectoryError) as error:
        common.stream_hash(profile, 'ordinary', common.HashBudget(profile))
    assert error.value.reason_code == 'SOURCE_CHANGED'


def test_hash_budget_entry_file_total_time_and_partial_failure(tmp_path, monkeypatch):
    profile = make_profile(tmp_path, budgets={'max_hash_entries': 1, 'max_hash_bytes': 5, 'max_hash_file_bytes': 5})
    (profile.root / 'a').write_bytes(b'12345')
    (profile.root / 'b').write_bytes(b'123456')
    budget = common.HashBudget(profile)
    common.stream_hash(profile, 'a', budget)
    assert budget.bytes == 5
    with pytest.raises(common.DirectoryError) as error:
        common.stream_hash(profile, 'a', budget)
    assert error.value.reason_code == 'BUDGET_EXHAUSTED'
    with pytest.raises(common.DirectoryError):
        common.stream_hash(profile, 'b', common.HashBudget(profile))
    timer = common.HashBudget(profile)
    timer.started -= 61
    with pytest.raises(common.DirectoryError):
        common.stream_hash(profile, 'a', timer)
    with pytest.raises(common.DirectoryError):
        common.HashBudget({'max_hash_bytes': common.HARD_BUDGETS['max_hash_bytes'] + 1})
    with pytest.raises(common.DirectoryError):
        common.stream_hash(profile, 'a', common.HashBudget(common.DEFAULT_BUDGETS))
    original = common.os.read
    def read_then_expire(fd, size):
        data = original(fd, size)
        charged.started -= 61
        return data
    charged = common.HashBudget(profile)
    monkeypatch.setattr(common.os, 'read', read_then_expire)
    with pytest.raises(common.DirectoryError):
        common.stream_hash(profile, 'a', charged)
    assert charged.bytes == 5


def test_hash_file_mutated_during_read_returns_no_partial_sha(tmp_path, monkeypatch):
    profile = make_profile(tmp_path)
    path = profile.root / 'a'
    path.write_bytes(b'original')
    original = common.os.read
    changed = []
    def mutate(fd, size):
        data = original(fd, size)
        if not changed:
            path.write_bytes(b'other')
            changed.append(True)
        return data
    monkeypatch.setattr(common.os, 'read', mutate)
    budget = common.HashBudget(profile)
    with pytest.raises(common.DirectoryError) as error:
        common.stream_hash(profile, 'a', budget)
    assert error.value.reason_code == 'SOURCE_CHANGED'
    assert budget.bytes >= len(b'original')


def test_archive_hash_root_is_explicit_and_profile_bound(tmp_path):
    arc = tmp_path / 'archive'
    arc.mkdir()
    (arc / 'file').write_bytes(b'archived')
    profile = make_profile(tmp_path, archive={'archive_root': str(arc)})
    result = common.stream_hash(profile, 'file', common.HashBudget(profile), root=arc)
    assert result['sha256'] == hashlib.sha256(b'archived').hexdigest()
    with pytest.raises(common.DirectoryError):
        common.stream_hash(profile, 'file', common.HashBudget(profile), root=tmp_path)


@pytest.mark.skipif(sys.platform != 'darwin', reason='actual no-replace primitive is Darwin-specific')
def test_real_same_volume_directory_rename_and_existing_target_noclobber(tmp_path):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    (source / 'batch').mkdir()
    (source / 'batch' / 'payload').write_bytes(b'original')
    identity = common.stat_entry(source, 'batch').st_ino
    common.rename_noreplace(source, 'batch', target, 'archived')
    assert not (source / 'batch').exists()
    assert (target / 'archived' / 'payload').read_bytes() == b'original'
    assert common.stat_entry(target, 'archived').st_ino == identity
    (source / 'second').mkdir()
    (source / 'second' / 'new').write_bytes(b'other')
    with pytest.raises(common.DirectoryError) as error:
        common.rename_noreplace(source, 'second', target, 'archived')
    assert error.value.reason_code == 'DESTINATION_EXISTS'
    assert (source / 'second' / 'new').read_bytes() == b'other'
    assert (target / 'archived' / 'payload').read_bytes() == b'original'


@pytest.mark.skipif(sys.platform != 'darwin', reason='actual no-replace primitive is Darwin-specific')
def test_real_target_created_immediately_before_syscall_is_preserved(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    (source / 'batch').mkdir()
    (source / 'batch' / 'original').write_bytes(b'source')
    primitive = common._renameat_noreplace
    def raced(source_fd, source_name, target_fd, target_name):
        os.mkdir(target_name, dir_fd=target_fd)
        child = os.open(target_name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=target_fd)
        try:
            descriptor = os.open('winner', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=child)
            os.write(descriptor, b'concurrent writer')
            os.close(descriptor)
        finally:
            os.close(child)
        primitive(source_fd, source_name, target_fd, target_name)
    monkeypatch.setattr(common, '_renameat_noreplace', raced)
    with pytest.raises(common.DirectoryError) as error:
        common.rename_noreplace(source, 'batch', target, 'batch')
    assert error.value.reason_code == 'DESTINATION_EXISTS'
    assert (target / 'batch' / 'winner').read_bytes() == b'concurrent writer'
    assert (source / 'batch' / 'original').read_bytes() == b'source'


def test_unavailable_rename_primitive_fails_closed(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    (source / 'batch').mkdir()
    monkeypatch.setattr(common.sys, 'platform', 'unsupported')
    with pytest.raises(common.DirectoryError) as error:
        common.rename_noreplace(source, 'batch', target, 'batch')
    assert error.value.reason_code == 'RENAME_UNAVAILABLE'
    assert (source / 'batch').is_dir() and not (target / 'batch').exists()


def test_root_lock_is_real_exclusive_and_releases_after_failure(tmp_path):
    profile = make_profile(tmp_path)
    with common.root_lock(profile.root):
        with pytest.raises(common.DirectoryError) as error:
            with common.root_lock(profile.root):
                pass
        assert error.value.reason_code == 'PROJECT_BUSY'
    with common.root_lock(profile.root):
        pass


@pytest.mark.parametrize('extra', [
    {'preset': []}, {'reference_sources': [{'path': 'a', 'role': []}]},
    {'classifications': [{'path': 'a', 'role': {}, 'reason': 'x'}]},
    {'budgets': {'max_hash_bytes': []}}, {'archive': {'archive_root': {}}},
    {'search': {'exclude': [{}]}},
])
def test_malformed_value_types_have_controlled_failures(tmp_path, extra):
    with pytest.raises(common.DirectoryError):
        make_profile(tmp_path, **extra)


def test_read_file_detects_root_replacement_even_if_old_handle_stays_open(tmp_path, monkeypatch):
    profile = make_profile(tmp_path)
    (profile.root / 'source').write_bytes(b'old payload')
    original = common.read_bytes
    def replace_root(root, rel, limit):
        data = original(root, rel, limit)
        root.rename(tmp_path / 'old-project')
        root.mkdir()
        (root / rel).write_bytes(b'new payload')
        return data
    monkeypatch.setattr(common, 'read_bytes', replace_root)
    with pytest.raises(common.DirectoryError) as error:
        common.read_file(profile.root, 'source', 100)
    assert error.value.reason_code == 'SOURCE_CHANGED'
    assert (profile.root / 'source').read_bytes() == b'new payload'


def test_cross_device_precondition_does_not_invoke_rename(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    (source / 'batch').mkdir()
    original = common.os.fstat
    target_inode = target.stat().st_ino
    class DifferentDevice:
        st_dev = source.stat().st_dev + 100
    def fake_device(fd):
        info = original(fd)
        return DifferentDevice() if info.st_ino == target_inode else info
    # open_dir needs inode to verify descriptor identity, then rename checks dev.
    DifferentDevice.st_ino = target_inode
    monkeypatch.setattr(common.os, 'fstat', fake_device)
    def forbidden(*args):
        raise AssertionError('cross-device rename attempted')
    monkeypatch.setattr(common, '_renameat_noreplace', forbidden)
    with pytest.raises(common.DirectoryError) as error:
        common.rename_noreplace(source, 'batch', target, 'batch')
    assert error.value.reason_code == 'CROSS_DEVICE'
    assert (source / 'batch').is_dir() and not (target / 'batch').exists()


def test_profile_input_has_256kib_limit_for_file_and_dictionary(tmp_path):
    profile = make_profile(tmp_path)
    data = {'schema_version': 1, 'project_root': str(profile.root),
            'classifications': [{'path': 'history', 'role': 'historical',
                                 'reason': 'x' * common.MAX_PROFILE_BYTES}]}
    with pytest.raises(common.DirectoryError) as error:
        common.load_profile(profile.root, profile.config, data)
    assert error.value.reason_code == 'BUDGET_EXHAUSTED'
    path = tmp_path / 'oversized-profile.json'
    path.write_bytes(common.canonical(data))
    with pytest.raises(common.DirectoryError):
        common.load_profile(profile.root, profile.config, path)
    # Exact file bytes, including padding, are bounded before JSON parsing.
    path.write_bytes(common.canonical({'schema_version': 1, 'project_root': str(profile.root)})
                     + b' ' * common.MAX_PROFILE_BYTES)
    with pytest.raises(common.DirectoryError):
        common.load_profile(profile.root, profile.config, path)


def test_path_key_preserves_unicode_execution_paths_but_rejects_alias_duplicates(tmp_path):
    import unicodedata
    assert common.path_key('Résumé/当前') == common.path_key(unicodedata.normalize('NFD', 'RÉSUMÉ/当前'))
    for extra in (
        {'scan_roots': ['History', 'history']},
        {'archive': {'candidates': ['Résumé', unicodedata.normalize('NFD', 'RÉSUMÉ')]}},
        {'reference_sources': [{'path': 'History/current', 'role': 'current'}, {'path': 'HISTORY/CURRENT', 'role': 'historical'}]},
        {'classifications': [{'path': 'History/active', 'role': 'active', 'reason': 'current'}, {'path': 'history/ACTIVE', 'role': 'historical', 'reason': 'old'}]},
    ):
        with pytest.raises(common.DirectoryError):
            make_profile(tmp_path, **extra)
    profile = make_profile(tmp_path, classifications=[{'path': 'History', 'role': 'historical', 'reason': 'archive'},
                                                     {'path': 'HISTORY/Current', 'role': 'active', 'reason': 'keep'}])
    assert common.path_key(profile.data['classifications'][1]['path']).startswith(common.path_key('History') + '/')


def test_case_unicode_aliases_cannot_bypass_new_protection(tmp_path):
    import unicodedata
    profile = make_profile(tmp_path, preset='unity')
    (profile.root / '.git').mkdir()
    assert (profile.root / '.GIT').exists()  # Actual local APFS alias reproduction.
    for path in ('.GIT', '.GiT/config', '.ENV.local', '.VENV/py', 'LIBRARY/data',
                 'aSsEtS/hero', 'PACKAGES', 'projectsettings/data', 'a.META'):
        assert common.protected(profile, path, archive=True)
    profile.config['exclude'] = ['Résumé/**']
    assert common.protected(profile, unicodedata.normalize('NFD', 'RÉSUMÉ/private'))
    assert not common.protected(profile, '中文目录/正常文档')


def test_native_canonical_roots_and_destinations_resolve_actual_aliases(tmp_path):
    profile = make_profile(tmp_path)
    alias = profile.root.with_name('PROJECT')
    assert alias.exists()  # Actual case-insensitive volume behavior.
    assert common.safe_root(alias) == profile.root
    assert common.canonical_destination(alias / 'new' / 'report.json') == profile.root / 'new' / 'report.json'
    (profile.root / 'Résumé').mkdir()
    (profile.root / 'Résumé' / '报告.json').write_bytes(b'{}')
    assert common.canonical_destination(alias / 'RÉSUMÉ' / '报告.json') == profile.root / 'Résumé' / '报告.json'
    common.validate_path_spelling(profile.root, 'Résumé/报告.json')
    with pytest.raises(common.DirectoryError) as error:
        common.validate_path_spelling(profile.root, 'RÉSUMÉ/报告.json')
    assert error.value.reason_code == 'PATH_ALIAS'
    common.validate_path_spelling(profile.root, 'Résumé/new/path', allow_missing=True)
    with pytest.raises((common.DirectoryError, FileNotFoundError)):
        common.canonical_destination(profile.root / 'missing' / 'file', allow_missing_parents=False)


def test_profile_external_boundary_uses_canonical_native_parent(tmp_path):
    profile = make_profile(tmp_path)
    raw = {'schema_version': 1, 'project_root': str(profile.root)}
    (profile.root / 'profile.json').write_text(json.dumps(raw))
    alias = profile.root.with_name('PROJECT') / 'profile.json'
    with pytest.raises(common.DirectoryError, match='outside project'):
        common.load_profile(profile.root, profile.config, alias)


def test_root_alias_and_unicode_ancestor_overlap_is_rejected(tmp_path):
    import unicodedata
    project = tmp_path / 'Résumé'
    project.mkdir()
    archive = tmp_path / 'Archive'
    archive.mkdir()
    (project / 'Records').mkdir()
    alias_project = tmp_path / unicodedata.normalize('NFD', 'RÉSUMÉ')
    assert alias_project.exists()
    profile = common.load_profile(project, load_config(project), {
        'schema_version': 1, 'project_root': str(alias_project),
        'archive': {'archive_root': str(archive), 'records_dir': str(alias_project / 'RECORDS')},
    })
    assert profile.root == project
    with pytest.raises(common.DirectoryError) as error:
        common.external_roots(profile, archive, alias_project / 'RECORDS')
    assert error.value.reason_code == 'PROTECTED_PATH'
    equal = common.load_profile(project, load_config(project), {
        'schema_version': 1, 'project_root': str(project),
        'archive': {'archive_root': str(archive), 'records_dir': str(archive.with_name('ARCHIVE'))},
    })
    with pytest.raises(common.DirectoryError):
        common.external_roots(equal, archive, archive.with_name('ARCHIVE'))


def test_native_canonical_destination_rejects_links_and_keeps_unicode_missing_suffix(tmp_path):
    (tmp_path / '目标').mkdir()
    (tmp_path / 'link').symlink_to(tmp_path / '目标', target_is_directory=True)
    with pytest.raises(common.DirectoryError):
        common.canonical_destination(tmp_path / 'link' / 'new.json')
    assert common.canonical_destination(tmp_path / '目标' / '新资料' / '报告.json') == tmp_path / '目标' / '新资料' / '报告.json'
    (tmp_path / '目标' / '原件.json').write_bytes(b'{}')
    (tmp_path / '目标' / 'alias.json').symlink_to(tmp_path / '目标' / '原件.json')
    with pytest.raises(common.DirectoryError):
        common.canonical_destination(tmp_path / '目标' / 'alias.json')


@pytest.mark.skipif(sys.platform != 'darwin', reason='actual Darwin/APFS alias collision')
def test_actual_case_alias_directory_target_collision_has_zero_loss(tmp_path):
    source, target = tmp_path / 'Source', tmp_path / 'Target'
    source.mkdir()
    target.mkdir()
    (source / 'Payload').mkdir()
    (source / 'Payload' / 'original').write_bytes(b'original')
    (target / 'Existing').mkdir()
    (target / 'Existing' / 'keep').write_bytes(b'keep')
    with pytest.raises(common.DirectoryError) as error:
        common.rename_noreplace(source, 'Payload', target, 'EXISTING')
    assert error.value.reason_code == 'DESTINATION_EXISTS'
    assert (source / 'Payload' / 'original').read_bytes() == b'original'
    assert (target / 'Existing' / 'keep').read_bytes() == b'keep'


def test_public_roots_overlap_handles_actual_aliases_without_external_grants(tmp_path):
    profile = make_profile(tmp_path)
    records = profile.root / 'Records'
    records.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    assert common.roots_overlap(profile.root.with_name('PROJECT'), records.with_name('RECORDS'))
    assert common.roots_overlap(records, profile.root)
    assert not common.roots_overlap(profile.root, outside)
