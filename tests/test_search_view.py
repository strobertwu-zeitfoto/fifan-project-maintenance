import copy
import json
import os
from pathlib import Path

import pytest

from fifan_maintenance import directory_common as dc
from fifan_maintenance import search_view as s
from fifan_maintenance.jsonc_edit import Parser, merge_settings


@pytest.fixture
def case(tmp_path):
    root = tmp_path / 'project'
    records = tmp_path / 'records'
    root.mkdir()
    records.mkdir()
    (root / 'README.md').write_text('current entry')
    (root / 'history').mkdir()
    (root / 'history/old.md').write_text('historical body')
    data = {'schema_version': 1, 'project_root': str(root), 'scan_roots': ['.'],
            'critical_paths': ['README.md'], 'search': {'exclude': ['history'], 'vscode': True},
            'archive': {'records_dir': str(records)}}
    profile = dc.load_profile(root, {'exclude': [], 'protected': []}, data)
    return profile, records


def reload_profile(profile, **changes):
    data = copy.deepcopy(profile.data)
    data.update(changes)
    return dc.load_profile(profile.root, profile.config, data)


def test_missing_settings_native_apply_restore_and_repeat(case):
    profile, records = case
    root = profile.root
    plan = s.search_preview(profile)
    assert plan['native_validation'] == 'Not run'
    assert not (root / '.ignore').exists() and not (root / '.vscode').exists()
    journal = s.apply(profile, plan, records)
    assert journal['status'] == 'Passed'
    assert journal['validation']['hidden_files'] == 1
    assert journal['validation']['critical_paths'] == {'README.md': 'Passed'}
    assert journal['validation']['vscode_ui'] == 'Not run'
    assert s.verify(profile, journal)['status'] == 'Passed'
    assert s.apply(profile, plan, records) == journal
    assert (root / 'history/old.md').exists()
    assert s.recover(profile, journal, records) == journal
    restore_plan = s.restore_preview(profile, journal)
    restored = s.restore(profile, restore_plan, records)
    assert restored['state'] == 'Restored'
    assert not (root / '.ignore').exists() and not (root / '.vscode').exists()
    assert s.restore(profile, restore_plan, records) == restored
    assert s.verify(profile, restored)['status'] == 'Passed'
    with pytest.raises(ValueError):
        s.apply(profile, plan, records)
    assert Path(journal['journal_path']).stat().st_mode & 0o777 == 0o600


def test_existing_jsonc_and_ignore_restored_exact_bytes(case):
    profile, records = case
    root = profile.root
    (root / '.vscode').mkdir()
    settings = b'\xef\xbb\xbf{\r\n // user api_key=private-value\r\n "files.exclude": {"user": false},\r\n "search.exclude": { /* keep comment */ "legacy/**": true, },\r\n "unrelated": "https://example.test/a//b",\r\n}\r\n'
    ignore = b'# user rule\r\n*.tmp\r\n!keep.tmp\r\n'
    (root / '.vscode/settings.json').write_bytes(settings)
    (root / '.ignore').write_bytes(ignore)
    os.chmod(root / '.ignore', 0o640)
    profile = reload_profile(profile, search={'exclude': ['history'], 'vscode': True, 'watcher_exclude': True})
    plan = s.search_preview(profile)
    edited = s._decode(plan['files'][1]['after'])
    assert edited.startswith(b'\xef\xbb\xbf')
    assert b'// user api_key=private-value\r\n' in edited
    assert b'"files.exclude": {"user": false}' in edited
    assert b' /* keep comment */ "legacy/**": true,' in edited
    parsed = Parser(edited.decode()).parse().value
    assert parsed['search.exclude']['history/**'] is True
    assert parsed['files.watcherExclude']['history/**'] is True
    journal = s.apply(profile, plan, records)
    assert journal['status'] == 'Passed'
    restored = s.restore(profile, s.restore_preview(profile, journal), records)
    assert s.verify(profile, restored)['status'] == 'Passed'
    assert (root / '.ignore').read_bytes() == ignore
    assert (root / '.ignore').stat().st_mode & 0o777 == 0o640
    assert (root / '.vscode/settings.json').read_bytes() == settings
    assert (root / '.vscode').is_dir()


@pytest.mark.parametrize('settings', [
    b'{"editor.tabSize":2}',
    b'{"search.exclude":{"user":true}}',
    b'{\n  "editor.tabSize":2\n}',
    b'\xef\xbb\xbf{/* keep */"editor.tabSize":2}\r\n',
    b'\xef\xbb\xbf{\r\n "search.exclude": {/* user */ "user":true,},\r\n}\r\n',
])
def test_jsonc_compact_and_pretty_search_full_cycle_preserves_user_bytes(case, settings):
    profile, records = case
    (profile.root / '.vscode').mkdir()
    path = profile.root / '.vscode/settings.json'
    path.write_bytes(settings)
    plan = s.search_preview(profile)
    after = s._decode(next(item['after'] for item in plan['files'] if item['path'] == '.vscode/settings.json'))
    parsed = Parser(after.decode()).parse().value
    assert parsed['search.exclude']['history/**'] is True
    if b'"editor.tabSize":2' in settings:
        assert b'"editor.tabSize":2' in after
    if b'/* keep */' in settings:
        assert b'/* keep */' in after
    if b'/* user */ "user":true,' in settings:
        assert b'/* user */ "user":true,' in after
    if settings.startswith(b'\xef\xbb\xbf'):
        assert after.startswith(b'\xef\xbb\xbf')
    if b'\r\n' in settings:
        assert b'\n' not in after.replace(b'\r\n', b'')
    assert merge_settings(after, {'search.exclude': {'history/**': True}}) == after
    journal = s.apply(profile, plan, records)
    assert journal['status'] == 'Passed', journal
    assert s.verify(profile, journal)['status'] == 'Passed'
    restored = s.restore(profile, s.restore_preview(profile, journal), records)
    assert s.verify(profile, restored)['status'] == 'Passed'
    assert path.read_bytes() == settings


@pytest.mark.parametrize('data', [b'{"search.exclude":false}', b'{"search.exclude":{"history/**":false}}',
    b'{"same":1,"same":2}', b'{"x":{"same":1,"same":2}}', b'{"x":NaN}', b'{/*missing', b'[]', b'{"x":01}'])
def test_jsonc_conflicts_no_project_write(case, data):
    profile, _ = case
    (profile.root / '.vscode').mkdir()
    target = profile.root / '.vscode/settings.json'
    target.write_bytes(data)
    with pytest.raises(ValueError):
        s.search_preview(profile)
    assert target.read_bytes() == data
    assert not (profile.root / '.ignore').exists()


@pytest.mark.parametrize('data', [b'# BEGIN FIFAN DIRECTORY SEARCH\n',
    b'# END FIFAN DIRECTORY SEARCH\n# BEGIN FIFAN DIRECTORY SEARCH\n',
    (s.BEGIN + '\n' + s.END + '\n' + s.BEGIN + '\n' + s.END + '\n').encode(),
    b'# BEGIN FIFAN DIRECTORY SEARCH malformed\n', b'!history/\n'])
def test_ignore_invalid_control_blocks_or_counterrule(case, data):
    profile, _ = case
    (profile.root / '.ignore').write_bytes(data)
    with pytest.raises(ValueError):
        s.search_preview(profile)
    assert (profile.root / '.ignore').read_bytes() == data


def test_existing_controlled_block_updates_once_and_special_glob_path(case):
    profile, records = case
    root = profile.root
    for rel in ('[old] space', 'old space'):
        (root / rel).mkdir()
        (root / rel / 'note.md').write_text('data')
    original = ('# user\n' + s.BEGIN + '\n/previous/\n' + s.END + '\n*.tmp\n').encode()
    (root / '.ignore').write_bytes(original)
    profile = reload_profile(profile, search={'exclude': ['[old] space'], 'vscode': True})
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['status'] == 'Passed'
    visible, _ = s._rg(profile)
    assert '[old] space/note.md' not in visible and 'old space/note.md' in visible
    assert (root / '.ignore').read_bytes().count(s.BEGIN.encode()) == 1
    assert (root / '.ignore').read_bytes().startswith(b'# user\n')


def test_critical_already_hidden_is_not_made_visible_by_explicit_path(case):
    profile, records = case
    (profile.root / '.ignore').write_text('/README.md\n')
    plan = s.search_preview(profile)
    journal = s.apply(profile, plan, records)
    assert journal['status'] == 'Failed' and journal['reason_code'] == 'CRITICAL_HIDDEN'
    assert (profile.root / '.ignore').read_text() == '/README.md\n'
    assert not (profile.root / '.vscode').exists()


def test_critical_hidden_after_apply_rolls_back(case):
    profile, records = case
    profile = reload_profile(profile, critical_paths=['history/old.md'])
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['state'] == 'RolledBack' and journal['reason_code'] == 'CRITICAL_HIDDEN'
    assert not (profile.root / '.ignore').exists()
    assert not (profile.root / '.vscode').exists()


def test_missing_engine_is_not_passed(case, monkeypatch):
    profile, records = case
    plan = s.search_preview(profile)
    monkeypatch.setattr(s.shutil, 'which', lambda _: None)
    journal = s.apply(profile, plan, records)
    assert journal['status'] == 'Blocked' and journal['reason_code'] == 'ENGINE_UNAVAILABLE'
    assert not (profile.root / '.ignore').exists()


def test_post_engine_failure_rolls_back_only_owned_config(case, monkeypatch):
    profile, records = case
    plan = s.search_preview(profile)
    original = s._rg
    called = []
    def fail_after(profile):
        if called:
            raise ValueError('ENGINE_TIMEOUT')
        called.append(True)
        return original(profile)
    monkeypatch.setattr(s, '_rg', fail_after)
    journal = s.apply(profile, plan, records)
    assert journal['state'] == 'RolledBack' and journal['reason_code'] == 'ENGINE_TIMEOUT'
    assert not (profile.root / '.ignore').exists()


def test_failed_validation_does_not_rollback_external_edits(case, monkeypatch):
    profile, records = case
    plan = s.search_preview(profile)
    original = s._rg
    called = []
    def fail_after(profile):
        if called:
            (profile.root / '.ignore').write_text('external subsequent work')
            raise ValueError('ENGINE_TIMEOUT')
        called.append(True)
        return original(profile)
    monkeypatch.setattr(s, '_rg', fail_after)
    journal = s.apply(profile, plan, records)
    assert journal['state'] == 'Blocked'
    assert (profile.root / '.ignore').read_text() == 'external subsequent work'
    with pytest.raises(ValueError):
        s.recover(profile, journal, records)


@pytest.mark.parametrize('which', ['.ignore', '.vscode/settings.json'])
def test_restore_rejects_same_bytes_different_inode(case, which):
    profile, records = case
    journal = s.apply(profile, s.search_preview(profile), records)
    target = profile.root / which
    replacement = target.with_name('replacement')
    replacement.write_bytes(target.read_bytes())
    os.chmod(replacement, target.stat().st_mode & 0o777)
    os.replace(replacement, target)
    assert s.verify(profile, journal)['status'] == 'Blocked'
    with pytest.raises(ValueError, match='OWNERSHIP_CHANGED'):
        s.restore_preview(profile, journal)


@pytest.mark.parametrize('target', ['.ignore', 'settings.json'])
def test_apply_interruption_after_publish_recovers_owned_files(case, monkeypatch, target):
    profile, records = case
    # Existing files take the atomic replacement path.
    (profile.root / '.vscode').mkdir()
    (profile.root / '.vscode/settings.json').write_bytes(b'{/* before */}\n')
    (profile.root / '.ignore').write_bytes(b'# before\n')
    plan = s.search_preview(profile)
    before = {item['path']: s._decode(item['before']) for item in plan['files']}
    original = s.os.replace
    def interrupted(src, dst, **kwargs):
        result = original(src, dst, **kwargs)
        if dst == target:
            raise KeyboardInterrupt()
        return result
    monkeypatch.setattr(s.os, 'replace', interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.apply(profile, plan, records)
    monkeypatch.setattr(s.os, 'replace', original)
    journal = dc.load_artifact(records / (plan['operation_id'] + '.directory.json'))
    assert journal['pending'] is not None
    recovered = s.recover(profile, journal, records)
    assert recovered['state'] == 'Recovered'
    assert s.recover(profile, recovered, records) == recovered
    for rel, data in before.items():
        assert (profile.root / rel).read_bytes() == data


def test_restore_interruption_after_publish_resumes(case, monkeypatch):
    profile, records = case
    (profile.root / '.ignore').write_bytes(b'# original\n')
    journal = s.apply(profile, s.search_preview(profile), records)
    restore_plan = s.restore_preview(profile, journal)
    original = s.os.replace
    def interrupted(src, dst, **kwargs):
        result = original(src, dst, **kwargs)
        if dst == '.ignore':
            raise KeyboardInterrupt()
        return result
    monkeypatch.setattr(s.os, 'replace', interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.restore(profile, restore_plan, records)
    monkeypatch.setattr(s.os, 'replace', original)
    current = dc.load_artifact(journal['journal_path'])
    assert s.recover(profile, current, records)['state'] == 'Restored'
    assert (profile.root / '.ignore').read_bytes() == b'# original\n'
    assert not (profile.root / '.vscode').exists()


def test_budget_limits_do_not_write_configs(case):
    profile, records = case
    profile = reload_profile(profile, budgets={**profile.budgets, 'max_entries': 1})
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['status'] == 'Blocked' and journal['reason_code'] == 'BUDGET_EXCEEDED'
    assert not (profile.root / '.ignore').exists()


def test_protection_symlink_and_runtime_records_grant(case, tmp_path):
    profile, records = case
    plan = s.search_preview(profile)
    wrong = tmp_path / 'other-records'
    wrong.mkdir()
    with pytest.raises(ValueError):
        s.apply(profile, plan, wrong)
    protected_profile = dc.load_profile(profile.root, {'exclude': [], 'protected': ['.ignore']}, profile.data)
    with pytest.raises(ValueError):
        s.search_preview(protected_profile)
    (profile.root / '.ignore').symlink_to(tmp_path / 'missing')
    with pytest.raises(ValueError):
        s.search_preview(profile)
    assert not (tmp_path / 'missing').exists()


@pytest.mark.parametrize('payload, reason', [
    ("import os;os.write(1,b'README.md')", 'ENGINE_INCOMPLETE'),
    ("import os;os.write(1,b'README.md\\0');os.write(2,b'secret=never-output')", 'ENGINE_INCOMPLETE'),
    ("import os;os.write(1,b'README.md\\0README.md\\0')", 'BUDGET_EXCEEDED'),
    ("import os;os.write(1,b'x'*4096)", 'BUDGET_EXCEEDED'),
    ("import time;time.sleep(2)", 'ENGINE_TIMEOUT'),
])
def test_streamed_engine_incomplete_and_budget_fail_closed(case, monkeypatch, payload, reason):
    import subprocess
    import sys
    profile, _ = case
    if reason == 'ENGINE_TIMEOUT':
        profile = reload_profile(profile, budgets={**profile.budgets, 'max_seconds': 1})
    elif '4096' in payload:
        profile = reload_profile(profile, budgets={**profile.budgets, 'max_artifact_bytes': 1024})
    elif reason == 'BUDGET_EXCEEDED':
        profile = reload_profile(profile, budgets={**profile.budgets, 'max_entries': 1})
    original = subprocess.Popen
    # Only the listing invocation is simulated. The executable version probe
    # still uses the installed rg; no target-project script is executed.
    def listing(argv, *args, **kwargs):
        if '--files' in argv:
            return original([sys.executable, '-B', '-c', payload], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return original(argv, *args, **kwargs)
    monkeypatch.setattr(s.subprocess, 'Popen', listing)
    with pytest.raises(ValueError) as error:
        s._rg(profile)
    assert getattr(error.value, 'reason_code', str(error.value)) == reason
    assert 'never-output' not in str(error.value)
    assert not (profile.root / '.ignore').exists()


def test_unrelated_rules_hiding_outside_declared_exclusion_roll_back(case, monkeypatch):
    profile, records = case
    (profile.root / 'also-current.md').write_text('keep visible')
    original = s._rg
    calls = []
    def hidden(profile):
        paths, summary = original(profile)
        if calls:
            paths.discard('also-current.md')
        calls.append(True)
        return paths, summary
    monkeypatch.setattr(s, '_rg', hidden)
    result = s.apply(profile, s.search_preview(profile), records)
    assert result['state'] == 'RolledBack' and result['reason_code'] == 'SEARCH_SCOPE_MISMATCH'
    assert not (profile.root / '.ignore').exists()


def test_verify_detects_partial_critical_directory_visibility_change(case):
    profile, records = case
    (profile.root / 'current').mkdir()
    (profile.root / 'current/a.md').write_text('a')
    (profile.root / 'current/b.md').write_text('b')
    profile = reload_profile(profile, critical_paths=['current'])
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['status'] == 'Passed'
    # A nested engine rule can change search semantics without changing either
    # owned top-level config. One remaining file is insufficient proof.
    (profile.root / 'current/.ignore').write_text('/b.md\n')
    result = s.verify(profile, journal)
    assert result['status'] == 'Blocked' and result['reason_code'] == 'CRITICAL_CHANGED'


def test_control_character_exclusion_path_cannot_inject_rules(case):
    profile, _ = case
    path = 'history\n!README.md'
    (profile.root / path).mkdir()
    profile = reload_profile(profile, search={'exclude': [path], 'vscode': False})
    with pytest.raises(ValueError) as error:
        s.search_preview(profile)
    assert error.value.reason_code == 'UNSUPPORTED_PATH'
    assert not (profile.root / '.ignore').exists()


def test_tampered_restore_description_and_directory_owner_never_expand_scope(case):
    profile, records = case
    journal = s.apply(profile, s.search_preview(profile), records)
    plan = s.restore_preview(profile, journal)
    plan['files'].append({'path': 'README.md', 'action': 'remove_owned_created_file'})
    plan = dc.seal(plan)
    with pytest.raises(ValueError) as error:
        s.restore(profile, plan, records)
    assert error.value.reason_code == 'BAD_JOURNAL'
    assert (profile.root / 'README.md').exists()
    (profile.root / 'unrelated-empty').mkdir()
    edited = copy.deepcopy(journal)
    edited['created_dirs'] = [{'path': 'unrelated-empty', 'owner': s._identity((profile.root / 'unrelated-empty').stat())}]
    edited = dc.seal(edited)
    with pytest.raises(ValueError):
        s.recover(profile, edited, records)
    assert (profile.root / 'unrelated-empty').is_dir()


def test_new_owned_settings_directory_keeps_unrelated_file_on_restore(case):
    profile, records = case
    journal = s.apply(profile, s.search_preview(profile), records)
    (profile.root / '.vscode/user-file.txt').write_text('user work')
    restored = s.restore(profile, s.restore_preview(profile, journal), records)
    assert restored['state'] == 'Restored'
    assert restored['retained_directories'] == ['.vscode']
    assert (profile.root / '.vscode/user-file.txt').read_text() == 'user work'
    assert not (profile.root / '.vscode/settings.json').exists()


@pytest.mark.parametrize('name', ['star*dir', 'why?dir', '#old', '!old', '目录 空间', 'part{one,two}'])
def test_literal_glob_directory_exclusion_uses_native_rg(case, name):
    profile, records = case
    (profile.root / name).mkdir()
    (profile.root / name / 'old.md').write_text('retain original')
    profile = reload_profile(profile, search={'exclude': [name], 'vscode': True})
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['state'] == 'Applied' and journal['status'] == 'Passed'
    assert (profile.root / name / 'old.md').read_text() == 'retain original'
    assert journal['validation']['hidden_files'] == 1


def test_higher_priority_rgignore_prevents_claiming_effect(case):
    profile, records = case
    (profile.root / '.rgignore').write_text('!history/\n!history/**\n')
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['state'] == 'RolledBack' and journal['reason_code'] == 'SEARCH_SCOPE_MISMATCH'
    assert not (profile.root / '.ignore').exists()
    assert (profile.root / '.rgignore').read_text() == '!history/\n!history/**\n'


@pytest.mark.parametrize('field', ['entries', 'plan', 'created_dirs', 'state'])
def test_malformed_journal_is_controlled_before_product_writes(case, field):
    profile, records = case
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['status'] == 'Passed', journal.get('reason_code')
    before = (profile.root / '.ignore').read_bytes()
    altered = copy.deepcopy(journal)
    altered[field] = 'bad type'
    altered = dc.seal(altered)
    with pytest.raises(ValueError):
        s.recover(profile, altered, records)
    assert (profile.root / '.ignore').read_bytes() == before


def test_new_file_link_publication_interrupted_can_be_recovered(case, monkeypatch):
    profile, records = case
    plan = s.search_preview(profile)
    original = s.os.link
    def interrupted(src, dst, **kwargs):
        result = original(src, dst, **kwargs)
        if dst == 'settings.json':
            raise KeyboardInterrupt()
        return result
    monkeypatch.setattr(s.os, 'link', interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.apply(profile, plan, records)
    monkeypatch.setattr(s.os, 'link', original)
    current = dc.load_artifact(records / (plan['operation_id'] + '.directory.json'))
    assert s.recover(profile, current, records)['state'] == 'Recovered'
    assert not (profile.root / '.ignore').exists() and not (profile.root / '.vscode').exists()


def test_unowned_interrupted_mkdir_is_not_removed_or_claimed(case, monkeypatch):
    profile, records = case
    plan = s.search_preview(profile)
    original = s.os.mkdir
    def interrupted(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == '.vscode':
            raise KeyboardInterrupt()
        return result
    monkeypatch.setattr(s.os, 'mkdir', interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.apply(profile, plan, records)
    monkeypatch.setattr(s.os, 'mkdir', original)
    journal = dc.load_artifact(records / (plan['operation_id'] + '.directory.json'))
    with pytest.raises(ValueError) as error:
        s.recover(profile, journal, records)
    assert error.value.reason_code == 'INTERRUPTED_AMBIGUOUS'
    assert (profile.root / '.vscode').is_dir()


def test_repeat_applied_operation_rechecks_native_semantics(case):
    profile, records = case
    plan = s.search_preview(profile)
    journal = s.apply(profile, plan, records)
    assert journal['state'] == 'Applied'
    before = Path(journal['journal_path']).read_bytes()
    (profile.root / '.rgignore').write_text('!history/\n!history/**\n')
    for action in (lambda: s.apply(profile, plan, records), lambda: s.recover(profile, journal, records)):
        with pytest.raises(ValueError) as error:
            action()
        assert error.value.reason_code == 'SEARCH_SCOPE_MISMATCH'
    assert Path(journal['journal_path']).read_bytes() == before
    assert s.verify(profile, journal)['status'] == 'Blocked'


def test_owned_search_settings_can_restore_after_excluded_subtree_archived(case, tmp_path):
    profile, records = case
    journal = s.apply(profile, s.search_preview(profile), records)
    os.rename(profile.root / 'history', tmp_path / 'isolated-archive')
    assert s.verify(profile, journal)['status'] == 'Passed'
    restored = s.restore(profile, s.restore_preview(profile, journal), records)
    assert restored['state'] == 'Restored'
    assert not (profile.root / '.ignore').exists() and not (profile.root / '.vscode').exists()
    assert (tmp_path / 'isolated-archive/old.md').read_text() == 'historical body'


@pytest.mark.parametrize('phase', ['restore', 'rollback'])
def test_process_exit_after_owned_directory_removal_can_recover(case, tmp_path, phase):
    import subprocess
    import sys
    profile, records = case
    profile_path = tmp_path / 'directory-profile.json'
    dc.write_artifact(profile_path, profile.data)
    plan = s.search_preview(profile)
    plan_path = tmp_path / 'search-plan.json'
    dc.write_artifact(plan_path, plan)
    journal_path = records / (plan['operation_id'] + '.directory.json')
    if phase == 'restore':
        assert s.apply(profile, plan, records)['state'] == 'Applied'
    code = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from fifan_maintenance import directory_common as dc
from fifan_maintenance import search_view as s
profile = dc.load_profile(sys.argv[2], {'exclude': [], 'protected': []}, sys.argv[3])
original_rmdir = s.os.rmdir
def interrupted(name, *args, **kwargs):
    result = original_rmdir(name, *args, **kwargs)
    if name == '.vscode':
        os._exit(83)
    return result
s.os.rmdir = interrupted
if sys.argv[7] == 'restore':
    journal = dc.load_artifact(sys.argv[6])
    s.restore(profile, s.restore_preview(profile, journal), sys.argv[5])
else:
    original_rg = s._rg
    calls = []
    def fail_after(profile):
        if calls:
            raise ValueError('ENGINE_TIMEOUT')
        calls.append(True)
        return original_rg(profile)
    s._rg = fail_after
    s.apply(profile, dc.load_artifact(sys.argv[4]), sys.argv[5])
'''
    child = subprocess.run([sys.executable, '-B', '-c', code, str(Path(s.__file__).parents[1]),
                            str(profile.root), str(profile_path), str(plan_path), str(records),
                            str(journal_path), phase], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    assert child.returncode == 83, child.stderr.decode(errors='replace')
    assert not (profile.root / '.vscode').exists()
    current = dc.load_artifact(journal_path)
    assert current['state'] == 'Restoring'
    recovered = s.recover(profile, current, records)
    assert recovered['state'] == ('Restored' if phase == 'restore' else 'Recovered')
    assert recovered['status'] == 'Passed'
    assert not (profile.root / '.ignore').exists() and not (profile.root / '.vscode').exists()
    assert (profile.root / 'README.md').read_text() == 'current entry'
    assert (profile.root / 'history/old.md').read_text() == 'historical body'
    assert s.recover(profile, recovered, records) == recovered


def test_removed_owned_directory_is_not_reclaimed_if_it_reappears(case, monkeypatch):
    profile, records = case
    journal = s.apply(profile, s.search_preview(profile), records)
    restored = s.restore(profile, s.restore_preview(profile, journal), records)
    assert restored['directory_cleanup']['phase'] == 'removed'
    (profile.root / '.vscode').mkdir()
    # Even an apparent identity match cannot authorize a new directory after a
    # recorded deletion. This models inode reuse without claiming it occurred.
    monkeypatch.setattr(s, '_same', lambda st, owner: True)
    with pytest.raises(ValueError) as error:
        s.recover(profile, restored, records)
    assert error.value.reason_code == 'OWNERSHIP_CHANGED'
    assert (profile.root / '.vscode').is_dir()


@pytest.mark.parametrize('alias_kind', ['case', 'unicode'])
def test_records_native_alias_is_compared_in_actual_namespace(case, tmp_path, alias_kind):
    import unicodedata
    profile, records = case
    if alias_kind == 'case':
        alias = records.with_name(records.name.upper())
    else:
        actual = tmp_path / 'é-records'
        actual.mkdir()
        records = actual
        alias = actual.with_name(unicodedata.normalize('NFD', actual.name))
        profile = reload_profile(profile, archive={'records_dir': str(actual)})
    if not alias.exists() or not os.path.samefile(alias, records):
        pytest.skip('fixture filesystem does not expose this native alias')
    assert os.path.samefile(s._records(profile, alias), records)
    # A profile spelling cannot turn the project itself into an external grant.
    project_alias = profile.root.with_name(profile.root.name.upper())
    if not project_alias.exists() or not os.path.samefile(project_alias, profile.root):
        pytest.skip('fixture filesystem does not expose a case alias')
    invalid = reload_profile(profile, archive={'records_dir': str(project_alias)})
    plan = s.search_preview(invalid)
    with pytest.raises(ValueError) as error:
        s.apply(invalid, plan, project_alias)
    assert error.value.reason_code == 'ROOT_OVERLAP'
    assert not (profile.root / '.ignore').exists()
    assert not list(profile.root.glob('*.directory.json'))


def test_exclusion_native_alias_is_not_silently_used_as_a_new_rule(case):
    profile, _ = case
    alias = profile.root / 'HISTORY'
    if not alias.exists() or not os.path.samefile(alias, profile.root / 'history'):
        pytest.skip('fixture filesystem does not expose a case alias')
    altered = reload_profile(profile, search={'exclude': ['HISTORY'], 'vscode': False})
    with pytest.raises(ValueError) as error:
        s.search_preview(altered)
    assert error.value.reason_code == 'PATH_ALIAS'
    assert not (profile.root / '.ignore').exists()


@pytest.mark.parametrize('phase', ['restore', 'rollback'])
def test_successful_rmdir_then_fsync_error_remains_recoverable(case, monkeypatch, phase):
    import errno
    profile, records = case
    plan = s.search_preview(profile)
    if phase == 'restore':
        journal = s.apply(profile, plan, records)
        restore_plan = s.restore_preview(profile, journal)
    original_rmdir, original_fsync = s.os.rmdir, s.os.fsync
    observed = {'armed_fd': None, 'injections': 0, 'removed': False}
    def remove(name, *args, **kwargs):
        result = original_rmdir(name, *args, **kwargs)
        if name == '.vscode':
            observed['removed'] = True
            observed['armed_fd'] = kwargs['dir_fd']
        return result
    def fail_only_post_remove_fsync(fd):
        if observed['armed_fd'] == fd:
            observed['armed_fd'] = None
            observed['injections'] += 1
            raise OSError(errno.EIO, 'injected post-rmdir fsync error')
        return original_fsync(fd)
    monkeypatch.setattr(s.os, 'rmdir', remove)
    monkeypatch.setattr(s.os, 'fsync', fail_only_post_remove_fsync)
    if phase == 'rollback':
        original_rg = s._rg
        calls = []
        def fail_validation(profile):
            if calls:
                raise ValueError('ENGINE_TIMEOUT')
            calls.append(True)
            return original_rg(profile)
        monkeypatch.setattr(s, '_rg', fail_validation)
        s.apply(profile, plan, records)
    else:
        # The initiating call may stop on the original fsync failure. The
        # persisted recovery state must remain usable, not falsely retained.
        try:
            s.restore(profile, restore_plan, records)
        except (OSError, ValueError):
            pass
    assert observed['removed'] is True and observed['injections'] == 1
    assert not (profile.root / '.vscode').exists()
    current = dc.load_artifact(records / (plan['operation_id'] + '.directory.json'))
    recovered = s.recover(profile, current, records)
    assert recovered['state'] == ('Restored' if phase == 'restore' else 'Recovered')
    assert recovered['directory_cleanup']['phase'] == 'removed'
    assert recovered['retained_directories'] == []
    assert not (profile.root / '.ignore').exists()
    assert (profile.root / 'README.md').read_text() == 'current entry'
    assert (profile.root / 'history/old.md').read_text() == 'historical body'


def test_native_fd_path_other_hardlink_name_keeps_exact_owned_names(case, monkeypatch):
    profile, records = case
    original = dc.canonical_destination
    alternatives = []
    def other_link(path, allow_missing_parents=True):
        result = original(path, allow_missing_parents)
        path = Path(path)
        if path.parent in {profile.root, profile.root / '.vscode'} and path.is_file() and path.stat().st_nlink > 1:
            for entry in path.parent.iterdir():
                if entry.name != path.name and entry.is_file() and os.path.samefile(entry, path):
                    alternatives.append((path.name, entry.name))
                    return entry
        return result
    monkeypatch.setattr(dc, 'canonical_destination', other_link)
    journal = s.apply(profile, s.search_preview(profile), records)
    assert journal['status'] == 'Passed', journal.get('reason_code')
    assert alternatives  # Both native names refer to real fixture hard links.
    assert s.verify(profile, journal)['status'] == 'Passed'
    restored = s.restore(profile, s.restore_preview(profile, journal), records)
    assert restored['state'] == 'Restored'
    assert not (profile.root / '.ignore').exists() and not (profile.root / '.vscode').exists()


def test_real_native_hardlink_observation_never_depends_on_fd_preferred_name(case):
    profile, _ = case
    for index in range(200):
        temporary = profile.root / ('.fifan-search-' + format(index, '032x') + '.tmp')
        destination = profile.root / ('.configuration-' + str(index))
        temporary.write_bytes(b'fixture')
        os.link(temporary, destination)
        assert temporary.stat().st_nlink == 2
        for path in (destination, temporary, destination, temporary):
            observed = s._observe(profile, path.name)
            assert observed['bytes'] == 7
            assert observed['owner'] == s._identity(path.stat())


@pytest.mark.parametrize('kind', ['case', 'unicode'])
def test_hardlink_fallback_still_rejects_false_native_spelling(case, monkeypatch, kind):
    import unicodedata
    profile, _ = case
    name = 'settings.json' if kind == 'case' else 'é-settings.json'
    wrong = name.upper() if kind == 'case' else unicodedata.normalize('NFD', name)
    actual = profile.root / name
    actual.write_bytes(b'fixture')
    if not (profile.root / wrong).exists() or not os.path.samefile(actual, profile.root / wrong):
        pytest.skip('fixture filesystem does not expose this native alias')
    other = profile.root / 'other-link.json'
    os.link(actual, other)
    original = dc.canonical_destination
    def other_link(path, allow_missing_parents=True):
        if Path(path) == profile.root / wrong:
            return other
        return original(path, allow_missing_parents)
    monkeypatch.setattr(dc, 'canonical_destination', other_link)
    with pytest.raises(ValueError) as error:
        s._observe(profile, wrong)
    assert error.value.reason_code == 'PATH_ALIAS'


def test_hardlink_spelling_fallback_entry_budget_does_not_authorize_unseen_name(case, monkeypatch):
    profile, _ = case
    profile = reload_profile(profile, budgets={**profile.budgets, 'max_entries': 1})
    actual, other = profile.root / '.ignore', profile.root / 'other-link'
    actual.write_bytes(b'fixture')
    os.link(actual, other)
    original = dc.canonical_destination
    def other_link(path, allow_missing_parents=True):
        if Path(path) == actual:
            return other
        return original(path, allow_missing_parents)
    monkeypatch.setattr(dc, 'canonical_destination', other_link)
    class Entry:
        def __init__(self, name):
            self.name = name
        def stat(self, follow_symlinks=False):
            return actual.stat()
    class Entries:
        def __enter__(self):
            return iter([Entry('unrelated'), Entry('.ignore')])
        def __exit__(self, *args):
            pass
    monkeypatch.setattr(s.os, 'scandir', lambda fd: Entries())
    with pytest.raises(ValueError) as error:
        s._observe(profile, '.ignore')
    assert error.value.reason_code == 'BUDGET_EXCEEDED'
