import json
import os
from pathlib import Path

import pytest

from fifan_maintenance import changes as c
from fifan_maintenance import sessions as s


@pytest.fixture
def case(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'a.md').write_text('one long body')
    return root, tmp_path / 'records', {'protected': ['private']}


def apply(case, old, new, path='a.md'):
    root, out, cfg = case
    return c.apply(root, c.preview(root, {'operations': [{'type': 'replace', 'path': path, 'old': old, 'new': new}]}, cfg), cfg, out)


def manifest(case, records):
    root, out, _ = case
    path = out / 'session.json'
    path.write_text(json.dumps({'schema_version': 1, 'root': str(root), 'journals': [r['journal_path'] for r in records]}))
    return path


def test_chain_report_preview_recover(case):
    root, _, cfg = case
    first = apply(case, 'one long body', 'two')
    second = apply(case, 'two', 'three')
    path = manifest(case, [first, second])
    result = s.report(root, cfg, path)
    assert result['status'] == 'Passed'
    assert result['journals'][0]['individual_verify']['status'] == 'Failed'
    assert result['journals'][0]['superseded_paths'] == ['a.md']
    assert result['dependencies'][1]['depends_on'] == [0]
    before = (root / 'a.md').read_bytes()
    journals = [Path(r['journal_path']).read_bytes() for r in [first, second]]
    preview = s.recovery_preview(root, cfg, path)
    assert [x['journal'] for x in preview['steps']] == [1, 0]
    assert (root / 'a.md').read_bytes() == before
    assert [Path(r['journal_path']).read_bytes() for r in [first, second]] == journals
    assert s.recover(root, cfg, path, preview)['completion'] == 'all_recovered'
    assert (root / 'a.md').read_text() == 'one long body'
    rerun = s.recovery_preview(root, cfg, path)
    assert all(x['status'] == 'skip_recovered' for x in rerun['steps'])
    assert s.recover(root, cfg, path, rerun)['restored'] == []
    assert s.report(root, cfg, path)['completion'] == 'all_recovered'


def test_broken_reordered_and_duplicate_chain(case):
    root, _, cfg = case
    first = apply(case, 'one', 'two')
    second = apply(case, 'two', 'three')
    for records in ([second, first], [first, first]):
        with pytest.raises(ValueError):
            s.recovery_preview(root, cfg, manifest(case, records))
    (root / 'a.md').write_text('external')
    with pytest.raises(ValueError):
        s.verify(root, cfg, manifest(case, [first, second]))


def test_preview_bound_to_current_material_and_configuration(case):
    root, _, cfg = case
    rec = apply(case, 'one', 'two')
    path = manifest(case, [rec])
    preview = s.recovery_preview(root, cfg, path)
    with pytest.raises(ValueError):
        s.recover(root, {**cfg, 'protected': ['other']}, path, preview)
    (root / 'a.md').write_text('else')
    with pytest.raises(ValueError):
        s.recover(root, cfg, path, preview)
    assert json.loads(Path(rec['journal_path']).read_text())['status'] == 'applied'


def test_interruption_uses_original_journal_progress(case, monkeypatch):
    root, _, cfg = case
    first = apply(case, 'one', 'two')
    second = apply(case, 'two', 'three')
    path = manifest(case, [first, second])
    preview = s.recovery_preview(root, cfg, path)
    original = c._recover
    def interrupted(root, path, config):
        result = original(root, path, config)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, '_recover', interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.recover(root, cfg, path, preview)
    assert (root / 'a.md').read_text().startswith('two')
    monkeypatch.setattr(c, '_recover', original)
    resumed = s.recovery_preview(root, cfg, path)
    assert resumed['steps'][0]['status'] == 'skip_recovered'
    assert s.recover(root, cfg, path, resumed)['restored'] == [first['plan']['operation_id']]


def test_history_does_not_promote_preview_or_checks(case):
    root, out, cfg = case
    plan = c.preview(root, {'operations': [{'type': 'replace', 'path': 'a.md', 'old': 'one long body', 'new': 'x'}]}, cfg)
    rec = c.apply(root, plan, cfg, out)
    (out / 'plan.json').write_text(json.dumps(plan))
    (out / 'report.json').write_text(json.dumps({'schema_version': 1, 'root': str(root), 'checks': ['documents'], 'findings': [{'body': 'DO NOT OUTPUT'}]}))
    (out / 'foreign.json').write_text(json.dumps({'schema_version': 1, 'root': '/other/project', 'checks': []}))
    result = s.history(root, cfg, [out])
    assert len(result['records']) == 3
    journal = next(x for x in result['records'] if x['kind'] == 'journal')
    assert journal['recorded_byte_reduction'] is True
    assert journal['applied_rewrite'] is True
    assert all(x['applied_rewrite'] is False for x in result['records'] if x['kind'] != 'journal')
    rendered = json.dumps(result)
    assert 'DO NOT OUTPUT' not in rendered
    assert 'one long body' not in rendered
    assert rec['backups'][0] not in rendered
    c.recover(root, Path(rec['journal_path']), cfg)
    journal = next(x for x in s.history(root, cfg, [out])['records'] if x['kind'] == 'journal')
    assert journal['recovered'] is True and journal['applied_rewrite'] is False


def test_history_budget_and_symlinks(case, tmp_path):
    root, out, cfg = case
    apply(case, 'one', 'two')
    (out / 'link.json').symlink_to(root / 'a.md')
    result = s.history(root, cfg, [out])
    assert result['skipped'] == 1
    with pytest.raises(ValueError):
        s.history(root, cfg, [out], max_files=1)
    with pytest.raises(ValueError):
        s.history(root, cfg, [out], max_bytes=10)
    with pytest.raises(ValueError):
        s.history(root, cfg, [root])
    link = tmp_path / 'linked'
    link.symlink_to(out, target_is_directory=True)
    with pytest.raises(ValueError):
        s.history(root, cfg, [link])


def test_session_reference_scope_hash_and_symlink(case, tmp_path):
    root, out, cfg = case
    rec = apply(case, 'one', 'two')
    path = manifest(case, [rec])
    value = json.loads(path.read_text())
    value['journals'] = [{'path': rec['journal_path'], 'sha256': '0' * 64}]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        s.verify(root, cfg, path)
    value['journals'] = [rec['journal_path']]
    value['reports'] = [{'path': str(out / 'foreign.json')}]
    (out / 'foreign.json').write_text(json.dumps({'root': '/other/project'}))
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        s.verify(root, cfg, path)
    value.pop('reports')
    value['root'] = '/other/project'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        s.verify(root, cfg, path)


def test_snapshot_owner_and_guard_dependencies(case):
    root, out, cfg = case
    request = {'version': 2, 'operations': [{'kind': 'snapshot', 'path': 'a.md', 'destination': 'archive/a.md', 'expected_sha256': c._hash((root / 'a.md').read_bytes()), 'origin': {'reference_base': '.', 'classification_basis': 'explicit archive'}}]}
    rec = c.apply(root, c.preview(root, request, cfg), cfg, out)
    path = manifest(case, [rec])
    assert s.recovery_preview(root, cfg, path)['status'] == 'Passed'
    archive = root / 'archive/a.md'
    other = archive.with_name('other')
    other.write_bytes(archive.read_bytes())
    os.chmod(other, archive.stat().st_mode & 0o777)
    os.replace(other, archive)
    with pytest.raises(ValueError):
        s.recovery_preview(root, cfg, path)
    assert archive.exists()


def test_lock_is_whole_chain(case):
    root, _, cfg = case
    rec = apply(case, 'one', 'two')
    path = manifest(case, [rec])
    preview = s.recovery_preview(root, cfg, path)
    with c._project_lock(root):
        with pytest.raises(ValueError, match='busy'):
            s.recover(root, cfg, path, preview)


def test_independent_batches_and_move(case):
    root, out, cfg = case
    (root / 'b.md').write_text('other')
    first = apply(case, 'one', 'two')
    second = c.apply(root, c.preview(root, {'operations': [{'type': 'move', 'path': 'b.md', 'destination': 'archive/b.md'}]}, cfg), cfg, out)
    path = manifest(case, [first, second])
    assert s.recover(root, cfg, path, s.recovery_preview(root, cfg, path))['status'] == 'Passed'
    assert (root / 'b.md').read_text() == 'other'
    assert not (root / 'archive').exists()


def test_seven_batches_with_guard_read_dependency(case):
    root, out, cfg = case
    (root / 'rule.md').write_text('Rule one')
    records = [apply(case, 'one', 'two', 'rule.md')]
    req = {'version': 2, 'operations': [{'type': 'replace', 'path': 'a.md', 'old': 'one', 'new': 'two'}],
           'guards': [{'kind': 'snippet', 'path': 'rule.md', 'value': 'Rule two'}]}
    records.append(c.apply(root, c.preview(root, req, cfg), cfg, out))
    old = 'two'
    for number in range(5):
        new = 'step' + str(number)
        records.append(apply(case, old, new))
        old = new
    path = manifest(case, records)
    assert s.verify(root, cfg, path)['status'] == 'Passed'
    assert s.recover(root, cfg, path, s.recovery_preview(root, cfg, path))['completion'] == 'all_recovered'
    assert (root / 'rule.md').read_text() == 'Rule one'
    assert (root / 'a.md').read_text() == 'one long body'
    assert s.verify(root, cfg, path)['status'] == 'Passed'


def test_guard_drift_and_created_directory_replacement(case):
    root, out, cfg = case
    (root / 'rule.md').write_text('Keep')
    req = {'version': 2, 'operations': [{'type': 'replace', 'path': 'a.md', 'old': 'one', 'new': 'two'}],
           'guards': [{'kind': 'snippet', 'path': 'rule.md', 'value': 'Keep'}]}
    rec = c.apply(root, c.preview(root, req, cfg), cfg, out)
    path = manifest(case, [rec])
    (root / 'rule.md').write_text('Changed')
    with pytest.raises(ValueError):
        s.recovery_preview(root, cfg, path)
    assert (root / 'a.md').read_text().startswith('two')


def test_partial_batch_and_recovery_after_write_before_receipt(case, monkeypatch):
    root, out, cfg = case
    original = c._atomic
    def interrupted(*args):
        original(*args)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, '_atomic', interrupted)
    with pytest.raises(KeyboardInterrupt):
        apply(case, 'one', 'two')
    monkeypatch.setattr(c, '_atomic', original)
    rec = json.loads(next(out.glob('*.json')).read_text())
    path = manifest(case, [rec])
    assert s.report(root, cfg, path)['completion'] == 'partial_or_unknown'
    preview = s.recovery_preview(root, cfg, path)
    monkeypatch.setattr(c, '_atomic', interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.recover(root, cfg, path, preview)
    monkeypatch.setattr(c, '_atomic', original)
    assert (root / 'a.md').read_text().startswith('one')
    resumed = s.recovery_preview(root, cfg, path)
    assert s.recover(root, cfg, path, resumed)['completion'] == 'all_recovered'


def test_snapshot_then_later_source_edit_is_reverse_safe(case):
    root, out, cfg = case
    req = {'version': 2, 'operations': [{'kind': 'snapshot', 'path': 'a.md', 'destination': 'archive/a.md',
           'expected_sha256': c._hash((root / 'a.md').read_bytes()),
           'origin': {'reference_base': '.', 'classification_basis': 'explicit archive'}}]}
    first = c.apply(root, c.preview(root, req, cfg), cfg, out)
    second = apply(case, 'one', 'two')
    path = manifest(case, [first, second])
    preview = s.recovery_preview(root, cfg, path)
    assert preview['status'] == 'Passed'
    assert s.recover(root, cfg, path, preview)['completion'] == 'all_recovered'
    assert not (root / 'archive').exists()


def test_created_directory_owner_change_blocks_preview(case):
    root, out, cfg = case
    rec = c.apply(root, c.preview(root, {'operations': [{'type': 'move', 'path': 'a.md', 'destination': 'archive/a.md'}]}, cfg), cfg, out)
    path = manifest(case, [rec])
    os.rename(root / 'archive', root / 'original-archive')
    (root / 'archive').mkdir()
    os.rename(root / 'original-archive/a.md', root / 'archive/a.md')
    with pytest.raises(ValueError, match='directory ownership'):
        s.recovery_preview(root, cfg, path)
    assert (root / 'archive/a.md').exists()


def test_profile_requires_explicit_wrapper_binding_and_validates_scope(case):
    root, out, cfg = case
    cfg.update({'exclude': [], 'include': ['**/*']})
    rec = apply(case, 'one', 'two')
    path = manifest(case, [rec])
    profile = out / 'profile.json'
    profile.write_text(json.dumps({'schema_version': 1, 'sources': ['a.md']}))
    value = json.loads(path.read_text())
    value['profiles'] = [str(profile)]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='binding'):
        s.verify(root, cfg, path)
    value['profiles'] = [{'path': str(profile), 'root': str(root)}]
    path.write_text(json.dumps(value))
    assert s.verify(root, cfg, path)['references']['profiles'][0]['root'] == str(root)
    profile.write_text(json.dumps({'schema_version': 1, 'sources': ['private/hidden.md']}))
    with pytest.raises(ValueError):
        s.verify(root, cfg, path)
    value['profiles'][0]['root'] = '/other/project'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='binding'):
        s.verify(root, cfg, path)


def test_noop_record_is_not_actual_rewrite(case):
    root, out, cfg = case
    apply(case, 'one', 'one')
    journal = s.history(root, cfg, [out])['records'][0]
    assert journal['status'] == 'applied'
    assert journal['applied_rewrite'] is False
    assert journal['recorded_byte_reduction'] is False


def test_history_file_metadata_filters_governed_md_without_body(case):
    root, out, cfg = case
    (root / 'only-check.md').write_text('checked')
    (root / 'pending.md').write_text('pending')
    (root / 'noop.md').write_text('noop')
    (root / 'recovered.md').write_text('restore')
    (root / 'no-evidence.md').write_text('unknown history')
    rewritten = apply(case, 'one long body', 'tiny')
    apply(case, 'noop', 'noop', 'noop.md')
    rec = apply(case, 'restore', 'restored', 'recovered.md')
    c.recover(root, Path(rec['journal_path']), cfg)
    pending = c.preview(root, {'operations': [{'type': 'replace', 'path': 'pending.md', 'old': 'pending', 'new': 'short'}]}, cfg)
    (out / 'preview.json').write_text(json.dumps(pending))
    (out / 'check.json').write_text(json.dumps({'schema_version': 1, 'root': str(root), 'checks': ['documents'],
        'scope': {'sources': ['only-check.md']}, 'files': {'only-check.md': {'size': 7, 'sha256': c._hash(b'checked')}}}))
    history = s.history(root, cfg, [out])
    assert history['status'] == 'Passed'
    files = {f['path']: f for r in history['records'] for f in r['files']}
    assert files['a.md']['treatment'] == 'rewritten'
    assert files['a.md']['before_bytes'] == 13
    assert files['a.md']['after_bytes'] == 4
    assert files['a.md']['byte_delta'] == -9
    assert files['a.md']['current_state']['status'] == 'matches_after'
    assert files['only-check.md']['treatment'] == 'check_only'
    assert files['pending.md']['treatment'] == 'preview_only'
    assert files['pending.md']['before_bytes'] is None
    assert files['recovered.md']['treatment'] == 'recovered'
    assert files['noop.md']['treatment'] == 'noop'
    governed = {f['path'] for f in files.values() if f['applied_rewrite']}
    assert governed == {'a.md'}
    assert 'no-evidence.md' not in files
    assert history['coverage']['project_document_coverage'] == 'Unknown'
    # Another selected batch changes the old journal's current state without
    # declaring that later work unauthorized.
    apply(case, 'tiny', 'latest')
    first = next(r for r in s.history(root, cfg, [out])['records'] if r['path'] == rewritten['journal_path'])
    assert first['files'][0]['current_state']['status'] == 'different'
    assert first['files'][0]['operation_current_state'] == 'different_or_unavailable'
    serialized = json.dumps(first)
    assert 'one long body' not in serialized and rewritten['backups'][0] not in serialized


def test_history_unknown_scope_and_bad_same_project_record_are_unknown(case):
    root, out, cfg = case
    rec = apply(case, 'one', 'two')
    (out / 'unknown-scope.json').write_text(json.dumps({'schema_version': 1, 'root': str(root), 'checks': ['documents']}))
    value = s.history(root, cfg, [out])
    report = next(r for r in value['records'] if r['kind'] == 'report')
    assert report['source_scope'] == 'Unknown' and report['files'] is None
    assert value['status'] == 'Unknown'
    (out / 'unknown-scope.json').unlink()
    broken = dict(rec)
    broken['record_sha256'] = '0' * 64
    (out / 'broken.json').write_text(json.dumps(broken))
    value = s.history(root, cfg, [out])
    assert value['status'] == 'Unknown'
    assert any(r['status'] == 'Unknown' and r['files'] is None for r in value['records'])


def test_history_snapshot_and_move_destinations_are_explicit(case):
    root, out, cfg = case
    (root / 'move.md').write_text('archive')
    req = {'version': 2, 'operations': [{'kind': 'snapshot', 'path': 'a.md', 'destination': 'archive/a.md',
           'expected_sha256': c._hash((root / 'a.md').read_bytes()),
           'origin': {'reference_base': '.', 'classification_basis': 'explicit archive'}},
           {'type': 'move', 'path': 'move.md', 'destination': 'archive/move.md'}]}
    c.apply(root, c.preview(root, req, cfg), cfg, out)
    files = s.history(root, cfg, [out])['records'][0]['files']
    snapshot, moved = files
    assert snapshot['destination'] == 'archive/a.md' and snapshot['treatment'] == 'snapshot_only'
    assert snapshot['applied_rewrite'] is False and snapshot['snapshot_created'] is True
    assert snapshot['before_bytes'] == snapshot['after_bytes'] == 13
    assert moved['destination'] == 'archive/move.md' and moved['treatment'] == 'moved'
    assert moved['current_state']['status'] == 'missing'
    assert moved['destination_current_state']['status'] == 'matches_after'


@pytest.mark.parametrize('bad_field', ['duplicate_journals', 'duplicate_root', 'nan'])
def test_session_strict_json_rejects_ambiguous_manifest_without_writes(case, bad_field):
    root, out, cfg = case
    rec = apply(case, 'one', 'two')
    path = manifest(case, [rec])
    value = json.loads(path.read_text())
    raw = path.read_text()
    if bad_field == 'duplicate_journals':
        raw = raw[:-1] + ', "journals": ' + json.dumps(value['journals']) + '}'
    elif bad_field == 'duplicate_root':
        raw = raw[:-1] + ', "root": ' + json.dumps(str(root)) + '}'
    else:
        raw = raw.replace('"schema_version": 1', '"schema_version": NaN')
    path.write_text(raw)
    project_before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    records_before = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    for action in (s.report, s.verify, s.recovery_preview):
        with pytest.raises(ValueError, match='invalid session JSON'):
            action(root, cfg, path)
    with pytest.raises(ValueError, match='invalid session JSON'):
        s.recover(root, cfg, path, {})
    assert {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()} == project_before
    assert {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()} == records_before


def test_history_strict_json_does_not_accept_duplicate_root_or_nan(case):
    root, out, cfg = case
    apply(case, 'one', 'two')
    (out / 'duplicate.json').write_text('{"schema_version":1,"root":' + json.dumps(str(root)) + ',"root":' + json.dumps(str(root)) + ',"checks":[]}')
    (out / 'nonstandard.json').write_text('{"schema_version":1,"root":' + json.dumps(str(root)) + ',"checks":[],"metrics":NaN}')
    before = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    result = s.history(root, cfg, [out])
    assert result['status'] == 'Unknown'
    assert result['coverage']['unreadable_materials'] == 2
    assert len(result['records']) == 1
    assert {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()} == before


@pytest.mark.parametrize('replace_moved_inode', [False, True])
def test_snapshot_then_move_restores_observed_inode_without_fabrication(case, replace_moved_inode):
    root, out, cfg = case
    source = (root / 'a.md').read_bytes()
    req = {'version': 2, 'operations': [{'kind': 'snapshot', 'path': 'a.md', 'destination': 'archive/a.md',
           'expected_sha256': c._hash(source),
           'origin': {'reference_base': '.', 'classification_basis': 'explicit archive'}}]}
    first = c.apply(root, c.preview(root, req, cfg), cfg, out)
    owned_inode = (root / 'archive/a.md').stat().st_ino
    second = c.apply(root, c.preview(root, {'operations': [{'type': 'move', 'path': 'archive/a.md',
                   'destination': 'relocated/a.md'}]}, cfg), cfg, out)
    moved = root / 'relocated/a.md'
    assert moved.stat().st_ino == owned_inode
    path = manifest(case, [first, second])
    preview = s.recovery_preview(root, cfg, path)
    if replace_moved_inode:
        replacement = root / 'relocated/replacement.md'
        replacement.write_bytes(moved.read_bytes())
        os.chmod(replacement, moved.stat().st_mode & 0o777)
        assert replacement.stat().st_ino != owned_inode
        os.replace(replacement, moved)
        before = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
        with pytest.raises(ValueError, match='ownership changed'):
            s.recovery_preview(root, cfg, path)
        with pytest.raises(ValueError, match='ownership changed'):
            s.recover(root, cfg, path, preview)
        assert moved.read_bytes() == source and moved.stat().st_ino != owned_inode
        assert not (root / 'archive/a.md').exists()
        assert {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()} == before
    else:
        assert s.recover(root, cfg, path, preview)['completion'] == 'all_recovered'
        assert (root / 'a.md').read_bytes() == source
        assert not moved.exists() and not (root / 'archive/a.md').exists()
        assert all(json.loads(Path(r['journal_path']).read_text())['status'] == 'recovered' for r in (first, second))


def test_applied_before_drift_is_not_terminal_but_can_recover(case):
    root, _, cfg = case
    rec = apply(case, 'one', 'two')
    path = manifest(case, [rec])
    (root / 'a.md').write_text('one long body')
    assert c.verify(root, rec, cfg)['status'] == 'Failed'
    assert s.report(root, cfg, path)['status'] == 'Failed'
    assert s.report(root, cfg, path)['completion'] == 'Unknown'
    with pytest.raises(ValueError, match='terminal state drift'):
        s.verify(root, cfg, path)
    preview = s.recovery_preview(root, cfg, path)
    assert preview['status'] == 'Passed'
    assert s.recover(root, cfg, path, preview)['completion'] == 'all_recovered'
    assert s.verify(root, cfg, path)['status'] == 'Passed'


def test_identical_replace_session_terminal_and_repeat_recovery(case):
    root, _, cfg = case
    rec = apply(case, 'one', 'one')
    path = manifest(case, [rec])
    assert s.verify(root, cfg, path)['status'] == 'Passed'
    assert s.report(root, cfg, path)['completion'] == 'all_applied'
    assert not s.history(root, cfg, [Path(rec['journal_path']).parent])['records'][0]['applied_rewrite']
    preview = s.recovery_preview(root, cfg, path)
    assert s.recover(root, cfg, path, preview)['completion'] == 'all_recovered'
    assert s.verify(root, cfg, path)['status'] == 'Passed'
    assert s.recover(root, cfg, path, s.recovery_preview(root, cfg, path))['restored'] == []
