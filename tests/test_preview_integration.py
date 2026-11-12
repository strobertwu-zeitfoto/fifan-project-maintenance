from __future__ import annotations

import json

import pytest

from fifan_maintenance.cli import main


def call_preview(tmp_path, request, capsys, profile=None, budget=4096):
    project = tmp_path / 'project'
    project.mkdir(exist_ok=True)
    request_path = tmp_path / 'request.json'
    request_path.write_text(json.dumps(request))
    args = ['preview', '--project', str(project), '--request', str(request_path),
            '--plan', str(tmp_path / 'plan.json'), '--receipt', str(tmp_path / 'receipt.json'),
            '--max-output-bytes', str(budget)]
    if profile:
        profile_path = tmp_path / 'profile.json'
        profile_path.write_text(json.dumps(profile))
        args.extend(['--task-profile', str(profile_path)])
    result = main(args)
    captured = capsys.readouterr()
    return result, captured


def test_large_unicode_diff_keeps_preview_with_actual_output_budget(tmp_path, capsys):
    project = tmp_path / 'project'
    project.mkdir()
    old = '\u4e2d' * 200000 + '\n'
    new = '\u6587' * 200000 + '\n'
    (project / 'a.md').write_text(old, encoding='utf-8')
    result, captured = call_preview(tmp_path, {'version': 2, 'operations': [
        {'type': 'replace', 'path': 'a.md', 'old': old, 'new': new}]}, capsys)
    assert result == 0, captured.err
    value = json.loads(captured.out)
    assert value['status'] == 'Preview' and value['diff_truncated']
    assert value['diff_bytes'] > 1024 * 1024
    assert len(captured.out.encode('utf-8')) <= 4096
    assert (project / 'a.md').read_text(encoding='utf-8') == old


@pytest.mark.parametrize('version', [2, 3])
def test_profile_guard_denied_before_any_body_read_or_plan(tmp_path, capsys, monkeypatch, version):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'a.md').write_text('old')
    (project / 'b.md').write_text('secret body')
    import fifan_maintenance.changes as changes
    def forbidden(*args):
        raise AssertionError('change backend read before authorization')
    monkeypatch.setattr(changes, '_read', forbidden)
    result, captured = call_preview(tmp_path, {'version': version, 'operations': [
        {'type': 'replace', 'path': 'a.md', 'old': 'old', 'new': 'new'}],
        'guards': [{'path': 'b.md', 'kind': 'snippet', 'value': 'secret body'}]}, capsys,
        {'schema_version': 2, 'sources': ['a.md'], 'reference_bodies': []})
    assert result == 2
    assert json.loads(captured.err)['project_writes'] == 0
    assert not (tmp_path / 'plan.json').exists()
    assert 'secret body' not in captured.err


def test_preview_measures_explicit_future_plan_before_creating_it(tmp_path, capsys):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'a.md').write_text('long original body')
    external = tmp_path / 'records'
    external.mkdir()
    # A disjoint external root is required, so output paths are its children.
    request = tmp_path / 'request.json'
    request.write_text(json.dumps({'version': 2, 'operations': [
        {'type': 'replace', 'path': 'a.md', 'old': 'long original body', 'new': 'short'}]}))
    profile = tmp_path / 'profile.json'
    profile.write_text(json.dumps({'schema_version': 2, 'sources': ['a.md'], 'goal': 'storage',
        'measurement': {'version': 1, 'active': ['a.md'], 'views': [], 'reused_archives': [],
            'new_archives': [], 'external_roots': [str(external)],
            'external_records': [{'root': str(external), 'path': 'plan.json'}],
            'allow_absent': [{'role': 'external_records', 'root': str(external), 'path': 'plan.json'}]}}))
    assert main(['preview', '--project', str(project), '--request', str(request),
        '--task-profile', str(profile), '--plan', str(external / 'plan.json'),
        '--receipt', str(external / 'receipt.json')]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)['goal_preview']['goal_result'] == 'Failed'
    receipt = json.loads((external / 'receipt.json').read_text())
    before = receipt['measurements']['before']['domains']['external_records']['items'][0]
    assert before['presence'] == 'Absent' and before['bytes'] == 0
    assert receipt['measurements']['candidate']['domains']['external_records']['bytes'] > 0


@pytest.mark.parametrize('version', [None, 2, 3])
def test_standard_replace_locator_all_versions(tmp_path, capsys, version):
    import hashlib
    project = tmp_path / 'project'
    project.mkdir()
    original = '旧正文\n'.encode('utf-8')
    (project / 'a.md').write_bytes(original)
    request = {'operations': [{'type': 'replace', 'path': 'a.md', 'old_locator': {
        'sha256': hashlib.sha256(original).hexdigest(), 'start_byte': 0,
        'end_byte': len('旧正文'.encode('utf-8'))}, 'new': '新正文'}]}
    if version is not None:
        request['version'] = version
    code, captured = call_preview(tmp_path, request, capsys)
    assert code == 0, captured.err
    plan = json.loads((tmp_path / 'plan.json').read_text())
    assert plan['operations'][0]['new'] == '新正文'
    assert (project / 'a.md').read_bytes() == original
