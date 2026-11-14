from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os

import pytest

from fifan_maintenance.advisory import audit
from fifan_maintenance.advisory_cli import add_parser, run
from fifan_maintenance.directory_common import validate_seal
from fifan_maintenance.project import DEFAULT_CONFIG


def setup(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    text = 'TASK-42 pending\nDo not delete\nLimit 17 files\nManual check pending\n'
    (root / 'baseline.md').write_text(text)
    (root / 'candidate.md').write_text(text)
    def ref(name):
        return {'path': name, 'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest()}
    request = {'schema_version': 1, 'project_root': str(root), 'documents': [
        {'baseline': ref('baseline.md'), 'candidate': ref('candidate.md'), 'requirements': [
            {'id': 'task', 'kind': 'task_id', 'text': 'TASK-42'},
            {'id': 'negative', 'kind': 'negation', 'text': 'Do not delete'},
            {'id': 'limit', 'kind': 'number', 'text': '17 files'},
            {'id': 'pending', 'kind': 'pending', 'text': 'Manual check pending'}]}]}
    return root, request, ref


def test_literal_success_is_not_semantic_acceptance_and_project_unchanged(tmp_path):
    root, request, ref = setup(tmp_path)
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    result = audit(root, deepcopy(DEFAULT_CONFIG), request)
    validate_seal(result)
    assert result['status'] == 'Passed'
    assert result['semantic_acceptance'] == 'Unknown'
    assert result['physical_space_released_bytes'] is None
    assert result['project_writes'] == 0
    assert all(r['baseline_lines'] and r['candidate_lines'] for r in result['documents'][0]['requirements'])
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before
    assert 'Do not delete' not in json.dumps(result)


@pytest.mark.parametrize('removed,identifier', [('TASK-42', 'task'), ('Do not delete', 'negative'),
                                               ('17 files', 'limit'), ('Manual check pending', 'pending')])
def test_missing_critical_literal_has_original_line_and_id(tmp_path, removed, identifier):
    root, request, ref = setup(tmp_path)
    candidate = root / 'candidate.md'
    candidate.write_text(candidate.read_text().replace(removed, ''))
    request['documents'][0]['candidate'] = ref('candidate.md')
    result = audit(root, DEFAULT_CONFIG, request)
    assert result['status'] == 'Blocked'
    missing = next(r for r in result['documents'][0]['requirements'] if r['id'] == identifier)
    assert missing['status'] == 'Failed' and missing['baseline_lines'] and not missing['candidate_lines']
    assert result['hard_blockers'][0]['requirement_id'] == identifier


def test_baseline_absent_is_unknown_and_blocks(tmp_path):
    root, request, ref = setup(tmp_path)
    request['documents'][0]['requirements'][0]['text'] = 'TASK-UNKNOWN'
    result = audit(root, DEFAULT_CONFIG, request)
    assert result['status'] == 'Blocked'
    assert result['documents'][0]['requirements'][0]['status'] == 'Unknown'


def test_declared_hash_binding_blocks_without_regeneration(tmp_path):
    root, request, ref = setup(tmp_path)
    (root / 'manifest.json').write_text('{}')
    (root / 'recover.json').write_text('{}')
    (root / 'candidate.md').write_text((root / 'candidate.md').read_text() + 'Extra\n')
    request['documents'][0]['candidate'] = ref('candidate.md')
    request['bindings'] = [{'file': ref('manifest.json'), 'source': 'baseline.md'}]
    request['recovery'] = [ref('recover.json')]
    result = audit(root, DEFAULT_CONFIG, request)
    assert result['bindings'][0]['affected'] and not result['bindings'][0]['regenerated']
    assert result['hard_blockers'][0]['reason_code'] == 'DECLARED_BINDING_IMPACT'
    assert result['recovery_entries'][0]['execution_status'] == 'Not run'
    assert (root / 'manifest.json').read_text() == '{}'


def test_search_measures_only_declared_sets_and_no_benefit_nochange(tmp_path):
    root, request, ref = setup(tmp_path)
    request['search'] = {'before': [ref('baseline.md')], 'after': [ref('candidate.md')]}
    search = audit(root, DEFAULT_CONFIG, request)['search']
    assert search['recommendation'] == 'NoChange' and search['effective_search_configuration'] == 'Unknown'
    request['search']['before'].append(ref('candidate.md'))
    search = audit(root, DEFAULT_CONFIG, request)['search']
    assert search['declared_scope_reduction'] == 1 and search['recommendation'] == 'Review'
    assert search['archive_benefit'] == 'Unknown'


@pytest.mark.parametrize('bad', ['../escape', '.env', '.git/secret', 'link.md', 'hard.md'])
def test_protected_symlink_hardlink_and_escape_refused(tmp_path, bad):
    root, request, ref = setup(tmp_path)
    (root / '.env').write_text('secret')
    (root / 'link.md').symlink_to(root / 'baseline.md')
    os.link(root / 'candidate.md', root / 'hard.md')
    request['documents'][0]['baseline'] = {'path': bad, 'sha256': '0' * 64}
    with pytest.raises((ValueError, OSError)):
        audit(root, DEFAULT_CONFIG, request)


def test_drift_oversize_and_config_protection_refused(tmp_path):
    root, request, ref = setup(tmp_path)
    (root / 'baseline.md').write_text('drift')
    with pytest.raises(ValueError):
        audit(root, DEFAULT_CONFIG, request)
    request['documents'][0]['baseline'] = ref('baseline.md')
    (root / 'baseline.md').write_bytes(b'x' * (1024 * 1024 + 1))
    request['documents'][0]['baseline'] = ref('baseline.md')
    with pytest.raises(ValueError):
        audit(root, DEFAULT_CONFIG, request)
    config = deepcopy(DEFAULT_CONFIG)
    config['protected'].append('candidate.md')
    request['documents'][0]['baseline'] = ref('candidate.md')
    with pytest.raises(ValueError):
        audit(root, config, request)


def test_source_changes_during_audit_are_rejected(tmp_path, monkeypatch):
    root, request, ref = setup(tmp_path)
    from fifan_maintenance import advisory
    original = advisory.read_file
    reads = 0
    def changed(*args, **kwargs):
        nonlocal reads
        reads += 1
        if reads == 3:
            (root / 'baseline.md').write_text('changed')
        return original(*args, **kwargs)
    monkeypatch.setattr(advisory, 'read_file', changed)
    with pytest.raises(ValueError):
        audit(root, DEFAULT_CONFIG, request)


def test_cli_new_external_report_and_bounded_stdout(tmp_path, capsys):
    root, request, ref = setup(tmp_path)
    request_path = tmp_path / 'request.json'
    request_path.write_text(json.dumps(request))
    output = tmp_path / 'report.json'
    parser = argparse.ArgumentParser()
    add_parser(parser.add_subparsers(dest='command'))
    args = parser.parse_args(['advisory', '--project', str(root), '--request', str(request_path),
                              '--output', str(output), '--max-output-bytes', '1024'])
    assert run(root, DEFAULT_CONFIG, args) == 0
    stdout = capsys.readouterr().out
    assert len(stdout.encode()) <= 1024
    assert json.loads(stdout)['details_omitted']
    assert json.loads(output.read_text())['status'] == 'Passed'
    assert run(root, DEFAULT_CONFIG, args) == 2
    assert json.loads(capsys.readouterr().err)['status'] == 'Blocked'
    args.output = str(root / 'out.json')
    assert run(root, DEFAULT_CONFIG, args) == 2
    assert not (root / 'out.json').exists()
    capsys.readouterr()
    args.output = str(tmp_path / 'link.json')
    (tmp_path / 'link.json').symlink_to(output)
    assert run(root, DEFAULT_CONFIG, args) == 2
    capsys.readouterr()
    args.output = None
    args.request = str(tmp_path / '.env')
    (tmp_path / '.env').write_text(json.dumps(request))
    assert run(root, DEFAULT_CONFIG, args) == 2
    capsys.readouterr()


def test_empty_requirement_scope_is_unknown_and_output_budget_rejected(tmp_path):
    root, request, ref = setup(tmp_path)
    request['documents'][0]['requirements'] = []
    assert audit(root, DEFAULT_CONFIG, request)['status'] == 'Unknown'
    request['documents'] = []
    assert audit(root, DEFAULT_CONFIG, request)['semantic_acceptance'] == 'Unknown'


def test_request_and_output_hardlinks_aliases_and_oversize_rejected(tmp_path, capsys):
    root, request, ref = setup(tmp_path)
    request_path = tmp_path / 'request.json'
    request_path.write_text(json.dumps(request))
    parser = argparse.ArgumentParser()
    add_parser(parser.add_subparsers(dest='command'))
    args = parser.parse_args(['advisory', '--project', str(root), '--request', str(request_path)])
    alias = tmp_path / 'alias.json'
    os.link(request_path, alias)
    args.request = str(alias)
    assert run(root, DEFAULT_CONFIG, args) == 2
    capsys.readouterr()
    alias.unlink()
    alias.symlink_to(request_path)
    assert run(root, DEFAULT_CONFIG, args) == 2
    capsys.readouterr()
    args.request = str(request_path)
    request_path.write_bytes(b' ' * (256 * 1024 + 1))
    assert run(root, DEFAULT_CONFIG, args) == 2
    capsys.readouterr()
    args.max_output_bytes = 256
    assert run(root, DEFAULT_CONFIG, args) == 2
    capsys.readouterr()


def test_native_case_alias_and_binding_undeclared_source_rejected(tmp_path):
    root, request, ref = setup(tmp_path)
    alias = root / 'BASELINE.md'
    if alias.exists():
        request['documents'][0]['baseline']['path'] = alias.name
        with pytest.raises(ValueError):
            audit(root, DEFAULT_CONFIG, request)
    root, request, ref = (root, {**request, 'documents': []}, ref)
    request['bindings'] = [{'file': ref('candidate.md'), 'source': 'not-declared.md'}]
    with pytest.raises(ValueError):
        audit(root, DEFAULT_CONFIG, request)


def test_bounded_locations_do_not_expand_with_repeated_text(tmp_path):
    root, request, ref = setup(tmp_path)
    for name in ('baseline.md', 'candidate.md'):
        (root / name).write_text('Keep\n' * 10000)
    doc = request['documents'][0]
    doc.update(baseline=ref('baseline.md'), candidate=ref('candidate.md'),
               requirements=[{'id': 'repeated', 'kind': 'text', 'text': 'Keep'}])
    result = audit(root, DEFAULT_CONFIG, request)
    lines = result['documents'][0]['requirements'][0]
    assert len(lines['baseline_lines']) == lines['location_limit_per_document'] == 32


@pytest.mark.parametrize('change', ['fields', 'duplicate-id', 'multiline', 'invalid-sha', 'duplicate-search'])
def test_malformed_contracts_refused(tmp_path, change):
    root, request, ref = setup(tmp_path)
    doc = request['documents'][0]
    if change == 'fields':
        request['execute'] = 'never'
    elif change == 'duplicate-id':
        doc['requirements'].append(doc['requirements'][0])
    elif change == 'multiline':
        doc['requirements'][0]['text'] = 'TASK-42\npending'
    elif change == 'invalid-sha':
        doc['baseline']['sha256'] = 'not-sha'
    elif change == 'duplicate-search':
        request['search'] = {'before': [ref('baseline.md')] * 2, 'after': []}
    with pytest.raises(ValueError):
        audit(root, DEFAULT_CONFIG, request)


@pytest.mark.parametrize('budget,value', [('max_files', 1), ('max_file_bytes', 1), ('max_total_bytes', 70)])
def test_project_budgets_remain_effective(tmp_path, budget, value):
    root, request, ref = setup(tmp_path)
    config = deepcopy(DEFAULT_CONFIG)
    config[budget] = value
    with pytest.raises(ValueError):
        audit(root, config, request)


def test_time_budget_and_no_document_unknown(tmp_path, monkeypatch):
    root, request, ref = setup(tmp_path)
    from fifan_maintenance import advisory
    ticks = iter([0, 11])
    monkeypatch.setattr(advisory.time, 'monotonic', lambda: next(ticks))
    with pytest.raises(ValueError):
        audit(root, DEFAULT_CONFIG, request)


def test_total_body_budget_includes_final_rereads(tmp_path, monkeypatch):
    root, request, ref = setup(tmp_path)
    for name in ('baseline.md', 'candidate.md'):
        (root / name).write_bytes(b'x' * 40)
    request['documents'][0].update(baseline=ref('baseline.md'), candidate=ref('candidate.md'),
                                    requirements=[{'id': 'keep', 'kind': 'text', 'text': 'x'}])
    config = deepcopy(DEFAULT_CONFIG)
    config['max_total_bytes'] = 100
    from fifan_maintenance import advisory
    original = advisory.read_file
    actual_bytes = 0
    def measured(*args, **kwargs):
        nonlocal actual_bytes
        data = original(*args, **kwargs)
        actual_bytes += len(data)
        return data
    monkeypatch.setattr(advisory, 'read_file', measured)
    with pytest.raises(ValueError):
        audit(root, config, request)
    assert actual_bytes <= config['max_total_bytes']


def test_exact_total_budget_reports_actual_io_with_reused_selections(tmp_path, monkeypatch):
    root, request, ref = setup(tmp_path)
    for name in ('baseline.md', 'candidate.md'):
        (root / name).write_bytes(b'x' * 40)
    request['documents'][0].update(baseline=ref('baseline.md'), candidate=ref('candidate.md'),
                                    requirements=[{'id': 'keep', 'kind': 'text', 'text': 'x'}])
    request['search'] = {'before': [ref('baseline.md')], 'after': [ref('candidate.md')]}
    config = deepcopy(DEFAULT_CONFIG)
    config['max_total_bytes'] = 160
    from fifan_maintenance import advisory
    original = advisory.read_file
    actual_bytes = 0
    def measured(*args, **kwargs):
        nonlocal actual_bytes
        data = original(*args, **kwargs)
        actual_bytes += len(data)
        return data
    monkeypatch.setattr(advisory, 'read_file', measured)
    result = audit(root, config, request)
    assert result['status'] == 'Passed'
    assert result['body_bytes_read'] == actual_bytes == 160


@pytest.mark.parametrize('budget', [160, 161])
def test_growth_after_final_fstat_never_physically_reads_over_budget(tmp_path, monkeypatch, budget):
    root, request, ref = setup(tmp_path)
    for name in ('baseline.md', 'candidate.md'):
        (root / name).write_bytes(b'x' * 40)
    request['documents'][0].update(baseline=ref('baseline.md'), candidate=ref('candidate.md'),
                                    requirements=[{'id': 'keep', 'kind': 'text', 'text': 'x'}])
    config = deepcopy(DEFAULT_CONFIG)
    config['max_total_bytes'] = budget
    from fifan_maintenance import advisory
    original_file_read = advisory.read_file
    original_os_read = os.read
    invocation = 0
    grew = False
    actual_bytes = 0
    def marked(*args, **kwargs):
        nonlocal invocation
        invocation += 1
        return original_file_read(*args, **kwargs)
    def measured(fd, count):
        nonlocal actual_bytes, grew
        if invocation == 4 and not grew:
            # The shared reader has already fstat'ed this FD. Grow the actual
            # file before its first read; strict IO must not consume the extra byte.
            assert os.fstat(fd).st_size == 40
            with (root / 'candidate.md').open('ab') as stream:
                stream.write(b'y')
            grew = True
        data = original_os_read(fd, count)
        actual_bytes += len(data)
        return data
    monkeypatch.setattr(advisory, 'read_file', marked)
    monkeypatch.setattr(os, 'read', measured)
    with pytest.raises((ValueError, OSError)):
        audit(root, config, request)
    assert grew and actual_bytes == 160
    assert actual_bytes <= budget
