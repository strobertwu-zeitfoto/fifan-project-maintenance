import hashlib

import pytest

from fifan_maintenance.dynamic_review import classify, review_pack, unresolved_compact_paths


def test_constant_fstring_only_resolves_its_own_expression():
    text = 'name = f"fixed"\nopen(f"{root}/old.blend1")\n'
    assert classify('a.py', text, 1, 8)['literal_only']
    assert not classify('a.py', text, 2, 6)['literal_only']
    assert classify('a.py', text, 2, 6)['reference_layer'] == 'file_access'


def test_utf8_columns_and_nested_interpolation_are_conservative():
    text = '值 = f"constant"\nname = f"{open(path).read()}"\n'
    assert classify('a.py', text, 1, 5)['literal_only']
    assert not classify('a.py', text, 2, 8)['literal_only']
    assert not classify('a.js', 'const x = `${value}`', 1, 12)['literal_only']
    assert not classify('a.py', 'invalid python !!!', 1, 1)['literal_only']


def test_compact_path_is_explicit_unknown():
    value = list(unresolved_compact_paths('README.md', 'See runs/{first,second}/result.md', 'a' * 64))
    assert value[0]['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN'
    assert value[0]['line'] == 1 and value[0]['column'] == 5


def test_review_deduplicates_origins_not_candidates_or_evidence():
    origin = {'path': 'a.py', 'sha256': 'a' * 64, 'line': 1, 'column': 1,
              'expression_sha256': hashlib.sha256(b'f"{x}"').hexdigest(),
              'reason_code': 'DYNAMIC_REFERENCE_UNKNOWN'}
    result = review_pack({'items': [{'source': name, 'unknowns': [dict(origin)]} for name in ('old/a', 'old/b')]})
    assert result['origin_count'] == 1
    assert result['groups'][0]['candidates'] == ['old/a', 'old/b']
    assert result['status'] == 'Unknown' and not result['authorizes_mutation']
    origin['sha256'] = 'b' * 64
    result = review_pack({'items': [{'source': 'old/a', 'unknowns': [origin]}]})
    assert result['groups'][0]['origin']['sha256'] == 'b' * 64
    with pytest.raises(ValueError):
        review_pack({'items': [{'unknowns': [{'reason_code': 'DYNAMIC_REFERENCE_UNKNOWN'}]}]})


@pytest.mark.parametrize('name,text,dependency,dynamic', [
    ('entry.py', 'label = f"hello"\n', False, False),
    ('entry.py', 'path = f"old/run/data.bin"\n', True, False),
    ('entry.py', 'path = f"{root}/data.bin"\n', False, True),
    ('entry.py', 'open(f"old/\\x72un/data.bin")\n', False, True),
    ('entry.py', 'open(f"old/" "run/data.bin")\n', False, True),
    ('README.md', 'See old/{run,other}/data.bin\n', False, True),
])
def test_native_impact_keeps_static_dependencies_and_real_unknowns(tmp_path, name, text, dependency, dynamic):
    from copy import deepcopy
    from fifan_maintenance import directory_common as dc
    from fifan_maintenance.directory_census import impact
    from fifan_maintenance.project import DEFAULT_CONFIG
    (tmp_path / 'old/run').mkdir(parents=True)
    (tmp_path / 'old/run/data.bin').write_bytes(b'fixture')
    (tmp_path / name).write_text(text)
    (tmp_path / 'closed.md').write_text('Temporary batch closed\n')
    profile = dc.load_profile(tmp_path, deepcopy(DEFAULT_CONFIG), {
        'schema_version': 1, 'project_root': str(tmp_path),
        'reference_sources': [{'path': name, 'role': 'current'}, {'path': 'closed.md', 'role': 'historical'}],
        'classifications': [{'path': 'old/run', 'role': 'historical', 'reason': 'closed fixture'}],
        'archive': {'candidates': ['old/run']}})
    request = {'schema_version': 1, 'batches': [{'source': 'old/run', 'destination': 'closed/run',
        'closure': {'decision': 'closed', 'reason': 'fixture completed', 'evidence': [
            {'path': 'closed.md', 'sha256': hashlib.sha256((tmp_path / 'closed.md').read_bytes()).hexdigest()}]}}]}
    batch = impact(profile, request)['batches'][0]
    assert bool(batch['current_dependencies']) == dependency
    assert any(x.get('reason_code') == 'DYNAMIC_REFERENCE_UNKNOWN' for x in batch['unknowns']) == dynamic
    if not dependency and not dynamic:
        assert batch['eligible']


def test_review_cli_sha_binding_protection_and_new_output(tmp_path, capsys):
    import json
    from fifan_maintenance.cli import main
    project = tmp_path / 'project'
    project.mkdir()
    text = 'value = f"{root}/old"\n'
    (project / 'entry.py').write_text(text)
    hint = {'path': 'entry.py', 'sha256': hashlib.sha256(text.encode()).hexdigest(),
            'line': 1, 'column': 9, 'expression_sha256': hashlib.sha256(b'f"').hexdigest(),
            'reason_code': 'DYNAMIC_REFERENCE_UNKNOWN'}
    request = tmp_path / 'observed.json'
    request.write_text(json.dumps({'items': [{'source': 'old', 'unknowns': [hint]}]}))
    args = ['reference-review', '--project', str(project), '--request', str(request), '--files', 'entry.py']
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['groups'][0]['classification']['reference_layer'] == 'dynamic_syntax'
    assert report['semantic_acceptance'] == 'Not run' and not report['authorizes_mutation']
    output = tmp_path / 'review-new.json'
    assert main(args + ['--output', str(output)]) == 0
    capsys.readouterr()
    assert json.loads(output.read_text())['origin_count'] == 1
    (project / 'entry.py').write_text('changed\n')
    assert main(args) == 2
    capsys.readouterr()
    assert main(args[:-1] + ['.env']) == 2
    capsys.readouterr()
    assert main(args + ['--output', str(request)]) == 2
    capsys.readouterr()


@pytest.mark.parametrize('body', [r'open(f"logs/finished.\x6cog")', 'open(f"logs/" "finished.log")'])
def test_cleanup_retains_unknown_for_escaped_or_joined_static_values(tmp_path, body):
    from test_cleanup_policy import fixture
    from fifan_maintenance import cleanup_policy
    profile, request, _, _ = fixture(tmp_path)
    (profile.root / 'current/consumer.py').write_text(body + '\n')
    result = cleanup_policy.qualify(profile, request)
    assert not result['items'][0]['eligible']
    assert any(item.get('reason_code') == 'DYNAMIC_REFERENCE_UNKNOWN'
               for item in result['items'][0]['unknowns'])


def test_escaped_braces_do_not_lose_actual_candidate_dependency(tmp_path):
    from copy import deepcopy
    from fifan_maintenance import directory_common as dc
    from fifan_maintenance.directory_census import impact
    from fifan_maintenance.project import DEFAULT_CONFIG
    (tmp_path / 'old/{run}').mkdir(parents=True)
    (tmp_path / 'old/{run}/data.bin').write_bytes(b'fixture')
    (tmp_path / 'entry.py').write_text('open(f"old/{{run}}/data.bin")\n')
    (tmp_path / 'closed.md').write_text('Closed synthetic fixture\n')
    profile = dc.load_profile(tmp_path, deepcopy(DEFAULT_CONFIG), {
        'schema_version': 1, 'project_root': str(tmp_path),
        'reference_sources': [{'path': 'entry.py', 'role': 'current'}, {'path': 'closed.md', 'role': 'historical'}],
        'classifications': [{'path': 'old/{run}', 'role': 'historical', 'reason': 'closed'}],
        'archive': {'candidates': ['old/{run}']}})
    request = {'schema_version': 1, 'batches': [{'source': 'old/{run}', 'destination': 'closed/run',
        'closure': {'decision': 'closed', 'reason': 'closed', 'evidence': [
            {'path': 'closed.md', 'sha256': hashlib.sha256((tmp_path / 'closed.md').read_bytes()).hexdigest()}]}}]}
    result = impact(profile, request)['batches'][0]
    assert not result['eligible']
