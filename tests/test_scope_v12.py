from __future__ import annotations

import json

import pytest

from fifan_maintenance.engine import run
from fifan_maintenance.comparison import compare_reports
from fifan_maintenance.models import Context
from fifan_maintenance.project import load_config
from fifan_maintenance.scope import task_config, derive_profile, historical_metadata


def profile(tmp_path, data):
    path = tmp_path.parent / (tmp_path.name + '-task.json')
    path.write_text(json.dumps(data))
    return path


def test_profile1_not_silently_reinterpreted_as_profile2(tmp_path):
    base = {'schema_version': 1, 'sources': ['a.md'], 'goal': 'body-slim'}
    with pytest.raises(ValueError):
        task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, base))
    base['schema_version'] = 2
    config = task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, base))
    assert config['_task']['goal'] == 'body-slim'
    assert 'goal' not in load_config(tmp_path)


def test_derive_retains_exact_body_grants_and_narrows_views(tmp_path):
    (tmp_path / 'a[1].md').write_text('# A\n')
    (tmp_path / 'a1.md').write_text('unauthorized')
    (tmp_path / 'keep.md').write_text('# Keep\n')
    parent = profile(tmp_path, {'schema_version': 2, 'sources': ['a[1].md', 'keep.md'], 'reference_bodies': [], 'views': [{'name': 'current', 'path': 'a[1].md', 'start_line': 1, 'end_line': 1, 'kind': 'current'}]})
    result = derive_profile(tmp_path, load_config(tmp_path), parent, sources=['keep.md'], checks=['links'])
    child = tmp_path.parent / (tmp_path.name + '-child.json')
    child.write_text(json.dumps(result['profile']))
    config = task_config(tmp_path, load_config(tmp_path), profile=child)
    ctx = Context(tmp_path, {}, config)
    assert ctx.read_text('a[1].md') == '# A\n'
    with pytest.raises(ValueError):
        ctx.read_text('a1.md')
    assert result['profile']['views'] == []
    assert result['changes']['permission_expansion'] is False
    narrowed = derive_profile(tmp_path, load_config(tmp_path), parent, sources=['keep.md'], reference_bodies=[])
    assert narrowed['profile']['reference_bodies'] == []
    with pytest.raises(ValueError):
        derive_profile(tmp_path, load_config(tmp_path), parent, sources=['a1.md'])
    with pytest.raises(ValueError):
        derive_profile(tmp_path, load_config(tmp_path), parent, sources=['keep.md'], reference_bodies=['**'])


@pytest.mark.parametrize('extra', [{'goal': {'kind': 'body-slim', 'minimum_reduction_bytes': True}}, {'history_budget': {'max_files': 100001}}, {'history_budget': {'max_depth': -1}}, {'goal': {'kind': 'navigation', 'exceptions': [{'path': '../escape', 'reason': 'x'}]}}])
def test_profile2_rejects_invalid_threshold_and_scope(tmp_path, extra):
    with pytest.raises(ValueError):
        task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, {'schema_version': 2, 'sources': ['a.md'], **extra}))


def test_history_has_separate_budget_lower_bound_and_no_bodies(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('source')
    (tmp_path / 'history/deep').mkdir(parents=True)
    (tmp_path / 'history/top.md').write_text('never read')
    (tmp_path / 'history/deep/hidden.md').write_text('never read')
    config = task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, {'schema_version': 2, 'sources': ['a.md'], 'historical_roots': ['history'], 'budgets': {'max_files': 1}, 'history_budget': {'max_files': 10, 'max_depth': 0, 'max_output_entries': 0}}))
    def forbidden(*args):
        raise AssertionError('history body read')
    monkeypatch.setattr(Context, 'read_bytes', forbidden)
    result = historical_metadata(Context(tmp_path, {}, config))
    assert result['file_count'] == 1
    assert result['body_bytes_read'] == 0
    assert result['count_is_lower_bound']
    assert result['entries'] == [] and result['entries_truncated']
    assert result['roots'][0]['reasons'] == ['DEPTH_LIMIT']


def test_per_root_limit_does_not_hide_an_independent_root(tmp_path):
    for rel in ['h1/a.md', 'h1/b.md', 'h2/c.md']:
        path = tmp_path / rel
        path.parent.mkdir(exist_ok=True)
        path.write_text('x')
    config = task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, {'schema_version': 2, 'sources': ['a.md'], 'historical_roots': ['h1', 'h2'], 'history_budget': {'max_files': 5, 'per_root_max_files': {'h1': 1}}}))
    result = historical_metadata(Context(tmp_path, {}, config))
    assert result['file_count'] == 2
    assert result['roots'][0]['status'] == 'Unknown'
    assert result['roots'][1]['status'] == 'Passed'


def test_domain_comparison_preserves_global_unknown(tmp_path):
    (tmp_path / 'a.md').write_text('[local](missing.md)\n[web](https://example.org)\n')
    before = run(tmp_path, files=['a.md'], checks=['links'])
    (tmp_path / 'a.md').write_text('explanation\n[local](missing.md)\n[web](https://example.org)\n')
    after = run(tmp_path, files=['a.md'], checks=['links'])
    compared = compare_reports(before, after)
    assert compared['status'] == 'Unknown' and compared['no_new_issues'] is None
    local = compared['domains']['local_targets']
    assert local['complete'] and local['no_new_issues'] is True
    assert local['counts'] == {'new': 0, 'existing': 1, 'resolved': 0}
    assert not compared['domains']['external']['complete']
    (tmp_path / 'a.md').write_text('[local](new-missing.md)\n[web](https://example.org)\n')
    changed = compare_reports(before, run(tmp_path, files=['a.md'], checks=['links']))
    assert changed['domains']['local_targets']['status'] == 'Failed'
    assert changed['domains']['local_targets']['counts']['new'] == 1


def test_history_empty_and_excluded_directories_consume_entry_budget(tmp_path, monkeypatch):
    from fifan_maintenance import scope
    (tmp_path / 'a.md').write_text('source')
    history = tmp_path / 'history'
    history.mkdir()
    for index in range(30):
        (history / ('empty-%02d' % index)).mkdir()
    config = task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, {
        'schema_version': 2, 'sources': ['a.md'], 'historical_roots': ['history'],
        'history_budget': {'max_files': 3, 'max_depth': 0}}))
    seen = []
    original = Context.resolve
    def counted(self, rel):
        if rel.startswith('history/'):
            seen.append(rel)
        return original(self, rel)
    monkeypatch.setattr(Context, 'resolve', counted)
    result = historical_metadata(Context(tmp_path, {}, config))
    assert result['status'] == 'Unknown'
    assert 'FILE_BUDGET' in result['roots'][0]['reasons']
    assert result['entry_count'] == 3
    assert result['directory_count'] == 3
    assert result['file_count'] == 0
    assert len(seen) <= 3
    assert result['count_is_lower_bound']
    assert 'history' in result['unvisited_directories']


def test_history_excluded_entries_cannot_bypass_global_budget(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('source')
    (tmp_path / 'history').mkdir()
    for index in range(20):
        (tmp_path / ('history/skip-%02d' % index)).mkdir()
    base = load_config(tmp_path)
    base['exclude'] = ['history/skip-*']
    config = task_config(tmp_path, base, profile=profile(tmp_path, {
        'schema_version': 2, 'sources': ['a.md'], 'historical_roots': ['history'],
        'history_budget': {'max_files': 4}}))
    monkeypatch.setattr(Context, 'read_bytes', lambda *args: pytest.fail('history body read'))
    result = historical_metadata(Context(tmp_path, {}, config))
    assert result['entry_count'] == 4
    assert result['excluded'] == 4
    assert result['file_count'] == 0
    assert result['status'] == 'Unknown'
    assert 'FILE_BUDGET' in result['roots'][0]['reasons']
    assert result['body_bytes_read'] == 0


def test_history_streams_directory_entries_without_eager_enumeration(tmp_path, monkeypatch):
    from fifan_maintenance import scope
    (tmp_path / 'a.md').write_text('source')
    (tmp_path / 'history').mkdir()
    for index in range(100):
        (tmp_path / ('history/empty-%03d' % index)).mkdir()
    config = task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, {
        'schema_version': 2, 'sources': ['a.md'], 'historical_roots': ['history'],
        'history_budget': {'max_files': 3, 'max_depth': 0}}))
    scandir = scope.os.scandir
    fetched = []
    class Counted:
        def __init__(self, fd):
            assert isinstance(fd, int)
            self.iterator = scandir(fd)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.iterator.close()
        def __next__(self):
            value = next(self.iterator)
            fetched.append(value.name)
            return value
    monkeypatch.setattr(scope.os, 'scandir', Counted)
    monkeypatch.setattr(scope.os, 'walk', lambda *args, **kwargs: pytest.fail('unbounded os.walk'))
    result = historical_metadata(Context(tmp_path, {}, config))
    assert len(fetched) == result['entry_count'] == 3
    assert 'FILE_BUDGET' in result['roots'][0]['reasons']


def test_history_directory_loop_checks_elapsed_time(tmp_path, monkeypatch):
    from fifan_maintenance import scope
    (tmp_path / 'a.md').write_text('source')
    (tmp_path / 'history').mkdir()
    for index in range(100):
        (tmp_path / ('history/empty-%03d' % index)).mkdir()
    config = task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, {
        'schema_version': 2, 'sources': ['a.md'], 'historical_roots': ['history'],
        'history_budget': {'max_files': 1000, 'max_depth': 0, 'max_seconds': 1}}))
    ticks = [0.0]
    def clock():
        ticks[0] += 0.1
        return ticks[0]
    monkeypatch.setattr(scope.time, 'monotonic', clock)
    result = historical_metadata(Context(tmp_path, {}, config))
    assert result['status'] == 'Unknown'
    assert 0 < result['entry_count'] < 10
    assert 'TIME_BUDGET' in result['roots'][0]['reasons']
    assert result['count_is_lower_bound']
    assert 'history' in result['unvisited_directories']


def test_history_nested_empty_directories_consume_per_root_budget(tmp_path):
    (tmp_path / 'a.md').write_text('source')
    (tmp_path / 'h1/one/two/three').mkdir(parents=True)
    (tmp_path / 'h2').mkdir()
    (tmp_path / 'h2/kept.md').write_text('metadata only')
    config = task_config(tmp_path, load_config(tmp_path), profile=profile(tmp_path, {
        'schema_version': 2, 'sources': ['a.md'], 'historical_roots': ['h1', 'h2'],
        'history_budget': {'max_files': 10, 'per_root_max_files': {'h1': 2}}}))
    result = historical_metadata(Context(tmp_path, {}, config))
    assert result['roots'][0]['entry_count'] == 2
    assert result['roots'][0]['directory_count'] == 2
    assert result['roots'][0]['status'] == 'Unknown'
    assert result['roots'][1]['status'] == 'Passed'
    assert result['roots'][1]['file_count'] == 1
    assert result['entry_count'] == 3
    assert result['file_count'] == 1
