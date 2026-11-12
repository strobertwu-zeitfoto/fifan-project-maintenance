from __future__ import annotations

import json
from pathlib import Path

import pytest

from fifan_maintenance.engine import run
from fifan_maintenance.project import load_config
from fifan_maintenance.scope import task_config


def test_exact_five_sources_and_1200_history_metadata(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    selected = []
    for i in range(5):
        path = f'key{i}.md'
        (root / path).write_text('# Current\n')
        selected.append(path)
    (root / 'history').mkdir()
    for i in range(1200):
        (root / 'history' / f'{i}.md').write_text('HISTORY MUST NOT BE READ\n')
    report = run(root, files=selected, historical_roots=['history'], checks=['links'])
    assert report['file_count'] == 5
    assert set(report['files']) == set(selected)
    assert report['historical_metadata']['file_count'] == 1200
    assert report['historical_metadata']['body_bytes_read'] == 0
    assert report['metrics']['inventory_read_bytes'] == 5 * len(b'# Current\n')
    assert not (root / '.fifan-maintenance.json').exists()


def test_preflight_metadata_only_and_file_not_directory(tmp_path, monkeypatch):
    (tmp_path / 'doc.md').write_text('# Current\n')
    from fifan_maintenance.models import Context
    def forbidden(*args):
        raise AssertionError('body read')
    monkeypatch.setattr(Context, 'read_bytes', forbidden)
    result = run(tmp_path, files=['doc.md'], checks=['links'], preflight=True)
    assert result['body_bytes_read'] == 0
    assert result['estimated_primary_bytes'] == 10
    result = run(tmp_path, files=['missing.md'], preflight=True)
    assert result['status'] == 'Blocked'


def test_profile_conflict_protection_and_hard_budgets(tmp_path):
    root = tmp_path / 'p'
    root.mkdir()
    profile = tmp_path / 'task.json'
    profile.write_text(json.dumps({'schema_version': 1, 'sources': ['a.md'], 'budgets': {'max_seconds': 12}}))
    cfg = load_config(root)
    assert task_config(root, cfg, profile=profile)['_task']['sources'] == ['a.md']
    with pytest.raises(ValueError):
        task_config(root, cfg, profile=profile, files=['b.md'])
    for files in [['../escape'], ['.env.local'], ['Library/no.md']]:
        with pytest.raises(ValueError):
            task_config(root, cfg, files=files)
    with pytest.raises(ValueError):
        task_config(root, cfg, files=['a.md'], max_seconds=301)
    with pytest.raises(ValueError):
        task_config(root, cfg, profile=root / 'task.json')


def test_reference_body_authorization_and_recheck(tmp_path):
    (tmp_path / 'a.md').write_text('[go](b.md#target)\n')
    (tmp_path / 'b.md').write_text('# Target\n')
    report = run(tmp_path, files=['a.md'], checks=['links'])
    assert any(f['code'] == 'anchor-body-not-authorized' for f in report['findings'])
    report = run(tmp_path, files=['a.md'], reference_bodies=['b.md'], checks=['links'])
    assert not report['findings']
    (tmp_path / 'b.md').write_text('# Changed\n')
    report = run(tmp_path, files=['a.md'], reference_bodies=['b.md'], checks=['links'])
    assert any(f['code'] == 'missing-anchor' for f in report['findings'])
    (tmp_path / 'b.md').unlink()
    report = run(tmp_path, files=['a.md'], checks=['links'])
    assert any(f['code'] == 'missing-target' for f in report['findings'])


def test_candidate_overlay_does_not_write(tmp_path):
    from fifan_maintenance.changes import overlay, preview
    (tmp_path / 'a.md').write_text('[go](archive.md#target)\n# Target\n')
    original = (tmp_path / 'a.md').read_bytes()
    import hashlib
    plan = preview(tmp_path, {'version': 2, 'operations': [{'kind': 'snapshot', 'path': 'a.md', 'destination': 'archive.md', 'expected_sha256': hashlib.sha256(original).hexdigest(), 'origin': {'reference_base': '.', 'classification_basis': 'explicit fixture'}}]}, load_config(tmp_path))
    proposed = overlay(tmp_path, plan, load_config(tmp_path))
    report = run(tmp_path, files=['a.md'], reference_bodies=['archive.md'], checks=['links'], overlay=proposed)
    assert report['candidate'] == 'Preview'
    assert not report['findings']
    assert not (tmp_path / 'archive.md').exists()
    assert (tmp_path / 'a.md').read_bytes() == original


def test_total_scoped_read_budget_is_shared_between_checks(tmp_path):
    (tmp_path / 'a.md').write_text('# Current\n')
    profile = tmp_path.parent / (tmp_path.name + '-profile.json')
    profile.write_text(json.dumps({'schema_version': 1, 'sources': ['a.md'], 'checks': ['documents', 'links'], 'budgets': {'max_total_bytes': 15}}))
    report = run(tmp_path, task_profile=profile)
    assert report['metrics']['inventory_read_bytes'] + report['metrics']['worker_read_bytes'] <= 15
    assert any(c['status'] == 'Unknown' for c in report['coverage'])


def test_repository_git_pathspec_never_enumerates_siblings(tmp_path, monkeypatch):
    from fifan_maintenance.models import Context, FileRecord
    from fifan_maintenance.checks import repository
    from types import SimpleNamespace
    (tmp_path / 'a.md').write_text('current')
    config = task_config(tmp_path, load_config(tmp_path), files=['a.md'])
    ctx = Context(tmp_path, {'a.md': FileRecord('a.md', 7, None, 0)}, config)
    seen = []
    def fake(argv, **kwargs):
        seen.append(argv)
        # Defensive filter also rejects an unexpected name in backend output.
        return SimpleNamespace(returncode=0, stdout=b'Library/private.bin\0a.md\0', stderr=b'')
    monkeypatch.setattr(repository, 'run_bounded', fake)
    assert not repository.run(ctx)
    assert seen[0][-1] == ':(literal)a.md'
    assert seen[0][-2] == '--'


def test_history_walk_errors_are_unknown(tmp_path, monkeypatch):
    from fifan_maintenance.models import Context
    from fifan_maintenance.scope import historical_metadata
    (tmp_path / 'history').mkdir()
    config = task_config(tmp_path, load_config(tmp_path), files=['a.md'], historical_roots=['history'])
    def denied(*args, **kwargs):
        kwargs['onerror'](PermissionError('denied'))
        return iter(())
    monkeypatch.setattr('fifan_maintenance.scope.os.walk', denied)
    result = historical_metadata(Context(tmp_path, {}, config))
    assert result['status'] == 'Unknown'
    assert result['file_count'] == 0


def test_assets_candidate_source_uses_overlay(tmp_path):
    from fifan_maintenance.models import Context
    from fifan_maintenance.checks import assets
    import base64
    (tmp_path / 'asset.png').write_bytes(b'image')
    config = load_config(tmp_path)
    config['asset_sources'] = {'asset.png': 'sources.md'}
    config['_overlay'] = {'sources.md': base64.b64encode(b'source record').decode()}
    ctx = Context(tmp_path, {}, config)
    assert not assets.run(ctx)
    assert not (tmp_path / 'sources.md').exists()


def test_repository_protected_names_not_reported_in_default_scan(tmp_path):
    import subprocess
    from fifan_maintenance.models import Context
    from fifan_maintenance.checks import repository
    from fifan_maintenance.inventory import collect
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path / 'obj').mkdir()
    (tmp_path / 'obj/cache.bin').write_bytes(b'protected')
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules/public.js').write_bytes(b'generated')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '--', '.'], check=True)
    config = load_config(tmp_path)
    config['protected'].append('obj/**')
    ctx = Context(tmp_path, {}, config, inventory=True)
    assert not collect(ctx)
    found = repository.run(ctx)
    assert {f.path for f in found if f.code == 'tracked_generated'} == {'node_modules/public.js'}


def test_protected_glob_base_file_is_excluded_everywhere(tmp_path):
    import subprocess
    from fifan_maintenance.models import Context
    from fifan_maintenance.inventory import collect
    from fifan_maintenance.checks import repository
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path / 'obj').write_bytes(b'protected base file')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '--', '.'], check=True)
    config = load_config(tmp_path)
    config['protected'].append('obj/**')
    ctx = Context(tmp_path, {}, config, inventory=True)
    with pytest.raises(ValueError):
        ctx.resolve('obj')
    assert not collect(ctx)
    assert not ctx.files
    assert not repository.run(ctx)
