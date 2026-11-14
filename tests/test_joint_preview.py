from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from fifan_maintenance import changes
from fifan_maintenance import directory_archive as da
from fifan_maintenance import directory_census as census
from fifan_maintenance import directory_common as dc
from fifan_maintenance import joint_preview as joint
from fifan_maintenance.project import load_config


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def fixture(tmp_path):
    project, archive, records = [tmp_path / name for name in ('project', 'archive', 'records')]
    for root in (project, archive, records):
        root.mkdir()
    (project / 'runs/closed').mkdir(parents=True)
    (project / 'runs/closed/report.md').write_text('# Report\n\nEvidence\n')
    (project / 'README.md').write_text('[old](runs/closed/report.md)\n')
    (project / 'closure.md').write_text('Explicit closed synthetic run\n')
    data = {'schema_version': 1, 'project_root': str(project), 'scan_roots': ['.'],
            'critical_paths': ['README.md'],
            'reference_sources': [{'path': 'README.md', 'role': 'current'}, {'path': 'closure.md', 'role': 'historical'}],
            'classifications': [{'path': 'runs/closed', 'role': 'historical', 'reason': 'Explicit closed fixture'}],
            'archive': {'archive_root': str(archive), 'records_dir': str(records), 'candidates': ['runs/closed'], 'require_no_open_handles': False}}
    config = load_config(project)
    profile = dc.load_profile(project, config, data)
    request = {'schema_version': 1, 'batches': [{'source': 'runs/closed', 'destination': 'history/closed',
               'closure': {'decision': 'closed', 'reason': 'Fixture finished', 'evidence': [{'path': 'closure.md', 'sha256': sha((project / 'closure.md').read_bytes())}]}}]}
    plan = changes.preview(project, {'operations': [{'type': 'replace', 'path': 'README.md',
                          'old': '[old](runs/closed/report.md)', 'new': '[archived](../archive/history/closed/report.md)'}]}, config)
    return profile, plan, request, archive, records


def preview(fixture):
    return joint.preview(*fixture)


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.lstat().st_ino, p.lstat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
            for p in root.rglob('*')}


def test_old_navigation_blocks_but_final_archive_target_previews_without_writes(fixture):
    profile, plan, request, archive, records = fixture
    before = snapshot(profile.root)
    assert census.impact(profile, request)['status'] == 'Blocked'
    result = preview(fixture)
    assert result['status'] == 'Preview', result
    assert result['format'] == joint.FORMAT and result['executable'] is False
    assert result['navigation']['targets'][0]['location'] == 'future_archive'
    assert 'fresh native directory archive-preview' in result['execution_order'][2]
    assert snapshot(profile.root) == before
    assert not list(archive.iterdir()) and not list(records.iterdir())
    assert joint.validate_candidate(profile, result, plan, request, archive, records)['status'] == 'Preview'
    with pytest.raises((dc.DirectoryError, KeyError)):
        da.apply(profile, result, archive, records)
    # The original state still blocks native execution; the projection cannot
    # make an archive plan eligible before actual file apply.
    with pytest.raises(dc.DirectoryError, match='archive impact'):
        da.archive_preview(profile, request, archive, records)


def test_final_dangling_archive_link_blocks(fixture):
    profile, _, request, archive, records = fixture
    plan = changes.preview(profile.root, {'operations': [{'type': 'replace', 'path': 'README.md',
                          'old': 'runs/closed/report.md', 'new': '../archive/history/closed/missing.md'}]}, profile.config)
    result = joint.preview(profile, plan, request, archive, records)
    assert result['status'] == 'Blocked'
    assert result['navigation']['issues'][0]['reason_code'] == 'FINAL_TARGET_MISSING'


def test_remaining_dynamic_access_stays_unknown(fixture):
    profile, plan, request, archive, records = fixture
    (profile.root / 'dynamic.py').write_text('open(f"runs/{name}/report.md")\n')
    data = copy.deepcopy(profile.data)
    data['reference_sources'].append({'path': 'dynamic.py', 'role': 'current'})
    profile = dc.load_profile(profile.root, profile.config, data)
    result = joint.preview(profile, plan, request, archive, records)
    assert result['status'] == 'Unknown'
    assert any(item['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN' for item in result['projected_impact']['batches'][0]['unknowns'])


@pytest.mark.parametrize('drift', ['source', 'payload', 'plan', 'request', 'config', 'profile', 'target'])
def test_rejects_bound_candidate_drift(fixture, drift):
    profile, plan, request, archive, records = fixture
    result = preview(fixture)
    if drift == 'source':
        (profile.root / 'README.md').write_text('new work')
    elif drift == 'payload':
        (profile.root / 'runs/closed/report.md').write_text('new payload')
    elif drift == 'plan':
        plan = copy.deepcopy(plan)
        plan['operations'][0]['new'] = 'other candidate'
    elif drift == 'request':
        request = copy.deepcopy(request)
        request['batches'][0]['destination'] = 'different'
    elif drift == 'config':
        profile.config = {**profile.config, 'document_max_bytes': 2000}
    elif drift == 'profile':
        profile.data['critical_paths'].append('other.md')
    else:
        (archive / 'history/closed').mkdir(parents=True)
    with pytest.raises((dc.DirectoryError, ValueError)):
        joint.validate_candidate(profile, result, plan, request, archive, records)


def test_real_file_apply_then_fresh_native_archive_restore_and_file_recovery(fixture, tmp_path):
    profile, plan, request, archive, records = fixture
    initial = (profile.root / 'README.md').read_bytes()
    payload = (profile.root / 'runs/closed/report.md').read_bytes()
    result = preview(fixture)
    assert result['status'] == 'Preview'
    file_record = changes.apply(profile.root, plan, profile.config, tmp_path / 'file-records')
    assert changes.verify(profile.root, file_record, profile.config)['status'] == 'Passed'
    native = da.archive_preview(profile, request, archive, records)
    assert native['format'] != result['format']
    record = da.apply(profile, native, archive, records)
    assert record['state'] == 'Archived'
    assert (archive / 'history/closed/report.md').read_bytes() == payload
    assert (profile.root / 'runs/closed/ARCHIVED.md').exists()
    restored = da.restore(profile, da.restore_preview(profile, record, archive), archive, records)
    assert da.verify(profile, restored, archive)['status'] == 'Passed'
    assert (profile.root / 'runs/closed/report.md').read_bytes() == payload
    changes.recover(profile.root, Path(file_record['journal_path']), profile.config)
    assert (profile.root / 'README.md').read_bytes() == initial


def test_symlink_payload_target_refused_without_following(fixture, tmp_path):
    profile, _, _, _, _ = fixture
    target = profile.root / 'runs/closed/report.md'
    target.unlink()
    outside = tmp_path / 'outside-secret.md'
    outside.write_text('do not read')
    target.symlink_to(outside)
    with pytest.raises((dc.DirectoryError, OSError)):
        preview(fixture)
    assert outside.read_text() == 'do not read'


def test_remaining_literal_reference_is_still_blocked(fixture):
    profile, _, request, archive, records = fixture
    plan = changes.preview(profile.root, {'operations': [{'type': 'replace', 'path': 'README.md',
                          'old': '[old]', 'new': '[new]'}]}, profile.config)
    result = joint.preview(profile, plan, request, archive, records)
    assert result['status'] == 'Blocked'
    assert result['projected_impact']['batches'][0]['current_dependencies']


@pytest.mark.parametrize('anchor, expected', [('report', 'Preview'), ('missing', 'Blocked')])
def test_future_archive_anchor_uses_authorized_candidate_payload(fixture, anchor, expected):
    profile, _, request, archive, records = fixture
    plan = changes.preview(profile.root, {'operations': [{'type': 'replace', 'path': 'README.md',
                          'old': 'runs/closed/report.md', 'new': '../archive/history/closed/report.md#' + anchor}]}, profile.config)
    result = joint.preview(profile, plan, request, archive, records)
    assert result['status'] == expected, result['navigation']


def test_candidate_bytes_are_charged_against_reference_budget(fixture):
    profile, plan, request, archive, records = fixture
    data = copy.deepcopy(profile.data)
    # Original files fit, but original+candidate bytes cannot fit.
    original = sum((profile.root / path).stat().st_size for path in ('README.md', 'closure.md'))
    data['budgets']['max_reference_bytes'] = original + 1
    profile = dc.load_profile(profile.root, profile.config, data)
    result = joint.preview(profile, plan, request, archive, records)
    assert result['status'] == 'Unknown'
    assert not result['projected_impact']['coverage']['complete']


def test_batched_reference_reader_uses_candidate_overlay(fixture):
    profile, plan, request, archive, records = fixture
    data = copy.deepcopy(profile.data)
    data['reference_batching'] = {'max_batches': 10, 'max_total_files': 100,
                                  'max_total_bytes': 10000, 'max_total_seconds': 60}
    data['budgets']['max_reference_files'] = 1
    profile = dc.load_profile(profile.root, profile.config, data)
    result = joint.preview(profile, plan, request, archive, records)
    assert result['status'] == 'Preview', result
    assert result['projected_impact']['kind'] == 'directory-impact-projection'
    assert result['projected_impact']['coverage']['batching']['batch_count'] == 2


def test_joint_cli_outputs_external_projection_and_rejects_input_overlap(fixture, tmp_path, capsys):
    import argparse
    import json
    from fifan_maintenance import joint_cli
    profile, plan, request, archive, records = fixture
    profile_path, plan_path, request_path = [tmp_path / name for name in ('profile.json', 'plan.json', 'request.json')]
    for path, value in ((profile_path, profile.data), (plan_path, plan), (request_path, request)):
        path.write_text(json.dumps(value))
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command')
    joint_cli.add_parser(commands)
    argv = ['joint-preview', '--project', str(profile.root), '--profile', str(profile_path),
            '--file-plan', str(plan_path), '--request', str(request_path),
            '--archive-root', str(archive), '--records-dir', str(records)]
    output = tmp_path / 'joint.json'
    args = parser.parse_args(argv + ['--output', str(output)])
    assert joint_cli.run(profile.root, profile.config, args) == 0
    assert json.loads(output.read_text())['format'] == joint.FORMAT
    assert 'Explicit closed synthetic run' not in capsys.readouterr().out
    with pytest.raises(dc.DirectoryError) as failure:
        joint_cli.run(profile.root, profile.config, parser.parse_args(argv + ['--output', str(plan_path)]))
    assert failure.value.reason_code == 'OUTPUT_INPUT_CONFLICT'
    unrelated = tmp_path / 'existing-report.json'
    unrelated.write_bytes(b'preserve original report')
    with pytest.raises(dc.DirectoryError) as failure:
        joint_cli.run(profile.root, profile.config, parser.parse_args(argv + ['--output', str(unrelated)]))
    assert failure.value.reason_code == 'OUTPUT_EXISTS'
    assert unrelated.read_bytes() == b'preserve original report'
    alias = tmp_path / 'input-alias.json'
    alias.symlink_to(plan_path)
    before = plan_path.read_bytes()
    with pytest.raises(dc.DirectoryError):
        joint_cli.run(profile.root, profile.config, parser.parse_args(argv + ['--output', str(alias)]))
    assert alias.is_symlink() and plan_path.read_bytes() == before


@pytest.mark.parametrize('concurrent_kind', ['file', 'symlink'])
def test_joint_cli_publication_preserves_concurrent_report(fixture, tmp_path, monkeypatch, concurrent_kind):
    import json
    from types import SimpleNamespace
    from fifan_maintenance import joint_cli
    profile, plan, request, archive, records = fixture
    inputs = [tmp_path / name for name in ('profile.json', 'plan.json', 'request.json')]
    for path, value in zip(inputs, (profile.data, plan, request)):
        path.write_text(json.dumps(value))
    output = tmp_path / 'concurrent-report.json'
    sentinel = b'concurrent unrelated report must survive'
    original_preview = joint.preview

    def preview_then_create_report(*args, **kwargs):
        result = original_preview(*args, **kwargs)
        # Deterministically occupy the destination after CLI preflight and
        # before publication. Publication must use no-replace semantics.
        if concurrent_kind == 'file':
            output.write_bytes(sentinel)
        else:
            other = tmp_path / 'other-report.json'
            other.write_bytes(sentinel)
            output.symlink_to(other)
        return result

    monkeypatch.setattr(joint, 'preview', preview_then_create_report)
    args = SimpleNamespace(profile=str(inputs[0]), file_plan=str(inputs[1]), request=str(inputs[2]),
                           archive_root=str(archive), records_dir=str(records), output=str(output), max_output_bytes=8192)
    with pytest.raises(dc.DirectoryError) as failure:
        joint_cli.run(profile.root, profile.config, args)
    assert failure.value.reason_code == ('OUTPUT_EXISTS' if concurrent_kind == 'file' else 'PROTECTED_PATH')
    assert output.read_bytes() == sentinel
    assert output.is_symlink() is (concurrent_kind == 'symlink')
    assert not list(tmp_path.glob('.fifan-directory-*.tmp'))
