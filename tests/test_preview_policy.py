from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from fifan_maintenance import changes
from fifan_maintenance.archive_coverage import archive_coverage
from fifan_maintenance.diagnostics import DiagnosticError, diagnose
from fifan_maintenance.models import Context
from fifan_maintenance.preview_policy import validate_preview_scope, preview_read_scope, authorize_read
from fifan_maintenance.project import DEFAULT_CONFIG, fingerprint


def fixture_config(sources=None, references=None, **limits):
    cfg = deepcopy(DEFAULT_CONFIG)
    cfg.update(limits)
    cfg['_task'] = {'sources': sources or ['a.md'], 'reference_bodies': references or [], 'views': [], 'budgets': {}}
    return cfg


def replace(path='a.md'):
    return {'type': 'replace', 'path': path, 'old': 'old', 'new': 'new'}


def nochange(path='a.md'):
    return {'version': 3, 'operations': [{'type': 'replace_many', 'path': path,
            'expected_sha256': hashlib.sha256(b'old').hexdigest(), 'patches': [{'old': 'old', 'new': 'old'}]}]}


def block_bodies(monkeypatch):
    # scope binds project.read_bytes at import time. Load its real metadata/
    # profile reader before this temporary body trap, so later CLI cases do not
    # inherit a monkeypatched function through a module-level imported alias.
    import fifan_maintenance.scope  # noqa: F401
    calls = []
    def fail(*args, **kwargs):
        calls.append(True)
        pytest.fail('policy must not read any document body')
    monkeypatch.setattr(Context, 'read_bytes', fail)
    monkeypatch.setattr(changes, '_read', fail)
    import fifan_maintenance.project as project
    monkeypatch.setattr(project, 'read_bytes', fail)
    return calls


def test_authorization_precedes_nochange_oldlocator_and_all_body_reads(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('old')
    cfg = fixture_config()
    denied = nochange('b.md')
    denied['operations'][0]['patches'] = [{'old_locator': {'sha256': hashlib.sha256(b'old').hexdigest(), 'start_byte': 0, 'end_byte': 3}, 'new': 'old'}]
    calls = block_bodies(monkeypatch)
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, cfg, denied)
    assert error.value.reason_code == 'BODY_NOT_AUTHORIZED'
    assert not calls


def test_unauthorized_guard_is_checked_even_with_nochange_source(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('same guarded bytes')
    req = nochange()
    req['guards'] = [{'kind': 'snippet', 'path': 'b.md', 'value': 'same guarded bytes'}]
    calls = block_bodies(monkeypatch)
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, fixture_config(), req)
    assert error.value.reason_code == 'BODY_NOT_AUTHORIZED'
    assert not calls


def test_archive_proof_all_participants_authorized_before_compilation(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('old')
    base = deepcopy(DEFAULT_CONFIG)
    coverage = {'version': 1, 'items': [{'source': {'path': 'a.md', 'selector': {'kind': 'snippet', 'value': 'old'}},
                'archive': {'path': 'b.md', 'selector': {'kind': 'snippet', 'value': 'old'}, 'reference_base': '.', 'classification_basis': 'approved'}}]}
    proof = archive_coverage(tmp_path, base, coverage)['proof']
    req = {**nochange(), 'archive_proofs': [proof]}
    calls = block_bodies(monkeypatch)
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, fixture_config(), req)
    assert error.value.reason_code == 'BODY_NOT_AUTHORIZED'
    allowed = validate_preview_scope(tmp_path, fixture_config(references=['b.md']), req)
    assert allowed['file_count'] == 2 and allowed['reference_bytes'] == 3 and allowed['body_bytes_read'] == 0
    assert not calls


def test_metadata_only_preflight_and_destinations_do_not_mutate_configuration(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('old')
    cfg = fixture_config()
    original = deepcopy(cfg)
    base = deepcopy(DEFAULT_CONFIG)
    base_hash = fingerprint(base)
    req = {'version': 2, 'operations': [{'kind': 'snapshot', 'path': 'a.md', 'destination': 'history/new.md',
            'expected_sha256': hashlib.sha256(b'old').hexdigest(), 'origin': {'reference_base': '.', 'classification_basis': 'approved'}}]}
    calls = block_bodies(monkeypatch)
    summary = validate_preview_scope(tmp_path, cfg, req)
    assert summary['total_bytes'] == 3 and summary['destinations'] == ['history/new.md']
    assert cfg == original and fingerprint(base) == base_hash
    assert not calls and not (tmp_path / 'history').exists()


@pytest.mark.parametrize('req', [
    {'operations': [replace()], 'unexpected': 'secret'},
    {'version': 2, 'operations': [replace()], 'guards': [{'kind': 'snippet', 'path': 'b.md', 'value': 'x', 'unexpected': True}]},
    {'version': 3, 'operations': [{'type': 'replace_many', 'path': 'a.md', 'expected_sha256': 'a' * 64, 'patches': [{'old_locator': {'sha256': 'a' * 64, 'start_byte': 0, 'end_byte': 1, 'path': 'b.md'}, 'new': 'x'}]}]},
    {'version': True, 'operations': [replace()]},
])
def test_invalid_request_schema_cannot_reach_body(tmp_path, monkeypatch, req):
    (tmp_path / 'a.md').write_text('old')
    calls = block_bodies(monkeypatch)
    with pytest.raises(DiagnosticError):
        validate_preview_scope(tmp_path, fixture_config(), req)
    assert not calls


def test_operation_source_cannot_use_reference_permission_and_protected_paths_stay_blocked(tmp_path):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('old')
    cfg = fixture_config(references=['b.md'])
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, cfg, {'operations': [replace('b.md')]})
    assert error.value.reason_code == 'BODY_NOT_AUTHORIZED'
    cfg['protected'] = ['a.md']
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, cfg, {'operations': [replace()]})
    assert error.value.reason_code == 'PROTECTED_PATH'


def test_preflight_metadata_enforces_unique_single_total_and_narrow_task_limits(tmp_path):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('old')
    req = {'version': 2, 'operations': [replace()], 'guards': [{'kind': 'snippet', 'path': 'b.md', 'value': 'old'}]}
    for limits in ({'max_file_bytes': 2}, {'max_total_bytes': 5}, {'max_files': 1}):
        with pytest.raises(DiagnosticError) as error:
            validate_preview_scope(tmp_path, fixture_config(references=['b.md'], **limits), req)
        assert error.value.reason_code == 'BUDGET_EXHAUSTED'
    cfg = fixture_config(references=['b.md'], max_total_bytes=5)
    cfg['_task']['budgets'] = {'max_total_bytes': 1000}
    with pytest.raises(DiagnosticError):
        validate_preview_scope(tmp_path, cfg, req)
    cfg = fixture_config(references=['b.md'])
    cfg['_task']['budgets'] = {'max_total_bytes': 5}
    with pytest.raises(DiagnosticError):
        validate_preview_scope(tmp_path, cfg, req)


def test_runtime_read_policy_accumulates_repeats_and_references_and_cleans_up(tmp_path):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('ref')
    cfg = fixture_config(references=['b.md'], max_total_bytes=8)
    assert authorize_read(tmp_path, 'a.md', 3) is False
    with preview_read_scope(tmp_path, cfg) as policy:
        assert authorize_read(tmp_path, 'a.md', 3) is True
        assert authorize_read(tmp_path, 'b.md', 3) is True
        assert policy.read_bytes == 6 and policy.primary_bytes == 3 and policy.reference_bytes == 3
        with pytest.raises(DiagnosticError) as error:
            authorize_read(tmp_path, 'a.md', 3)
        assert error.value.reason_code == 'BUDGET_EXHAUSTED'
        assert policy.read_bytes == 6
    assert authorize_read(tmp_path, 'a.md', 3) is False


def test_runtime_blocks_growth_after_preflight_and_leaks_no_scope_after_error(tmp_path):
    (tmp_path / 'a.md').write_text('old')
    cfg = fixture_config(max_file_bytes=4)
    validate_preview_scope(tmp_path, cfg, {'operations': [replace()]})
    (tmp_path / 'a.md').write_text('GROWN')
    with pytest.raises(DiagnosticError):
        with preview_read_scope(tmp_path, cfg):
            authorize_read(tmp_path, 'a.md', 5)
    assert authorize_read(tmp_path, 'a.md', 5) is False


def test_nested_scopes_other_roots_and_zero_size_unique_limits(tmp_path):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('ref')
    other = tmp_path / 'other'
    other.mkdir()
    outer_cfg = fixture_config(references=['b.md'], max_files=1)
    with preview_read_scope(tmp_path, outer_cfg) as outer:
        assert authorize_read(other, 'anything', 99999999) is False
        assert authorize_read(tmp_path / 'missing-root', 'anything', 99999999) is False
        assert authorize_read(tmp_path, 'a.md', 0)
        with preview_read_scope(tmp_path, fixture_config(references=['b.md'])):
            assert authorize_read(tmp_path, 'b.md', 3)
        with pytest.raises(DiagnosticError):
            authorize_read(tmp_path, 'b.md', 0)
        assert outer.read_bytes == 0
    assert authorize_read(tmp_path, 'b.md', 3) is False


def test_runtime_unauthorized_read_and_diagnostics_never_echo_body(tmp_path):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('password=PRIVATE')
    with preview_read_scope(tmp_path, fixture_config()):
        with pytest.raises(DiagnosticError) as error:
            authorize_read(tmp_path, 'b.md', 16)
    assert error.value.reason_code == 'BODY_NOT_AUTHORIZED'
    assert 'PRIVATE' not in json.dumps(diagnose(error.value))


def test_physical_project_reader_counts_once_with_active_scope(tmp_path):
    # The Root integration invokes authorize_read after FD fstat, before bytes.
    from fifan_maintenance.project import read_bytes
    (tmp_path / 'a.md').write_text('old')
    with preview_read_scope(tmp_path, fixture_config(max_total_bytes=5)) as policy:
        assert read_bytes(tmp_path, 'a.md', 1000) == b'old'
        assert policy.read_bytes == 3
        with pytest.raises(DiagnosticError):
            read_bytes(tmp_path, 'a.md', 1000)


def test_physical_changes_reader_uses_task_budget_instead_of_base_budget(tmp_path):
    (tmp_path / 'a.md').write_text('old')
    with preview_read_scope(tmp_path, fixture_config(max_total_bytes=5)) as policy:
        assert changes._read(tmp_path, 'a.md', deepcopy(DEFAULT_CONFIG))[0] == b'old'
        assert policy.read_bytes == 3
        with pytest.raises(DiagnosticError):
            changes._read(tmp_path, 'a.md', deepcopy(DEFAULT_CONFIG))
    assert authorize_read(tmp_path, 'a.md', 3) is False


def test_fstat_then_growth_is_rejected_without_reading_base_limit(tmp_path, monkeypatch):
    import os
    import fifan_maintenance.preview_policy as policy_module
    from fifan_maintenance.project import read_bytes
    (tmp_path / 'a.md').write_bytes(b'old')
    original_authorize = policy_module.authorize_read
    original_read = os.read
    observed = []

    def grow_after_authorization(root, rel, size):
        active = original_authorize(root, rel, size)
        if active:
            with (tmp_path / 'a.md').open('ab') as stream:
                stream.write(b'GROWTH' * 1000)
        return active

    def limited_read(fd, size):
        observed.append(size)
        return original_read(fd, size)

    monkeypatch.setattr(policy_module, 'authorize_read', grow_after_authorization)
    monkeypatch.setattr(os, 'read', limited_read)
    with preview_read_scope(tmp_path, fixture_config(max_file_bytes=4)):
        with pytest.raises((ValueError, OSError)):
            read_bytes(tmp_path, 'a.md', 1000000)
    assert observed and max(observed) <= 4  # observed size + one EOF/growth probe


def test_runtime_time_budget_and_nested_error_scope_restore(tmp_path, monkeypatch):
    import fifan_maintenance.preview_policy as policy_module
    (tmp_path / 'a.md').write_text('old')
    current = [10.0]
    monkeypatch.setattr(policy_module.time, 'monotonic', lambda: current[0])
    with preview_read_scope(tmp_path, fixture_config(max_seconds=1)) as outer:
        with pytest.raises(RuntimeError):
            with preview_read_scope(tmp_path, fixture_config()):
                raise RuntimeError('fixture failure')
        assert authorize_read(tmp_path, 'a.md', 1) is True
        assert outer.read_bytes == 1
        current[0] = 12.0
        with pytest.raises(DiagnosticError) as error:
            authorize_read(tmp_path, 'a.md', 1)
        assert error.value.reason_code == 'BUDGET_EXHAUSTED'
    assert authorize_read(tmp_path, 'a.md', 1) is False


def test_proof_tampering_and_legacy_no_profile_preserve_body_boundary(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'b.md').write_text('old')
    base = deepcopy(DEFAULT_CONFIG)
    coverage = {'version': 1, 'items': [{'source': {'path': 'a.md', 'selector': {'kind': 'snippet', 'value': 'old'}},
                'archive': {'path': 'b.md', 'selector': {'kind': 'snippet', 'value': 'old'}, 'reference_base': '.', 'classification_basis': 'approved'}}]}
    proof = archive_coverage(tmp_path, base, coverage)['proof']
    proof['proof_sha256'] = '0' * 64
    calls = block_bodies(monkeypatch)
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, fixture_config(references=['b.md']), {**nochange(), 'archive_proofs': [proof]})
    assert error.value.reason_code == 'PROOF_BINDING_MISMATCH'
    assert validate_preview_scope(tmp_path, base, {'operations': [replace()]})['status'] == 'Passed'
    assert not calls


def test_metadata_symlink_and_destinations_remain_protected(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('old')
    (tmp_path / 'link.md').symlink_to(tmp_path / 'a.md')
    cfg = fixture_config(sources=['a.md', 'link.md'])
    calls = block_bodies(monkeypatch)
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, cfg, {'operations': [replace('link.md')]})
    assert error.value.reason_code == 'PROTECTED_PATH'
    with pytest.raises(DiagnosticError) as error:
        validate_preview_scope(tmp_path, cfg, {'operations': [{'type': 'move', 'path': 'a.md', 'destination': '.git/new.md'}]})
    assert error.value.reason_code == 'PROTECTED_PATH'
    assert not calls


@pytest.mark.parametrize('version', [None, 2])
def test_real_cli_profile_replace_old_locator_succeeds(tmp_path, capsys, version):
    from fifan_maintenance.cli import main
    from fifan_maintenance.project import load_config
    project = tmp_path / 'project'
    project.mkdir()
    raw = b'prefix old suffix\r\n'
    (project / 'a.md').write_bytes(raw)
    base_fingerprint = fingerprint(load_config(project))
    profile = tmp_path / 'profile.json'
    profile.write_text(json.dumps({'schema_version': 1, 'sources': ['a.md']}))
    operation = {'type': 'replace', 'path': 'a.md', 'old_locator': {'sha256': hashlib.sha256(raw).hexdigest(),
                 'start_byte': 7, 'end_byte': 10}, 'new': 'new'}
    request = {'operations': [operation]}
    if version is not None:
        request['version'] = version
    request_path, plan_path = tmp_path / 'request.json', tmp_path / 'plan.json'
    request_path.write_text(json.dumps(request))
    code = main(['preview', '--project', str(project), '--request', str(request_path), '--task-profile', str(profile), '--plan', str(plan_path)])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)['status'] == 'Preview'
    plan = json.loads(plan_path.read_text())
    assert plan['operations'][0]['old'] == 'old' and plan['operations'][0]['new'] == 'new'
    assert (project / 'a.md').read_bytes() == raw  # Preview did not apply anything.
    if version == 2:
        assert '_task' not in plan['config_snapshot']
        assert fingerprint(plan['config_snapshot']) == base_fingerprint
    assert authorize_read(project, 'a.md', 100000000) is False


@pytest.mark.parametrize('version', [None, 2])
def test_real_cli_profile_old_locator_unauthorized_source_reads_zero_bodies(tmp_path, monkeypatch, capsys, version):
    import fifan_maintenance.project as project_module
    from fifan_maintenance.cli import main
    project = tmp_path / 'project'
    project.mkdir()
    raw = b'PRIVATE_UNAUTHORIZED'
    (project / 'a.md').write_bytes(b'allowed')
    (project / 'b.md').write_bytes(raw)
    profile = tmp_path / 'profile.json'
    profile.write_text(json.dumps({'schema_version': 1, 'sources': ['a.md']}))
    request = {'operations': [{'type': 'replace', 'path': 'b.md', 'old_locator': {
                'sha256': hashlib.sha256(raw).hexdigest(), 'start_byte': 0, 'end_byte': len(raw)}, 'new': 'new'}]}
    if version is not None:
        request['version'] = version
    request_path, plan_path = tmp_path / 'request.json', tmp_path / 'plan.json'
    request_path.write_text(json.dumps(request))
    reads = []
    original_project_read, original_change_read = project_module.read_bytes, changes._read
    def spy_project(root, rel, *args, **kwargs):
        if root == project and rel in {'a.md', 'b.md'}:
            reads.append(('project', rel))
        return original_project_read(root, rel, *args, **kwargs)
    def spy_change(root, rel, *args, **kwargs):
        if root == project and rel in {'a.md', 'b.md'}:
            reads.append(('changes', rel))
        return original_change_read(root, rel, *args, **kwargs)
    monkeypatch.setattr(project_module, 'read_bytes', spy_project)
    monkeypatch.setattr(changes, '_read', spy_change)
    code = main(['preview', '--project', str(project), '--request', str(request_path), '--task-profile', str(profile), '--plan', str(plan_path)])
    captured = capsys.readouterr()
    assert code == 2 and json.loads(captured.err)['reason_code'] == 'BODY_NOT_AUTHORIZED'
    assert reads == [] and not plan_path.exists()
    assert 'PRIVATE_UNAUTHORIZED' not in captured.out + captured.err
    assert authorize_read(project, 'b.md', 1) is False


@pytest.mark.parametrize('locator', [
    {'sha256': 'a' * 64, 'start_byte': -1, 'end_byte': 1},
    {'sha256': 'a' * 64, 'start_byte': True, 'end_byte': 2},
    {'sha256': 'a' * 64, 'start_byte': 2, 'end_byte': 2},
    {'sha256': 'not-a-hash', 'start_byte': 0, 'end_byte': 1},
    {'sha256': 'a' * 64, 'start_byte': 0, 'end_byte': 1, 'path': 'b.md'},
    {'sha256': 'a' * 64, 'start_byte': 0, 'end_byte': 100},
])
def test_replace_locator_schema_and_range_rejected_without_bodies(tmp_path, monkeypatch, locator):
    (tmp_path / 'a.md').write_text('old')
    calls = block_bodies(monkeypatch)
    request = {'operations': [{'type': 'replace', 'path': 'a.md', 'old_locator': locator, 'new': 'new'}]}
    with pytest.raises(DiagnosticError):
        validate_preview_scope(tmp_path, fixture_config(), request)
    assert not calls


def test_replace_literal_and_locator_are_mutually_exclusive(tmp_path, monkeypatch):
    (tmp_path / 'a.md').write_text('old')
    calls = block_bodies(monkeypatch)
    request = {'operations': [{'type': 'replace', 'path': 'a.md', 'old': 'old', 'old_locator': {
        'sha256': hashlib.sha256(b'old').hexdigest(), 'start_byte': 0, 'end_byte': 3}, 'new': 'new'}]}
    with pytest.raises(DiagnosticError):
        validate_preview_scope(tmp_path, fixture_config(), request)
    assert not calls


def test_authorization_only_for_existing_move_keeps_original_scope(tmp_path, monkeypatch):
    from fifan_maintenance.preview_policy import validate_preview_authorization
    req = {'operations': [{'type': 'move', 'path': 'a.md', 'destination': 'archive/a.md'}]}
    calls = block_bodies(monkeypatch)
    allowed = validate_preview_authorization(tmp_path, fixture_config(), req)
    assert allowed['status'] == 'Passed' and allowed['destinations'] == ['archive/a.md']
    with pytest.raises(DiagnosticError) as missing:
        validate_preview_scope(tmp_path, fixture_config(), req)
    assert missing.value.reason_code == 'SOURCE_UNAVAILABLE'
    with pytest.raises(DiagnosticError) as denied:
        validate_preview_authorization(tmp_path, fixture_config(sources=['other.md']), req)
    assert denied.value.reason_code == 'BODY_NOT_AUTHORIZED'
    req['operations'][0]['destination'] = '.git/a.md'
    with pytest.raises(DiagnosticError) as protected:
        validate_preview_authorization(tmp_path, fixture_config(), req)
    assert protected.value.reason_code == 'PROTECTED_PATH'
    assert not calls
