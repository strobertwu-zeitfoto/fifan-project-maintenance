from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import unicodedata

import pytest

from fifan_maintenance import cleanup_policy as cp
from fifan_maintenance import directory_common as dc
from fifan_maintenance.project import load_config


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path, *, kind='completed_log', budget=None, accept=False):
    root, q, records = (tmp_path / name for name in ('project', 'quarantine', 'records'))
    for path in (root, q, records):
        path.mkdir()
    (root / 'current').mkdir()
    (root / 'current' / 'README.md').write_text('# Current\n\nKeep current sources.\n')
    proof = root / 'current' / 'closed.md'
    proof.write_text('# Closed\n\nThe previous task is finished.\n')
    (root / 'logs').mkdir()
    source = 'logs/finished.log'
    (root / source).write_bytes(b'old log\n')
    build = {'platform': 'mac', 'branch': 'main', 'configuration': 'release', 'purpose': 'rollback'}
    keep = []
    retained = []
    if kind == 'old_build':
        (root / 'builds').mkdir()
        (root / 'builds' / 'old.zip').write_bytes(b'old WIP snapshot')
        (root / 'builds' / 'keep.zip').write_bytes(b'current rollback binary\x00')
        source = 'builds/old.zip'
        keep = [{'path': 'builds/keep.zip', 'reason': 'rollback baseline', 'build': build,
                 'sha256': sha(root / 'builds/keep.zip'), 'evidence': [{'path': 'current/closed.md', 'sha256': sha(proof)}]}]
        retained = ['builds/keep.zip']
    data = {'schema_version': 1, 'project_root': str(root), 'scan_roots': ['.'], 'current': ['current'],
            'keep': keep, 'candidates': [{'path': source, 'kind': kind}], 'protected': [],
            'reference_sources': [{'path': 'current', 'role': 'current'}, {'path': 'logs', 'role': 'historical'}],
            'quarantine_root': str(q), 'records_dir': str(records), 'budgets': budget or {}}
    profile = cp.load_profile(root, load_config(root), data)
    item = {'source': source, 'kind': kind, 'reason': 'retired task output',
            'closure': {'decision': 'closed', 'reason': 'closed with proof',
                        'evidence': [{'path': 'current/closed.md', 'sha256': sha(proof)}]},
            'loss': {'accepted': accept, 'rebuildable': 'Unknown', 'unique_evidence': False,
                     'description': 'lose the original snapshot only after explicit purge approval'},
            'retained': retained}
    if kind == 'old_build':
        item['build'] = build
    request = {'schema_version': 1, 'approval': {'reference': 'synthetic explicit batch', 'actions': ['quarantine']}, 'items': [item]}
    return profile, request, q, records


def refreshed(profile):
    """A changed test policy is a newly loaded profile, not mutation of a live grant."""
    return cp.load_profile(profile.root, profile.config, {**profile.data, 'budgets': profile.budgets})


def test_inspect_metadata_zero_reads_and_rdu_does_not_authorize_execution(tmp_path, monkeypatch):
    profile, request, _, _ = fixture(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError('body read')
    monkeypatch.setattr(dc, 'read_file', forbidden)
    monkeypatch.setattr(dc, 'stream_hash', forbidden)
    result = cp.inspect(refreshed(profile), request)
    assert result['status'] == 'Passed'
    assert result['counts']['D'] == 1 and result['counts']['R'] >= 3 and result['counts']['U'] >= 1
    assert result['body_bytes_read'] == result['candidate_hash_bytes'] == 0
    assert result['candidate_is_execution_approval'] is False
    assert cp.inspect(refreshed(profile))['counts']['D'] == 0
    dc.validate_seal(result)


def test_quarantine_does_not_require_irreversible_loss_acceptance(tmp_path):
    profile, request, _, _ = fixture(tmp_path, accept=False)
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Passed'
    assert result['items'][0]['eligible'] is True
    assert result['items'][0]['purge_authorized'] is False
    assert result['items'][0]['retained_runtime_validation'] == 'Not run'
    assert result['candidate_hash_bytes'] == 0
    dc.validate_seal(result)
    again = cp.qualify(refreshed(profile), request)
    assert again['material_sha256'] == result['material_sha256']


def test_purge_flag_needs_explicit_actions_disposition_and_loss_acceptance(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    request['approval']['actions'].append('purge')
    assert cp.qualify(refreshed(profile), request)['items'][0]['purge_authorized'] is False
    request['items'][0]['disposition'] = 'purge'
    assert cp.qualify(refreshed(profile), request)['items'][0]['purge_authorized'] is False
    request['items'][0]['loss']['accepted'] = True
    assert cp.qualify(refreshed(profile), request)['items'][0]['purge_authorized'] is True


def test_same_batch_historical_log_is_not_read_and_kept_consumers_still_block(tmp_path, monkeypatch):
    profile, request, _, _ = fixture(tmp_path)
    path = profile.root / 'logs/finished.log'
    path.write_bytes(b'logs/finished.log\n' * 100000)
    # Deliberately over the ordinary file budget; D logs are not consumers.
    profile.budgets['max_reference_file_bytes'] = 128
    original = dc.read_file
    reads = []
    def observed(root, rel, limit):
        reads.append(rel)
        assert rel != 'logs/finished.log'
        return original(root, rel, limit)
    monkeypatch.setattr(dc, 'read_file', observed)
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Passed'
    assert result['reference_bytes_read'] < 128
    assert result['material']['items'][0]['skipped_discarded_references'] == ['logs/finished.log']
    (profile.root / 'current' / 'consumer.txt').write_text('load logs/finished.log\n')
    blocked = cp.qualify(refreshed(profile), request)
    assert blocked['status'] == 'Blocked'
    assert any(b['reason_code'] == 'RETAINED_DEPENDENCIES' for b in blocked['items'][0]['blockers'])
    assert 'current/consumer.txt' in blocked['material']['items'][0]['current_paths']


def test_unapproved_or_current_log_cannot_borrow_same_batch_exemption(tmp_path):
    profile, request, _, _ = fixture(tmp_path, budget={'max_reference_file_bytes': 128})
    (profile.root / 'logs' / 'retained.log').write_bytes(b'logs/finished.log\n' * 30)
    assert cp.qualify(refreshed(profile), request)['status'] == 'Unknown'
    profile.data['current'].append('logs/finished.log')
    profile.data['reference_sources'][1]['role'] = 'current'
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked'
    assert not result['material']['items'][0]['skipped_discarded_references']


def test_current_without_self_reference_is_protected_and_cannot_be_d(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    profile.data['current'].append('logs/finished.log')
    profile.data['reference_sources'].append({'path': 'logs/finished.log', 'role': 'current'})
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked'
    assert any(b['reason_code'] == 'CURRENT_KEEP_OR_PROTECTED' for b in result['items'][0]['blockers'])


def test_missing_current_body_scope_or_new_dynamic_consumer_keeps_unknown(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    profile.data['reference_sources'][0] = {'path': 'current/closed.md', 'role': 'current'}
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Unknown'
    assert any(u['reason_code'] == 'CURRENT_REFERENCE_SCOPE_MISSING' for u in result['items'][0]['unknowns'])
    profile.data['reference_sources'][0] = {'path': 'current', 'role': 'current'}
    (profile.root / 'current' / 'consumer.py').write_text('value = f"{root}/future"\n')
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Unknown'
    assert any(u['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN' for u in result['items'][0]['unknowns'])


def test_dynamic_resolution_binds_exact_source_expression_and_external_proof(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    (profile.root / 'current' / 'consumer.py').write_text('value = f"{root}/future"\n')
    initial = cp.qualify(refreshed(profile), request)
    unknown = next(u for u in initial['items'][0]['unknowns'] if u['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN')
    resolution = {k: unknown[k] for k in ('path', 'sha256', 'line', 'column', 'line_sha256', 'expression_sha256')}
    resolution.update(source='logs/finished.log', reason='expression targets a retained future namespace',
                      evidence=request['items'][0]['closure']['evidence'])
    request['items'][0]['dynamic_reference_resolutions'] = [resolution]
    assert cp.qualify(refreshed(profile), request)['status'] == 'Passed'
    (profile.root / 'current' / 'consumer.py').write_text('value = f"{root}/other"\n')
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'


def test_closure_proof_drift_and_same_d_proof_are_blocked(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    (profile.root / 'current' / 'closed.md').write_text('# Changed evidence\n')
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'
    request['items'][0]['closure']['evidence'] = [{'path': 'logs/finished.log', 'sha256': sha(profile.root / 'logs/finished.log')}]
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked'
    assert any(b['reason_code'] == 'EVIDENCE_IN_DISCARD' for b in result['items'][0]['blockers'])


def test_unique_evidence_is_r_and_not_discardable(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    request['items'][0]['loss']['unique_evidence'] = True
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked'
    assert not result['material']['items'][0]['skipped_discarded_references']


def test_old_build_group_is_actual_keep_snapshot_not_latest_or_rebuildability(tmp_path):
    profile, request, _, _ = fixture(tmp_path, kind='old_build')
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Passed'
    assert result['items'][0]['retained'][0]['sha256'] == sha(profile.root / 'builds/keep.zip')
    assert result['items'][0]['rebuildability'] == 'Unknown'
    assert result['items'][0]['retained_runtime_validation'] == 'Not run'
    request['items'][0]['build']['platform'] = 'ios'
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'
    request['items'][0]['build']['platform'] = 'mac'
    (profile.root / 'builds/keep.zip').write_bytes(b'changed artifact')
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'


def test_relocation_retains_stable_r_material_and_reenumerates_consumers(tmp_path):
    profile, request, q, _ = fixture(tmp_path)
    before = cp.qualify(refreshed(profile), request)
    os.rename(profile.root / 'logs/finished.log', q / 'payload.log')
    mapping = {'logs/finished.log': {'root': str(q), 'path': 'payload.log'}}
    after = cp.qualify(refreshed(profile), request, relocations=mapping)
    assert after['status'] == 'Passed'
    assert before['material_sha256'] == after['material_sha256']
    baseline = cp.rebaseline(refreshed(profile), request)
    assert baseline['status'] == 'Passed'
    assert baseline['material']['current_paths']
    (profile.root / 'current' / 'new-reader.txt').write_text('logs/finished.log\n')
    assert cp.qualify(refreshed(profile), request, relocations=mapping)['status'] == 'Blocked'
    (profile.root / 'current' / 'new-reader.txt').unlink()
    (q / 'payload.log').unlink()
    assert cp.qualify(refreshed(profile), request, relocations={'logs/finished.log': None})['status'] == 'Passed'


def test_exact_historical_d_declaration_can_be_missing_after_move(tmp_path):
    profile, request, q, _ = fixture(tmp_path)
    profile.data['reference_sources'][1]['path'] = 'logs/finished.log'
    before = cp.qualify(refreshed(profile), request)
    os.rename(profile.root / 'logs/finished.log', q / 'payload.log')
    after = cp.qualify(refreshed(profile), request, relocations={'logs/finished.log': {'root': str(q), 'path': 'payload.log'}})
    assert after['status'] == 'Passed'
    assert before['material_sha256'] == after['material_sha256']


def test_runtime_roots_require_matching_explicit_disjoint_native_roots(tmp_path):
    profile, request, q, records = fixture(tmp_path)
    assert cp.runtime_roots(profile, q, records) == (q, records)
    for first, second in ((None, records), (records, q)):
        with pytest.raises(dc.DirectoryError):
            cp.runtime_roots(profile, first, second)
    profile.data['records_dir'] = str(profile.root.with_name('PROJECT'))
    with pytest.raises(dc.DirectoryError):
        cp.runtime_roots(profile, q, profile.root.with_name('PROJECT'))


def test_alias_protection_includes_hard_formal_roots_and_current(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    for path in ('.ENV', '.GIT/config', 'LIBRARY/cache', 'Temp/cache', 'SRC/code.bin', 'Assets/a.png', 'a.META', 'SaveData/game.bin', 'logs/source.PY'):
        assert cp.protected(profile, path)
    profile.data['protected'].append('Résumé')
    assert cp.protected(profile, unicodedata.normalize('NFD', 'RÉSUMÉ/x'))
    assert cp.protected(profile, 'CURRENT/README.md')


def test_budget_failure_retains_lower_bound_and_bounded_inspect_summary(tmp_path):
    profile, request, _, _ = fixture(tmp_path, budget={'max_entries': 2})
    result = cp.inspect(refreshed(profile), request)
    assert result['status'] == 'Unknown' and result['coverage']['count_is_lower_bound']
    assert result['work_entries'] <= 2
    assert len(dc.canonical(result)) < 8192
    profile.budgets['max_reference_bytes'] = 1
    assert cp.qualify(refreshed(profile), request)['status'] == 'Unknown'


def test_profile_file_fd_strict_json_input_limit_and_no_relocation_json(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    external = tmp_path / 'profile.json'
    external.write_text(json.dumps(profile.data))
    assert cp.load_profile(profile.root, profile.config, external).sha256 == profile.sha256
    external.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(dc.DirectoryError):
        cp.load_profile(profile.root, profile.config, external)
    too_big = {**profile.data, 'rules': [{'kind': 'completed_log', 'glob': 'logs/*', 'reason': 'x' * 262144}]}
    with pytest.raises(dc.DirectoryError):
        cp.load_profile(profile.root, profile.config, too_big)
    (profile.root / 'internal.json').write_text(json.dumps(profile.data))
    with pytest.raises(dc.DirectoryError):
        cp.load_profile(profile.root, profile.config, profile.root.with_name('PROJECT') / 'internal.json')
    with pytest.raises(dc.DirectoryError):
        cp.validate_request(profile, {**request, 'relocations': {'logs/finished.log': None}})


def test_root_replacement_link_and_shared_link_sources_block(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    os.link(profile.root / 'logs/finished.log', profile.root / 'logs/alias.log')
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'
    (profile.root / 'logs/alias.log').unlink()
    (profile.root / 'logs/finished.log').unlink()
    (profile.root / 'logs/finished.log').symlink_to(profile.root / 'current/README.md')
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'
    profile.root.rename(tmp_path / 'old-project')
    profile.root.mkdir()
    with pytest.raises(dc.DirectoryError):
        cp.validate_profile_root(profile)


@pytest.mark.parametrize('mutate', [
    lambda r: r['approval'].update(actions=[]),
    lambda r: r['items'][0].update(source='../escape'),
    lambda r: r['items'][0].update(kind='cache'),
    lambda r: r['items'][0]['loss'].update(accepted='yes'),
    lambda r: r['items'][0]['closure'].update(evidence=[]),
    lambda r: r['items'].append(copy.deepcopy(r['items'][0])),
])
def test_bad_request_shapes_rejected(tmp_path, mutate):
    profile, request, _, _ = fixture(tmp_path)
    mutate(request)
    with pytest.raises(dc.DirectoryError):
        cp.validate_request(profile, request)


def test_directory_keep_binds_all_payload_files_without_runtime_claim(tmp_path):
    profile, request, _, _ = fixture(tmp_path, kind='old_build')
    (profile.root / 'builds' / 'keep.zip').unlink()
    (profile.root / 'builds' / 'keep-package').mkdir()
    (profile.root / 'builds' / 'keep-package' / 'binary').write_bytes(b'actual kept payload\x00')
    declaration = profile.data['keep'][0]
    declaration.update(path='builds/keep-package')
    declaration.pop('sha256')
    request['items'][0]['retained'] = ['builds/keep-package']
    before = cp.qualify(refreshed(profile), request)
    assert before['status'] == 'Passed'
    assert before['items'][0]['retained'][0]['entries'] == 2
    assert before['items'][0]['retained_runtime_validation'] == 'Not run'
    (profile.root / 'builds' / 'keep-package' / 'binary').write_bytes(b'new kept payload\x00')
    after = cp.qualify(refreshed(profile), request)
    assert after['status'] == 'Passed'  # caller compares with the original material before any action
    assert after['material_sha256'] != before['material_sha256']


def test_retained_historical_streaming_log_is_scanned_under_separate_body_budget(tmp_path):
    profile, request, _, _ = fixture(tmp_path, budget={'max_reference_file_bytes': 128})
    kept = profile.root / 'logs' / 'retained.log'
    kept.write_bytes(b'closed safe retained transcript\n' * 20000)
    profile.data['streaming_references'].append('logs/retained.log')
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Passed'
    assert result['reference_bytes_read'] >= kept.stat().st_size
    assert 'logs/retained.log' in [entry['path'] for entry in result['material']['items'][0]['reference_fingerprints']]


def test_many_inspect_entries_keep_real_counts_in_small_metadata_report(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    for number in range(400):
        (profile.root / 'logs' / ('entry-' + str(number) + '.txt')).write_bytes(b'x')
    result = cp.inspect(refreshed(profile))
    assert result['counts']['U'] >= 400
    assert result['coverage']['complete']
    assert len(result['samples']) <= 10 and len(result['coverage']['gaps']) <= 8
    assert len(dc.canonical(result)) < 8192


def test_rules_are_only_hints_and_cannot_admit_an_undeclared_candidate(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    profile.data['rules'].append({'kind': 'completed_log', 'glob': 'logs/*', 'reason': 'hint only'})
    (profile.root / 'logs' / 'other.log').write_text('other')
    request['items'][0]['source'] = 'logs/other.log'
    with pytest.raises(dc.DirectoryError):
        cp.validate_request(profile, request)


def test_hard_protected_child_keep_and_current_alias_cannot_be_hidden_by_candidate_parent(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    profile.data['candidates'] = [{'path': 'logs', 'kind': 'completed_log'}]
    request['items'][0]['source'] = 'logs'
    profile.data['current'].append('LOGS/finished.log')
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked'


@pytest.mark.parametrize('change', [
    {'keep': None}, {'candidates': None}, {'rules': None},
    {'candidates': [{'path': 'x', 'kind': []}]},
    {'rules': [{'kind': {}, 'glob': 'x/*', 'reason': 'hint'}]},
    {'scan_roots': ['Résumé', unicodedata.normalize('NFD', 'RÉSUMÉ')]},
])
def test_profile_bad_types_aliases_are_controlled_rejections(tmp_path, change):
    profile, _, _, _ = fixture(tmp_path)
    with pytest.raises(dc.DirectoryError):
        cp.load_profile(profile.root, profile.config, {**profile.data, **change})


def test_old_build_and_disposable_d_only_skip_internal_historical_log_text(tmp_path):
    profile, request, q, _ = fixture(tmp_path)
    (profile.root / 'old-export').mkdir()
    (profile.root / 'old-export' / 'process.txt').write_bytes(b'retired only process trace\n' * 10000)
    source = 'old-export'
    profile.data['candidates'] = [{'path': source, 'kind': 'disposable_output'}]
    profile.data['reference_sources'].append({'path': source, 'role': 'historical'})
    request['items'][0].update(source=source, kind='disposable_output')
    profile.budgets['max_reference_file_bytes'] = 128
    before = cp.qualify(refreshed(profile), request)
    assert before['status'] == 'Passed'
    assert before['reference_bytes_read'] < 128
    os.rename(profile.root / source, q / 'payload')
    mapping = {source: {'root': str(q), 'path': 'payload'}}
    after = cp.qualify(refreshed(profile), request, relocations=mapping)
    assert after['status'] == 'Passed'
    assert after['material_sha256'] == before['material_sha256']
    assert cp.rebaseline(refreshed(profile), request, relocations=mapping)['status'] == 'Passed'


def test_unapproved_old_build_log_and_retained_current_log_never_get_extension_exemption(tmp_path):
    profile, request, _, _ = fixture(tmp_path, budget={'max_reference_file_bytes': 128})
    (profile.root / 'old-export').mkdir()
    (profile.root / 'old-export' / 'process.txt').write_bytes(b'process\n' * 1000)
    profile.data['candidates'].append({'path': 'old-export', 'kind': 'disposable_output'})
    profile.data['reference_sources'].append({'path': 'old-export', 'role': 'historical'})
    assert cp.qualify(refreshed(profile), request)['status'] == 'Unknown'
    profile.data['streaming_references'].append('old-export/process.txt')
    request['items'].append({**copy.deepcopy(request['items'][0]), 'source': 'old-export', 'kind': 'disposable_output'})
    profile.data['current'].append('old-export/process.txt')
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'


def test_non_process_retained_reference_inside_d_is_not_silently_discarded(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    (profile.root / 'old-export').mkdir()
    (profile.root / 'old-export' / 'audit.md').write_text('# Retained historical audit\n')
    profile.data['candidates'] = [{'path': 'old-export', 'kind': 'disposable_output'}]
    profile.data['reference_sources'].append({'path': 'old-export', 'role': 'historical'})
    request['items'][0].update(source='old-export', kind='disposable_output')
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked'
    assert any(entry['reason_code'] == 'RETAINED_REFERENCE_ORIGINAL_IN_DISCARD' for entry in result['items'][0]['blockers'])


def test_reference_added_between_body_pass_and_metadata_pass_does_not_get_eligibility(tmp_path, monkeypatch):
    profile, request, _, _ = fixture(tmp_path)
    original = cp._RetainedReferences.load_all
    added = []
    def add_after_body(reader):
        original(reader)
        if not added:
            (profile.root / 'current/new-consumer.txt').write_text('logs/finished.log\n')
            added.append(True)
    monkeypatch.setattr(cp._RetainedReferences, 'load_all', add_after_body)
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Unknown'
    assert any(entry['reason_code'] == 'REFERENCE_SET_OR_STATE_CHANGED' for entry in result['items'][0]['unknowns'])
    # A fresh preview sees the new consumer, rather than accepting the previous set.
    assert cp.qualify(refreshed(profile), request)['status'] == 'Blocked'


def test_same_bytes_replacement_of_retained_original_changes_material_identity(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    before = cp.qualify(refreshed(profile), request)
    path = profile.root / 'current/closed.md'
    tmp = profile.root / 'current/owned-replacement.tmp'
    tmp.write_bytes(path.read_bytes())
    os.replace(tmp, path)
    after = cp.qualify(refreshed(profile), request)
    assert after['status'] == 'Passed'
    assert after['material_sha256'] != before['material_sha256']


def test_internal_relocation_not_accepted_from_unmatched_scope_or_rebaseline_without_request(tmp_path):
    profile, request, q, _ = fixture(tmp_path)
    with pytest.raises(dc.DirectoryError):
        cp.rebaseline(refreshed(profile), relocations={'logs/finished.log': None})
    with pytest.raises(dc.DirectoryError):
        cp.rebaseline(refreshed(profile), request, relocations={'other.log': None})
    with pytest.raises(dc.DirectoryError):
        cp.qualify(refreshed(profile), request, relocations={'logs/finished.log': {'root': str(profile.root), 'path': 'anything'}})


def test_inspect_unique_evidence_is_r_even_when_requested_as_discard(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    request['items'][0]['loss']['unique_evidence'] = True
    result = cp.inspect(refreshed(profile), request)
    assert result['counts']['D'] == 0
    assert next(entry for entry in result['samples'] if entry['path'] == 'logs/finished.log')['classification'] == 'R'


def web_build_fixture(tmp_path):
    profile, request, quarantine, records = fixture(tmp_path, kind='old_build')
    source = 'builds/old-web'
    (profile.root / source).mkdir()
    (profile.root / source / 'main.js').write_bytes(b'console.log("old packaged runtime");\n')
    (profile.root / source / 'runtime.py').write_bytes(b'# packaged runtime, never executed\n')
    data = copy.deepcopy(profile.data)
    data['candidates'] = [{'path': source, 'kind': 'old_build'}]
    profile = cp.load_profile(profile.root, profile.config, data)
    request['items'][0]['source'] = source
    return profile, request, quarantine, records


def test_exact_old_build_directory_accepts_packaged_runtime_code(tmp_path):
    from fifan_maintenance import cleanup_operations as operations
    profile, request, quarantine, records = web_build_fixture(tmp_path)
    assert cp.qualify(refreshed(profile), request)['status'] == 'Passed'
    plan = operations.preview(profile, request, quarantine, records)
    assert plan['kind'] == 'quarantine'
    files = {entry['path'] for entry in plan['items'][0]['manifest']['entries'] if entry['kind'] == 'file'}
    assert files == {'main.js', 'runtime.py'}
    assert (profile.root / 'builds/old-web/main.js').read_bytes() == b'console.log("old packaged runtime");\n'
    assert not list(quarantine.iterdir()) and not list(records.iterdir())


@pytest.mark.parametrize('source', ['src/old-web', 'current/old-web'])
def test_old_build_label_cannot_unlock_formal_or_current_roots(tmp_path, source):
    profile, request, _, _ = web_build_fixture(tmp_path)
    (profile.root / source).mkdir(parents=True)
    (profile.root / source / 'bundle.js').write_text('packaged bytes')
    data = copy.deepcopy(profile.data)
    data['candidates'] = [{'path': source, 'kind': 'old_build'}]
    profile = cp.load_profile(profile.root, profile.config, data)
    request['items'][0]['source'] = source
    assert cp.protected(profile, source + '/bundle.js')
    assert cp.qualify(profile, request)['status'] == 'Blocked'


def test_packaged_code_exception_is_literal_native_and_keeps_all_other_guards(tmp_path):
    profile, request, quarantine, _ = web_build_fixture(tmp_path)
    for path in ('BUILDS/old-web/main.js', 'builds/OLD-WEB/main.js', 'builds/old-web/MAIN.JS',
                 'builds/old-web-neighbor/bundle.js', 'standalone.js', 'current/source.py',
                 'builds/old-web/original.META', 'builds/old-web/game.save', 'builds/old-web/production.db'):
        assert cp.protected(profile, path)
    assert not cp.protected(profile, 'builds/old-web/main.js')
    # The original namespace still governs a manifest after the exact build moves.
    os.rename(profile.root / 'builds/old-web', quarantine / 'payload')
    assert not cp.protected(profile, 'builds/old-web/main.js')
    assert cp.protected(profile, 'BUILDS/old-web/main.js')


def test_current_child_keep_and_explicit_protected_cannot_be_overridden_by_build_label(tmp_path):
    profile, request, _, _ = web_build_fixture(tmp_path)
    for key, value in (
        ('current', ['builds/old-web/runtime.py']),
        ('protected', ['builds/old-web/runtime.py']),
        ('keep', profile.data['keep'] + [{'path': 'builds/old-web/runtime.py', 'reason': 'current required code'}]),
    ):
        data = {**profile.data, key: value}
        restricted = cp.load_profile(profile.root, profile.config, data)
        assert cp.protected(restricted, 'builds/old-web/main.js')
        assert cp.qualify(restricted, request)['status'] == 'Blocked'
    config = copy.deepcopy(profile.config)
    config['protected'].append('builds/old-web/main.js')
    restricted = cp.load_profile(profile.root, config, profile.data)
    assert cp.protected(restricted, 'builds/old-web/main.js')


def test_standalone_code_file_and_non_build_output_stay_protected(tmp_path):
    profile, request, _, _ = web_build_fixture(tmp_path)
    (profile.root / 'old-runtime.js').write_text('old standalone source')
    data = {**profile.data, 'candidates': [{'path': 'old-runtime.js', 'kind': 'old_build'}]}
    standalone = cp.load_profile(profile.root, profile.config, data)
    request['items'][0]['source'] = 'old-runtime.js'
    assert cp.qualify(standalone, request)['status'] == 'Blocked'
    data = {**profile.data, 'candidates': [{'path': 'builds/old-web', 'kind': 'disposable_output'}]}
    ordinary = cp.load_profile(profile.root, profile.config, data)
    assert cp.protected(ordinary, 'builds/old-web/main.js')


def test_load_and_inspect_never_open_declared_external_roots(tmp_path, monkeypatch):
    profile, _, _, _ = fixture(tmp_path)
    forbidden = (tmp_path / 'ungranted-q', tmp_path / 'ungranted-records')
    data = {**profile.data, 'quarantine_root': str(forbidden[0]), 'records_dir': str(forbidden[1])}
    actual = dc._open_directory
    accessed = []
    def guarded(path):
        path = Path(path)
        if any(path == item or path.is_relative_to(item) for item in forbidden):
            accessed.append(str(path))
            raise AssertionError('profile declaration must not open an ungranted external root')
        return actual(path)
    monkeypatch.setattr(dc, '_open_directory', guarded)
    loaded = cp.load_profile(profile.root, profile.config, data)
    assert cp.inspect(loaded)['body_bytes_read'] == 0
    assert accessed == []
    assert not any(path.exists() for path in forbidden)


def test_wrong_project_declaration_rejected_before_any_foreign_lookup(tmp_path, monkeypatch):
    profile, _, _, _ = fixture(tmp_path)
    other = tmp_path / 'other-project'
    actual = dc._open_directory
    def guarded(path):
        if Path(path) == other or Path(path).is_relative_to(other):
            raise AssertionError('mismatched project declaration must not be inspected')
        return actual(path)
    monkeypatch.setattr(dc, '_open_directory', guarded)
    with pytest.raises(dc.DirectoryError) as error:
        cp.load_profile(profile.root, profile.config, {**profile.data, 'project_root': str(other)})
    assert error.value.reason_code == 'PROFILE_CONFLICT'


def test_runtime_roots_only_canonicalize_explicit_arguments_not_unmatched_declarations(tmp_path, monkeypatch):
    profile, _, q, records = fixture(tmp_path)
    # Explicit runtime aliases are resolved to the already approved native names.
    assert cp.runtime_roots(profile, q.with_name('QUARANTINE'), records.with_name('RECORDS')) == (q, records)
    denied = tmp_path / 'ungranted-declaration'
    data = {**profile.data, 'quarantine_root': str(denied)}
    loaded = cp.load_profile(profile.root, profile.config, data)
    actual = dc._open_directory
    def guarded(path):
        if Path(path) == denied:
            raise AssertionError('runtime must not inspect an unmatched declared root')
        return actual(path)
    monkeypatch.setattr(dc, '_open_directory', guarded)
    with pytest.raises(dc.DirectoryError) as error:
        cp.runtime_roots(loaded, q, records)
    assert error.value.reason_code == 'PROFILE_CONFLICT'


@pytest.mark.parametrize('change', ['profile', 'config', 'budgets'])
def test_live_profile_control_mutation_requires_new_load(tmp_path, change):
    profile, request, _, _ = fixture(tmp_path)
    assert cp.qualify(profile, request)['status'] == 'Passed'
    if change == 'profile':
        profile.data['current'] = []
    elif change == 'config':
        profile.config['protected'].append('current')
    else:
        profile.budgets['max_entries'] += 1
    with pytest.raises(dc.DirectoryError) as error:
        cp.qualify(profile, request)
    assert error.value.reason_code == 'PROFILE_CONFLICT'


def test_project_config_metadata_changes_stop_same_long_workflow_without_body_reread(tmp_path, monkeypatch):
    profile, request, _, _ = fixture(tmp_path)
    assert cp.qualify(profile, request)['status'] == 'Passed'
    # Creation after a Missing signature is drift too.
    path = profile.root / '.fifan-maintenance.json'
    path.write_text('{}')
    def forbidden(*args, **kwargs):
        raise AssertionError('config drift gate must not reread any body')
    monkeypatch.setattr(dc, 'read_file', forbidden)
    with pytest.raises(dc.DirectoryError) as error:
        cp.validate_profile_root(profile)
    assert error.value.reason_code == 'SOURCE_CHANGED'
    fresh = cp.load_profile(profile.root, profile.config, profile.data)
    before = path.stat()
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
    with pytest.raises(dc.DirectoryError) as error:
        cp.validate_profile_root(fresh)
    assert error.value.reason_code == 'SOURCE_CHANGED'


def test_recomputing_public_profile_sha_does_not_refresh_a_live_control_grant(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    profile.data['current'] = []
    profile.sha256 = dc.digest(profile.data)
    with pytest.raises(dc.DirectoryError) as error:
        cp.qualify(profile, request)
    assert error.value.reason_code == 'PROFILE_CONFLICT'


def test_old_build_code_exception_keeps_native_unicode_spelling(tmp_path):
    profile, _, _, _ = web_build_fixture(tmp_path)
    source = 'builds/旧版-Résumé'
    (profile.root / source).mkdir()
    (profile.root / source / 'runtimé.js').write_text('packaged unicode runtime')
    data = {**profile.data, 'candidates': [{'path': source, 'kind': 'old_build'}]}
    unicode_build = cp.load_profile(profile.root, profile.config, data)
    assert not cp.protected(unicode_build, source + '/runtimé.js')
    assert cp.protected(unicode_build, unicodedata.normalize('NFD', source) + '/runtimé.js')
    assert cp.protected(unicode_build, source + '/' + unicodedata.normalize('NFD', 'runtimé.js'))
    alternate = cp.load_profile(profile.root, profile.config, {
        **data, 'candidates': [{'path': 'BUILDS/旧版-Résumé', 'kind': 'old_build'}]})
    assert cp.protected(alternate, 'BUILDS/旧版-Résumé/runtimé.js')


def directory_keep_fixture(tmp_path):
    profile, request, quarantine, records = fixture(tmp_path, kind='old_build')
    keep = profile.root / 'builds/keep-package'
    (keep / 'nested').mkdir(parents=True)
    (keep / 'nested/binary.dat').write_bytes(b'kept build bytes\x00')
    data = copy.deepcopy(profile.data)
    data['keep'][0]['path'] = 'builds/keep-package'
    data['keep'][0].pop('sha256')
    profile = cp.load_profile(profile.root, profile.config, data)
    request['items'][0]['retained'] = ['builds/keep-package']
    return profile, request, quarantine, records


def test_keep_child_same_content_mode_and_mtime_replacement_changes_material(tmp_path):
    profile, request, _, _ = directory_keep_fixture(tmp_path)
    keep = profile.root / 'builds/keep-package'
    target = keep / 'nested/binary.dat'
    before = cp.qualify(profile, request)
    assert before['status'] == 'Passed'
    root_before, original = keep.stat(), target.stat()
    replacement = profile.root / 'replacement.tmp'
    replacement.write_bytes(target.read_bytes())
    os.chmod(replacement, original.st_mode & 0o7777)
    os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
    os.replace(replacement, target)
    assert target.stat().st_ino != original.st_ino
    assert target.stat().st_mtime_ns == original.st_mtime_ns
    assert dc._stable(keep.stat()) == dc._stable(root_before)
    after = cp.qualify(profile, request)
    assert after['status'] == 'Passed'
    assert before['items'][0]['retained'][0]['sha256'] == after['items'][0]['retained'][0]['sha256']
    assert after['material_sha256'] != before['material_sha256']


@pytest.mark.parametrize('target', ['directory', 'file'])
def test_unchanged_keep_bytes_with_timestamp_drift_changes_material(tmp_path, target):
    profile, request, _, _ = directory_keep_fixture(tmp_path) if target == 'directory' else fixture(tmp_path, kind='old_build')
    path = profile.root / ('builds/keep-package/nested' if target == 'directory' else 'builds/keep.zip')
    before = cp.qualify(profile, request)
    old = path.stat()
    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns + 1000000000))
    after = cp.qualify(profile, request)
    assert before['status'] == after['status'] == 'Passed'
    assert before['items'][0]['retained'][0]['sha256'] == after['items'][0]['retained'][0]['sha256']
    assert after['material_sha256'] != before['material_sha256']


def test_keep_state_manifest_records_full_observations_but_content_sha_stays_separate(tmp_path):
    profile, request, _, _ = directory_keep_fixture(tmp_path)
    before = cp.qualify(profile, request)
    retained = before['items'][0]['retained'][0]
    entries = retained['manifest']
    assert [entry['path'] for entry in entries] == ['.', 'nested', 'nested/binary.dat']
    for entry in entries:
        assert {'path', 'kind', 'device', 'inode', 'mode', 'mtime_ns', 'ctime_ns', 'nlink'} <= set(entry)
        actual = (profile.root / retained['path'] / entry['path']).stat()
        assert entry['device'] == actual.st_dev and entry['inode'] == actual.st_ino
        assert entry['mtime_ns'] == actual.st_mtime_ns and entry['ctime_ns'] == actual.st_ctime_ns
    assert retained['state_sha256'] == dc.digest(entries)
    content = [{key: entry[key] for key in ('path', 'kind', 'mode', 'bytes', 'sha256') if key in entry} for entry in entries]
    assert retained['sha256'] == dc.digest(content)
    again = cp.qualify(profile, request)
    assert again['material_sha256'] == before['material_sha256']


def test_keep_state_remains_stable_across_unrelated_payload_quarantine_and_restore(tmp_path):
    from fifan_maintenance import cleanup_operations as operations
    profile, request, quarantine, records = directory_keep_fixture(tmp_path)
    before = cp.qualify(profile, request)
    plan = operations.preview(profile, request, quarantine, records)
    journal = operations.apply(profile, plan, quarantine, records, approve_plan=plan['fingerprint'])
    moved = plan['items'][0]
    relocated = {moved['source']: {'root': str(quarantine), 'path': moved['quarantine_relative']}}
    after_quarantine = cp.qualify(profile, request, relocations=relocated)
    assert after_quarantine['material_sha256'] == before['material_sha256']
    restore = operations.restore_preview(profile, journal, quarantine, records)
    operations.restore(profile, restore, quarantine, records, approve_plan=restore['fingerprint'])
    after_restore = cp.qualify(profile, request)
    assert after_restore['material_sha256'] == before['material_sha256']
    assert after_restore['items'][0]['retained'][0]['manifest'] == before['items'][0]['retained'][0]['manifest']


def test_rule_hints_match_metadata_without_granting_disposal(tmp_path, monkeypatch):
    profile, _, _, _ = fixture(tmp_path)
    profile.data['rules'] = [
        {'kind': 'completed_log', 'glob': 'logs/*.log', 'reason': 'closed log clue'},
        {'kind': 'disposable_output', 'glob': 'logs/*', 'reason': 'temporary output clue'},
        {'kind': 'old_build', 'glob': 'missing/*.zip', 'reason': 'no match'}]
    profile.data['current'].append('logs/finished.log')
    profile = refreshed(profile)
    def forbidden(*args, **kwargs):
        pytest.fail('rules must not read bodies or hashes')
    monkeypatch.setattr(dc, 'read_file', forbidden)
    monkeypatch.setattr(dc, 'stream_hash', forbidden)
    result = cp.inspect(profile)
    assert result['counts']['D'] == 0
    assert result['body_bytes_read'] == result['candidate_hash_bytes'] == 0
    groups = result['rule_hints']['groups']
    assert [group['rule_index'] for group in groups] == [0, 1]
    assert [group['reason'] for group in groups] == ['closed log clue', 'temporary output clue']
    assert all(group['matched_count'] == 1 for group in groups)
    assert all(group['samples'] == [{'path': 'logs/finished.log', 'classification': 'R'}] for group in groups)
    assert result['rule_hints']['matched_paths_count'] == 1
    profile.data['current'].remove('logs/finished.log')
    result = cp.inspect(refreshed(profile))
    assert result['counts']['D'] == 0
    assert result['rule_hints']['groups'][0]['samples'][0]['classification'] == 'U'


def test_rule_hints_use_existing_scan_budget_and_bound_output(tmp_path):
    profile, _, _, _ = fixture(tmp_path)
    profile.data['scan_roots'] = ['logs/finished.log']
    profile.data['rules'] = [{'kind': 'completed_log', 'glob': 'logs/*', 'reason': 'clue'} for _ in range(12)]
    result = cp.inspect(refreshed(profile))
    assert len(result['rule_hints']['groups']) == 8
    assert result['rule_hints']['matching_rules_count'] == 12
    assert result['rule_hints']['groups_truncated'] is True
    assert result['rule_hints']['complete'] is False
    assert result['status'] == 'Unknown'
    profile.budgets['max_entries'] = 3
    result = cp.inspect(refreshed(profile))
    assert result['status'] == 'Unknown'
    assert result['rule_hints']['complete'] is False
    assert result['work_entries'] == 3
    assert result['coverage']['gaps'][0]['reason_code'] == 'BUDGET_EXHAUSTED'
    assert result['counts']['D'] == 0


@pytest.mark.parametrize('serialized', [r'{"path":"../logs/fin\u0069shed.log"}', r'{"path":"../logs/finished.log"}'])
def test_cleanup_current_json_decodes_escaped_path_before_reference_check(tmp_path, serialized):
    profile, request, _, _ = fixture(tmp_path)
    (profile.root / 'current/consumer.json').write_text(serialized)
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked', result
    assert result['items'][0]['eligible'] is False


def test_rule_hint_samples_are_bounded_and_explicitly_incomplete(tmp_path):
    profile, _, _, _ = fixture(tmp_path)
    for index in range(9):
        (profile.root / 'logs' / ('extra-%s.log' % index)).write_bytes(b'opaque')
    profile.data['scan_roots'] = ['logs']
    profile.data['rules'] = [{'kind': 'completed_log', 'glob': 'logs/*.log', 'reason': 'metadata clue'}]
    result = cp.inspect(refreshed(profile))
    group = result['rule_hints']['groups'][0]
    assert group['matched_count'] == 10 and len(group['samples']) == 8
    assert group['samples_truncated'] is True
    assert result['status'] == 'Unknown' and result['rule_hints']['complete'] is False
    assert result['coverage']['complete'] is True
    assert result['counts']['D'] == 0


@pytest.mark.parametrize('encoded', [r'cat logs/fin\u0069shed.log', 'cat logs/finished.log'])
def test_json_embedded_command_current_consumer_is_not_discardable(tmp_path, encoded):
    profile, request, _, _ = fixture(tmp_path)
    (profile.root / 'current/consumer.json').write_text('{"command":"' + encoded + '"}')
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Blocked'
    assert not result['items'][0]['eligible']


def test_json_mixed_dynamic_only_one_resolution_does_not_grant_cleanup(tmp_path):
    profile, request, _, _ = fixture(tmp_path)
    (profile.root / 'current/consumer.json').write_text(r'{"command":"echo ${MESSAGE}; cat \u0024{ROOT}/data.bin"}')
    initial = cp.qualify(refreshed(profile), request)
    raw = next(x for x in initial['items'][0]['unknowns'] if x['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN')
    resolution = {k: raw[k] for k in ('path', 'sha256', 'line', 'column', 'line_sha256', 'expression_sha256')}
    resolution.update(source='logs/finished.log', reason='Only MESSAGE was reviewed',
                      evidence=copy.deepcopy(request['items'][0]['closure']['evidence']))
    request['items'][0]['dynamic_reference_resolutions'] = [resolution]
    result = cp.qualify(refreshed(profile), request)
    assert result['status'] == 'Unknown'
    assert not result['items'][0]['eligible']
    assert any(x['reason_code'] == 'REFERENCE_SYNTAX_UNKNOWN' for x in result['items'][0]['unknowns'])


@pytest.mark.parametrize('encoded', [r'../logs/finished \u006cog.log', '../logs/finished log.log'])
def test_json_whole_relative_space_path_is_not_discardable(tmp_path, encoded):
    profile, request, _, _ = fixture(tmp_path)
    source = 'logs/finished log.log'
    (profile.root / 'logs/finished.log').rename(profile.root / source)
    data = copy.deepcopy(profile.data)
    data['candidates'][0]['path'] = source
    profile = cp.load_profile(profile.root, profile.config, data)
    request['items'][0]['source'] = source
    (profile.root / 'current/consumer.json').write_text('{"path":"' + encoded + '"}')
    result = cp.qualify(profile, request)
    assert result['status'] == 'Blocked'
    assert not result['items'][0]['eligible']
