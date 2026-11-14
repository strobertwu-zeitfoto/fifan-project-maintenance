"""Only synthetic tmp_path projects; no user projects or installed writes."""
from copy import deepcopy
import json

import pytest

from fifan_maintenance import cleanup_policy as cp
from fifan_maintenance import cleanup_operations as co
from fifan_maintenance import directory_common as dc
from fifan_maintenance import directory_archive as da
from fifan_maintenance.directory_census import _References, impact
from fifan_maintenance.reference_batches import advance, estimate
from test_cleanup_policy import fixture as cleanup_fixture
from test_directory_census import archive_fixture

OPTIONS = {'max_batches': 20, 'max_total_bytes': 65536, 'max_total_files': 100, 'max_total_seconds': 30}


def batched_cleanup(tmp_path):
    original, request, q, records = cleanup_fixture(tmp_path)
    for index in range(5):
        (original.root / ('current/source-%d.txt' % index)).write_text('Retained source document number %d.\n' % index)
    data = {**original.data, 'budgets': {**original.budgets, 'max_reference_bytes': 64, 'max_reference_file_bytes': 64, 'max_reference_files': 1},
            'reference_batching': dict(OPTIONS), 'require_no_open_handles': False}
    return cp.load_profile(original.root, original.config, data), request, q, records


def reader_for(profile, request):
    reader = cp._RetainedReferences(profile, cp.validate_request(profile, request)['items'])
    return reader, reader.reference_roots()


def test_metadata_estimate_no_body_reads_and_complete_batches_match_legacy(tmp_path, monkeypatch):
    profile, request, _, _ = batched_cleanup(tmp_path)
    reader, roots = reader_for(profile, request)
    original = dc.read_file
    def forbidden(*args, **kwargs):
        pytest.fail('estimate must not read reference bodies')
    monkeypatch.setattr(dc, 'read_file', forbidden)
    predicted = estimate(reader, roots)
    assert predicted['batch_count'] == 7 and predicted['body_bytes_read'] == 0
    assert predicted['estimated_parse_bytes'] > profile.budgets['max_reference_bytes']
    monkeypatch.setattr(dc, 'read_file', original)
    result = cp.qualify(profile, request)
    assert result['status'] == 'Passed' and result['coverage']['complete']
    assert result['coverage']['batching']['batch_count'] == 7
    assert result['reference_bytes_read'] == predicted['estimated_parse_bytes']
    assert set(result['coverage']['batching']['usage']['phase_seconds']) == {'inventory', 'resume_validation', 'parse', 'final_inventory'}
    assert all(value >= 0 for value in result['coverage']['batching']['usage']['phase_seconds'].values())
    data = deepcopy(profile.data)
    del data['reference_batching']
    data['budgets']['max_reference_bytes'] = 65536
    data['budgets']['max_reference_files'] = 100
    baseline = cp.qualify(cp.load_profile(profile.root, profile.config, data), request)
    assert result['items'][0]['status'] == baseline['items'][0]['status']
    assert result['items'][0]['retained_dependencies'] == baseline['items'][0]['retained_dependencies']
    assert result['material']['items'][0]['reference_fingerprints'] == baseline['material']['items'][0]['reference_fingerprints']
    data['budgets']['max_reference_bytes'] = 64
    data['budgets']['max_reference_files'] = 1
    assert cp.qualify(cp.load_profile(profile.root, profile.config, data), request)['status'] == 'Unknown'


def test_interrupted_resume_reuses_parse_but_freshly_hashes_same_session(tmp_path, monkeypatch):
    profile, request, _, _ = batched_cleanup(tmp_path)
    reader, roots = reader_for(profile, request)
    first = advance(reader, roots, max_batches=2)
    assert first['status'] == 'Partial' and not first['complete']
    assert not reader.coverage()['complete']
    # Simulate process restart through actual JSON serialization; retain receipt
    # identity out of band rather than trusting an arbitrary new seal.
    persisted = json.loads(json.dumps(first))
    reader, roots = reader_for(profile, request)
    observed = []
    original = _References._analyze
    def analyzed(self, path, *args, **kwargs):
        observed.append(path)
        return original(self, path, *args, **kwargs)
    monkeypatch.setattr(_References, '_analyze', analyzed)
    final = advance(reader, roots, resume=persisted, expected_fingerprint=first['fingerprint'], max_batches=20)
    assert final['status'] == 'Passed' and final['complete']
    assert len(observed) == 5
    assert final['usage']['validation_bytes_read'] == first['usage']['reference_bytes_read']
    assert final['mutation_authorized'] is False and final['inspection_only'] is True
    assert reader.coverage()['complete']
    assert dc.canonical(persisted) == dc.canonical(first)
    dc.validate_seal(persisted)


@pytest.mark.parametrize('change', ['new', 'changed', 'removed', 'tampered', 'resealed', 'missing', 'missing-resealed', 'scope', 'no-anchor'])
def test_resume_rejects_drift_tampering_and_missing_batches(tmp_path, change):
    profile, request, _, _ = batched_cleanup(tmp_path)
    reader, roots = reader_for(profile, request)
    first = advance(reader, roots, max_batches=2)
    fingerprint = first['fingerprint']
    if change == 'new':
        (profile.root / 'current/new.txt').write_text('new retained file')
    elif change == 'changed':
        (profile.root / first['batches'][0]['paths'][0]).write_text('changed')
    elif change == 'removed':
        (profile.root / first['batches'][0]['paths'][0]).unlink()
    elif change in ('tampered', 'resealed'):
        first['batches'][0]['facts'][first['batches'][0]['paths'][0]]['value']['sha256'] = '0' * 64
        if change == 'resealed':
            first = dc.seal(first)
    elif change in ('missing', 'missing-resealed'):
        first['batches'].pop(0)
        if change == 'missing-resealed':
            first = dc.seal(first)
            fingerprint = first['fingerprint']  # even newly endorsed envelope cannot hide chunk gap
    elif change == 'scope':
        request['items'][0]['source'] = 'logs/other.log'
    elif change == 'no-anchor':
        fingerprint = None
    with pytest.raises(dc.DirectoryError):
        reader, roots = reader_for(profile, request)
        advance(reader, roots, resume=first, expected_fingerprint=fingerprint, max_batches=20)


@pytest.mark.parametrize('limit,value', [('max_total_bytes', 1), ('max_total_files', 1), ('max_batches', 1)])
def test_insufficient_aggregate_budget_blocks_all_qualification(tmp_path, limit, value):
    profile, request, _, _ = batched_cleanup(tmp_path)
    data = deepcopy(profile.data)
    data['reference_batching'][limit] = value
    limited = cp.load_profile(profile.root, profile.config, data)
    reader, roots = reader_for(limited, request)
    with pytest.raises(dc.DirectoryError):
        estimate(reader, roots)
    result = cp.qualify(limited, request)
    assert result['status'] != 'Passed' and not result['coverage']['complete']


def test_oversized_file_not_split_to_evade_single_file_limit(tmp_path):
    profile, request, _, _ = batched_cleanup(tmp_path)
    (profile.root / 'current/too-big.txt').write_bytes(b'x' * 65)
    result = cp.qualify(profile, request)
    assert result['status'] == 'Unknown' and not result['coverage']['complete']


def test_new_reference_during_batch_scan_rejected(tmp_path, monkeypatch):
    profile, request, _, _ = batched_cleanup(tmp_path)
    reader, roots = reader_for(profile, request)
    original = _References.read
    def read(self, path):
        value = original(self, path)
        (profile.root / 'current/new.txt').write_text('new retained original')
        return value
    monkeypatch.setattr(_References, 'read', read)
    with pytest.raises(dc.DirectoryError) as error:
        advance(reader, roots, max_batches=20)
    assert error.value.reason_code == 'SOURCE_CHANGED'


def test_preview_apply_restore_use_fresh_complete_batches_and_detect_new_consumer(tmp_path):
    profile, request, q, records = batched_cleanup(tmp_path)
    plan = co.preview(profile, request, q, records)
    held = co.apply(profile, plan, q, records, approve_plan=plan['fingerprint'])
    assert held['state'] == 'Quarantined'
    restore = co.restore_preview(profile, held, q, records)
    assert co.restore(profile, restore, q, records, approve_plan=restore['fingerprint'])['state'] == 'Restored'
    plan = co.preview(profile, request, q, records)
    (profile.root / 'current/new.txt').write_text('Load logs/finished.log\n')
    with pytest.raises(dc.DirectoryError):
        co.apply(profile, plan, q, records, approve_plan=plan['fingerprint'])
    assert (profile.root / 'logs/finished.log').is_file()


def test_directory_impact_and_real_archive_use_batches(tmp_path):
    project, archive, records = [tmp_path / name for name in ('project', 'archive', 'records')]
    for path in (project, archive, records):
        path.mkdir()
    profile, request = archive_fixture(project)
    (project / 'refs/a.txt').write_text('Another retained original\n')
    data = deepcopy(profile.data)
    data['reference_batching'] = dict(OPTIONS)
    data['budgets'].update(max_reference_bytes=64, max_reference_file_bytes=64, max_reference_files=1)
    data['archive'].update(archive_root=str(archive), records_dir=str(records), require_no_open_handles=False)
    profile = dc.load_profile(project, profile.config, data)
    result = impact(profile, request)
    assert result['status'] == 'Passed' and result['coverage']['batching']['batch_count'] == 2
    plan = da.archive_preview(profile, request, archive, records)
    journal = da.apply(profile, plan, archive, records)
    assert journal['state'] == 'Archived'
    restored = da.restore_preview(profile, journal, archive)
    assert da.restore(profile, restored, archive, records)['state'] == 'Restored'


@pytest.mark.parametrize('options', [{}, {**OPTIONS, 'extra': 1}, {**OPTIONS, 'max_batches': True}, {**OPTIONS, 'max_batches': 1001}])
def test_profile_strict_opt_in_contract(tmp_path, options):
    profile, _, _, _ = cleanup_fixture(tmp_path)
    with pytest.raises(dc.DirectoryError):
        cp.load_profile(profile.root, profile.config, {**profile.data, 'reference_batching': options})
    with pytest.raises(dc.DirectoryError):
        dc.load_profile(profile.root, profile.config, {'schema_version': 1, 'project_root': str(profile.root), 'reference_batching': options})


def test_cli_receipt_is_exact_and_resume_uses_external_anchor(tmp_path, capsys):
    from fifan_maintenance.cli import main
    profile, request, _, _ = batched_cleanup(tmp_path)
    config = tmp_path / 'profile.json'
    req = tmp_path / 'request.json'
    config.write_text(json.dumps(profile.data))
    req.write_text(json.dumps(request))
    args = ['--project', str(profile.root), '--profile', str(config), '--request', str(req)]
    predicted = tmp_path / 'estimate.json'
    assert main(['cleanup', 'reference-estimate', *args, '--output', str(predicted)]) == 0
    capsys.readouterr()
    assert dc.load_artifact(predicted)['body_bytes_read'] == 0
    initial = tmp_path / 'initial.json'
    assert main(['cleanup', 'reference-advance', *args, '--output', str(initial)]) == 0
    summary = json.loads(capsys.readouterr().out)
    first = dc.load_artifact(initial)
    assert first['status'] == summary['status'] == 'Partial'
    dc.validate_seal(first)
    final = tmp_path / 'final.json'
    assert main(['cleanup', 'reference-advance', *args, '--resume', str(initial),
                 '--reference-fingerprint', summary['fingerprint'], '--max-batches', '20', '--output', str(final)]) == 0
    capsys.readouterr()
    assert dc.load_artifact(final)['complete']
    assert dc.load_artifact(initial) == first
    # Public inspection outputs may never create project files.
    assert main(['cleanup', 'reference-advance', *args, '--output', str(profile.root / 'unsafe.json')]) == 2
    capsys.readouterr()
    assert not (profile.root / 'unsafe.json').exists()


def test_fresh_hash_rejects_facts_even_if_new_outer_and_batch_seals_are_endorsed(tmp_path):
    profile, request, _, _ = batched_cleanup(tmp_path)
    reader, roots = reader_for(profile, request)
    first = advance(reader, roots)
    chunk = first['batches'][0]
    chunk['facts'][chunk['paths'][0]]['value']['sha256'] = '0' * 64
    first['batches'][0] = dc.seal(chunk)
    first = dc.seal(first)
    reader, roots = reader_for(profile, request)
    with pytest.raises(dc.DirectoryError) as error:
        advance(reader, roots, resume=first, expected_fingerprint=first['fingerprint'])
    assert error.value.reason_code == 'SOURCE_CHANGED'


def test_aggregate_time_and_metadata_limits_reject_coverage(tmp_path, monkeypatch):
    import fifan_maintenance.reference_batches as batches
    profile, request, _, _ = batched_cleanup(tmp_path)
    reader, roots = reader_for(profile, request)
    original = batches._inventory
    clock = [0.0]
    monkeypatch.setattr(batches.time, 'monotonic', lambda: clock[0])
    def inventory(*args):
        value = original(*args)
        clock[0] += OPTIONS['max_total_seconds'] + 1
        return value
    monkeypatch.setattr(batches, '_inventory', inventory)
    with pytest.raises(dc.DirectoryError) as error:
        advance(reader, roots)
    assert error.value.reason_code == 'BUDGET_EXHAUSTED'


def test_keyboard_interrupt_preserves_last_checkpoint_and_resumes_same_receipt(tmp_path, monkeypatch):
    profile, request, _, _ = batched_cleanup(tmp_path)
    reader, roots = reader_for(profile, request)
    checkpoint = advance(reader, roots)
    original_checkpoint = deepcopy(checkpoint)
    original = _References.read
    attempts = []
    def interrupted(self, path):
        attempts.append(path)
        if len(attempts) == 2:
            raise KeyboardInterrupt('synthetic interruption after a completed uncheckpointed batch')
        return original(self, path)
    monkeypatch.setattr(_References, 'read', interrupted)
    reader, roots = reader_for(profile, request)
    with pytest.raises(KeyboardInterrupt):
        advance(reader, roots, resume=checkpoint, expected_fingerprint=checkpoint['fingerprint'], max_batches=2)
    assert checkpoint == original_checkpoint
    dc.validate_seal(checkpoint)
    monkeypatch.setattr(_References, 'read', original)
    reader, roots = reader_for(profile, request)
    result = advance(reader, roots, resume=checkpoint, expected_fingerprint=checkpoint['fingerprint'], max_batches=20)
    assert result['complete'] and result['status'] == 'Passed'
