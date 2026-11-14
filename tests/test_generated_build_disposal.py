"""Explicit unknown-provenance generated builds, only temporary fixtures."""
from copy import deepcopy
import hashlib

import pytest

from fifan_maintenance import cleanup_policy as cp
from fifan_maintenance import cleanup_operations as ops
from fifan_maintenance import directory_common as dc
from test_cleanup_policy import web_build_fixture


def generated_case(tmp_path):
    profile, request, q, records = web_build_fixture(tmp_path)
    data = deepcopy(profile.data)
    data['candidates'][0]['disposal_policy'] = 'generated_artifact'
    request['items'][0].pop('build')
    request['items'][0]['retained'] = []
    request['items'][0]['generated_disposal'] = {'generated_only': True, 'reason': 'Explicitly approved generated runtime distribution; no unique source'}
    request['items'][0]['loss']['accepted'] = True
    profile = cp.load_profile(profile.root, profile.config, data)
    return profile, request, q, records


def untouched(profile):
    return {path: hashlib.sha256((profile.root / path).read_bytes()).hexdigest()
            for path in ('current/README.md', 'current/closed.md', 'builds/keep.zip', 'builds/old.zip')}


def test_legacy_unknown_provenance_rejects_and_explicit_contract_full_cycle(tmp_path):
    original, missing, _, _ = web_build_fixture(tmp_path)
    missing['items'][0].pop('build')
    with pytest.raises(dc.DirectoryError) as error:
        cp.qualify(original, missing)
    assert error.value.reason_code == 'BUILD_GROUP_UNKNOWN'
    # Use the same original project and payload, not a recreated failure case.
    data = deepcopy(original.data)
    data['candidates'][0]['disposal_policy'] = 'generated_artifact'
    profile = cp.load_profile(original.root, original.config, data)
    request = missing
    request['items'][0].update(retained=[], disposition='purge',
        generated_disposal={'generated_only': True, 'reason': 'Approved exact generated distribution; loss explicitly accepted'})
    request['items'][0]['loss']['accepted'] = True
    request['approval']['actions'].append('purge')
    q, records = profile.data['quarantine_root'], profile.data['records_dir']
    before = untouched(profile)
    result = cp.qualify(profile, request)
    assert result['status'] == 'Passed'
    assert result['items'][0]['build_provenance'] == {'status': 'Unknown', 'metadata': {}, 'missing_fields': ['branch', 'configuration', 'platform', 'purpose']}
    assert result['items'][0]['retention_comparison'] == 'WaivedByExplicitLossApproval'
    assert result['items'][0]['rebuildability'] == 'Unknown'
    plan = ops.preview(profile, request, q, records)
    held = ops.apply(profile, plan, q, records, approve_plan=plan['fingerprint'])
    assert held['state'] == 'Quarantined'
    assert ops.verify(profile, held, q, records)['status'] == 'Passed'
    rollback = ops.restore_preview(profile, held, q, records)
    assert ops.restore(profile, rollback, q, records, approve_plan=rollback['fingerprint'])['state'] == 'Restored'
    second = ops.preview(profile, request, q, records)
    held = ops.apply(profile, second, q, records, approve_plan=second['fingerprint'])
    purge = ops.purge_preview(profile, held, q, records)
    purged = ops.purge(profile, purge, q, records, approve_plan=purge['fingerprint'])
    assert purged['state'] == 'Purged'
    assert ops.verify(profile, purged, q, records)['status'] == 'Passed'
    assert untouched(profile) == before
    assert not (profile.root / request['items'][0]['source']).exists()


@pytest.mark.parametrize('grant', ['profile', 'request', 'loss', 'unique', 'generated-only', 'reason'])
def test_missing_exact_grants_do_not_waive_legacy_metadata(tmp_path, grant):
    profile, request, _, _ = generated_case(tmp_path)
    if grant == 'profile':
        data = deepcopy(profile.data)
        data['candidates'][0].pop('disposal_policy')
        profile = cp.load_profile(profile.root, profile.config, data)
    elif grant == 'request':
        request['items'][0].pop('generated_disposal')
    elif grant == 'loss':
        request['items'][0]['loss']['accepted'] = False
    elif grant == 'unique':
        request['items'][0]['loss']['unique_evidence'] = True
    elif grant == 'generated-only':
        request['items'][0]['generated_disposal']['generated_only'] = False
    else:
        request['items'][0]['generated_disposal']['reason'] = ''
    with pytest.raises(dc.DirectoryError):
        cp.qualify(profile, request)


def test_partial_build_metadata_preserved_and_separately_unknown(tmp_path):
    profile, request, _, _ = generated_case(tmp_path)
    request['items'][0]['build'] = {'platform': 'web', 'branch': 'Unknown'}
    result = cp.qualify(profile, request)
    assert result['status'] == 'Passed'
    provenance = result['items'][0]['build_provenance']
    assert provenance['metadata'] == {'platform': 'web', 'branch': 'Unknown'}
    assert provenance['status'] == 'Unknown' and provenance['missing_fields'] == ['branch', 'configuration', 'purpose']
    assert result['material']['items'][0]['build_provenance'] == provenance


@pytest.mark.parametrize('protected_path', ['src/generated', 'current/generated', 'builds/keep.zip'])
def test_generated_policy_does_not_unlock_formal_current_or_keep(tmp_path, protected_path):
    profile, request, q, records = generated_case(tmp_path)
    source = profile.root / protected_path
    if not source.exists():
        source.mkdir(parents=True)
        (source / 'main.js').write_text('generated source cannot unlock protected root')
    data = deepcopy(profile.data)
    data['candidates'][0]['path'] = protected_path
    profile = cp.load_profile(profile.root, profile.config, data)
    request['items'][0]['source'] = protected_path
    result = cp.qualify(profile, request)
    assert result['status'] == 'Blocked'
    with pytest.raises(dc.DirectoryError):
        ops.preview(profile, request, q, records)


@pytest.mark.parametrize('case', ['symlink', 'database', 'open', 'drift', 'unapproved'])
def test_generated_policy_preserves_native_safety_gates(tmp_path, case):
    profile, request, q, records = generated_case(tmp_path)
    source = profile.root / request['items'][0]['source']
    before = untouched(profile)
    if case == 'symlink':
        (source / 'link').symlink_to(profile.root / 'current/README.md')
    elif case == 'database':
        (source / 'original.sqlite').write_bytes(b'private saved data')
    elif case == 'unapproved':
        request['items'][0]['source'] = 'builds/unknown'
    if case == 'open':
        with (source / 'main.js').open('rb'):
            with pytest.raises(dc.DirectoryError) as error:
                ops.preview(profile, request, q, records)
        assert error.value.reason_code == 'OPEN_HANDLES'
    elif case == 'drift':
        plan = ops.preview(profile, request, q, records)
        (source / 'main.js').write_text('changed generated payload')
        with pytest.raises(dc.DirectoryError) as error:
            ops.apply(profile, plan, q, records, approve_plan=plan['fingerprint'])
        assert error.value.reason_code == 'SOURCE_CHANGED'
    else:
        with pytest.raises(dc.DirectoryError):
            ops.preview(profile, request, q, records)
    assert untouched(profile) == before
    assert source.is_dir()
