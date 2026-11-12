from __future__ import annotations

from copy import deepcopy
import hashlib
import os

import pytest

from fifan_maintenance import directory_common as dc
from fifan_maintenance.directory_census import census, impact
from fifan_maintenance.project import DEFAULT_CONFIG


def profile(root, **changes):
    data = {'schema_version': 1, 'project_root': str(root)}
    data.update(changes)
    return dc.load_profile(root, deepcopy(DEFAULT_CONFIG), data)


def archive_fixture(tmp_path, references=None, classifications=None, budgets=None):
    (tmp_path / 'old/run').mkdir(parents=True)
    (tmp_path / 'old/run/data.bin').write_bytes(b'data')
    (tmp_path / 'refs').mkdir()
    evidence = b'Approved closed batch; no further work remains.\n'
    (tmp_path / 'refs/closure.md').write_bytes(evidence)
    prof = profile(tmp_path, reference_sources=references or [{'path': 'refs', 'role': 'current'}],
                   classifications=classifications or [{'path': 'old/run', 'role': 'historical', 'reason': 'approved closed'}],
                   archive={'candidates': ['old/run']}, budgets=budgets or {})
    req = {'schema_version': 1, 'batches': [{'source': 'old/run', 'destination': 'closed/run',
           'closure': {'decision': 'closed', 'reason': 'Root-approved historical batch',
                       'evidence': [{'path': 'refs/closure.md', 'sha256': hashlib.sha256(evidence).hexdigest()}]}}]}
    return prof, req


def test_census_metadata_only_counts_overlap_empty_dirs_and_unique_inodes(tmp_path, monkeypatch):
    (tmp_path / 'data/sub/empty').mkdir(parents=True)
    (tmp_path / 'data/a.txt').write_bytes(b'abc')
    (tmp_path / 'data/sub/b.txt').write_bytes(b'12345')
    os.link(tmp_path / 'data/a.txt', tmp_path / 'data/link.txt')
    prof = profile(tmp_path, scan_roots=['data', 'data/sub'], classifications=[{'path': 'data', 'role': 'historical', 'reason': 'explicit'}])
    def forbidden(*args, **kwargs):
        pytest.fail('metadata census must not read or hash document bodies')
    monkeypatch.setattr(dc, 'read_file', forbidden)
    monkeypatch.setattr(dc, 'stream_hash', forbidden)
    result = census(prof)
    dc.validate_seal(result)
    assert result['status'] == 'Passed'
    assert result['file_count'] == 3 and result['directory_count'] == 3
    assert result['logical_bytes'] == 11 and result['unique_inode_logical_bytes'] == 8
    assert result['observed_unique_file_inodes'] == 2
    assert result['overlapping_roots_removed'] == 1
    assert result['physical_space_released_bytes'] is None
    assert result['hash_coverage']['hash_bytes'] == 0
    assert result['coverage']['roots'][0]['observed_bytes'] == 11


def test_excluded_symlink_special_depth_and_budget_are_lower_bounds(tmp_path):
    (tmp_path / 'data/deep/more').mkdir(parents=True)
    (tmp_path / 'data/deep/more/unread.txt').write_bytes(b'not zero')
    (tmp_path / 'data/link').symlink_to(tmp_path / 'data/deep')
    os.mkfifo(tmp_path / 'data/pipe')
    (tmp_path / 'data/.env').write_text('password=PRIVATE')
    prof = profile(tmp_path, scan_roots=['data'], budgets={'max_depth': 0})
    result = census(prof)
    assert result['status'] == 'Unknown' and result['coverage']['count_is_lower_bound']
    reasons = {item['reason_code'] for item in result['coverage']['gaps']}
    assert {'DEPTH_LIMIT', 'PROTECTED_PATH', 'SYMLINK_OR_SPECIAL'} <= reasons
    assert result['file_count'] == 0 and result['coverage']['excluded_entries'] == 1
    (tmp_path / 'another').mkdir()
    limited = profile(tmp_path, scan_roots=['data', 'another'], budgets={'max_entries': 1})
    result = census(limited)
    assert result['coverage']['work_entries'] == 1
    assert result['status'] == 'Unknown' and result['coverage']['unvisited_roots']


def test_hash_only_explicit_same_size_groups_and_budget_failures(tmp_path, monkeypatch):
    (tmp_path / 'data').mkdir()
    for name, raw in [('a', b'abc'), ('b', b'abc'), ('c', b'xyz'), ('single', b'unique!')]:
        (tmp_path / ('data/' + name)).write_bytes(raw)
    prof = profile(tmp_path, scan_roots=['data'])
    original = dc.stream_hash
    seen = []
    def spy(profile, rel, budget):
        seen.append(rel)
        return original(profile, rel, budget)
    monkeypatch.setattr(dc, 'stream_hash', spy)
    result = census(prof, hash_candidates=['data/a', 'data/b', 'data/c', 'data/single'])
    assert set(seen) == {'data/a', 'data/b', 'data/c'}
    assert result['duplicates'][0]['paths'] == ['data/a', 'data/b']
    assert not result['duplicates'][0]['deletion_authorized']
    limited = profile(tmp_path, scan_roots=['data'], budgets={'max_hash_bytes': 2})
    result = census(limited, hash_candidates=['data/a', 'data/b'])
    assert result['status'] == 'Unknown' and not result['hash_coverage']['complete']
    outside = census(prof, hash_candidates=['other/file'])
    assert outside['hash_coverage']['gaps'][0]['reason_code'] == 'CANDIDATE_NOT_OBSERVED'


def test_current_reference_blocks_and_override_is_per_file_and_fingerprint(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/entry.md').write_text('[consumer](../old/run/data.bin)\n')
    blocked = impact(prof, req)
    assert blocked['status'] == 'Blocked'
    batch = blocked['batches'][0]
    assert not batch['eligible'] and batch['current_dependencies']
    assert 'consumer' not in str(batch['current_dependencies'])
    fingerprint = hashlib.sha256((tmp_path / 'refs/entry.md').read_bytes()).hexdigest()
    req['batches'][0]['historical_references'] = [{'path': 'refs/entry.md', 'sha256': fingerprint, 'reason': 'Root confirms closed replay-only entry'}]
    allowed = impact(prof, req)
    assert allowed['status'] == 'Passed' and allowed['batches'][0]['eligible']
    assert allowed['batches'][0]['historical_replay_requires_restore']
    assert allowed['material_sha256'] == impact(prof, req)['material_sha256']
    (tmp_path / 'refs/entry.md').write_text('old/run still active; changed\n')
    assert impact(prof, req)['status'] == 'Blocked'


def test_history_only_references_and_known_absent_keep_missing_status(tmp_path):
    prof, req = archive_fixture(tmp_path, references=[{'path': 'refs', 'role': 'historical'}])
    (tmp_path / 'refs/old.sh').write_text('cat old/run/data.bin\n')
    req['batches'][0]['known_absent'] = [{'path': 'missing.lock', 'reason': 'Previously absent, do not fabricate'}]
    result = impact(prof, req)
    assert result['status'] == 'Passed'
    batch = result['batches'][0]
    assert batch['known_absent'][0]['path'] == 'old/run/missing.lock'
    assert batch['known_absent'][0]['status'] == 'Missing'
    assert batch['historical_dependencies'] and not batch['current_dependencies']
    (tmp_path / 'old/run/missing.lock').write_bytes(b'new lock')
    assert impact(prof, req)['status'] == 'Blocked'


def test_dynamic_budget_encoding_and_missing_reference_scope_are_unknown(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/consumer.py').write_text('name = os.path.join(root, variable)\n')
    result = impact(prof, req)
    assert result['status'] == 'Unknown' and not result['batches'][0]['eligible']
    assert any(item['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN' for item in result['batches'][0]['unknowns'])
    limited = profile(tmp_path, reference_sources=[{'path': 'refs', 'role': 'current'}], classifications=prof.data['classifications'], archive=prof.data['archive'], budgets={'max_reference_bytes': 1})
    assert impact(limited, req)['status'] != 'Passed'
    (tmp_path / 'refs/consumer.py').write_bytes(b'\xff')
    assert impact(prof, req)['status'] == 'Unknown'


def test_keep_active_unclassified_and_closure_drift_never_auto_approve(tmp_path):
    prof, req = archive_fixture(tmp_path)
    classes = [{'path': 'old', 'role': 'keep', 'reason': 'must remain'}, {'path': 'old/run', 'role': 'historical', 'reason': 'claimed'}]
    keep = profile(tmp_path, reference_sources=prof.data['reference_sources'], classifications=classes, archive=prof.data['archive'])
    assert impact(keep, req)['status'] == 'Blocked'
    unknown = profile(tmp_path, reference_sources=prof.data['reference_sources'], archive=prof.data['archive'])
    assert impact(unknown, req)['status'] == 'Unknown'
    (tmp_path / 'refs/closure.md').write_text('changed closure evidence')
    result = impact(prof, req)
    assert result['status'] == 'Blocked'
    assert any(item['reason_code'] == 'SOURCE_CHANGED' for item in result['batches'][0]['blockers'])


def test_unauthorized_closure_and_protected_reference_are_not_read(tmp_path, monkeypatch):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'private.md').write_text('private closure evidence')
    req['batches'][0]['closure']['evidence'] = [{'path': 'private.md', 'sha256': '0' * 64}]
    original = dc.read_file
    paths = []
    def spy(root, rel, limit):
        paths.append(rel)
        assert rel != 'private.md'
        return original(root, rel, limit)
    monkeypatch.setattr(dc, 'read_file', spy)
    assert impact(prof, req)['status'] == 'Blocked'
    assert 'private.md' not in paths


def test_relative_script_paths_and_literal_prefix_boundaries(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/current.sh').write_text('cat ../old/run/data.bin\n')
    result = impact(prof, req)
    assert result['status'] == 'Blocked'
    assert any(hit['kind'] == 'relative-literal' for hit in result['batches'][0]['current_dependencies'])
    (tmp_path / 'refs/current.sh').write_text('cat old/run-other/file\n')
    assert impact(prof, req)['status'] == 'Passed'
    (tmp_path / 'refs/current.sh').write_text('path = "old/" + variable\n')
    assert impact(prof, req)['status'] == 'Unknown'


def test_historical_override_does_not_exempt_other_batch(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'old/second').mkdir()
    source = (tmp_path / 'refs/shared.md')
    source.write_text('old/run/data.bin and old/second/data.bin\n')
    data = deepcopy(prof.data)
    data['archive']['candidates'].append('old/second')
    data['classifications'].append({'path': 'old/second', 'role': 'historical', 'reason': 'explicit'})
    prof = dc.load_profile(tmp_path, prof.config, data)
    req['batches'].append({**deepcopy(req['batches'][0]), 'source': 'old/second', 'destination': 'closed/second'})
    req['batches'][0]['historical_references'] = [{'path': 'refs/shared.md', 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'reason': 'Only first batch approved historical'}]
    result = impact(prof, req)
    assert result['batches'][0]['eligible']
    assert result['batches'][1]['status'] == 'Blocked'


def test_permission_error_and_directory_change_are_unknown(tmp_path, monkeypatch):
    (tmp_path / 'data/blocked').mkdir(parents=True)
    (tmp_path / 'data/blocked/file').write_bytes(b'not zero')
    prof = profile(tmp_path, scan_roots=['data'])
    original = dc.open_dir
    from contextlib import contextmanager
    @contextmanager
    def deny(root, rel='.'):
        if rel == 'data/blocked':
            raise PermissionError('fixture denial')
        with original(root, rel) as fd:
            yield fd
    monkeypatch.setattr(dc, 'open_dir', deny)
    result = census(prof)
    assert result['status'] == 'Unknown' and result['coverage']['count_is_lower_bound']
    assert any(gap['reason_code'] == 'DIRECTORY_UNAVAILABLE' for gap in result['coverage']['gaps'])
    assert not result['top_directories'][0]['observed_bytes']
    assert result['top_directories'][0]['bytes_are_lower_bound']


def test_census_over_twenty_thousand_entries_is_metadata_only(tmp_path, monkeypatch):
    directory = tmp_path / 'many'
    directory.mkdir()
    count = 20017
    for index in range(count):
        fd = os.open(str(directory / str(index)), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    prof = profile(tmp_path, scan_roots=['many'])
    monkeypatch.setattr(dc, 'read_file', lambda *args, **kwargs: pytest.fail('census body read'))
    result = census(prof)
    assert result['status'] == 'Passed' and result['file_count'] == count
    assert result['directory_count'] == 1
    assert result['coverage']['work_entries'] == count + 2
    assert result['logical_bytes'] == 0  # Known empty regular files, not unexamined content.
    assert result['hash_coverage']['hash_entries'] == 0


def test_critical_body_scope_is_not_invented_or_read_to_force_pass(tmp_path, monkeypatch):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'README.md').write_text('unread current old/run entry')
    data = deepcopy(prof.data)
    data['critical_paths'] = ['README.md']
    prof = dc.load_profile(tmp_path, prof.config, data)
    original = dc.read_file
    def spy(root, rel, limit):
        assert rel != 'README.md'
        return original(root, rel, limit)
    monkeypatch.setattr(dc, 'read_file', spy)
    result = impact(prof, req)
    assert result['status'] == 'Unknown'
    assert any(item['reason_code'] == 'CRITICAL_REFERENCE_SCOPE_MISSING' for item in result['batches'][0]['unknowns'])


def test_file_uri_and_current_priority_over_overlapping_history(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/history').mkdir()
    (tmp_path / 'refs/history/consumer.md').write_text('[local](file://' + str(tmp_path / 'old/run/data.bin') + ')\n')
    data = deepcopy(prof.data)
    data['reference_sources'].append({'path': 'refs/history', 'role': 'historical'})
    prof = dc.load_profile(tmp_path, prof.config, data)
    result = impact(prof, req)
    assert result['status'] == 'Blocked'
    assert any(hit['kind'] in ('local-link', 'file-uri') for hit in result['batches'][0]['current_dependencies'])


def test_nonclosed_and_empty_evidence_are_blocked_not_automatic_success(tmp_path):
    prof, req = archive_fixture(tmp_path)
    req['batches'][0]['closure']['decision'] = 'pending'
    assert impact(prof, req)['status'] == 'Blocked'
    req['batches'][0]['closure']['decision'] = 'closed'
    req['batches'][0]['closure']['evidence'] = []
    assert impact(prof, req)['status'] == 'Blocked'
    req['batches'][0]['closure']['decision'] = True
    with pytest.raises(dc.DirectoryError):
        impact(prof, req)


def test_loaded_profile_root_replacement_is_rejected_before_body(tmp_path, monkeypatch):
    owner = tmp_path / 'project'
    owner.mkdir()
    prof, req = archive_fixture(owner)
    owner.rename(tmp_path / 'original')
    owner.mkdir()
    (owner / 'old/run').mkdir(parents=True)
    (owner / 'refs').mkdir()
    (owner / 'refs/closure.md').write_text('replacement must not be read')
    monkeypatch.setattr(dc, 'read_file', lambda *args, **kwargs: pytest.fail('replacement root body read'))
    for run in (lambda: census(prof), lambda: impact(prof, req)):
        with pytest.raises(dc.DirectoryError) as error:
            run()
        assert error.value.reason_code == 'SOURCE_CHANGED'


def test_reference_replacement_during_read_cannot_approve_archive(tmp_path, monkeypatch):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/consumer.md').write_text('nothing here\n')
    original = dc.read_file
    def replace_while_reading(root, rel, limit):
        raw = original(root, rel, limit)
        if rel == 'refs/consumer.md':
            temporary = tmp_path / 'replacement.md'
            temporary.write_text('current old/run/data.bin\n')
            os.replace(temporary, tmp_path / rel)
        return raw
    monkeypatch.setattr(dc, 'read_file', replace_while_reading)
    result = impact(prof, req)
    assert result['status'] != 'Passed'
    assert not result['batches'][0]['eligible']
    assert not result['coverage']['complete']


def _requires_real_alias(first, alias):
    try:
        same = first.samefile(alias)
    except FileNotFoundError:
        same = False
    if not same:
        pytest.skip('fixture filesystem does not expose this APFS-style alias')


def test_alias_protected_census_roots_never_hash_or_count_hidden_payload(tmp_path, monkeypatch):
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git/state').write_bytes(b'private')
    (tmp_path / '.env').write_bytes(b'private')
    (tmp_path / 'Library').mkdir()
    (tmp_path / 'Library/cache').write_bytes(b'private')
    _requires_real_alias(tmp_path / '.git', tmp_path / '.GIT')
    _requires_real_alias(tmp_path / '.env', tmp_path / '.ENV')
    _requires_real_alias(tmp_path / 'Library', tmp_path / 'library')
    prof = profile(tmp_path, scan_roots=['.GIT', '.ENV', 'library'])
    monkeypatch.setattr(dc, 'read_file', lambda *args, **kwargs: pytest.fail('protected alias body read'))
    monkeypatch.setattr(dc, 'stream_hash', lambda *args, **kwargs: pytest.fail('protected alias hash'))
    result = census(prof, hash_candidates=['.GIT/state', '.ENV', 'library/cache'])
    assert result['status'] == 'Unknown' and result['file_count'] == 0
    assert result['coverage']['excluded_entries'] == 3
    assert result['coverage']['count_is_lower_bound']


def test_unity_assets_alias_cannot_be_historically_approved(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'Assets').mkdir()
    (tmp_path / 'Assets/data').write_bytes(b'current asset')
    _requires_real_alias(tmp_path / 'Assets', tmp_path / 'assets')
    prof = profile(tmp_path, preset='unity', reference_sources=prof.data['reference_sources'],
                   classifications=[{'path': 'Assets', 'role': 'historical', 'reason': 'cannot override protected preset'}],
                   archive={'candidates': ['Assets']})
    req['batches'][0]['source'] = 'assets'
    result = impact(prof, req)
    assert result['status'] == 'Blocked' and not result['batches'][0]['eligible']
    assert any(item['reason_code'] == 'PROTECTED_PATH' for item in result['batches'][0]['blockers'])


def test_case_unicode_keep_descendant_beats_historical_parent(tmp_path):
    import unicodedata
    prof, req = archive_fixture(tmp_path)
    child = tmp_path / 'old/run/cafe\u0301'
    child.mkdir()
    (child / 'Keep.txt').write_bytes(b'active')
    declared_keep = unicodedata.normalize('NFC', 'OLD/RUN/CAFE\u0301/KEEP.TXT')
    _requires_real_alias(child / 'Keep.txt', tmp_path / declared_keep)
    data = deepcopy(prof.data)
    data['classifications'].append({'path': declared_keep, 'role': 'keep', 'reason': 'explicit keep wins'})
    prof = dc.load_profile(tmp_path, prof.config, data)
    result = impact(prof, req)
    assert result['status'] == 'Blocked'
    assert any(item['reason_code'] == 'CURRENT_OR_CRITICAL_PATH' for item in result['batches'][0]['blockers'])


def test_alias_current_literal_and_unicode_references_cannot_be_missed(tmp_path):
    import unicodedata
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/current.txt').write_text('use OLD/RUN/data.bin\n')
    assert impact(prof, req)['status'] == 'Blocked'
    unicode_dir = tmp_path / 'old/cafe\u0301'
    unicode_dir.mkdir()
    source = str(dc.safe_root(unicode_dir).relative_to(prof.root))
    data = deepcopy(prof.data)
    data['archive']['candidates'] = [source]
    data['classifications'] = [{'path': source, 'role': 'historical', 'reason': 'explicit'}]
    prof = dc.load_profile(tmp_path, prof.config, data)
    req['batches'][0]['source'] = source
    (tmp_path / 'refs/current.txt').write_text('use ' + unicodedata.normalize('NFC', source).upper() + '/file.bin\n')
    assert impact(prof, req)['status'] == 'Blocked'


def test_alias_scan_overlap_is_refused_and_hardlinked_root_declarations_not_inflated(tmp_path):
    (tmp_path / 'data/sub').mkdir(parents=True)
    (tmp_path / 'data/sub/file').write_bytes(b'payload')
    _requires_real_alias(tmp_path / 'data/sub', tmp_path / 'DATA/sub')
    prof = profile(tmp_path, scan_roots=['data', 'DATA/sub'])
    with pytest.raises(dc.DirectoryError):
        census(prof)
    os.link(tmp_path / 'data/sub/file', tmp_path / 'data/alias-file')
    prof = profile(tmp_path, scan_roots=['data/sub/file', 'data/alias-file'])
    result = census(prof)
    assert result['status'] == 'Unknown'
    assert result['file_count'] == 1 and result['logical_bytes'] == len(b'payload')
    assert any(item['reason_code'] == 'DUPLICATE_SOURCE_IDENTITY' for item in result['coverage']['gaps'])


@pytest.mark.parametrize('field', ['source', 'destination'])
def test_alias_batch_overlap_rejected_before_reference_reads(tmp_path, monkeypatch, field):
    prof, req = archive_fixture(tmp_path)
    second = deepcopy(req['batches'][0])
    second.update(source='old/second', destination='closed/second')
    second[field] = ('OLD/RUN/sub' if field == 'source' else 'CLOSED/RUN/sub')
    req['batches'].append(second)
    monkeypatch.setattr(dc, 'read_file', lambda *args, **kwargs: pytest.fail('overlap body read'))
    with pytest.raises(dc.DirectoryError) as error:
        impact(prof, req)
    assert error.value.reason_code == 'PROFILE_CONFLICT'


def test_alias_history_override_never_exempts_current_native_file(tmp_path):
    prof, req = archive_fixture(tmp_path)
    path = tmp_path / 'refs/current.txt'
    path.write_text('old/run/data.bin\n')
    _requires_real_alias(path, tmp_path / 'REFS/CURRENT.TXT')
    req['batches'][0]['historical_references'] = [{'path': 'REFS/CURRENT.TXT', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'reason': 'alias cannot grant broader scope'}]
    result = impact(prof, req)
    assert result['status'] == 'Blocked' and result['batches'][0]['current_dependencies']
    assert not result['batches'][0]['eligible']


def test_folded_historical_or_reference_grant_cannot_widen_native_authorization(tmp_path, monkeypatch):
    prof, req = archive_fixture(tmp_path)
    data = deepcopy(prof.data)
    data['classifications'] = [{'path': 'OLD/RUN', 'role': 'historical', 'reason': 'non-native grant is not inferred'}]
    candidate = dc.load_profile(tmp_path, prof.config, data)
    assert impact(candidate, req)['status'] == 'Unknown'
    data['classifications'] = prof.data['classifications']
    data['reference_sources'] = [{'path': 'REFS', 'role': 'historical'}]
    candidate = dc.load_profile(tmp_path, prof.config, data)
    monkeypatch.setattr(dc, 'read_file', lambda *args, **kwargs: pytest.fail('folded reference grant body read'))
    result = impact(candidate, req)
    assert result['status'] != 'Passed' and not result['batches'][0]['eligible']


def test_declared_current_original_inside_candidate_blocks_without_self_reference(tmp_path):
    prof, req = archive_fixture(tmp_path, references=[{'path': 'old/run/current.txt', 'role': 'current'}, {'path': 'refs', 'role': 'historical'}])
    (tmp_path / 'old/run/current.txt').write_bytes(b'\n')
    assert prof.data['critical_paths'] == []
    result = impact(prof, req)
    batch = result['batches'][0]
    assert result['status'] == 'Blocked' and not batch['eligible']
    assert batch['current_dependencies'] == []  # Gate is the declaration, not a text hit.
    assert any(item['reason_code'] == 'CURRENT_REFERENCE_SOURCE' for item in batch['blockers'])
    assert [item['role'] for item in batch['reference_fingerprints'] if item['path'] == 'old/run/current.txt'] == ['current']
    data = deepcopy(prof.data)
    data['reference_sources'][0]['role'] = 'historical'  # Explicit profile change, not inferred from text.
    historical = dc.load_profile(tmp_path, prof.config, data)
    assert historical.sha256 != prof.sha256
    assert impact(historical, req)['status'] == 'Passed'


@pytest.mark.parametrize('declaration', ['old/run/current.txt', 'old/run', 'old'])
def test_historical_reference_override_cannot_move_declared_current_original(tmp_path, declaration):
    prof, req = archive_fixture(tmp_path, references=[{'path': declaration, 'role': 'current'}, {'path': 'refs', 'role': 'historical'}])
    current = tmp_path / 'old/run/current.txt'
    current.write_bytes(b'\n')
    req['batches'][0]['historical_references'] = [{'path': 'old/run/current.txt', 'sha256': hashlib.sha256(current.read_bytes()).hexdigest(), 'reason': 'Only reference interpretation is historical'}]
    result = impact(prof, req)
    batch = result['batches'][0]
    assert result['status'] == 'Blocked' and not batch['eligible']
    assert any(item['reason_code'] == 'CURRENT_REFERENCE_SOURCE' for item in batch['blockers'])
    assert [item['role'] for item in batch['reference_fingerprints'] if item['path'] == 'old/run/current.txt'] == ['historical']


@pytest.mark.parametrize('text', [
    'path = "../old/Caf%C3%A9.app/file.bin"\n',
    'path = "old\\CAFE\u0301.APP\\file.bin"\n',
    'path = "old/CAFÉ.APP/file.bin"\n',
    '[old payload](../old/Caf%C3%A9.app/file.bin)\n',
])
def test_candidate_component_filter_preserves_encoded_unicode_case_and_windows_paths(tmp_path, text):
    from fifan_maintenance import directory_census as ci
    (tmp_path / 'refs').mkdir()
    (tmp_path / 'refs/source.md').write_text(text)
    prof = profile(tmp_path, reference_sources=[{'path': 'refs/source.md', 'role': 'current'}])
    reader = ci._References(prof, ('old/Café.app',))
    reader.load_all()
    found, unknown = ci._references_to(reader, 'refs/source.md', 'old/Café.app')
    assert found and not unknown


def test_component_filter_keeps_inside_relative_consumers_and_all_dynamic_expressions(tmp_path):
    from fifan_maintenance import directory_census as ci
    (tmp_path / 'old/run').mkdir(parents=True)
    (tmp_path / 'old/run/source.txt').write_text('"data.bin"\nvalue = Path.Combine(root, leaf)\n')
    prof = profile(tmp_path, reference_sources=[{'path': 'old/run/source.txt', 'role': 'historical'}])
    reader = ci._References(prof, ('old/run', 'unrelated/candidate'))
    reader.load_all()
    found, unknown = ci._references_to(reader, 'old/run/source.txt', 'old/run')
    assert any(item['line'] == 1 for item in found)
    assert len(unknown) == 1 and unknown[0]['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN'
    outside_found, outside_unknown = ci._references_to(reader, 'old/run/source.txt', 'unrelated/candidate')
    assert not outside_found
    assert outside_unknown == unknown


def test_component_filter_avoids_deep_path_work_for_unrelated_log_lines(tmp_path, monkeypatch):
    from fifan_maintenance import directory_census as ci
    (tmp_path / 'unrelated.log').write_text('Compiler: /some/unrelated/object.cpp: invalid /path/to/setting\n' * 1000)
    prof = profile(tmp_path, reference_sources=[{'path': 'unrelated.log', 'role': 'historical'}])
    def forbidden(*args, **kwargs):
        pytest.fail('unrelated complete components must not enter deep path normalization')
    monkeypatch.setattr(ci, '_reference_keys', forbidden)
    reader = ci._References(prof, ('old/closed.app',))
    reader.load_all()
    assert reader.coverage()['complete']
    assert ci._references_to(reader, 'unrelated.log', 'old/closed.app') == ([], [])


@pytest.mark.parametrize('encoded', [r'old/\u0072un/data.bin', r'old\/run\/data.bin', 'old/run/data.bin'])
def test_json_decoded_current_reference_blocks_archive(tmp_path, encoded):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/current.json').write_text('{"path":"' + encoded + '"}')
    result = impact(prof, req)
    assert result['status'] == 'Blocked'
    assert not result['batches'][0]['eligible']
    assert result['batches'][0]['current_dependencies']


def test_invalid_json_references_remain_unknown(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/current.json').write_text('{"path":"other/file", broken}')
    result = impact(prof, req)
    assert result['status'] == 'Unknown'
    assert not result['batches'][0]['eligible']
    assert result['batches'][0]['unknowns']


def test_json_escaped_dynamic_reference_cannot_be_declared_absent(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/current.json').write_text(r'{"path":"\u0024{ROOT}/run/data.bin"}')
    result = impact(prof, req)
    assert result['status'] == 'Unknown'
    assert not result['batches'][0]['eligible']
    assert any(x['reason_code'] == 'REFERENCE_SYNTAX_UNKNOWN' for x in result['batches'][0]['unknowns'])


@pytest.mark.parametrize('encoded', [r'cat old/\u0072un/data.bin', 'cat old/run/data.bin'])
def test_json_embedded_command_uses_decoded_static_scanner(tmp_path, encoded):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/current.json').write_text('{"command":"' + encoded + '"}')
    result = impact(prof, req)
    assert result['status'] == 'Blocked'
    assert result['batches'][0]['current_dependencies']
    assert not result['batches'][0]['eligible']


def test_json_mixed_dynamic_keeps_each_unmapped_expression_unknown(tmp_path):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'refs/current.json').write_text(r'{"command":"echo ${MESSAGE}; cat \u0024{ROOT}/data.bin"}')
    initial = impact(prof, req)
    raw = next(x for x in initial['batches'][0]['unknowns'] if x['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN')
    resolution = {k: v for k, v in raw.items() if k != 'reason_code'}
    resolution.update(source='old/run', reason='Explicitly reviewed only the raw MESSAGE expression',
                      evidence=deepcopy(req['batches'][0]['closure']['evidence']))
    req['batches'][0]['dynamic_reference_resolutions'] = [resolution]
    result = impact(prof, req)
    assert result['status'] == 'Unknown'
    assert not result['batches'][0]['eligible']
    assert not any(x['reason_code'] == 'DYNAMIC_REFERENCE_UNKNOWN' for x in result['batches'][0]['unknowns'])
    assert any(x['reason_code'] == 'REFERENCE_SYNTAX_UNKNOWN' for x in result['batches'][0]['unknowns'])


@pytest.mark.parametrize('encoded', [r'../old/my \u0072un/data.bin', '../old/my run/data.bin'])
def test_json_whole_relative_path_with_spaces_keeps_string_boundary(tmp_path, encoded):
    prof, req = archive_fixture(tmp_path)
    (tmp_path / 'old/run').rename(tmp_path / 'old/my run')
    data = deepcopy(prof.data)
    data['classifications'][0]['path'] = 'old/my run'
    data['archive']['candidates'] = ['old/my run']
    prof = dc.load_profile(tmp_path, prof.config, data)
    req['batches'][0]['source'] = 'old/my run'
    (tmp_path / 'refs/current.json').write_text('{"path":"' + encoded + '"}')
    result = impact(prof, req)
    assert result['status'] == 'Blocked'
    assert not result['batches'][0]['eligible']
    assert result['batches'][0]['current_dependencies']


@pytest.mark.parametrize('source', ['old/run', 'old/my run', 'old/Café', 'old/目录 名'])
@pytest.mark.parametrize('style', ['relative', 'absolute', 'embedded'])
def test_json_reference_encoding_preserves_dependency_decision(tmp_path, source, style):
    import json
    prof, req = archive_fixture(tmp_path)
    if source != 'old/run':
        (tmp_path / 'old/run').rename(tmp_path / source)
    data = deepcopy(prof.data)
    data['classifications'][0]['path'] = source
    data['archive']['candidates'] = [source]
    prof = dc.load_profile(tmp_path, prof.config, data)
    req['batches'][0]['source'] = source
    target = '../' + source + '/data.bin'
    if style == 'absolute':
        target = str(tmp_path / source / 'data.bin')
    elif style == 'embedded':
        target = "cat '" + target + "'"
    plain = json.dumps({'value': target}, ensure_ascii=False)
    escaped = json.dumps({'value': target}, ensure_ascii=True).replace('run', r'\u0072un')
    for serialized in (plain, escaped):
        (tmp_path / 'refs/current.json').write_text(serialized)
        result = impact(prof, req)
        assert result['status'] == 'Blocked', (source, style, serialized, result)
        assert result['batches'][0]['current_dependencies']
        assert not result['batches'][0]['eligible']
