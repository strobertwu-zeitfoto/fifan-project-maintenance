"""The Python 3.15 runtime is protected without changing old config hashes."""
import copy
from pathlib import Path

import pytest

from fifan_maintenance import changes as c, inventory
from fifan_maintenance import cleanup_policy as cp, cleanup_operations as co
from fifan_maintenance import directory_archive as da, directory_common as dc
from fifan_maintenance.models import Context
from fifan_maintenance.project import DEFAULT_CONFIG, fingerprint, load_config
from fifan_maintenance.reading import read_document

PATHS = ['.venv315', '.venv315/private.md', '.VENV315/private.md',
         'nested/.venv315/private.md', 'nested/.VeNv315/private.md']


@pytest.mark.parametrize('rel', PATHS)
def test_runtime_read_and_old_write_reject_before_body_io(tmp_path, monkeypatch, rel):
    config = copy.deepcopy(DEFAULT_CONFIG)
    config['exclude'] = config['protected'] = []
    original = copy.deepcopy(config)
    assert inventory.excluded(rel, config)
    def forbidden(*args, **kwargs):
        raise AssertionError('protected body IO attempted')
    import fifan_maintenance.project as project
    monkeypatch.setattr(project, 'read_bytes', forbidden)
    monkeypatch.setattr(c, '_read', forbidden)
    with pytest.raises(ValueError, match='protected'):
        Context(tmp_path, {}, config).read_bytes(rel)
    with pytest.raises(ValueError, match='protected'):
        read_document(tmp_path, config, rel)
    for version in (1, 2, 3):
        req = {'operations': [{'type': 'replace', 'path': rel, 'old': 'before', 'new': 'after'}]}
        if version != 1:
            req['version'] = version
        with pytest.raises(ValueError, match='protected'):
            c.preview(tmp_path, req, config)
    assert config == original


def test_inventory_never_reads_runtime_bodies_but_keeps_similar_names(tmp_path, monkeypatch):
    for folder in ['.venv315', 'nested/.VENV315', '.venv315-not-env']:
        (tmp_path / folder).mkdir(parents=True)
        (tmp_path / folder / 'private.md').write_text('before')
    cfg = load_config(tmp_path)
    ctx = Context(tmp_path, {}, cfg, inventory=True)
    reads = []
    original = ctx.read_bytes
    def observed(rel):
        assert '.venv315' not in inventory.protection_key(rel).split('/')
        reads.append(rel)
        return original(rel)
    monkeypatch.setattr(ctx, 'read_bytes', observed)
    inventory.collect(ctx)
    assert set(ctx.files) == {'.venv315-not-env/private.md'}
    assert reads == ['.venv315-not-env/private.md']
    assert '.venv315' in inventory.ALWAYS_EXCLUDED
    selected = Context(tmp_path, {}, {**cfg, '_task': {'sources': ['nested/.VENV315/private.md']}})
    findings = inventory.collect(selected)
    assert not selected.files and findings[0].status == 'Unknown'


def profiles(root, outside, source):
    cfg = load_config(root)
    archive, quarantine, records = [outside / name for name in ['archive', 'quarantine', 'records']]
    for path in (archive, quarantine, records):
        path.mkdir()
    directory = dc.load_profile(root, cfg, {'schema_version': 1, 'project_root': str(root),
        'scan_roots': ['.'], 'critical_paths': [], 'reference_sources': [{'path': 'closed.md', 'role': 'historical'}],
        'classifications': [{'path': source, 'role': 'historical', 'reason': 'closed synthetic fixture'}],
        'archive': {'archive_root': str(archive), 'records_dir': str(records), 'candidates': [source], 'require_no_open_handles': False}})
    cleanup = cp.load_profile(root, cfg, {'schema_version': 1, 'project_root': str(root),
        'scan_roots': ['.'], 'current': [], 'keep': [], 'protected': [],
        'reference_sources': [{'path': 'closed.md', 'role': 'historical'}],
        'candidates': [{'path': source, 'kind': 'completed_log'}],
        'quarantine_root': str(quarantine), 'records_dir': str(records), 'require_no_open_handles': False})
    return directory, cleanup, archive, quarantine, records


@pytest.mark.parametrize('source', ['.venv315', '.VENV315', 'nested/.VeNv315'])
def test_directory_and_cleanup_refuse_runtime_without_body_reads_or_moves(tmp_path, monkeypatch, source):
    root = tmp_path / 'project'; root.mkdir()
    (root / source).mkdir(parents=True)
    body = root / source / 'private.md'; body.write_text('before')
    proof = root / 'closed.md'; proof.write_text('closed fixture')
    before = body.stat().st_ino, body.read_bytes(), (root / source).stat().st_ino
    directory, cleanup, archive, quarantine, records = profiles(root, tmp_path, source)
    assert dc.protected(directory, source, archive=True)
    assert cp.protected(cleanup, source)
    assert dc.protected(directory, source + "/private.md", archive=True)
    assert cp.protected(cleanup, source + "/private.md")
    assert not dc.protected(directory, ".venv315-not-env", archive=True)
    assert not cp.protected(cleanup, ".venv315-not-env")
    original_read, original_hash = dc.read_file, dc.stream_hash
    reads = []
    def observed_read(owner, rel, *args, **kwargs):
        assert '.venv315' not in inventory.protection_key(rel).split('/')
        reads.append(rel)
        return original_read(owner, rel, *args, **kwargs)
    def observed_hash(profile, rel, *args, **kwargs):
        assert '.venv315' not in inventory.protection_key(rel).split('/')
        reads.append(rel)
        return original_hash(profile, rel, *args, **kwargs)
    monkeypatch.setattr(dc, 'read_file', observed_read)
    monkeypatch.setattr(dc, 'stream_hash', observed_hash)
    closure = {'decision': 'closed', 'reason': 'closed fixture', 'evidence': [{'path': 'closed.md', 'sha256': c._hash(proof.read_bytes())}]}
    request = {'schema_version': 1, 'batches': [{'source': source, 'destination': 'fixture/runtime', 'closure': closure}]}
    with pytest.raises(dc.DirectoryError):
        da.archive_preview(directory, request, archive, records)
    req = {'schema_version': 1, 'approval': {'reference': 'synthetic explicit batch', 'actions': ['quarantine']},
           'items': [{'source': source, 'kind': 'completed_log', 'reason': 'closed fixture', 'closure': closure,
                      'retained': [], 'loss': {'accepted': False, 'rebuildable': 'Unknown', 'unique_evidence': False, 'description': 'synthetic'}}]}
    qualification = cp.qualify(cleanup, req)
    assert qualification['items'][0]['eligible'] is False
    assert {'reason_code': 'CURRENT_KEEP_OR_PROTECTED'} in qualification['items'][0]['blockers']
    with pytest.raises(dc.DirectoryError):
        co.preview(cleanup, req, quarantine, records)
    assert (body.stat().st_ino, body.read_bytes(), (root / source).stat().st_ino) == before
    assert not list(archive.iterdir()) and not list(quarantine.iterdir()) and not list(records.iterdir())


def test_similar_name_roundtrip_and_config_fingerprint_remains_compatible(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    folder = root / '.venv315-not-env'; folder.mkdir()
    body = folder / 'private.md'; body.write_text('before')
    cfg = load_config(root)
    # Recorded before this protection patch; changing DEFAULT_CONFIG breaks it.
    assert fingerprint(DEFAULT_CONFIG) == '2f9242aaea93344e1d9b7a80d14b1fc999797f98785b691869ea1892203aacc1'
    original = copy.deepcopy(cfg)
    path = '.venv315-not-env/private.md'
    assert not inventory.excluded(path, cfg)
    assert read_document(root, cfg, path)['content'] == 'before'
    rec = c.apply(root, c.preview(root, {'operations': [{'type': 'replace', 'path': path, 'old': 'before', 'new': 'after'}]}, cfg), cfg, tmp_path / 'records')
    (root / '.venv315').mkdir()
    assert c.verify(root, rec, load_config(root))['status'] == 'Passed'
    restored = c.recover(root, Path(rec['journal_path']), load_config(root))
    assert c.verify(root, restored, cfg)['status'] == 'Passed' and body.read_text() == 'before'
    assert cfg == original


@pytest.mark.parametrize('version', [1, 2, 3])
def test_runtime_destinations_reject_without_changing_source(tmp_path, version):
    (tmp_path / 'safe.md').write_text('before')
    cfg = load_config(tmp_path)
    for destination in ['.venv315/new.md', 'nested/.VENV315/new.md']:
        operations = [{'type': 'move', 'path': 'safe.md', 'destination': destination}]
        if version == 2:
            operations += [{'kind': 'snapshot', 'path': 'safe.md', 'destination': destination,
                            'expected_sha256': c._hash(b'before'),
                            'origin': {'reference_base': '.', 'classification_basis': 'synthetic snapshot'}}]
        for operation in operations:
            req = {'operations': [operation]}
            if version != 1:
                req['version'] = version
            with pytest.raises(ValueError, match='protected'):
                c.preview(tmp_path, req, cfg)
        assert (tmp_path / 'safe.md').read_text() == 'before'
        assert not (tmp_path / '.venv315').exists() and not (tmp_path / 'nested').exists()


def test_v3_many_rejects_runtime_before_body_read(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('protected body read')
    monkeypatch.setattr(c, '_read', forbidden)
    req = {'version': 3, 'operations': [{'type': 'replace_many', 'path': 'nested/.VENV315/private.md',
                                      'patches': [{'old': 'before', 'new': 'after'}]}]}
    with pytest.raises(ValueError, match='protected'):
        c.preview(tmp_path, req, load_config(tmp_path))
