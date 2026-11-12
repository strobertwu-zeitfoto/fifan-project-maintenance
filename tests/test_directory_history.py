"""Real typed directory artifacts are declarations, never implicit ARC grants."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from fifan_maintenance import changes
from fifan_maintenance import directory_archive as archive
from fifan_maintenance import directory_census as census
from fifan_maintenance import directory_common as dc
from fifan_maintenance import directory_metrics as metrics
from fifan_maintenance import search_view as search
from fifan_maintenance import sessions
from fifan_maintenance.project import load_config


@pytest.fixture
def materials(tmp_path):
    root, arc, rec = [tmp_path / name for name in ('project', 'archive', 'records')]
    for path in (root, arc, rec):
        path.mkdir()
    (root / 'history/run/empty').mkdir(parents=True)
    secret = b'token=NEVER_PRINT_ARCHIVE_BODY\x00\xff'
    (root / 'history/run/old.bin').write_bytes(secret)
    (root / 'README.md').write_text('Current entry remains here\n')
    decision = b'Explicit approved closed fixture\n'
    (root / 'closure.md').write_bytes(decision)
    (root / '.vscode').mkdir()
    (root / '.vscode/settings.json').write_bytes(b'{/* password=NEVER_PRINT_CONFIG */}\n')
    profile = dc.load_profile(root, load_config(root), {
        'schema_version': 1, 'project_root': str(root), 'scan_roots': ['.'],
        'critical_paths': ['README.md'],
        'reference_sources': [{'path': 'README.md', 'role': 'current'}, {'path': 'closure.md', 'role': 'historical'}],
        'classifications': [{'path': 'history/run', 'role': 'historical', 'reason': 'explicit approved fixture'}],
        'search': {'exclude': ['history'], 'vscode': True},
        'archive': {'archive_root': str(arc), 'records_dir': str(rec), 'candidates': ['history/run'],
                    'require_no_open_handles': False},
    })
    request = {'schema_version': 1, 'batches': [{'source': 'history/run', 'destination': 'closed/run',
        'closure': {'decision': 'closed', 'reason': 'NEVER_PRINT_CLOSURE_REASON',
                    'evidence': [{'path': 'closure.md', 'sha256': hashlib.sha256(decision).hexdigest()}]}}]}
    values = {}
    def save(name, data):
        dc.write_artifact(rec / (name + '.json'), data)
        values[name] = data
        return data
    save('census', census.census(profile))
    save('impact', census.impact(profile, request))
    plan = save('search-plan', search.search_preview(profile))
    search_record = search.apply(profile, plan, rec)
    values['search-journal'] = search_record
    save('search-verify', search.verify(profile, search_record))
    save('search-restore-plan', search.restore_preview(profile, search_record))
    before = save('metrics-before', metrics.measure(profile, request, arc, rec))
    plan = save('archive-plan', archive.archive_preview(profile, request, arc, rec))
    archive_record = archive.apply(profile, plan, arc, rec)
    values['archive-journal'] = archive_record
    save('archive-verify', archive.verify(profile, archive_record, arc))
    save('archive-restore-plan', archive.restore_preview(profile, archive_record, arc))
    after = save('metrics-after', metrics.measure(profile, request, arc, rec))
    save('metrics-evaluation', metrics.evaluate(before, after))
    return profile, request, arc, rec, values, secret


def test_real_search_archive_and_report_history_is_metadata_only(materials, tmp_path, monkeypatch):
    profile, _, arc, rec, values, secret = materials
    # History must still work when the declared ARC cannot be opened. This is
    # an intentional fixture move, not a grant for history to follow payload.
    moved_arc = tmp_path / 'retained-archive'
    os.rename(arc, moved_arc)
    original_read = changes._read
    read_paths = []
    def records_only(root, rel, config):
        assert Path(root) == rec, 'history attempted a project/payload body read'
        read_paths.append(rel)
        return original_read(root, rel, config)
    monkeypatch.setattr(changes, '_read', records_only)
    def forbidden(*args, **kwargs):
        pytest.fail('history must not verify or open an undeclared archive root')
    monkeypatch.setattr(archive, 'verify', forbidden)
    monkeypatch.setattr(metrics, 'measure', forbidden)
    monkeypatch.setattr(dc, 'external_roots', forbidden)
    before = {p.name: p.read_bytes() for p in rec.iterdir()}
    result = sessions.history(profile.root, profile.config, [rec])
    by_name = {Path(item['path']).stem: item for item in result['records']}
    assert by_name['archive-plan']['operation_kind'] == 'directory-archive'
    assert by_name['archive-plan']['files'][0]['path'] == 'history/run'
    assert by_name['archive-plan']['files'][0]['destination'] == 'closed/run'
    assert by_name[values['archive-journal']['operation_id'] + '.directory']['recorded_state'] == 'Archived'
    assert by_name[values['search-journal']['operation_id'] + '.directory']['recorded_state'] == 'Applied'
    assert by_name['census']['files'][0]['path'] == '.'
    assert by_name['census']['files'][0]['treatment'] == 'metadata_check_only'
    assert by_name['impact']['files'][0]['treatment'] == 'impact_check_only'
    assert by_name['metrics-before']['files'][0]['treatment'] == 'metadata_measurement_only'
    assert by_name['metrics-after']['source_scope'] == 'Declared'
    assert by_name['metrics-evaluation']['files'] is None
    assert by_name['metrics-evaluation']['source_scope'] == 'Unknown'
    assert by_name['search-verify']['recorded_status'] == 'Passed'
    assert by_name['search-verify']['verification'] == 'Not run'
    assert all(item['verification'] == 'Not run' and item['applied_rewrite'] is False for item in result['records'])
    assert all(item['status'] != 'Passed' for item in result['records'])
    assert result['coverage']['unbound_directory_materials'] == 1  # archive.verify has no root binding
    assert result['status'] == 'Unknown'
    output = json.dumps(result)
    assert 'NEVER_PRINT_' not in output and 'base64' not in output and 'locator_text' not in output
    assert {p.name: p.read_bytes() for p in rec.iterdir()} == before
    assert (moved_arc / 'closed/run/old.bin').read_bytes() == secret
    assert read_paths


@pytest.mark.parametrize('name', ['search-journal', 'archive-journal'])
def test_old_session_explicitly_rejects_real_new_journals(materials, tmp_path, monkeypatch, name):
    profile, _, _, rec, values, _ = materials
    manifest = tmp_path / ('session-' + name + '.json')
    dc.write_artifact(manifest, {'schema_version': 1, 'root': str(profile.root),
                                'journals': [values[name]['journal_path']]})
    before = {p.name: p.read_bytes() for p in rec.iterdir()}
    def forbidden(*args, **kwargs):
        pytest.fail('new journal was passed to the legacy operation engine')
    monkeypatch.setattr(changes, '_validate_record', forbidden)
    monkeypatch.setattr(changes, '_recover', forbidden)
    for action in (sessions.report, sessions.verify, sessions.recovery_preview):
        with pytest.raises(ValueError) as error:
            action(profile.root, profile.config, manifest)
        assert error.value.reason_code == 'DIRECTORY_FORMAT_UNSUPPORTED'
    with pytest.raises(ValueError) as error:
        sessions.recover(profile.root, profile.config, manifest, {})
    assert error.value.reason_code == 'DIRECTORY_FORMAT_UNSUPPORTED'
    assert {p.name: p.read_bytes() for p in rec.iterdir()} == before


def test_foreign_project_root_is_skipped_but_conflicting_bindings_are_unknown(materials):
    profile, _, _, rec, values, _ = materials
    foreign = copy.deepcopy(values['archive-plan'])
    foreign['project_root'] = '/different-project'
    foreign['batches'][0]['source'] = 'NEVER_PRINT_FOREIGN_SOURCE'
    dc.write_artifact(rec / 'foreign-plan.json', dc.seal(foreign))
    conflict = copy.deepcopy(values['archive-journal'])
    conflict['root'] = str(profile.root)
    conflict['plan']['project_root'] = '/different-project'
    conflict['plan'] = dc.seal(conflict['plan'])
    dc.write_artifact(rec / 'conflict.json', dc.seal(conflict))
    value = sessions.history(profile.root, profile.config, [rec])
    assert not any(item['path'].endswith('foreign-plan.json') for item in value['records'])
    item = next(item for item in value['records'] if item['path'].endswith('conflict.json'))
    assert item['status'] == 'Unknown' and item['files'] is None
    assert 'NEVER_PRINT_FOREIGN_SOURCE' not in json.dumps(value)


def test_bad_current_project_reports_are_unknown_not_silent_zero(materials):
    profile, _, _, rec, values, _ = materials
    broken = copy.deepcopy(values['census'])
    broken['file_count'] += 1  # Invalid seal, still explicitly current project.
    dc.write_artifact(rec / 'bad-census.json', broken)
    metric = copy.deepcopy(values['metrics-before'])
    metric['cohort']['batches'][0]['source'] = 'changed-without-cohort-sha'
    dc.write_artifact(rec / 'bad-metrics.json', metric)
    wrong_root = copy.deepcopy(values['metrics-before'])
    wrong_root['cohort']['roots']['project']['path'] = '/different-project'
    wrong_root['cohort_sha256'] = dc.digest(wrong_root['cohort'])
    dc.write_artifact(rec / 'conflicting-metrics-root.json', wrong_root)
    result = sessions.history(profile.root, profile.config, [rec])
    assert result['status'] == 'Unknown'
    for name in ('bad-census.json', 'bad-metrics.json', 'conflicting-metrics-root.json'):
        item = next(item for item in result['records'] if item['path'].endswith(name))
        assert item['status'] == 'Unknown' and item['source_scope'] == 'Unknown'
        assert item['files'] is None
