#!/usr/bin/env python3
"""Offline patch-upgrade probe on an explicitly named, synthetic workspace.

Run prepare with the installed 1.4.0 wheel; upgrade that same environment, then
run verify with 1.4.1. No business paths, network or target commands are used.
The workspace must be new on prepare. Existing fixtures are never overwritten.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

from fifan_maintenance import __version__, changes, sessions
from fifan_maintenance import directory_common as dc, directory_archive as da, search_view
from fifan_maintenance import cleanup_policy as cp, cleanup_operations as co
from fifan_maintenance.project import load_config


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def prepare(base, expected_version='1.4.0'):
    if __version__ != expected_version:
        raise ValueError('prepare requires installed version ' + expected_version)
    base.mkdir(parents=True, exist_ok=False)
    root, arc, rec, quarantine = [base / n for n in ('project', 'archive', 'records', 'quarantine')]
    for p in (root, arc, rec, quarantine):
        p.mkdir()
    (root / 'current').mkdir()
    (root / 'current/README.md').write_text('# Current\n')
    (root / 'notes.md').write_text('one')
    (root / 'history/run').mkdir(parents=True)
    (root / 'history/run/data.bin').write_bytes(b'original archive\x00')
    (root / 'old.log').write_text('completed synthetic log')
    (root / 'closed.md').write_text('closed synthetic evidence')
    cfg = load_config(root)
    evidence = [{'path': 'closed.md', 'sha256': hashlib.sha256((root / 'closed.md').read_bytes()).hexdigest()}]
    closure = {'decision': 'closed', 'reason': 'synthetic patch upgrade', 'evidence': evidence}
    file_plan = changes.preview(root, {'operations': [{'type': 'replace', 'path': 'notes.md', 'old': 'one', 'new': 'two'}]}, cfg)
    file_record = changes.apply(root, file_plan, cfg, rec)
    session_path = base / 'session.json'
    save(session_path, {'schema_version': 1, 'root': str(root), 'journals': [file_record['journal_path']]})
    directory_data = {'schema_version': 1, 'project_root': str(root),
        'reference_sources': [{'path': 'current', 'role': 'current'}, {'path': 'closed.md', 'role': 'historical'}],
        'critical_paths': ['current/README.md'],
        'classifications': [{'path': 'history/run', 'role': 'historical', 'reason': 'closed synthetic'}],
        'search': {'exclude': ['history'], 'vscode': False},
        'archive': {'archive_root': str(arc), 'records_dir': str(rec), 'candidates': ['history/run'], 'require_no_open_handles': False}}
    save(base / 'directory-profile.json', directory_data)
    directory = dc.load_profile(root, cfg, directory_data)
    archive_plan = da.archive_preview(directory, {'schema_version': 1, 'batches': [
        {'source': 'history/run', 'destination': 'saved/run', 'closure': closure}]}, arc, rec)
    archive_record = da.apply(directory, archive_plan, arc, rec)
    search_record = search_view.apply(directory, search_view.search_preview(directory), rec)
    cleanup_data = {'schema_version': 1, 'project_root': str(root), 'current': ['current'],
        'candidates': [{'path': 'old.log', 'kind': 'completed_log'}],
        'reference_sources': [{'path': 'current', 'role': 'current'}, {'path': 'closed.md', 'role': 'historical'}],
        'quarantine_root': str(quarantine), 'records_dir': str(rec), 'require_no_open_handles': False}
    save(base / 'cleanup-profile.json', cleanup_data)
    cleanup = cp.load_profile(root, cfg, cleanup_data)
    request = {'schema_version': 1, 'approval': {'reference': 'synthetic fixture', 'actions': ['quarantine']},
        'items': [{'source': 'old.log', 'kind': 'completed_log', 'reason': 'synthetic fixture', 'closure': closure,
                   'loss': {'accepted': False, 'rebuildable': 'Unknown', 'unique_evidence': False, 'description': 'recoverable isolation'}, 'retained': []}]}
    save(base / 'cleanup-request.json', request)
    cleanup_plan = co.preview(cleanup, request, quarantine, rec)
    save(base / 'cleanup-plan.json', cleanup_plan)
    cleanup_record = co.apply(cleanup, cleanup_plan, quarantine, rec, approve_plan=cleanup_plan['fingerprint'])
    index = {'producer': __version__, 'file_journal': file_record['journal_path'],
        'directory_journal': archive_record['journal_path'], 'search_journal': search_record['journal_path'],
        'cleanup_journal': cleanup_record['journal_path']}
    save(base / 'index.json', index)
    return {'status': 'Passed', 'phase': 'prepare', 'version': __version__, 'records': 4}


def verify(base, expected_version='1.4.1'):
    if __version__ != expected_version:
        raise ValueError('verify requires installed version ' + expected_version)
    root, arc, rec, quarantine = [base / n for n in ('project', 'archive', 'records', 'quarantine')]
    cfg = load_config(root)
    index = json.loads((base / 'index.json').read_text())
    for key in ('file_journal', 'directory_journal', 'search_journal', 'cleanup_journal'):
        path = Path(index[key])
        if (not path.is_relative_to(rec) or path == rec
                or any(p.is_symlink() for p in (path, *path.parents))):
            raise ValueError('journal must belong to this synthetic workspace')
    file_record = dc.load_artifact(index['file_journal'])
    assert changes.verify(root, file_record, cfg)['status'] == 'Passed'
    assert sessions.verify(root, cfg, base / 'session.json')['status'] == 'Passed'
    changes.recover(root, Path(index['file_journal']), cfg)
    assert sessions.report(root, cfg, base / 'session.json')['completion'] == 'all_recovered'
    assert (root / 'notes.md').read_text() == 'one'
    directory = dc.load_profile(root, cfg, base / 'directory-profile.json')
    journal = dc.load_artifact(index['directory_journal'])
    assert da.verify(directory, journal, arc)['status'] == 'Passed'
    restored = da.restore(directory, da.restore_preview(directory, journal, arc), arc, rec)
    assert da.verify(directory, restored, arc)['status'] == 'Passed'
    assert (root / 'history/run/data.bin').read_bytes() == b'original archive\x00'
    search = dc.load_artifact(index['search_journal'])
    assert search_view.verify(directory, search)['status'] == 'Passed'
    search = search_view.restore(directory, search_view.restore_preview(directory, search), rec)
    assert search_view.verify(directory, search)['status'] == 'Passed'
    cleanup = cp.load_profile(root, cfg, base / 'cleanup-profile.json')
    journal = dc.load_artifact(index['cleanup_journal'])
    assert co.verify(cleanup, journal, quarantine, rec)['status'] == 'Passed'
    plan = co.restore_preview(cleanup, journal, quarantine, rec)
    save(base / 'cleanup-restore-plan.json', plan)
    restored = co.restore(cleanup, plan, quarantine, rec, approve_plan=plan['fingerprint'])
    assert co.verify(cleanup, restored, quarantine, rec)['status'] == 'Passed'
    assert (root / 'old.log').read_text() == 'completed synthetic log'
    noop = changes.preview(root, {'operations': [{'type': 'replace', 'path': 'notes.md', 'old': 'one', 'new': 'one'}]}, cfg)
    record = changes.apply(root, noop, cfg, rec)
    assert changes.verify(root, record, cfg)['status'] == 'Passed'
    changes.recover(root, Path(record['journal_path']), cfg)
    return {'status': 'Passed', 'phase': 'verify', 'version': __version__, 'producer': index['producer'],
            'old_file_session_directory_search_cleanup': 'verified and restored', 'new_noop': 'Passed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'verify'])
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--expected-version', help='Exact installed version; defaults preserve the 1.4.0-to-1.4.1 probe')
    args = parser.parse_args()
    workspace = args.workspace.absolute()
    if any(p.is_symlink() for p in (workspace, *workspace.parents)):
        raise ValueError('workspace and ancestors must not be symlinks')
    expected = args.expected_version or ('1.4.0' if args.phase == 'prepare' else '1.4.1')
    result = prepare(workspace, expected) if args.phase == 'prepare' else verify(workspace, expected)
    result['python'] = sys.version
    result['executable'] = sys.executable
    save(workspace / (args.phase + '-result.json'), result)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
