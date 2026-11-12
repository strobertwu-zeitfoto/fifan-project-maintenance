from pathlib import Path
from types import SimpleNamespace

import pytest

from fifan_maintenance import cleanup_cli
from fifan_maintenance.directory_common import DirectoryError


def output_case(tmp_path, output):
    root, quarantine, records = [tmp_path / x for x in ('project', 'quarantine', 'records')]
    for path in (root, quarantine, records):
        path.mkdir(exist_ok=True)
    profile_path = tmp_path / 'profile.json'
    profile_path.write_text('{}')
    profile = SimpleNamespace(root=root, data={'quarantine_root': str(quarantine)})
    args = SimpleNamespace(command='cleanup', cleanup_action='inspect', output=str(output),
                           profile=str(profile_path), quarantine_root=None)
    return profile, args


def test_inspect_output_cannot_mutate_declared_quarantine_without_runtime_root(tmp_path):
    destination = tmp_path / 'quarantine' / 'payload' / 'new-report.json'
    profile, args = output_case(tmp_path, destination)
    with pytest.raises(DirectoryError) as error:
        cleanup_cli._preflight_outputs(profile, args)
    assert error.value.reason_code == 'OUTPUT_INSIDE_QUARANTINE'
    assert not destination.exists()


@pytest.mark.parametrize('alias', [False, True])
def test_public_output_inside_project_is_rejected_before_creation(tmp_path, alias):
    root = tmp_path / 'project'
    profile, args = output_case(tmp_path, root / 'new-report.json')
    if alias:
        other = root.with_name('PROJECT')
        if not other.exists():
            pytest.skip('requires a case-insensitive fixture filesystem')
        args.output = str(other / 'new-report.json')
    with pytest.raises(DirectoryError) as error:
        cleanup_cli._preflight_outputs(profile, args)
    assert error.value.reason_code == 'OUTPUT_INSIDE_PROJECT'
    assert not (root / 'new-report.json').exists()


def test_output_cannot_preempt_future_operation_journal(tmp_path):
    destination = tmp_path / 'records' / ('cleanup-' + 'a' * 32) / 'journal.json'
    profile, args = output_case(tmp_path, destination)
    args.records_dir = str(tmp_path / 'records')
    with pytest.raises(DirectoryError) as error:
        cleanup_cli._preflight_outputs(profile, args)
    assert error.value.reason_code == 'OUTPUT_INSIDE_OPERATION_RECORDS'
    assert not destination.parent.exists()


def test_report_target_cannot_overwrite_input_or_existing_file(tmp_path):
    destination = tmp_path / 'profile.json'
    profile, args = output_case(tmp_path, destination)
    before = destination.read_bytes()
    with pytest.raises(DirectoryError) as error:
        cleanup_cli._preflight_outputs(profile, args)
    assert error.value.reason_code == 'OUTPUT_INPUT_CONFLICT'
    assert destination.read_bytes() == before
    foreign = tmp_path / 'foreign.txt'
    foreign.write_bytes(b'keep this')
    args.output = str(foreign)
    with pytest.raises(DirectoryError) as error:
        cleanup_cli._preflight_outputs(profile, args)
    assert error.value.reason_code == 'DESTINATION_EXISTS'
    assert foreign.read_bytes() == b'keep this'
