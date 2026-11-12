import json

import pytest

from fifan_maintenance import changes, sessions
from fifan_maintenance.diagnostics import DiagnosticError
from fifan_maintenance.project import load_config


@pytest.mark.parametrize('format', ['fifan-cleanup-plan', 'fifan-cleanup-journal',
                                  'fifan-maintenance-workflow'])
def test_old_validators_explicitly_reject_cleanup_material_before_writes(tmp_path, format):
    config = load_config(tmp_path)
    for validator in (changes._validate_plan, changes._validate_record):
        with pytest.raises(DiagnosticError) as error:
            validator(tmp_path, {'format': format, 'schema_version': 1}, config)
        assert error.value.reason_code == 'CLEANUP_FORMAT_UNSUPPORTED'
    assert list(tmp_path.iterdir()) == []


def test_old_session_does_not_invoke_legacy_record_validator_for_cleanup(tmp_path, monkeypatch):
    project, records = tmp_path / 'project', tmp_path / 'records'
    project.mkdir()
    records.mkdir()
    journal = records / 'cleanup.json'
    journal.write_text(json.dumps({'format': 'fifan-cleanup-journal', 'schema_version': 1}))
    manifest = records / 'session.json'
    manifest.write_text(json.dumps({'schema_version': 1, 'root': str(project),
                                   'journals': [str(journal)]}))
    def forbidden(*args, **kwargs):
        raise AssertionError('cleanup material reached the old execution protocol')
    monkeypatch.setattr(changes, '_validate_record', forbidden)
    with pytest.raises(DiagnosticError) as error:
        sessions._session(project, load_config(project), manifest)
    assert error.value.reason_code == 'CLEANUP_FORMAT_UNSUPPORTED'
    assert list(project.iterdir()) == []


def test_old_cli_report_rejects_new_cleanup_format(tmp_path, capsys):
    from fifan_maintenance.cli import main
    project = tmp_path / 'project'
    project.mkdir()
    report = tmp_path / 'report.json'
    report.write_text(json.dumps({'format': 'fifan-cleanup-report', 'schema_version': 1}))
    assert main(['report', '--project', str(project), '--input', str(report)]) == 2
    value = json.loads(capsys.readouterr().err)
    assert value['reason_code'] == 'CLEANUP_FORMAT_UNSUPPORTED'
    assert value['project_writes'] == 0
