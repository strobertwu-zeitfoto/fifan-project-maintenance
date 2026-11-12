from __future__ import annotations

import json

from fifan_maintenance.cli import main
from fifan_maintenance.diagnostics import DiagnosticError, diagnose


def test_diagnostics_never_echo_arbitrary_error_content():
    error = DiagnosticError('SOURCE_CHANGED', 'password=DO_NOT_ECHO', expected_sha256='a' * 64, actual_sha256='b' * 64, patch_index=2, path='token=DO_NOT_ECHO')
    result = diagnose(error)
    assert result['reason_code'] == 'SOURCE_CHANGED'
    assert result['details']['patch_index'] == 2
    assert 'DO_NOT_ECHO' not in json.dumps(result)
    assert diagnose(ValueError('multiple writes to same path'))['reason_code'] == 'MULTIPLE_WRITES'
    assert diagnose(ValueError('project busy'))['reason_code'] == 'PROJECT_BUSY'
    assert diagnose(ValueError('preservation guard failed'))['reason_code'] == 'PRESERVATION_GUARD_FAILED'


def test_cli_blocked_reports_no_project_write_and_keeps_old_fields(tmp_path, capsys):
    (tmp_path / 'a.md').write_text('# A\n')
    result = main(['read', '--project', str(tmp_path), '--file', 'a.md', '--heading', 'not found'])
    assert result == 2
    output = json.loads(capsys.readouterr().err)
    assert output['status'] == 'Blocked' and output['error'] == 'SelectionError'
    assert output['reason_code'] == 'HEADING_NOT_FOUND'
    assert output['project_writes'] == 0
    assert (tmp_path / 'a.md').read_text() == '# A\n'


def test_invalid_request_does_not_escape_as_attributeerror(tmp_path, capsys):
    request = tmp_path.parent / (tmp_path.name + '-invalid.json')
    request.write_text('[]')
    result = main(['preview', '--project', str(tmp_path), '--request', str(request), '--plan', str(tmp_path.parent / (tmp_path.name + '-plan.json'))])
    assert result == 2
    output = json.loads(capsys.readouterr().err)
    assert output['reason_code'] == 'INVALID_INPUT'
    assert output['project_writes'] == 0


def test_compiler_details_keep_indices_without_arbitrary_paths():
    from fifan_maintenance.changes import ChangeRequestError
    result = diagnose(ChangeRequestError('SOURCE_CHANGED', 'unsafe input',
        operation_index=3, patch_index=2, path='password=DO_NOT_ECHO'))
    assert result['details']['operation_index'] == 3
    assert result['details']['patch_index'] == 2
    assert 'DO_NOT_ECHO' not in json.dumps(result)
