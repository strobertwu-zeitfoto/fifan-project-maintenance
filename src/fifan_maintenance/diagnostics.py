"""Controlled diagnostics; arbitrary exception text never becomes output."""
from __future__ import annotations

import re


class DiagnosticError(ValueError):
    def __init__(self, reason_code, message='validation rejected', **metadata):
        super().__init__(message)
        self.reason_code = reason_code
        self.safe_metadata = metadata


_HINTS = {
    'SOURCE_CHANGED': 'Re-read the changed source, then build a new preview.',
    'CURSOR_BINDING_MISMATCH': 'Keep the same source, profile and selectors; restart after source changes.',
    'HEADING_NOT_FOUND': 'Read the filtered outline and use its exact heading or section-id.',
    'SELECTOR_AMBIGUOUS': 'Use a unique source-bound section or exact original byte range.',
    'PATCH_OVERLAP': 'All patches must select disjoint ranges in the same original source.',
    'MULTIPLE_WRITES': 'Use replace_many for multiple changes in one file.',
    'PRESERVATION_GUARD_FAILED': 'Keep the guarded content unchanged, or declare an already-authorized precise exception.',
    'PROFILE_CONFLICT': 'Do not declare conflicting task selections.',
    'BODY_NOT_AUTHORIZED': 'Declare only already-authorized reference bodies in the task profile.',
    'PROTECTED_PATH': 'Keep the project protection rules; choose an allowed path.',
    'REPORT_BINDING_MISMATCH': 'Compare reports with identical project, scope, versions and budgets.',
    'JOURNAL_INVALID': 'Use the exact valid journal emitted by apply; keep the operations directory.',
    'BUDGET_EXHAUSTED': 'Narrow the scope or explicitly choose an allowed budget.',
    'PROJECT_BUSY': 'Wait for the other maintenance operation to release the project lock.',
    'INVALID_INPUT': 'Check the documented input schema and paths.',
}


def diagnose(error):
    code = getattr(error, 'reason_code', None)
    if not isinstance(code, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{1,79}', code):
        message = str(error).lower()
        patterns = [
            ('PROJECT_BUSY', ('project busy', 'another maintenance')),
            ('PATCH_OVERLAP', ('overlapping patch', 'patch overlap')),
            ('MULTIPLE_WRITES', ('multiple writes', 'read/write path conflict', 'paths must be disjoint', 'paths overlap')),
            ('PRESERVATION_GUARD_FAILED', ('preservation guard failed',)),
            ('CURSOR_BINDING_MISMATCH', ('cursor does not match', 'invalid read cursor', 'cursor is out')),
            ('HEADING_NOT_FOUND', ('unknown or ambiguous heading', 'heading not found')),
            ('SELECTOR_AMBIGUOUS', ('ambiguous', 'match exactly once', 'unique')),
            ('SOURCE_CHANGED', ('source changed', 'source fingerprint', 'no longer matches', 'changed during', 'changed before', 'subsequently changed', 'changed during overlay')),
            ('PROFILE_CONFLICT', ('conflicting task', 'conflicting config', 'profile conflict', 'unsupported task profile')),
            ('BODY_NOT_AUTHORIZED', ('body outside task scope', 'body is not authorized', 'outside explicit task sources')),
            ('PROTECTED_PATH', ('protected', 'excluded', 'path escape', 'path must remain', 'symlink')),
            ('REPORT_BINDING_MISMATCH', ('comparison project mismatch', 'report project mismatch', 'config mismatch')),
            ('JOURNAL_INVALID', ('journal', 'record integrity', 'recorded', 'invalid completed', 'invalid restored', 'backup')),
            ('BUDGET_EXHAUSTED', ('budget', 'limit', 'oversized', 'exceeds', 'too large')),
        ]
        code = next((name for name, needles in patterns if any(needle in message for needle in needles)), 'INVALID_INPUT')
    metadata = {}
    raw = getattr(error, 'safe_metadata', getattr(error, 'details', {}))
    if isinstance(raw, dict):
        for key in ('operation_index', 'patch_index', 'start_byte', 'end_byte', 'limit', 'actual', 'expected'):
            if type(raw.get(key)) is int:
                metadata[key] = raw[key]
        for key in ('expected_sha256', 'actual_sha256'):
            value = raw.get(key)
            if isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value):
                metadata[key] = value
    return {'reason_code': code, 'hint': _HINTS.get(code, 'Check the documented contract for this operation.'), 'details': metadata}
