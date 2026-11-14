"""CLI hooks for the explicit read-only maintenance advisory."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .advisory import MAX_REQUEST_BYTES, audit, external_path
from .directory_common import DirectoryError, load_artifact, safe_root, write_artifact


def add_parser(commands):
    cmd = commands.add_parser('advisory', help='Audit explicitly declared literal preservation and binding impact')
    cmd.add_argument('--project', '--root', required=True)
    cmd.add_argument('--request', required=True)
    cmd.add_argument('--output')
    cmd.add_argument('--max-output-bytes', type=int, default=8192)


def run(root, config, args):
    try:
        root = safe_root(args.project)
        if str(root) != args.project:
            raise DirectoryError('PATH_ALIAS', 'project spelling differs')
        if type(args.max_output_bytes) is not int or not 1024 <= args.max_output_bytes <= 30720:
            raise DirectoryError('BUDGET_EXHAUSTED', 'invalid stdout budget')
        request = external_path(root, config, args.request)
        output = external_path(root, config, args.output) if args.output else None
        if output is not None and (output == request or output.exists()):
            raise DirectoryError('OUTPUT_EXISTS', 'audit output must be new')
        result = audit(root, config, load_artifact(request, limit=MAX_REQUEST_BYTES))
        if output:
            write_artifact(output, result, limit=8 * 1024 * 1024)
        text = json.dumps(result, ensure_ascii=True)
        if len(text.encode('ascii')) > args.max_output_bytes:
            text = json.dumps({k: result[k] for k in ('status', 'status_scope', 'fingerprint', 'project_writes',
                                                     'semantic_acceptance', 'physical_space_released_bytes')})
            text = text[:-1] + ', "details_omitted": true, "report_written": ' + str(bool(output)).lower() + '}'
        print(text)
        return 2 if result['status'] == 'Blocked' else 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        from .diagnostics import diagnose
        print(json.dumps({'status': 'Blocked', **diagnose(error), 'project_writes': 0}), file=sys.stderr)
        return 2
