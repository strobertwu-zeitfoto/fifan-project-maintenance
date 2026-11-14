"""Read-only joint projection CLI, separate from native directory plan dispatch."""
from __future__ import annotations

from pathlib import Path


def add_parser(commands):
    cmd = commands.add_parser('joint-preview', help='Read-only file-change plus archive final navigation projection')
    cmd.add_argument('--project', '--root', required=True)
    cmd.add_argument('--profile', required=True)
    cmd.add_argument('--file-plan', required=True)
    cmd.add_argument('--request', required=True)
    cmd.add_argument('--archive-root', required=True)
    cmd.add_argument('--records-dir', required=True)
    cmd.add_argument('--output')
    cmd.add_argument('--max-output-bytes', type=int, default=8192)


def run(root, config, args):
    from . import directory_common as dc
    from .directory_cli import _protect_runtime_output
    from .joint_preview import preview
    from .reading import bounded_json, _redact
    profile = dc.load_profile(root, config, args.profile)
    bounded_json({}, min(args.max_output_bytes, profile.budgets['max_output_bytes']))
    if args.output:
        requested = Path(args.output).expanduser().absolute()
        output = dc.canonical_destination(requested)
        if output != requested:
            raise dc.DirectoryError('PATH_ALIAS')
        _protect_runtime_output(profile, args, output)
        if output == root or root in output.parents:
            raise dc.DirectoryError('OUTPUT_INSIDE_PROJECT')
        for name in ('profile', 'file_plan', 'request'):
            source = dc.canonical_destination(Path(getattr(args, name)).expanduser().absolute())
            if dc._key(str(source)) == dc._key(str(output)):
                raise dc.DirectoryError('OUTPUT_INPUT_CONFLICT')
        if output.exists():
            raise dc.DirectoryError('OUTPUT_EXISTS')
    limit = profile.budgets['max_artifact_bytes']
    result = preview(profile, dc.load_artifact(args.file_plan, limit), dc.load_artifact(args.request, limit), args.archive_root, args.records_dir)
    if args.output:
        # Exclusive publication closes the preflight/publication race: a new
        # report from another writer is preserved, even after preview starts.
        try:
            dc.write_artifact(output, _redact(result), limit=limit)
        except FileExistsError as error:
            raise dc.DirectoryError('OUTPUT_EXISTS') from error
    print(bounded_json(result, min(args.max_output_bytes, profile.budgets['max_output_bytes'])), end='')
    if result.get('status') == 'Blocked':
        return 2
    return 1 if result.get('status') == 'Failed' else 0
