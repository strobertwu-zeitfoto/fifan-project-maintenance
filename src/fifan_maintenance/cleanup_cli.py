"""Explicit cleanup entry points; old maintenance commands keep NoDelete."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unicodedata


PREVIEWS = {'preview', 'restore-preview', 'purge-preview'}


def add_parser(commands):
    cleanup = commands.add_parser('cleanup', help='Explicit disposable-artifact cleanup')
    actions = cleanup.add_subparsers(dest='cleanup_action', required=True)
    for name in ('inspect', 'preview', 'apply', 'verify', 'restore-preview',
                 'restore', 'purge-preview', 'purge', 'recover', 'history'):
        cmd = actions.add_parser(name)
        _common(cmd)
        if name in {'inspect', 'preview'}:
            cmd.add_argument('--request', required=name == 'preview')
        if name in PREVIEWS or name in {'apply', 'restore', 'purge'}:
            cmd.add_argument('--plan', required=True)
        if name in {'verify', 'restore-preview', 'purge-preview', 'recover'}:
            cmd.add_argument('--journal', required=True)
        if name != 'inspect':
            cmd.add_argument('--records-dir', required=True)
        if name not in {'inspect', 'history'}:
            cmd.add_argument('--quarantine-root', required=True)
        if name in {'apply', 'restore', 'purge', 'recover'}:
            cmd.add_argument('--approve-plan', required=name != 'recover')
        if name == 'recover':
            cmd.add_argument('--approve-purge')
        if name == 'purge-preview':
            cmd.add_argument('--approval-file')
        if name == 'history':
            cmd.add_argument('--max-records', type=int, default=1000)
            cmd.add_argument('--max-record-bytes', type=int, default=32 * 1024 * 1024)
    maintenance = commands.add_parser('maintenance', help='Cleanup before retained-material governance')
    group = maintenance.add_subparsers(dest='maintenance_action', required=True)
    cmd = group.add_parser('workflow')
    _common(cmd)
    cmd.add_argument('--mode', choices=('inspect', 'quarantine', 'purge'), default='inspect')
    cmd.add_argument('--records-dir', required=True)
    cmd.add_argument('--quarantine-root')
    cmd.add_argument('--request')
    cmd.add_argument('--plan')
    cmd.add_argument('--approve-plan')
    cmd.add_argument('--resume')
    cmd.add_argument('--after', help='Explicit external JSON after-action descriptor')
    cmd.add_argument('--after-archive-root')


def _common(cmd):
    cmd.add_argument('--project', '--root', required=True)
    cmd.add_argument('--profile', '--cleanup-profile', dest='profile', required=True)
    cmd.add_argument('--output')
    cmd.add_argument('--max-output-bytes', type=int, default=8192)


def _blocked(error):
    from .diagnostics import diagnose
    value = {'status': 'Blocked', **diagnose(error), 'project_writes': 0,
             'message': 'Cleanup input or output preflight rejected.'}
    print(json.dumps(value, ensure_ascii=False), file=sys.stderr)
    return 2


def _preflight_outputs(profile, args):
    from .directory_common import canonical_destination, DirectoryError, safe_root
    action = getattr(args, 'cleanup_action', None)
    outputs = [args.output]
    if action in PREVIEWS:
        outputs.append(args.plan)
    inputs = [getattr(args, key, None) for key in
              ('profile', 'request', 'journal', 'resume', 'after', 'approval_file')]
    if action not in PREVIEWS:
        inputs.append(getattr(args, 'plan', None))
    input_paths = [canonical_destination(Path(p).expanduser().absolute()) for p in inputs if p]
    resolved = []
    quarantine = getattr(args, 'quarantine_root', None)
    quarantine = safe_root(quarantine) if quarantine else None
    records = getattr(args, 'records_dir', None)
    records = safe_root(records) if records else None
    for value in outputs:
        if value is None:
            continue
        path = canonical_destination(Path(value).expanduser().absolute())
        if path == profile.root or path.is_relative_to(profile.root):
            raise DirectoryError('OUTPUT_INSIDE_PROJECT')
        # This comparison only restricts writes; it never opens a declared Q
        # root or grants access when inspect has no runtime quarantine grant.
        declared = profile.data.get('quarantine_root')
        if declared:
            key = lambda text: unicodedata.normalize('NFC', unicodedata.normalize('NFC', str(text)).casefold()).rstrip('/')
            prefix, candidate = key(declared), key(path)
            if candidate == prefix or candidate.startswith(prefix + '/'):
                raise DirectoryError('OUTPUT_INSIDE_QUARANTINE')
        if quarantine is not None and (path == quarantine or path.is_relative_to(quarantine)):
            raise DirectoryError('OUTPUT_INSIDE_QUARANTINE')
        if records is not None and path.is_relative_to(records):
            parents = path.relative_to(records).parts[:-1]
            if any(part.startswith(('cleanup-', 'maintenance-')) for part in parents):
                raise DirectoryError('OUTPUT_INSIDE_OPERATION_RECORDS')
        if path in input_paths or path in resolved:
            raise DirectoryError('OUTPUT_INPUT_CONFLICT')
        # Fresh output names preserve previous evidence and unrelated files.
        if path.exists():
            raise DirectoryError('DESTINATION_EXISTS')
        resolved.append(path)


def _summary(value):
    fields = ('format', 'schema_version', 'kind', 'status', 'state', 'project_root',
              'root', 'operation_id', 'fingerprint', 'journal_path', 'plan_path',
              'reason_code', 'completion', 'workflow_path', 'mode')
    result = {key: value[key] for key in fields if key in value}
    if 'status' not in result:
        if result.get('state') in {'Quarantined', 'Restored', 'Purged'}:
            result['status'] = 'Passed'
        elif result.get('state') in {'NeedsAttention', 'PartiallyPurged'}:
            result['status'] = 'Blocked'
        elif result.get('format') == 'fifan-cleanup-plan':
            result['status'] = 'Preview'
        else:
            result['status'] = 'Unknown'
    for key in ('items', 'batches'):
        if isinstance(value.get(key), list):
            result[key + '_count'] = len(value[key])
    return result


def _emit(profile, args, result):
    from .directory_common import write_artifact
    from .reading import bounded_json, _redact
    if args.output:
        write_artifact(Path(args.output).expanduser().absolute(), _redact(result),
                       limit=profile.budgets['max_artifact_bytes'])
    print(bounded_json(result, min(args.max_output_bytes, profile.budgets['max_output_bytes'])), end='')
    if result.get('status') == 'Blocked':
        return 2
    return 1 if result.get('status') == 'Failed' else 0


def run(root, config, args):
    from . import cleanup_policy as policy
    from .directory_common import load_artifact, write_artifact
    from .reading import bounded_json
    try:
        profile = policy.load_profile(root, config, args.profile)
        bounded_json({}, min(args.max_output_bytes, profile.budgets['max_output_bytes']))
        _preflight_outputs(profile, args)
        limit = profile.budgets['max_artifact_bytes']
        def artifact(name):
            path = getattr(args, name, None)
            return load_artifact(Path(path).expanduser().absolute(), limit=limit) if path else None
        request, plan, journal = artifact('request'), None, artifact('journal')
        if getattr(args, 'cleanup_action', None) not in PREVIEWS:
            plan = artifact('plan')
        approval = artifact('approval_file')
        after = artifact('after')
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        return _blocked(error)
    if args.command == 'maintenance':
        from .maintenance_workflow import workflow
        result = workflow(profile, mode=args.mode, request=request, plan=args.plan,
                          approve_plan=args.approve_plan, Q=args.quarantine_root,
                          records_dir=args.records_dir, resume=args.resume,
                          after=after, after_archive_root=args.after_archive_root)
        return _emit(profile, args, result)
    action = args.cleanup_action
    if action == 'inspect':
        return _emit(profile, args, policy.inspect(profile, request))
    if action == 'history':
        from .cleanup_reporting import history
        result = history(profile, args.records_dir, max_records=args.max_records,
                         max_bytes=args.max_record_bytes)
        return _emit(profile, args, result)
    from . import cleanup_operations as operations
    q, records = args.quarantine_root, args.records_dir
    if action == 'preview':
        result = operations.preview(profile, request, q, records)
    elif action == 'restore-preview':
        result = operations.restore_preview(profile, journal, q, records)
    elif action == 'purge-preview':
        result = operations.purge_preview(profile, journal, q, records, approval=approval)
    elif action == 'apply':
        result = operations.apply(profile, plan, q, records, approve_plan=args.approve_plan)
    elif action == 'restore':
        result = operations.restore(profile, plan, q, records, approve_plan=args.approve_plan)
    elif action == 'purge':
        result = operations.purge(profile, plan, q, records, approve_plan=args.approve_plan)
    elif action == 'verify':
        result = operations.verify(profile, journal, q, records)
    else:
        result = operations.recover(profile, journal, q, records,
                                    approve_plan=args.approve_plan, approve_purge=args.approve_purge)
    if action in PREVIEWS:
        write_artifact(Path(args.plan).expanduser().absolute(), result, limit=limit)
        return _emit(profile, args, {**_summary(result), 'plan_path': str(Path(args.plan).expanduser().absolute())})
    if action in {'apply', 'restore', 'purge', 'recover'}:
        result = _summary(result)
    return _emit(profile, args, result)
