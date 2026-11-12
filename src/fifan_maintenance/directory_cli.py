"""Directory commands are separate from the established file-change formats."""
from __future__ import annotations

from pathlib import Path
import stat


def add_parser(commands):
    group = commands.add_parser('directory', help='Bounded directory and search maintenance')
    actions = group.add_subparsers(dest='directory_action', required=True)
    names = ('census', 'impact', 'search-preview', 'archive-preview', 'apply',
             'verify', 'locate', 'restore-preview', 'restore', 'recover', 'workflow')
    for name in names:
        cmd = actions.add_parser(name)
        cmd.add_argument('--project', '--root', required=True)
        cmd.add_argument('--profile', required=True)
        cmd.add_argument('--output')
        cmd.add_argument('--max-output-bytes', type=int, default=8192)
        if name == 'census':
            cmd.add_argument('--hash-candidates', nargs='+')
        if name in ('impact', 'archive-preview', 'workflow'):
            cmd.add_argument('--request', required=name != 'workflow')
        if name in ('search-preview', 'archive-preview', 'apply', 'restore-preview', 'restore', 'workflow'):
            cmd.add_argument('--plan', required=name != 'workflow')
        if name in ('verify', 'locate', 'restore-preview', 'recover', 'workflow'):
            cmd.add_argument('--journal', required=name != 'workflow')
        if name == 'locate':
            cmd.add_argument('--original', required=True)
        if name not in ('census', 'impact', 'search-preview'):
            cmd.add_argument('--archive-root')
        if name in ('archive-preview', 'apply', 'restore', 'recover', 'workflow'):
            cmd.add_argument('--records-dir', required=True)
        if name == 'workflow':
            cmd.add_argument('--phase', choices=('inspect', 'search', 'archive', 'restore'), default='inspect')
            cmd.add_argument('--resume')


def _summary(value):
    """A private plan or journal must never be printed as a public report."""
    allowed = ('format', 'schema_version', 'kind', 'status', 'state', 'root', 'project_root',
               'operation_id', 'fingerprint', 'journal_path', 'workflow_path',
               'plan_path', 'phase', 'completion', 'reason_code')
    result = {key: value[key] for key in allowed if key in value}
    if 'status' not in result:
        result['status'] = 'Passed' if result.get('state') in ('Archived', 'Restored') else 'Unknown'
    if isinstance(value.get('batches'), list):
        result['batch_count'] = len(value['batches'])
    if isinstance(value.get('operations'), list):
        result['operation_count'] = len(value['operations'])
    return result


def _implementation(value):
    if value.get('kind') == 'search-config':
        from . import search_view
        return search_view
    if value.get('kind') == 'directory-archive':
        from . import directory_archive
        return directory_archive
    from .directory_common import DirectoryError
    raise DirectoryError('DIRECTORY_FORMAT_UNSUPPORTED')


def _output(profile, args, value):
    from .cli import output_file
    from .reading import bounded_json, _redact
    import json
    if args.output:
        output_file(args.output, json.dumps(_redact(value), ensure_ascii=False, indent=2), profile.root)
    print(bounded_json(value, min(args.max_output_bytes, profile.budgets['max_output_bytes'])), end='')
    if value.get('status') == 'Blocked':
        return 2
    return 1 if value.get('status') == 'Failed' else 0


def _protect_runtime_output(profile, args, path):
    """Reserve payload roots and the engine's private record namespace."""
    from .directory_common import canonical_destination, DirectoryError, _key
    archive = profile.data.get('archive', {})
    roots = [(getattr(args, 'archive_root', None) or archive.get('archive_root'), 'archive'),
             (getattr(args, 'records_dir', None) or archive.get('records_dir'), 'records')]
    key = _key(str(path))
    for value, kind in roots:
        if not value:
            continue
        root = canonical_destination(Path(value).expanduser().absolute())
        root_key = _key(str(root))
        if key != root_key and not key.startswith(root_key + '/'):
            continue
        relative = key[len(root_key):].lstrip('/')
        if (kind == 'archive' or not relative or relative.endswith('.directory.json')
                or any(part.startswith('workflow-') for part in relative.split('/')[:-1])):
            raise DirectoryError('OUTPUT_INPUT_CONFLICT', 'output overlaps private records or archive payload')


def run(root, config, args):
    from .directory_common import load_profile, load_artifact, write_artifact, DirectoryError, canonical_destination
    profile = load_profile(root, config, args.profile)
    action = args.directory_action
    from .reading import bounded_json
    bounded_json({}, min(args.max_output_bytes, profile.budgets['max_output_bytes']))
    # Check all output destinations before running a mutating operation. A
    # preview must not acquire a project write through its plan filename.
    outputs = [args.output]
    if action in ('search-preview', 'archive-preview', 'restore-preview'):
        outputs.append(args.plan)
    for name in outputs:
        if name is None:
            continue
        path = canonical_destination(Path(name).expanduser().absolute())
        _protect_runtime_output(profile, args, path)
        if path.is_relative_to(profile.root):
            raise DirectoryError('OUTPUT_INSIDE_PROJECT')
        for parent in (path, *path.parents):
            if parent.is_symlink():
                raise DirectoryError('PROTECTED_PATH')
        if path.exists() and not stat.S_ISREG(path.stat().st_mode):
            raise DirectoryError('PROTECTED_PATH')
        input_names = ('profile', 'request', 'journal', 'resume')
        if action not in ('search-preview', 'archive-preview', 'restore-preview'):
            input_names += ('plan',)
        from .directory_common import _key
        if any(getattr(args, key, None) and _key(str(path)) == _key(str(canonical_destination(Path(getattr(args, key)).expanduser().absolute()))) for key in input_names):
            raise DirectoryError('OUTPUT_INPUT_CONFLICT')
    # Output aliases must not overwrite a profile, input request, private plan,
    # or journal after a successful project mutation.
    if args.output:
        output = canonical_destination(Path(args.output).expanduser().absolute())
        inputs = [getattr(args, name, None) for name in ('profile', 'request', 'plan', 'journal', 'resume')]
        if any(path and _key(str(output)) == _key(str(canonical_destination(Path(path).expanduser().absolute()))) for path in inputs):
            raise DirectoryError('OUTPUT_INPUT_CONFLICT')
    limit = profile.budgets['max_artifact_bytes']
    if action == 'census':
        from .directory_census import census
        return _output(profile, args, census(profile, hash_candidates=args.hash_candidates))
    if action == 'impact':
        from .directory_census import impact
        return _output(profile, args, impact(profile, load_artifact(args.request, limit=limit)))
    if action == 'workflow':
        from .directory_workflow import workflow
        result = workflow(profile, phase=args.phase,
            request=load_artifact(args.request, limit=limit) if args.request else None,
            plan=load_artifact(args.plan, limit=limit) if args.plan else None,
            journal=load_artifact(args.journal, limit=limit) if args.journal else None,
            archive_root=args.archive_root, records_dir=args.records_dir, resume=args.resume)
        return _output(profile, args, result)
    if action in ('search-preview', 'archive-preview'):
        if action == 'search-preview':
            from .search_view import search_preview
            result = search_preview(profile)
        else:
            from .directory_archive import archive_preview
            result = archive_preview(profile, load_artifact(args.request, limit=limit),
                                     args.archive_root, args.records_dir)
        write_artifact(args.plan, result, limit=limit)
        public = {**_summary(result), 'plan_path': str(Path(args.plan).expanduser().absolute())}
        return _output(profile, args, public)
    if action in ('apply', 'restore'):
        value = load_artifact(args.plan, limit=limit)
        module = _implementation(value)
        function = module.apply if action == 'apply' else module.restore
        if value['kind'] == 'directory-archive':
            result = function(profile, value, args.archive_root, args.records_dir)
        else:
            result = function(profile, value, args.records_dir)
        return _output(profile, args, _summary(result))
    value = load_artifact(args.journal, limit=limit)
    module = _implementation(value)
    if action == 'locate':
        if value['kind'] != 'directory-archive':
            raise DirectoryError('DIRECTORY_FORMAT_UNSUPPORTED')
        return _output(profile, args, module.locate(profile, value, args.original, args.archive_root))
    if action == 'restore-preview':
        if value['kind'] == 'directory-archive':
            result = module.restore_preview(profile, value, args.archive_root)
        else:
            result = module.restore_preview(profile, value)
        write_artifact(args.plan, result, limit=limit)
        return _output(profile, args, {**_summary(result), 'plan_path': str(Path(args.plan).expanduser().absolute())})
    if action == 'verify':
        result = module.verify(profile, value, args.archive_root) if value['kind'] == 'directory-archive' else module.verify(profile, value)
        return _output(profile, args, result)
    if action == 'recover':
        result = module.recover(profile, value, args.archive_root, args.records_dir) if value['kind'] == 'directory-archive' else module.recover(profile, value, args.records_dir)
        return _output(profile, args, _summary(result))
    raise DirectoryError('DIRECTORY_FORMAT_UNSUPPORTED')
