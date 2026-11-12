"""Bounded, explicit record views and lock-protected recovery orchestration.

A session is a user-selected ordered list of evidence, never a project ledger.
Only summaries and fingerprints leave this module; recorded bodies stay private.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from . import changes as c
from .project import strict_json

MAX_RECORDS = 1000
MAX_TOTAL = 64 * 1024 * 1024


def _external(root, path):
    path = Path(path).absolute()
    if '..' in path.parts or path == root or root in path.parents:
        raise ValueError('session material must be canonical and outside project')
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('symlink session material')
    return path


def _load(root, path, budget):
    path = _external(root, path)
    raw, _ = c._read(path.parent, path.name, {'max_file_bytes': c.MAX_BYTES})
    budget[0] += len(raw)
    budget[1] += 1
    if budget[0] > budget[2] or budget[1] > budget[3]:
        raise ValueError('session material budget exceeded')
    try:
        data = strict_json(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError('invalid session JSON') from exc
    if not isinstance(data, dict):
        raise ValueError('session material must be an object')
    return data, c._hash(raw), path


def _reference(root, ref, budget):
    if isinstance(ref, str):
        ref = {'path': ref}
    if not isinstance(ref, dict) or set(ref) - {'path', 'sha256'} or 'path' not in ref:
        raise ValueError('invalid session reference')
    if not isinstance(ref['path'], str) or not Path(ref['path']).is_absolute():
        raise ValueError('session references require absolute paths')
    data, sha, path = _load(root, ref['path'], budget)
    if 'sha256' in ref and ref['sha256'] != sha:
        raise ValueError('session reference fingerprint mismatch')
    return data, {'path': str(path), 'sha256': sha}


def _session(root, config, session_path):
    root = c._root(root)
    budget = [0, 0, MAX_TOTAL, MAX_RECORDS + 1]
    manifest, sha, path = _load(root, session_path, budget)
    if (set(manifest) - {'schema_version', 'root', 'journals', 'reports', 'profiles'}
            or manifest.get('schema_version') != 1 or manifest.get('root') != str(root)):
        raise ValueError('session scope/schema mismatch')
    journals = manifest.get('journals')
    if not isinstance(journals, list) or not 1 <= len(journals) <= MAX_RECORDS:
        raise ValueError('session requires an explicit ordered journal list')
    records, refs, seen = [], [], set()
    for entry in journals:
        record, ref = _reference(root, entry, budget)
        c._reject_cleanup_material(record)
        if _is_directory_material(record):
            from .diagnostics import DiagnosticError
            raise DiagnosticError('DIRECTORY_FORMAT_UNSUPPORTED', 'Use the explicit directory recovery commands')
        try:
            c._validate_record(root, record, config)
        except (KeyError, TypeError, UnicodeError) as exc:
            raise ValueError('invalid session journal') from exc
        if ref['path'] != record['journal_path'] or ref['path'] in seen:
            raise ValueError('duplicate or relocated session journal')
        seen.add(ref['path'])
        refs.append(ref)
        records.append(record)
    optional = {}
    for key in ('reports', 'profiles'):
        entries = manifest.get(key, [])
        if not isinstance(entries, list):
            raise ValueError('invalid session reference list')
        optional[key] = []
        for entry in entries:
            wrapper_root = None
            if key == 'profiles' and isinstance(entry, dict) and 'root' in entry:
                wrapper_root = entry['root']
                entry = {k: v for k, v in entry.items() if k != 'root'}
            data, ref = _reference(root, entry, budget)
            bound = data.get('root', data.get('project_root'))
            if key == 'profiles' and wrapper_root is not None:
                if wrapper_root != str(root) or (bound is not None and bound != str(root)):
                    raise ValueError('session profile project binding mismatch')
                from .scope import task_config
                task_config(root, config, profile=Path(ref['path']))
                # Bind the data-only validator's second read to the selected file.
                _, checked_sha, _ = _load(root, ref['path'], budget)
                if checked_sha != ref['sha256']:
                    raise ValueError('session profile changed during validation')
                ref['root'] = wrapper_root
            elif bound != str(root):
                raise ValueError('session reference project binding unknown/mismatched')
            optional[key].append(ref)
    return root, records, {'path': str(path), 'sha256': sha, 'journals': refs, **optional}


def _effects(record):
    before, after = {}, {}
    for op in record['plan']['operations']:
        kind = c._kind(op)
        source = (op['before_sha256'], op['mode'])
        before[op['path']] = source
        if kind == 'replace':
            after[op['path']] = (op['after_sha256'], op['mode'])
        else:
            before[op['destination']] = None
            after[op['destination']] = (op['after_sha256'], op['mode'])
            if kind == 'move':
                after[op['path']] = None
    for evidence in record['plan'].get('guard_evidence', []):
        before[evidence['path']] = (evidence['before_file_sha256'], evidence['source_mode'])
        after.setdefault(evidence['path'], (evidence['after_file_sha256'], evidence['source_mode']))
    # Unchanged snapshot sources are read dependencies too.
    for rel, value in before.items():
        after.setdefault(rel, value)
    return before, after


def _chain(records):
    latest, dependencies, final, seen_ids = {}, [], {}, set()
    for index, record in enumerate(records):
        identity = record['plan']['operation_id']
        if identity in seen_ids:
            raise ValueError('duplicate session operation')
        seen_ids.add(identity)
        before, after = _effects(record)
        parents = set()
        for rel, value in before.items():
            if rel in latest:
                if latest[rel][1] != value:
                    raise ValueError('session chain broken, forked or out of order')
                parents.add(latest[rel][0])
        for rel, value in after.items():
            latest[rel] = index, value
        if record['status'] != 'recovered':
            for op_index in record['completed']:
                if op_index in record['restored']:
                    continue
                op = record['plan']['operations'][op_index]
                targets = [op['path']] if c._kind(op) == 'replace' else [op['destination']]
                if c._kind(op) == 'move':
                    targets.append(op['path'])
                for rel in targets:
                    final[rel] = index
        dependencies.append({'journal': index, 'depends_on': sorted(parents)})
    return dependencies, final


class _View:
    """Read only fingerprints, then simulate reverse transitions in memory."""
    def __init__(self, root, config):
        self.root, self.config, self.values, self.identities = root, config, {}, {}

    def get(self, rel):
        if rel not in self.values:
            c._relative(rel, self.config)
            if c._missing(self.root, rel):
                self.values[rel] = None
            else:
                data, mode = c._read(self.root, rel, self.config)
                self.values[rel] = c._hash(data), mode
                with c._parent(self.root, rel) as (fd, name):
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    self.identities[rel] = st.st_dev, st.st_ino
        return self.values[rel]

    def state(self, op, owner):
        kind = c._kind(op)
        before = op['before_sha256'], op['mode']
        if kind == 'snapshot':
            dest = self.get(op['destination'])
            if dest is None:
                return 'before'
            if (dest == (op['after_sha256'], op['mode']) and owner is not None
                    and self.identities.get(op['destination']) == (owner['device'], owner['inode'])):
                return 'after'
        elif kind == 'replace':
            source = self.get(op['path'])
            if source == before == (op['after_sha256'], op['mode']):
                return 'both'
            if source == before:
                return 'before'
            if source == (op['after_sha256'], op['mode']):
                return 'after'
        else:
            source, dest = self.get(op['path']), self.get(op['destination'])
            if source == before and dest is None:
                return 'before'
            if source is None and dest == before:
                return 'after'
            if source == before and dest == before and self.identities.get(op['path']) == self.identities.get(op['destination']):
                return 'linked'
        raise ValueError('session current state drift or ownership changed')


def _simulate(root, records, config, *, terminal=False):
    view, steps, baseline = _View(root, config), [], {}
    for record in records:
        for rel, value in _effects(record)[0].items():
            baseline.setdefault(rel, value)
    for number in reversed(range(len(records))):
        record = records[number]
        ops = record['plan']['operations']
        if record['status'] == 'recovered':
            steps.append({'journal': number, 'path': record['journal_path'],
                          'status': 'skip_recovered', 'operations': [],
                          'owned_directories_cleanup_if_empty': [], 'owned_temporary_copies': []})
            continue
        eligible = record['completed'] + ([] if record['intent'] is None else [record['intent']])
        states = [view.state(op, c._owner(record, i)) for i, op in enumerate(ops)]
        for i, state in enumerate(states):
            if (i not in eligible or i in record['restored']) and state not in ('before', 'both'):
                raise ValueError('unstarted/restored session operation changed')
            if terminal and record['status'] == 'applied' and i in record['completed'] and i not in record['restored'] and state not in ('after', 'both'):
                raise ValueError('applied session terminal state drift')
        replacements = {op['path']: i for i, op in enumerate(ops) if c._kind(op) == 'replace'}
        changed = {op['path'] for op in ops if c._kind(op) in {'move', 'replace'}}
        for op in ops:
            if c._kind(op) == 'snapshot' and op['path'] not in changed:
                if view.get(op['path']) != (op['before_sha256'], op['mode']):
                    raise ValueError('snapshot read dependency changed')
        for evidence in record['plan'].get('guard_evidence', []):
            i = replacements.get(evidence['path'])
            after = i is not None and states[i] == 'after'
            sha = evidence['after_file_sha256'] if after else evidence['before_file_sha256']
            if view.get(evidence['path']) != (sha, evidence['source_mode']):
                raise ValueError('session guard dependency changed')
        for owner in record.get('created_files', []):
            # Temporary ownership is checked on the actual disk, never fabricated.
            c._check_owned_temp(root, owner, ops[owner['index']], config)
        retained_dirs = []
        for directory in record['created_dirs']:
            if not c._missing(root, directory['path']):
                with c._parent(root, directory['path']) as (fd, name):
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino) != (directory['device'], directory['inode']):
                        raise ValueError('session created directory ownership changed')
                retained_dirs.append(directory['path'])
        changes = []
        for i in reversed(eligible):
            if i in record['restored']:
                continue
            op = ops[i]
            kind = c._kind(op)
            if states[i] in ('after', 'linked'):
                if kind != 'snapshot':
                    view.values[op['path']] = op['before_sha256'], op['mode']
                    if kind == 'move':
                        # Recovery moves the observed file back without changing
                        # its inode. Never substitute the older journal's owner:
                        # matching bytes on a replacement inode must still fail.
                        identity = view.identities.get(op['destination'])
                        view.identities.pop(op['path'], None)
                        if identity is not None:
                            view.identities[op['path']] = identity
                    else:
                        # Atomic replacement creates a new inode; its identity
                        # cannot be predicted by a read-only simulation.
                        view.identities.pop(op['path'], None)
                if kind != 'replace':
                    view.values[op['destination']] = None
                    view.identities.pop(op['destination'], None)
            changes.append({'operation': i, 'path': op['path'], 'kind': kind,
                            'destination': op.get('destination'), 'observed': states[i],
                            'expected_sha256': op['before_sha256'] if kind != 'snapshot' else None})
        steps.append({'journal': number, 'path': record['journal_path'],
                      'status': 'skip_recovered' if record['status'] == 'recovered' else 'recover',
                      'operations': changes, 'owned_directories_cleanup_if_empty': retained_dirs,
                      'owned_temporary_copies': [o['temp'] for o in record.get('created_files', [])]})
    for rel, value in baseline.items():
        if view.get(rel) != value:
            raise ValueError('session baseline/current state drift')
    return steps


def _preview(root, config, session_path, *, terminal=False):
    root, records, refs = _session(root, config, session_path)
    dependencies, final = _chain(records)
    steps = _simulate(root, records, config, terminal=terminal)
    result = {'schema_version': 1, 'root': str(root), 'status': 'Passed',
              'references': refs, 'config_sha256': c._digest(config),
              'dependencies': dependencies, 'final_constraints': final, 'steps': steps}
    result['fingerprint'] = c._digest(result)
    return result


def recovery_preview(root, config, session_path):
    root = c._root(root)
    with c._project_lock(root, exclusive=False):
        return _preview(root, config, session_path)


def verify(root, config, session_path):
    root = c._root(root)
    with c._project_lock(root, exclusive=False):
        result = _preview(root, config, session_path, terminal=True)
    return {**result, 'meaning': 'session chain and current terminal state; individual journal verify is unchanged'}


def report(root, config, session_path):
    root = c._root(root)
    with c._project_lock(root, exclusive=False):
        _, records, refs = _session(root, config, session_path)
        dependencies, final = _chain(records)
        summaries = []
        for i, record in enumerate(records):
            item = {'journal': i, 'operation_id': record['plan']['operation_id'],
                    'operation_status': record['status'],
                    'superseded_paths': [p for p in _effects(record)[1] if p in final and final[p] > i],
                    'individual_verify': c._verify(root, record, config)}
            summaries.append(item)
        try:
            _simulate(root, records, config, terminal=True)
            status = 'Passed'
        except (ValueError, OSError):
            status = 'Failed'
        statuses = [r['status'] for r in records]
        completion = 'all_recovered' if all(s == 'recovered' for s in statuses) else 'all_applied' if all(s == 'applied' for s in statuses) else 'partial_or_unknown'
        return {'schema_version': 1, 'root': str(root), 'status': status, 'completion': completion if status == 'Passed' else 'Unknown',
                'references': refs, 'journals': summaries, 'dependencies': dependencies,
                'final_constraints': final, 'semantic_acceptance': 'Unknown'}


def recover(root, config, session_path, recovery_plan):
    root = c._root(root)
    with c._project_lock(root):
        current = _preview(root, config, session_path)
        if not isinstance(recovery_plan, dict) or recovery_plan != current:
            raise ValueError('session recovery preview changed; preview again')
        restored = []
        for step in current['steps']:
            if step['status'] == 'skip_recovered':
                continue
            # The original journals own interruption progress and write-time checks.
            record = c._recover(root, Path(step['path']), config)
            restored.append(record['plan']['operation_id'])
        return {'schema_version': 1, 'root': str(root), 'status': 'Passed',
                'completion': 'all_recovered', 'restored': restored,
                'session_path': current['references']['path']}


def _observed_file(root, config, path, before, after):
    try:
        if c._missing(root, path):
            return {'status': 'missing', 'sha256': None, 'bytes': None}
        data, _ = c._read(root, path, config)
        sha = c._hash(data)
        status = 'matches_before_and_after' if sha == before == after else 'matches_after' if sha == after else 'matches_before' if sha == before else 'different'
        return {'status': status, 'sha256': sha, 'bytes': len(data)}
    except (OSError, ValueError):
        return {'status': 'Unknown', 'sha256': None, 'bytes': None}


def _operation_files(root, config, plan, record=None, backups=None):
    files = []
    for index, op in enumerate(plan['operations']):
        kind = c._kind(op)
        completed = record is not None and index in record['completed']
        restored = record is not None and index in record['restored']
        active = completed and not restored
        changed = op['before_sha256'] != op['after_sha256']
        treatment = ('preview_only' if record is None else 'recovered' if restored or record['status'] == 'recovered'
                     else 'snapshot_only' if active and kind == 'snapshot'
                     else 'moved' if active and kind == 'move'
                     else 'rewritten' if active and changed else 'noop' if active else 'Unknown')
        before_bytes = after_bytes = None
        if backups is not None:
            before = backups[index]
            after = (before.decode('utf-8').replace(op['old'], op['new'], 1).encode('utf-8')
                     if kind == 'replace' else before)
            before_bytes, after_bytes = len(before), len(after)
        try:
            state = c._state(root, op, config, c._owner(record, index) if record else None)
            current = 'matches_' + state
        except (OSError, ValueError):
            # A later authorized batch can cause this difference as well.
            current = 'different_or_unavailable'
        files.append({'path': op['path'], 'kind': kind, 'destination': op.get('destination'),
                      'before_sha256': op['before_sha256'], 'after_sha256': op['after_sha256'],
                      'before_bytes': before_bytes, 'after_bytes': after_bytes,
                      'byte_delta': after_bytes - before_bytes if before_bytes is not None else None,
                      'treatment': treatment, 'completed_operation': completed,
                      'applied_rewrite': active and (kind == 'move' or kind == 'replace' and changed),
                      'snapshot_created': active and kind == 'snapshot',
                      'current_state': _observed_file(root, config, op['path'], op['before_sha256'], op['after_sha256']),
                      'destination_current_state': (_observed_file(root, config, op['destination'], None, op['after_sha256'])
                                                    if kind != 'replace' else None),
                      'operation_current_state': current})
    return files


def _report_files(report, config):
    scope = report.get('scope')
    sources = scope.get('sources') if isinstance(scope, dict) else None
    observed = report.get('files')
    known = False
    selected = set()
    if isinstance(sources, list) and all(isinstance(p, str) for p in sources):
        selected.update(sources)
        known = True
    if isinstance(observed, dict):
        selected.update(observed)
        known = True
    elif isinstance(observed, list):
        for item in observed:
            if isinstance(item, str):
                selected.add(item)
            elif isinstance(item, dict) and isinstance(item.get('path'), str):
                selected.add(item['path'])
            else:
                raise ValueError('invalid report file scope')
        known = True
    files = []
    for path in sorted(selected):
        c._relative(path, config)
        metadata = observed.get(path, {}) if isinstance(observed, dict) else {}
        if not isinstance(metadata, dict):
            metadata = {}
        size = metadata.get('size')
        if type(size) is not int or size < 0:
            size = None
        sha = metadata.get('sha256')
        if not isinstance(sha, str) or len(sha) != 64 or any(x not in '0123456789abcdef' for x in sha):
            sha = None
        files.append({'path': path, 'kind': 'check', 'destination': None,
                      'before_sha256': None, 'after_sha256': None,
                      'before_bytes': None, 'after_bytes': None, 'byte_delta': None,
                      'checked_sha256': sha, 'checked_bytes': size,
                      'treatment': 'check_only', 'applied_rewrite': False,
                      'current_state': {'status': 'Unknown', 'sha256': None, 'bytes': None}})
    return (files if known else None), 'Known' if known else 'Unknown'


def _is_directory_material(data):
    return (str(data.get('format', '')).startswith('fifan-directory-')
            or data.get('kind') in {'directory-census', 'directory-impact', 'search-config', 'directory-archive'})


def _history_bindings(data):
    """Project bindings only; external roots and references never grant reads."""
    values = []
    containers = [data]
    if isinstance(data.get('plan'), dict):
        containers.append(data['plan'])
    for value in containers:
        values.extend(value[key] for key in ('root', 'project_root') if key in value)
    if data.get('format') == 'fifan-directory-metrics':
        cohort = data.get('cohort')
        if isinstance(cohort, dict) and isinstance(cohort.get('roots'), dict):
            project = cohort['roots'].get('project')
            if isinstance(project, dict) and 'path' in project:
                values.append(project['path'])
    return values


def _directory_history(data, config):
    """Summarize explicit metadata, without following roots or verifying payload.

    Metrics observations are unsealed in their actual public format. Census,
    impact, operation plans/journals and workflow receipts require their seals.
    A stored Passed is reported separately and never becomes current verify.
    """
    from .directory_common import digest, validate_seal
    format = data.get('format')
    operation_formats = {'fifan-directory-plan', 'fifan-directory-journal',
                         'fifan-directory-restore-plan', 'fifan-directory-workflow'}
    metrics_formats = {'fifan-directory-metrics', 'fifan-directory-metrics-evaluation'}
    kind = data.get('kind')
    report_kind = kind if kind in {'directory-census', 'directory-impact'} else None
    verification_report = (format is None and kind in {'search-config', 'directory-archive'}
                           and isinstance(data.get('operation_id'), str) and isinstance(data.get('status'), str))
    if format in operation_formats or report_kind is not None:
        validate_seal(data)
    elif format in metrics_formats or verification_report:
        if 'fingerprint' in data:
            validate_seal(data)
    else:
        raise ValueError('unsupported directory material')
    # Current search.verify returns an unversioned read-only summary; this does
    # not authorize treating arbitrary unversioned operations as valid plans.
    if (not verification_report or 'schema_version' in data) and (type(data.get('schema_version')) is not int or data['schema_version'] != 1):
        raise ValueError('unsupported directory schema')
    plan = data
    if format == 'fifan-directory-journal':
        plan = data.get('plan')
        if not isinstance(plan, dict):
            raise ValueError('invalid directory journal plan')
        validate_seal(plan)
        if (plan.get('format') != 'fifan-directory-plan' or type(plan.get('schema_version')) is not int or plan['schema_version'] != 1
                or plan.get('kind') != kind or plan.get('operation_id') != data.get('operation_id')):
            raise ValueError('directory journal/plan mismatch')
        if any(key in data and key in plan and data[key] != plan[key]
               for key in ('profile_sha256', 'config_sha256', 'root_identity')):
            raise ValueError('directory journal/plan binding mismatch')
    files = None
    source_scope = 'Unknown'

    def declaration(path, scope_kind, treatment, destination=None):
        if path != '.' or scope_kind != 'directory':
            c._relative(path, config)
        if destination is not None:
            c._relative(destination, {})
        return {'path': path, 'scope_kind': scope_kind, 'destination': destination,
                'kind': kind or format, 'treatment': treatment,
                'applied_rewrite': False, 'document_body_governance': False,
                'current_state': {'status': 'Unknown', 'sha256': None, 'bytes': None}}

    def batches(value, treatment):
        if not isinstance(value, list):
            raise ValueError('invalid directory batches')
        result = []
        for entry in value:
            if not isinstance(entry, dict) or 'source' not in entry:
                raise ValueError('invalid directory batch')
            result.append(declaration(entry['source'], 'directory', treatment, entry.get('destination')))
        return result

    if format in {'fifan-directory-plan', 'fifan-directory-journal', 'fifan-directory-restore-plan'}:
        if kind == 'search-config':
            declarations = plan.get('files')
            if not isinstance(declarations, list):
                raise ValueError('invalid search declaration')
            files = [declaration(entry['path'], 'file', 'search_config_recorded') for entry in declarations]
        elif kind == 'directory-archive':
            files = batches(plan.get('batches'), 'archive_operation_recorded')
        else:
            raise ValueError('unsupported directory operation kind')
        source_scope = 'Declared'
    elif report_kind == 'directory-census':
        roots = data.get('scan_roots')
        if not isinstance(roots, list):
            raise ValueError('invalid census scope')
        files = [declaration(path, 'directory', 'metadata_check_only') for path in roots]
        source_scope = 'Declared'
    elif report_kind == 'directory-impact':
        files = batches(data.get('batches'), 'impact_check_only')
        source_scope = 'Declared'
    elif format == 'fifan-directory-workflow':
        request = data.get('request')
        if isinstance(request, dict) and 'batches' in request:
            files = batches(request['batches'], 'workflow_batch_recorded')
            source_scope = 'Declared'
        # Search/inspect workflows without explicit batches do not declare the
        # payload scope in their receipt. Do not follow artifact paths to guess.
    elif format == 'fifan-directory-metrics':
        cohort = data.get('cohort')
        if not isinstance(cohort, dict) or data.get('cohort_sha256') != digest(cohort):
            raise ValueError('invalid metrics cohort')
        files = batches(cohort.get('batches'), 'metadata_measurement_only')
        source_scope = 'Declared'
    # A metrics evaluation and native verify summary carry no source list.
    # Their explicit Unknown scope is not an empty set or a completed action.
    material_kind = format or report_kind or kind
    return {'kind': material_kind, 'operation_kind': kind, 'status': 'recorded',
            'recorded_status': data.get('status', 'Unknown'),
            'recorded_state': data.get('state', 'preview_only' if format in {'fifan-directory-plan', 'fifan-directory-restore-plan'} else 'Unknown'),
            'files': files, 'source_scope': source_scope, 'applied_rewrite': False,
            'document_body_governance': False, 'verification': 'Not run',
            'meaning': 'Stored declarations or observations only; current payload and external roots were not verified.'}


def history(root, config, records_dirs, *, max_files=MAX_RECORDS, max_bytes=MAX_TOTAL):
    root = c._root(root)
    if not 1 <= max_files <= MAX_RECORDS or not 1 <= max_bytes <= MAX_TOTAL:
        raise ValueError('invalid history budget')
    if not records_dirs:
        raise ValueError('explicit records directories required')
    budget, entries, skipped, visited = [0, 0, max_bytes, max_files], [], 0, 0
    unreadable = 0
    unbound_directory = 0
    pending = [_external(root, p) for p in records_dirs]
    seen = set()
    with c._project_lock(root, exclusive=False):
        while pending:
            directory = pending.pop()
            if str(directory) in seen:
                continue
            seen.add(str(directory))
            fd = c._open_directory(directory)
            try:
                names = []
                with os.scandir(fd) as iterator:
                    for entry in iterator:
                        visited += 1
                        if visited > max_files:
                            raise ValueError('history entry budget exceeded')
                        names.append(entry.name)
                for name in sorted(names):
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    path = directory / name
                    if stat.S_ISLNK(st.st_mode):
                        skipped += 1
                    elif stat.S_ISDIR(st.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(st.st_mode) and name.endswith('.json'):
                        try:
                            data, sha, _ = _load(root, path, budget)
                        except (ValueError, OSError):
                            if budget[0] > max_bytes or budget[1] > max_files:
                                raise ValueError('history material budget exceeded')
                            unreadable += 1
                            skipped += 1
                            continue
                        plan = data.get('plan', data)
                        bindings = _history_bindings(data)
                        if str(root) not in bindings:
                            if _is_directory_material(data) and not any(isinstance(v, str) and v for v in bindings):
                                unbound_directory += 1
                            skipped += 1
                            continue
                        item = {'path': str(path), 'sha256': sha, 'semantic_acceptance': 'Unknown',
                                'files': None, 'source_scope': 'Unknown'}
                        try:
                            if any(value != str(root) for value in bindings):
                                raise ValueError('conflicting record project bindings')
                            if _is_directory_material(data):
                                item.update(_directory_history(data, config))
                            elif 'backups' in data:
                                backups = c._validate_record(root, data, config)
                                item['files'] = _operation_files(root, config, plan, data, backups)
                                item['source_scope'] = 'Known'
                                result = c._verify(root, data, config)
                                applied = data['status'] == 'applied'
                                item.update(kind='journal', status=data['status'], applied_rewrite=applied and any(c._kind(o) == 'move' or (c._kind(o) == 'replace' and o['before_sha256'] != o['after_sha256']) for o in plan['operations']),
                                            recorded_byte_reduction=applied and any(c._kind(o) == 'replace' and len(b) > len(b.decode('utf-8').replace(o['old'], o['new'], 1).encode('utf-8')) for o, b in zip(plan['operations'], backups)),
                                            archive_created=applied and any(c._kind(o) in {'move', 'snapshot'} for o in plan['operations']), recovered=data['status'] == 'recovered',
                                            current_drift=result['journal_consistency'] == 'Failed', verification=result['status'])
                            elif 'operations' in data:
                                c._validate_plan(root, data, config, current=False)
                                item['files'] = _operation_files(root, config, data)
                                item['source_scope'] = 'Known'
                                item.update(kind='plan', status='preview_only', applied_rewrite=False)
                            elif data.get('schema_version') == 1 and 'checks' in data:
                                item['files'], item['source_scope'] = _report_files(data, config)
                                item.update(kind='report', status='check_only', applied_rewrite=False)
                            else:
                                skipped += 1
                                continue
                        except (ValueError, OSError, KeyError, TypeError, UnicodeError):
                            item.update(kind='Unknown', status='Unknown', source_scope='Unknown', files=None)
                        entries.append(item)
            finally:
                os.close(fd)
    status = 'Unknown' if unreadable or unbound_directory or any(x['status'] == 'Unknown' or x['source_scope'] == 'Unknown' for x in entries) else 'Passed'
    return {'schema_version': 1, 'root': str(root), 'status': status, 'records': entries,
            'coverage': {'status': status, 'explicit_record_directories_complete': True,
                         'project_document_coverage': 'Unknown', 'unreadable_materials': unreadable,
                         'unbound_directory_materials': unbound_directory,
                         'meaning': 'Only explicit record materials were searched; absent paths are not proof of no governance.'},
            'skipped': skipped, 'read_bytes': budget[0], 'visited_entries': visited,
            'semantic_acceptance': 'Unknown'}
