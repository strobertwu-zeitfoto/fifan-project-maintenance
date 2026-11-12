"""Fixed cleanup-first maintenance sequence; approvals remain runtime inputs.

The private receipt coordinates existing engines. It does not grant permission,
replace their locks, select blocked subsets, or turn missing inputs into zeros.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import secrets

from . import directory_common as dc

FORMAT = 'fifan-maintenance-workflow'
AFTER_KINDS = {'directory-inspect', 'directory-search', 'directory-archive', 'task-check', 'file-plan'}


def _fail(code):
    raise dc.DirectoryError(code, code)


def _reason(error):
    return getattr(error, 'reason_code', 'MAINTENANCE_WORKFLOW_FAILED')


def _external_input(profile, value, limit=None):
    if not isinstance(value, (str, os.PathLike)):
        _fail('INVALID_INPUT')
    raw = Path(value).expanduser().absolute()
    parent = dc.safe_root(raw.parent)
    if parent == profile.root or parent.is_relative_to(profile.root):
        _fail('PROTECTED_PATH')
    path = dc.canonical_destination(parent / raw.name, allow_missing_parents=False)
    if path == profile.root or path.is_relative_to(profile.root):
        _fail('PROTECTED_PATH')
    return path, dc.load_artifact(path, limit or profile.budgets['max_artifact_bytes'])


def _record_path(records, value, *, allow_missing_parents=False):
    raw = Path(value).expanduser().absolute()
    if '..' in raw.parts or raw == records or not raw.is_relative_to(records):
        _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
    actual = dc.canonical_destination(raw, allow_missing_parents=allow_missing_parents)
    if actual == records or not actual.is_relative_to(records):
        _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
    return actual


def _result_status(value):
    if 'status' in value:
        return value['status']
    if value.get('has_failures'):
        return 'Failed'
    coverage = value.get('coverage')
    if not isinstance(coverage, list) or any(c.get('status') != 'Passed' for c in coverage):
        return 'Unknown'
    return 'Passed'


def _artifact_fingerprint(value):
    return value.get('fingerprint', value.get('operation_id'))


def _public(value):
    fields = ('format', 'schema_version', 'root', 'operation_id', 'workflow_path', 'mode',
              'status', 'state', 'completion', 'reason_code', 'next_action', 'cleanup_state',
              'cleanup_journal', 'cleanup_status', 'inspection_status', 'global_coverage_status',
              'after_action', 'after_metrics', 'measurements', 'report_path', 'measurement_note', 'preexisting_plan', 'measurement_span')
    result = {key: copy.deepcopy(value[key]) for key in fields if key in value}
    if 'after_metrics' not in result:
        metrics = _empty_after_metrics()
        action = result.get('after_action', {})
        if action.get('write_performed'):
            domain = {'file-plan': 'body', 'directory-search': 'search', 'directory-archive': 'archive'}.get(action.get('kind'))
            if domain:
                metrics[domain] = {'status': 'Unknown', 'reason_code': 'AFTER_METRICS_NOT_RECORDED'}
                if result.get('status') == 'Passed':
                    result['status'] = 'Unknown'
        result['after_metrics'] = metrics
        if action:
            action['metrics'] = copy.deepcopy(metrics)
    result['steps'] = copy.deepcopy(value.get('steps', [])[-6:])
    result['step_count'] = len(value.get('steps', []))
    result['earlier_steps_in_receipt'] = result['step_count'] > 6
    result['model_calls'] = 0
    result['global_no_dependencies'] = 'Unknown'
    return result


def _after_declaration(profile, after, after_archive_root, mode, records):
    if after is None:
        if after_archive_root is not None:
            _fail('INVALID_INPUT')
        return None, {}, None
    if not isinstance(after, dict) or after.get('kind') not in AFTER_KINDS or 'profile' not in after:
        _fail('INVALID_INPUT')
    fields = {'kind', 'profile'} | {
        'directory-inspect': {'request'}, 'directory-search': {'plan', 'approve_plan'},
        'directory-archive': {'request', 'plan', 'approve_plan', 'archive_root'},
        'task-check': {'checks'}, 'file-plan': {'checks', 'plan', 'approve_plan'},
    }[after['kind']]
    if set(after) - fields:
        _fail('INVALID_INPUT')
    declaration = copy.deepcopy(after)
    path, data = _external_input(profile, after['profile'], 256 * 1024)
    inputs = {'profile': {'path': str(path), 'sha256': dc.digest(data)}}
    directory = None
    if after['kind'].startswith('directory-'):
        directory = dc.load_profile(profile.root, profile.config, data, external_metadata=False)
    else:
        from .scope import task_config
        task_config(profile.root, profile.config, profile=path, checks=after.get('checks'))
    candidate = None
    if 'plan' in after:
        plan_path, plan = _external_input(profile, after['plan'])
        inputs['plan'] = {'path': str(plan_path), 'sha256': dc.digest(plan)}
        candidate = plan
    if 'request' in after:
        if not isinstance(after['request'], dict):
            _fail('INVALID_INPUT')
    arc = None
    if after_archive_root is not None:
        if after['kind'] not in {'directory-archive', 'directory-search'}:
            _fail('INVALID_INPUT')
        arc = dc.safe_root(after_archive_root)
    search_write = (after['kind'] == 'directory-search' and mode != 'inspect' and candidate is not None
                    and isinstance(after.get('approve_plan'), str)
                    and after['approve_plan'] == _artifact_fingerprint(candidate))
    declared_arc = directory.data['archive'].get('archive_root') if directory is not None else None
    if search_write and declared_arc is not None:
        if arc is None or declared_arc != str(arc):
            _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
    if arc is not None:
        if declared_arc is None or declared_arc != str(arc):
            _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
        if dc.roots_overlap(profile.root, arc) or dc.roots_overlap(records, arc):
            _fail('PROTECTED_PATH')
    if 'archive_root' in after:
        if arc is None or after['archive_root'] != str(arc):
            _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
    return declaration, inputs, arc


class _Run:
    def __init__(self, profile, mode, request, plan, approval, records, quarantine, after,
                 after_inputs, after_arc, resume, t0=None, plan_source=None):
        self.profile, self.records, self.quarantine = profile, records, quarantine
        self.approval = approval  # Runtime only: never recovered from our receipt.
        self.after_arc = after_arc
        self.limit = profile.budgets['max_artifact_bytes']
        self.last_fingerprint = self.last_identity = None
        if resume is not None:
            self.path = _record_path(records, resume)
            value = dc.load_artifact(self.path, self.limit)
            dc.validate_seal(value)
            bindings = {'format': FORMAT, 'schema_version': 1, 'root': str(profile.root),
                        'profile_sha256': profile.sha256, 'config_sha256': dc.digest(profile.config),
                        'records_dir': str(records), 'quarantine_root': str(quarantine) if quarantine else None,
                        'mode': mode, 'workflow_path': str(self.path),
                        'after_archive_root': str(after_arc) if after_arc else None}
            if any(value.get(key) != expected for key, expected in bindings.items()):
                _fail('PROFILE_CONFLICT')
            if request is not None and dc.digest(request) != value.get('request_sha256'):
                _fail('SOURCE_CHANGED')
            if after != value.get('after') or after_inputs != value.get('after_inputs'):
                _fail('SOURCE_CHANGED')
            if plan is not None and _artifact_fingerprint(plan) != value.get('approved_plan_fingerprint'):
                _fail('SOURCE_CHANGED')
            self.value = value
            self.directory = dc.safe_root(self.path.parent)
            self.last_fingerprint = value['fingerprint']
            info = dc.stat_entry(self.directory, self.path.name)
            self.last_identity = info.st_dev, info.st_ino
        else:
            identifier = secrets.token_hex(16)
            with dc.open_dir(records) as fd:
                os.mkdir('maintenance-' + identifier, 0o700, dir_fd=fd)
                os.fsync(fd)
            self.directory = dc.safe_root(records / ('maintenance-' + identifier))
            self.path = self.directory / 'workflow.json'
            self.value = {'format': FORMAT, 'schema_version': 1, 'root': str(profile.root),
                          'profile_sha256': profile.sha256, 'config_sha256': dc.digest(profile.config),
                          'records_dir': str(records), 'quarantine_root': str(quarantine) if quarantine else None,
                          'mode': mode, 'workflow_path': str(self.path), 'operation_id': identifier,
                          'request': copy.deepcopy(request), 'request_sha256': dc.digest(request) if request is not None else None,
                          'approved_plan_fingerprint': _artifact_fingerprint(plan) if plan is not None else None,
                          'after': after, 'after_inputs': after_inputs, 'after_archive_root': str(after_arc) if after_arc else None,
                          'state': 'Prepared', 'status': 'Unknown', 'steps': [], 'measurements': [],
                          'measurement_data': {'T0': t0}, 'cleanup': {}, 'after_progress': {},
                          'completion': 'incomplete', 'preexisting_plan': plan_source,
                          'measurement_span': 'T0 starts after supplied inputs/preview preparation and before this workflow writes run artifacts; earlier preview costs are not a whole-lifecycle measurement.',
                          'measurement_note': 'Final receipt/report writes after the last observation are not measured.'}

    def checkpoint(self):
        if self.last_fingerprint is not None:
            current = dc.load_artifact(self.path, self.limit)
            dc.validate_seal(current)
            info = dc.stat_entry(self.directory, self.path.name)
            if current.get('fingerprint') != self.last_fingerprint or (info.st_dev, info.st_ino) != self.last_identity:
                _fail('JOURNAL_CHANGED')
        sealed = dc.seal(self.value)
        dc.write_artifact(self.path, sealed, replace=self.last_fingerprint is not None, limit=self.limit)
        self.value['fingerprint'] = sealed['fingerprint']
        info = dc.stat_entry(self.directory, self.path.name)
        self.last_fingerprint = self.value['fingerprint']
        self.last_identity = info.st_dev, info.st_ino

    def observation(self, name, value):
        return self.save(name + '-' + secrets.token_hex(6), value)

    def save(self, name, value):
        path = self.directory / (name + '.json')
        try:
            current = dc.load_artifact(path, self.limit)
        except FileNotFoundError:
            dc.write_artifact(path, value, limit=self.limit)
        else:
            if current != value:
                _fail('JOURNAL_CHANGED')
        return str(path)

    def load(self, path):
        return dc.load_artifact(_record_path(self.records, path), self.limit)

    def exists(self, path):
        path = _record_path(self.records, path, allow_missing_parents=True)
        try:
            dc.stat_entry(path.parent, path.name)
            return True
        except FileNotFoundError:
            return False

    def step(self, name, result, artifact=None):
        self.value['steps'].append({'step': name, 'status': _result_status(result),
                                    'state': result.get('state'), 'artifact': artifact})
        self.checkpoint()

    def before_write(self):
        from .cleanup_policy import validate_profile_root
        validate_profile_root(self.profile)

    def expect(self, result, state=None):
        if result.get('status') != 'Passed' or state is not None and result.get('state') != state:
            _fail(result.get('reason_code', 'MAINTENANCE_STAGE_INCOMPLETE'))

    def after_input(self, name):
        ref = self.value['after_inputs'][name]
        _, data = _external_input(self.profile, ref['path'])
        if dc.digest(data) != ref['sha256']:
            _fail('SOURCE_CHANGED')
        return ref['path'], data


def _cleanup_plan_request(plan):
    request = plan.get('request')
    if not isinstance(request, dict):
        _fail('ARTIFACT_INVALID')
    return request


def _require_cleanup_approval(run, plan):
    dc.validate_seal(plan)
    if plan.get('format') != 'fifan-cleanup-plan' or plan.get('kind') != 'quarantine':
        _fail('CLEANUP_FORMAT_UNSUPPORTED')
    if not isinstance(run.approval, str) or run.approval != plan['fingerprint']:
        _fail('APPROVAL_REQUIRED')
    if plan['fingerprint'] != run.value['approved_plan_fingerprint']:
        _fail('SOURCE_CHANGED')
    from . import cleanup_policy as policy
    original = policy.validate_request(run.profile, _cleanup_plan_request(plan))
    supplied = policy.validate_request(run.profile, run.value['request'])
    if dc.digest(original) != dc.digest(supplied):
        _fail('SOURCE_CHANGED')
    if run.value['mode'] == 'purge':
        from .cleanup_operations import request_allows_purge
        if not request_allows_purge(original):
            _fail('APPROVAL_REQUIRED')


def _measurement(run, stage, plan=None, journal=None):
    from .cleanup_reporting import measure
    if stage in run.value['measurement_data']:
        value = run.value['measurement_data'][stage]
    else:
        value = measure(run.profile, run.value['request'], run.quarantine, run.records,
                        plan=plan, journal=journal, stage=stage)
        run.value['measurement_data'][stage] = value
    existing = next((item for item in run.value['measurements'] if item['stage'] == stage), None)
    if existing is not None:
        if run.load(existing['artifact']) != value:
            _fail('JOURNAL_CHANGED')
        return value
    path = run.observation('measurement-' + stage, value)
    run.value['measurements'].append({'stage': stage, 'status': value.get('status', 'Unknown'), 'artifact': path})
    run.checkpoint()
    return value


def _inspect(run):
    from .cleanup_policy import inspect
    if 'inspect_path' in run.value:
        return run.load(run.value['inspect_path'])
    result = inspect(run.profile, run.value['request'])
    run.value['inspect_path'] = run.observation('inspect', result)
    run.step('inspect', result, run.value['inspect_path'])
    return result


def _cleanup(run, supplied_plan):
    from . import cleanup_operations as ops
    progress = run.value['cleanup']
    if 'plan_path' in progress:
        plan = run.load(progress['plan_path'])
    else:
        if supplied_plan is None:
            _fail('APPROVAL_REQUIRED')
        plan = supplied_plan
        _require_cleanup_approval(run, plan)
        progress['plan_path'] = run.save('cleanup-plan', plan)
        progress['operation_id'] = plan['operation_id']
        progress['journal_path'] = str(run.records / ('cleanup-' + plan['operation_id']) / 'journal.json')
        progress['intent'] = 'quarantine'
        run.value['state'] = 'Cleaning'
        run.checkpoint()  # Every future apply retry is bound to this exact id.
    _require_cleanup_approval(run, plan)
    path = progress['journal_path']
    journal = run.load(path) if run.exists(path) else None
    if journal is None:
        run.before_write()
        journal = ops.apply(run.profile, plan, run.quarantine, run.records, approve_plan=run.approval)
    elif (journal.get('state') not in {'Quarantined', 'Purged'}
          or journal.get('intent') is not None
          or journal.get('direction') != {'Quarantined': 'quarantine', 'Purged': 'purge'}.get(journal.get('state'))
          or (journal.get('state') == 'Quarantined'
              and (journal.get('purge_plan') is not None or journal.get('restore_plan') is not None))):
        # An action plan/direction is durable before its continuation updates
        # state. Quarantined alone is not a terminal quarantine receipt here.
        if journal.get('direction') == 'purge' or journal.get('purge_plan') is not None:
            if run.value['mode'] != 'purge' or 'purge_plan_path' not in progress:
                _fail('APPROVAL_REQUIRED')
            purge_plan = run.load(progress['purge_plan_path'])
            run.before_write()
            journal = ops.recover(run.profile, journal, run.quarantine, run.records,
                                  approve_plan=run.approval, approve_purge=purge_plan['fingerprint'])
        else:
            run.before_write()
            journal = ops.recover(run.profile, journal, run.quarantine, run.records, approve_plan=run.approval)
    checked = ops.verify(run.profile, journal, run.quarantine, run.records)
    run.expect(checked)
    if journal.get('state') not in {'Quarantined', 'Purged'}:
        _fail('MAINTENANCE_STAGE_INCOMPLETE')
    run.value['cleanup_journal'], run.value['cleanup_state'] = path, journal['state']
    if journal['state'] == 'Purged' and run.value['mode'] != 'purge':
        _fail('CLEANUP_STATE_CHANGED')
    if journal['state'] == 'Quarantined':
        _measurement(run, 'T1', plan, journal)
    elif 'T1' not in run.value['measurement_data']:
        # A process can exit after purge but before recording T2; T1 must have
        # been checkpointed before purge intent, never reconstructed afterward.
        _fail('MEASUREMENT_BASELINE_MISSING')
    if run.value['mode'] == 'purge' and journal['state'] != 'Purged':
        if 'purge_plan_path' in progress:
            purge_plan = run.load(progress['purge_plan_path'])
        else:
            existing = run.directory / 'purge-plan.json'
            if run.exists(existing):
                purge_plan = run.load(existing)
            else:
                # No new approval object: only the original exact request's
                # purge action/loss permission can authorize this preparation.
                purge_plan = ops.purge_preview(run.profile, journal, run.quarantine, run.records)
            progress['purge_plan_path'] = run.save('purge-plan', purge_plan)
            progress['purge_fingerprint'] = purge_plan['fingerprint']
            progress['intent'] = 'purge'
            run.value['state'] = 'Purging'
            run.checkpoint()
        run.before_write()
        journal = ops.purge(run.profile, purge_plan, run.quarantine, run.records,
                            approve_plan=purge_plan['fingerprint'])
        checked = ops.verify(run.profile, journal, run.quarantine, run.records)
        run.expect(checked, 'Purged')
        if journal.get('state') != 'Purged':
            _fail('MAINTENANCE_STAGE_INCOMPLETE')
    if journal['state'] == 'Purged':
        _measurement(run, 'T2', plan, journal)
    run.value['cleanup_state'] = journal['state']
    run.value['cleanup_status'] = checked['status']
    progress['complete'] = True
    run.step('cleanup-verified', checked, path)
    return plan, journal


def _rebaseline(run, journal):
    from .cleanup_policy import rebaseline
    if run.value['after_progress'].get('intent') and 'baseline_path' in run.value:
        return run.load(run.value['baseline_path'])
    run.value['state'] = 'Rebaselining'
    run.checkpoint()
    original = journal['quarantine_plan']
    relocations = {item['source']: (None if journal['state'] == 'Purged' else
                   {'root': str(run.quarantine), 'path': item['quarantine_relative']})
                   for item in original['items']}
    value = rebaseline(run.profile, run.value['request'], relocations=relocations)
    if 'baseline_path' in run.value:
        previous = run.load(run.value['baseline_path'])
        if previous.get('material') != value.get('material'):
            _fail('SOURCE_CHANGED')
        run.expect(value)
        return value
    run.value['baseline_path'] = run.observation('retained-baseline', value)
    run.step('rebaseline', value, run.value['baseline_path'])
    run.expect(value)
    return value


def _after_profile(run):
    path, data = run.after_input('profile')
    kind = run.value['after']['kind']
    if kind.startswith('directory-'):
        return dc.load_profile(run.profile.root, run.profile.config, data, external_metadata=False)
    from .scope import task_config
    return task_config(run.profile.root, run.profile.config, profile=Path(path), checks=run.value['after'].get('checks'))


def _after_readonly(run, profile):
    after = run.value['after']
    if after['kind'] == 'directory-search':
        from .search_view import search_preview
        return search_preview(profile)
    if after['kind'].startswith('directory-'):
        from .directory_census import census, impact
        value = census(profile)
        if isinstance(after.get('request'), dict):
            # The explicit directory request authorizes only its own declared
            # references. Never follow a plan's external ARC without a grant.
            inspected = impact(profile, after['request'])
            statuses = [value['status'], inspected['status']]
            status = ('Blocked' if 'Blocked' in statuses else 'Failed' if 'Failed' in statuses
                      else 'Unknown' if 'Unknown' in statuses else 'Passed')
            value = {'status': status, 'census': value, 'impact': inspected}
        return value
    from .engine import run as check
    return check(run.profile.root, task_profile=run.value['after_inputs']['profile']['path'],
                 checks=after.get('checks'))


def _after_plan(run):
    _, plan = run.after_input('plan')
    fingerprint = _artifact_fingerprint(plan)
    approval = run.value['after'].get('approve_plan')
    if not isinstance(approval, str) or not approval or approval != fingerprint:
        return None
    return plan


def _empty_after_metrics():
    return {name: {'status': 'Not run'} for name in ('body', 'search', 'archive')}


def _archive_observation(run, profile, plan):
    from .directory_metrics import measure
    try:
        return measure(profile, plan['request'], run.after_arc, run.records)
    except (ValueError, OSError) as error:
        return {'status': 'Unknown', 'reason_code': _reason(error)}


def _after_metrics(run, kind, profile, plan, journal, verified):
    metrics = _empty_after_metrics()
    if kind == 'directory-search':
        validation = journal.get('validation') or {}
        metrics['search'] = {key: copy.deepcopy(validation[key]) for key in
                             ('before', 'after', 'hidden_files', 'critical_paths', 'critical_scope') if key in validation}
        metrics['search'].update(status='Passed' if validation.get('status') == 'Passed' else 'Unknown',
                                 current=copy.deepcopy(verified.get('current_search')),
                                 measurement_span='Actual search apply baseline after cleanup; excludes earlier preview.',
                                 vscode_ui='Not run')
    elif kind == 'file-plan':
        from . import changes
        backups = changes._validate_record(run.profile.root, journal, run.profile.config)
        files, other = [], []
        for op, before in zip(journal['plan']['operations'], backups):
            item = {'path': op['path'], 'kind': changes._kind(op), 'before_bytes': len(before),
                    'before_sha256': op.get('before_sha256', op.get('expected_sha256')),
                    'after_sha256': op.get('after_sha256', op.get('expected_sha256'))}
            if item['kind'] == 'replace':
                item['after_bytes'] = len(before) - len(op['old'].encode('utf-8')) + len(op['new'].encode('utf-8'))
                item['reduction_bytes'] = item['before_bytes'] - item['after_bytes']
                files.append(item)
            else:
                item['destination'] = op['destination']
                other.append(item)
        metrics['body'] = {'status': 'Passed' if files else 'Not run',
                           'basis': 'verified journal content; not an additional live measurement or semantic acceptance',
                           'files': files, 'file_count': len(files), 'other_operations': other,
                           'before_bytes': sum(f['before_bytes'] for f in files) if files else None,
                           'after_bytes': sum(f['after_bytes'] for f in files) if files else None,
                           'reduction_bytes': sum(f['reduction_bytes'] for f in files) if files else None}
    elif kind == 'directory-archive':
        from .directory_metrics import evaluate
        progress = run.value['after_progress']
        before = run.load(progress['archive_before_path']) if progress.get('archive_before_path') else None
        if before is not None and dc.digest(before) != progress.get('archive_before_sha256'):
            _fail('JOURNAL_CHANGED')
        observed = _archive_observation(run, profile, plan)
        after_path = run.observation('after-archive-after', observed)
        progress['archive_after_path'] = after_path
        if before is None:
            value = {'status': 'Unknown', 'reason_code': 'AFTER_BASELINE_MISSING'}
        else:
            value = evaluate(before, observed)
        evaluation_path = run.observation('after-archive-evaluation', value)
        progress['archive_evaluation_path'] = evaluation_path
        metrics['archive'] = {key: copy.deepcopy(value[key]) for key in
                              ('status', 'reason_code', 'reasons', 'project_reduction_bytes', 'archive_increase_bytes',
                               'records_increase_bytes', 'combined_delta_bytes') if key in value}
        metrics['archive'].update(before_artifact=progress.get('archive_before_path'), after_artifact=after_path,
                                  evaluation_artifact=evaluation_path, storage_release='Unknown',
                                  measurement_span='After cleanup, immediately before and after the approved archive action.',
                                  records_overlap='Records overlaps cleanup T3; do not add these metrics.')
    artifact = dc.seal({'format': 'fifan-cleanup-report', 'schema_version': 1, 'kind': 'after-metrics',
                        'root': str(run.profile.root), 'profile_sha256': run.profile.sha256,
                        'operation_id': run.value['operation_id'], 'metrics': metrics})
    path = run.observation('after-metrics', artifact)
    summary = copy.deepcopy(metrics)
    body = summary['body']
    if 'files' in body:
        body['files_omitted'] = max(0, len(body['files']) - 8)
        body['files'] = body['files'][:8]
        body['other_operations_omitted'] = max(0, len(body['other_operations']) - 8)
        body['other_operations'] = body['other_operations'][:8]
    search = summary['search']
    for key in ('critical_paths', 'critical_scope'):
        if key in search:
            entries = search[key]
            search[key + '_count'] = len(entries)
            search[key + '_omitted'] = max(0, len(entries) - 8)
            search[key] = dict(list(entries.items())[:8])
    summary['artifact'] = path
    run.value['after_metrics'] = summary
    return summary


def _verify_after_file(run, profile, plan, journal):
    from . import changes
    from .preview_policy import validate_preview_authorization
    if plan is None or journal.get('plan') != plan:
        _fail('SOURCE_CHANGED')
    request = changes._validate_plan(run.profile.root, plan, run.profile.config, current=False)
    validate_preview_authorization(run.profile.root, profile, request)
    value = changes.verify(run.profile.root, journal, run.profile.config)
    run.expect(value)
    return value


def _after_action(run):
    run.before_write()
    after = run.value['after']
    if after is None:
        run.value['after_action'] = {'status': 'Not run', 'kind': None, 'write_performed': False, 'metrics': _empty_after_metrics()}
        run.value['after_metrics'] = _empty_after_metrics()
        return None
    profile = _after_profile(run)
    progress = run.value['after_progress']
    kind = after['kind']
    writable = kind in {'directory-search', 'directory-archive', 'file-plan'} and run.value['mode'] != 'inspect'
    plan = _after_plan(run) if writable and 'plan' in run.value['after_inputs'] else None
    if writable and plan is not None and kind.startswith('directory-'):
        declared = profile.data['archive'].get('records_dir')
        writable = declared is not None and declared == str(run.records)
        if kind == 'directory-archive' and run.after_arc is None:
            writable = False
    if not writable or plan is None:
        value = _after_readonly(run, profile)
        path = run.observation('after-check', value)
        run.value['after_action'] = {'kind': kind, 'status': _result_status(value),
                                    'write_performed': False, 'artifact': path,
                                    'write_authorization': 'Not supplied or inspect mode', 'metrics': _empty_after_metrics()}
        run.value['after_metrics'] = _empty_after_metrics()
        run.step('after-check', value, path)
        return value
    if kind.startswith('directory-'):
        declared = profile.data['archive'].get('records_dir')
        if declared is None or declared != str(run.records):
            _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
        if kind == 'directory-archive' and run.after_arc is None:
            _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
    if not progress:
        progress['plan_path'] = run.save('after-plan', plan)
        progress['operation_id'] = plan['operation_id']
        if kind == 'file-plan':
            progress['journal_path'] = str(run.records / (plan['operation_id'] + '.json'))
        else:
            progress['journal_path'] = str(run.records / (plan['operation_id'] + '.directory.json'))
        progress['intent'] = kind
        run.value['state'] = 'AfterAction'
        run.checkpoint()
    else:
        saved = run.load(progress['plan_path'])
        if saved != plan or progress['operation_id'] != plan['operation_id']:
            _fail('SOURCE_CHANGED')
    path = progress['journal_path']
    journal = run.load(path) if run.exists(path) else None
    run.before_write()
    if kind == 'directory-search':
        from . import search_view as engine
        if plan.get('kind') != 'search-config':
            _fail('DIRECTORY_FORMAT_UNSUPPORTED')
        if journal is None:
            journal = engine.apply(profile, plan, run.records)
        elif journal.get('state') != 'Applied':
            journal = engine.recover(profile, journal, run.records)
        value = engine.verify(profile, journal)
        run.expect(value, 'Applied')
    elif kind == 'directory-archive':
        from . import directory_archive as engine
        if plan.get('kind') != 'directory-archive':
            _fail('DIRECTORY_FORMAT_UNSUPPORTED')
        if journal is None:
            if not progress.get('archive_before_path'):
                baseline = _archive_observation(run, profile, plan)
                progress['archive_before_path'] = run.observation('after-archive-before', baseline)
                progress['archive_before_sha256'] = dc.digest(baseline)
                run.checkpoint()
            journal = engine.apply(profile, plan, run.after_arc, run.records)
        elif journal.get('state') != 'Archived':
            journal = engine.recover(profile, journal, run.after_arc, run.records)
        value = engine.verify(profile, journal, run.after_arc)
        run.expect(value, 'Archived')
    else:
        from . import changes
        from .preview_policy import validate_preview_scope
        request = changes._validate_plan(run.profile.root, plan, run.profile.config, current=False)
        if journal is None:
            validate_preview_scope(run.profile.root, profile, request)
            journal = changes.apply(run.profile.root, plan, run.profile.config, run.records)
        elif journal.get('plan') != plan:
            _fail('SOURCE_CHANGED')
        elif journal.get('status') != 'applied':
            # Legacy recover means undo. Never call it as a forward retry of a
            # partially applied file plan or create a fresh plan to conceal it.
            _fail('AFTER_FILE_PLAN_INTERRUPTED')
        value = _verify_after_file(run, profile, plan, journal)
    check_status, check_path = 'Not run', None
    if kind == 'file-plan' and (after.get('checks') or profile.get('_task', {}).get('checks')):
        checked = _after_readonly(run, profile)
        check_status = _result_status(checked)
        check_path = run.observation('after-file-check', checked)
        run.step('after-file-check', checked, check_path)
    progress['complete'] = True
    result_path = run.observation('after-verify', value)
    run.value['after_action'] = {'kind': kind, 'status': (check_status if check_status != 'Not run' else value['status']),
                                'mechanical_status': value['status'], 'check_status': check_status,
                                'check_artifact': check_path, 'write_performed': True,
                                'journal_path': path, 'artifact': result_path}
    metrics = _after_metrics(run, kind, profile, plan, journal, value)
    run.value['after_action']['metrics'] = metrics
    if any(metrics[name]['status'] == 'Unknown' for name in ('body', 'search', 'archive')) and run.value['after_action']['status'] == 'Passed':
        run.value['after_action']['status'] = 'Unknown'
    run.step('after-verified', value, result_path)
    return {'status': run.value['after_action']['status']}


def _report(run, plan, journal, inspect_result, after_result):
    run.before_write()
    from .cleanup_reporting import evaluate
    last_stage = ('T3' if after_result is not None else 'T2' if run.value.get('cleanup_state') == 'Purged'
                  else 'T1' if run.value.get('cleanup_state') == 'Quarantined' else 'T0')
    if last_stage == 'T3':
        _measurement(run, 'T3', plan, journal)
    if last_stage != 'T0':
        result = evaluate(run.value['measurement_data']['T0'], run.value['measurement_data'][last_stage], stage=last_stage)
        run.value['report_path'] = run.observation('final-report', result)
        run.value['metrics_status'] = result.get('status', 'Unknown')
    else:
        run.value['report_path'] = run.value['measurements'][0]['artifact']
    run.value['inspection_status'] = _result_status(inspect_result)
    run.value['global_coverage_status'] = 'Passed' if run.value['inspection_status'] == 'Passed' else 'Unknown'
    statuses = [run.value['inspection_status']]
    if after_result is not None:
        statuses.append(_result_status(after_result))
    if run.value['mode'] != 'inspect':
        statuses.append(run.value.get('metrics_status', 'Unknown'))
    run.value['status'] = ('Blocked' if 'Blocked' in statuses else 'Failed' if 'Failed' in statuses
                           else 'Unknown' if any(s not in {'Passed', 'Not run'} for s in statuses) else 'Passed')
    run.value['state'] = 'Completed'
    run.value['completion'] = ('inspect_only' if run.value['mode'] == 'inspect' else
                               'purged' if run.value.get('cleanup_state') == 'Purged' else 'quarantined')
    run.value.pop('reason_code', None)
    run.value.pop('next_action', None)
    run.step('report', {'status': run.value['status']}, run.value['report_path'])


def _verify_completed(run):
    """Terminal resume is read-only; its original measurements stay historical."""
    result = _public(run.value)
    try:
        if run.value['mode'] != 'inspect':
            from . import cleanup_operations as ops
            plan = run.load(run.value['cleanup']['plan_path'])
            _require_cleanup_approval(run, plan)
            journal = run.load(run.value['cleanup']['journal_path'])
            expected = 'Purged' if run.value['mode'] == 'purge' else 'Quarantined'
            run.expect(ops.verify(run.profile, journal, run.quarantine, run.records), expected)
        after = run.value['after']
        if after is not None:
            effective = _after_profile(run)
            if run.value['after_action'].get('write_performed'):
                journal = run.load(run.value['after_progress']['journal_path'])
                if after['kind'] == 'directory-search':
                    from .search_view import verify
                    run.expect(verify(effective, journal), 'Applied')
                elif after['kind'] == 'directory-archive':
                    from .directory_archive import verify
                    run.expect(verify(effective, journal, run.after_arc), 'Archived')
                else:
                    _verify_after_file(run, effective, _after_plan(run), journal)
                    if after.get('checks') or effective.get('_task', {}).get('checks'):
                        current = _after_readonly(run, effective)
                        status = _result_status(current)
                        if status != 'Passed':
                            result['status'] = status
                            result['after_action']['current_check_status'] = status
            else:
                current = _after_readonly(run, effective)
                status = _result_status(current)
                if status != 'Passed':
                    result['status'] = 'Unknown' if status == 'Preview' else status
                    result['after_action']['current_check_status'] = status
        result['live_verification'] = 'Passed'
    except (ValueError, OSError) as error:
        result.update(status='Blocked', reason_code=_reason(error), live_verification='Blocked')
        result['recorded_state'] = run.value['state']
    return result


def workflow(profile, *, mode='inspect', request=None, plan=None, approve_plan=None,
             Q=None, records_dir=None, resume=None, after=None, after_archive_root=None):
    """Inspect, approved cleanup, fresh retained baseline, explicit after, report.

    Resume must repeat runtime roots and original quarantine approval. A stored
    workflow/engine receipt is evidence, never a replacement approval source.
    """
    from . import cleanup_policy as policy
    from .cleanup_reporting import measure
    if mode not in {'inspect', 'quarantine', 'purge'} or records_dir is None:
        _fail('INVALID_INPUT')
    policy.validate_profile_root(profile)
    records = dc.safe_root(records_dir)
    if dc.roots_overlap(profile.root, records):
        _fail('PROTECTED_PATH')
    declared = profile.data.get('records_dir')
    if declared is not None and declared != str(records):
        _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
    quarantine = None
    if Q is not None or mode != 'inspect':
        quarantine, checked_records = policy.runtime_roots(profile, Q, records)
        if checked_records != records:
            _fail('EXTERNAL_ROOT_NOT_AUTHORIZED')
    plan_source = None
    if plan is not None and not isinstance(plan, dict):
        path, plan = _external_input(profile, plan)
        plan_source = {'origin': 'existing-file', 'path': str(path), 'fingerprint': _artifact_fingerprint(plan)}
    elif isinstance(plan, dict):
        plan_source = {'origin': 'supplied-plan-data', 'fingerprint': _artifact_fingerprint(plan)}
    if request is not None:
        policy.validate_request(profile, request)
    if mode != 'inspect' and (not isinstance(approve_plan, str) or (resume is None and (plan is None or request is None))):
        _fail('APPROVAL_REQUIRED')
    declaration, after_inputs, after_arc = _after_declaration(profile, after, after_archive_root, mode, records)
    # T0 observes the actual existing records set and exact future namespace.
    # No workflow directory, copied plan or receipt has been created yet.
    t0 = None
    if resume is None:
        t0 = measure(profile, request, quarantine, records, plan=plan, stage='T0')
    run = _Run(profile, mode, request, plan, approve_plan, records, quarantine,
               declaration, after_inputs, after_arc, resume, t0, plan_source)
    with dc.root_lock(run.directory):
        if run.value['state'] == 'Completed':
            return _verify_completed(run)
        previous = run.value.get('reason_code')
        if previous:
            run.value.setdefault('previous_attempts', []).append({'reason_code': previous, 'state': run.value['state']})
        run.checkpoint()
        try:
            run.before_write()
            if resume is not None and request is None:
                request = run.value['request']
            _measurement(run, 'T0')
            inspected = _inspect(run)
            cleanup_plan = journal = None
            if mode != 'inspect':
                cleanup_plan, journal = _cleanup(run, plan)
                _rebaseline(run, journal)
            after_result = _after_action(run)
            _report(run, cleanup_plan, journal, inspected, after_result)
        except Exception as error:
            run.value['state'], run.value['status'] = 'NeedsAttention', 'Blocked'
            run.value['completion'] = 'incomplete'
            run.value['reason_code'] = _reason(error)
            run.value['next_action'] = 'Inspect this receipt and the recorded engine journal; resume only with matching runtime approvals.'
            run.checkpoint()
        return _public(run.value)
