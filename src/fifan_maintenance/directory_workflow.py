"""Explicit, resumable batches over the directory APIs; no semantic decisions."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import secrets

from .directory_common import (DirectoryError, digest, external_roots, load_artifact,
                               open_dir, root_lock, safe_root, seal, stat_entry,
                               validate_seal, write_artifact, canonical_destination, roots_overlap)


def _public(value):
    keys = ('status', 'state', 'phase', 'last_action', 'workflow_path', 'root', 'reason_code',
            'operation_id', 'completion', 'metrics', 'steps', 'next_action')
    result = {key: value[key] for key in keys if key in value}
    steps = result.get('steps', [])
    result['step_count'] = len(steps)
    result['steps'] = steps[-5:]
    result['earlier_steps_in_receipt'] = len(steps) > 5
    if isinstance(result.get('metrics'), dict):
        fields = ('status', 'project_reduction_bytes', 'archive_increase_bytes',
                  'records_increase_bytes', 'combined_delta_bytes', 'storage_release',
                  'exclusive_attribution', 'measurement_note', 'warnings')
        result['metrics'] = {key: value['metrics'][key] for key in fields if key in value['metrics']}
    return result


def _record_location(records, value):
    raw = Path(value).expanduser().absolute()
    # Reject ungranted namespaces before canonical lookup opens their metadata.
    # A caller can use the canonical workflow_path returned by this tool; an
    # alternate spelling of the records-root prefix is conservatively refused.
    if '..' in raw.parts or raw == records or not raw.is_relative_to(records):
        raise DirectoryError('PROFILE_CONFLICT')
    path = canonical_destination(raw, allow_missing_parents=False)
    if path == records or not path.is_relative_to(records):
        raise DirectoryError('PROFILE_CONFLICT')
    return path


class _Run:
    def __init__(self, profile, phase, records_dir, archive_root, request, resume):
        self.profile = profile
        self.records = safe_root(records_dir)
        if roots_overlap(self.records, profile.root):
            raise DirectoryError('PROTECTED_PATH')
        declared = profile.data.get('archive', {}).get('records_dir')
        if declared is not None and canonical_destination(declared) != self.records:
            raise DirectoryError('EXTERNAL_ROOT_NOT_AUTHORIZED')
        self.arc = archive_root
        self.limit = profile.budgets['max_artifact_bytes']
        if phase == 'archive' or archive_root is not None:
            self.arc, _ = external_roots(profile, archive_root, records_dir)
        if resume:
            path = _record_location(self.records, resume)
            value = load_artifact(path, limit=self.limit)
            validate_seal(value)
            if (value.get('format') != 'fifan-directory-workflow' or value.get('schema_version') != 1
                    or value.get('root') != str(profile.root) or value.get('profile_sha256') != profile.sha256
                    or value.get('records_dir') != str(self.records)
                    or value.get('workflow_path') != str(path)
                    or value.get('archive_root') != (str(self.arc) if self.arc else None)
                    or (phase != value.get('phase') and not (phase == 'restore' and value.get('phase') in {'archive', 'search'}))):
                raise DirectoryError('PROFILE_CONFLICT')
            if request is not None and digest(request) != value.get('request_sha256'):
                raise DirectoryError('SOURCE_CHANGED')
            self.value = value
            self.path = path
            self.directory = safe_root(path.parent)
            self.last_fingerprint = value['fingerprint']
            info = stat_entry(self.directory, path.name)
            self.last_identity = (info.st_dev, info.st_ino)
        else:
            identifier = secrets.token_hex(16)
            name = 'workflow-' + identifier
            with open_dir(self.records) as fd:
                os.mkdir(name, 0o700, dir_fd=fd)
                os.fsync(fd)
            self.directory = safe_root(self.records / name)
            self.path = self.directory / 'workflow.json'
            self.value = {'format': 'fifan-directory-workflow', 'schema_version': 1,
                'root': str(profile.root), 'profile_sha256': profile.sha256,
                'records_dir': str(self.records), 'archive_root': str(self.arc) if self.arc else None,
                'operation_id': identifier, 'phase': phase, 'state': 'Prepared',
                'status': 'Unknown', 'request': copy.deepcopy(request),
                'request_sha256': digest(request) if request is not None else None,
                'steps': [], 'batches': [], 'workflow_path': str(self.path)}
            self.last_fingerprint = None
            self.last_identity = None

    def checkpoint(self):
        if self.last_fingerprint is not None:
            current = load_artifact(self.path, limit=self.limit)
            validate_seal(current)
            info = stat_entry(self.directory, self.path.name)
            if current.get('fingerprint') != self.last_fingerprint or (info.st_dev, info.st_ino) != self.last_identity:
                raise DirectoryError('JOURNAL_CHANGED')
        sealed = seal(self.value)
        write_artifact(self.path, sealed, replace=self.last_fingerprint is not None, limit=self.limit)
        # Preserve references to the active batch dictionaries across commits.
        # Replacing the whole tree would detach a caller's in-flight progress.
        self.value['fingerprint'] = sealed['fingerprint']
        info = stat_entry(self.directory, self.path.name)
        self.last_fingerprint = self.value['fingerprint']
        self.last_identity = (info.st_dev, info.st_ino)

    def save(self, name, value):
        path = self.directory / (name + '-' + secrets.token_hex(6) + '.json')
        write_artifact(path, value, limit=self.limit)
        return str(path)

    def step(self, name, result, artifact=None):
        # These are execution receipts, not claims about current old states.
        entry = {'step': name, 'status': result.get('status', 'Unknown'), 'state': result.get('state'), 'artifact': artifact}
        if result.get('reason_code'):
            entry['reason_code'] = result['reason_code']
        self.value['steps'].append(entry)
        self.checkpoint()

    def before_write(self):
        from .project import load_config
        if digest(load_config(self.profile.root)) != digest(self.profile.config):
            raise DirectoryError('SOURCE_CHANGED')

    def record_path(self, path):
        return _record_location(self.records, path)

    def journal_exists(self, path):
        path = self.record_path(path)
        try:
            stat_entry(path.parent, path.name)
            return True
        except FileNotFoundError:
            return False

    def load_saved_plan(self, path):
        return load_artifact(self.record_path(path), limit=self.limit)

    def load_journal(self, path):
        path = self.record_path(path)
        value = load_artifact(path, limit=self.limit)
        if value.get('journal_path') != str(path):
            raise DirectoryError('PROFILE_CONFLICT')
        binding = value.get('plan', value)
        if binding.get('root', binding.get('project_root')) != str(self.profile.root) or binding.get('profile_sha256') != self.profile.sha256:
            raise DirectoryError('PROFILE_CONFLICT')
        return value

    def expect(self, result, state=None):
        if result.get('status') != 'Passed' or state is not None and result.get('state') != state:
            raise DirectoryError(result.get('reason_code') or 'WORKFLOW_VERIFICATION_FAILED')


def _inspect(run):
    from .directory_census import census, impact
    from .search_view import search_preview
    jobs = [('census', lambda: census(run.profile))]
    request = run.value.get('request')
    if request is not None:
        jobs.append(('impact', lambda: impact(run.profile, request)))
    if any(run.profile.data.get('search', {}).values()):
        jobs.append(('search-preview', lambda: search_preview(run.profile)))
    if request is not None and run.arc is not None:
        from .directory_archive import archive_preview
        jobs.append(('archive-preview', lambda: archive_preview(run.profile, request, run.arc, run.records)))
    statuses = []
    for name, function in jobs:
        try:
            result = function()
            artifact = run.save(name, result)
            run.step(name, result, artifact)
            statuses.append(result.get('status', 'Unknown'))
        except (ValueError, OSError) as error:
            code = getattr(error, 'reason_code', 'INSPECT_BLOCKED')
            run.step(name, {'status': 'Blocked', 'reason_code': code})
            statuses.append('Blocked')
    run.value['status'] = ('Blocked' if 'Blocked' in statuses else 'Failed' if 'Failed' in statuses
                           else 'Unknown' if 'Unknown' in statuses else 'Passed')
    run.value['state'] = 'Inspected'


def _search(run, supplied_plan):
    from . import search_view as engine
    path = run.value.get('search_journal')
    if path and run.journal_exists(path):
        current = run.load_journal(path)
        if current.get('state') != 'Applied':
            run.before_write()
            current = engine.recover(run.profile, current, run.records)
        checked = engine.verify(run.profile, current)
        run.expect(checked, 'Applied')
        run.step('search-current-verify', checked)
    else:
        if path:
            if not run.value.get('search_plan'):
                raise DirectoryError('JOURNAL_INVALID')
            plan = run.load_saved_plan(run.value['search_plan'])
            if str(run.records / (plan.get('operation_id', '') + '.directory.json')) != str(run.record_path(path)):
                raise DirectoryError('JOURNAL_INVALID')
        else:
            plan = supplied_plan if supplied_plan is not None else engine.search_preview(run.profile)
        if plan.get('kind') != 'search-config':
            raise DirectoryError('DIRECTORY_FORMAT_UNSUPPORTED')
        run.value['search_plan'] = run.save('search-plan', plan)
        path = str(run.records / (plan['operation_id'] + '.directory.json'))
        run.value['search_journal'] = path
        run.value['state'] = 'Applying'
        run.checkpoint()
        run.before_write()
        current = engine.apply(run.profile, plan, run.records)
        run.expect(current, 'Applied')
        checked = engine.verify(run.profile, current)
        run.expect(checked, 'Applied')
        run.step('search-verified', checked, path)
    run.value['state'], run.value['status'] = 'Completed', 'Passed'
    run.value['completion'] = 'search_applied'


def _new_archive(run, batch, item, purpose):
    from . import directory_archive as engine
    request = {'schema_version': 1, 'batches': [batch]}
    plan = engine.archive_preview(run.profile, request, run.arc, run.records)
    item['plan_path'] = run.save('archive-plan', plan)
    item['journal_path'] = str(run.records / (plan['operation_id'] + '.directory.json'))
    item['stage'] = purpose
    run.checkpoint()
    run.before_write()
    journal = engine.apply(run.profile, plan, run.arc, run.records)
    checked = engine.verify(run.profile, journal, run.arc)
    run.expect(checked, 'Archived')
    run.step(purpose, checked, item['journal_path'])
    return journal


def _restore_one(run, item, journal):
    from . import directory_archive as engine
    plan = engine.restore_preview(run.profile, journal, run.arc)
    item['restore_plan_path'] = run.save('restore-plan', plan)
    run.checkpoint()
    run.before_write()
    journal = engine.restore(run.profile, plan, run.arc, run.records)
    checked = engine.verify(run.profile, journal, run.arc)
    run.expect(checked, 'Restored')
    run.step('restore-verified', checked, item['journal_path'])
    return journal


def _finish_pilot(run, item):
    # Preserve provenance while atomically releasing the active operation slot.
    # A crash after this checkpoint must not treat the restored pilot as the
    # final archive, nor replay its already-restored plan.
    for name in ('journal_path', 'plan_path', 'restore_plan_path'):
        if name in item:
            item['pilot_' + name] = item.pop(name)
    item['pilot_done'], item['stage'] = True, 'New'
    run.checkpoint()


def _resume_prepared_archive(run, batch, item):
    from . import directory_archive as engine
    if not item.get('plan_path'):
        raise DirectoryError('JOURNAL_INVALID')
    plan = run.load_saved_plan(item['plan_path'])
    if (plan.get('kind') != 'directory-archive'
            or digest(plan.get('request')) != digest({'schema_version': 1, 'batches': [batch]})
            or str(run.records / (plan.get('operation_id', '') + '.directory.json')) != str(run.record_path(item['journal_path']))):
        raise DirectoryError('JOURNAL_INVALID')
    run.before_write()
    journal = engine.apply(run.profile, plan, run.arc, run.records)
    checked = engine.verify(run.profile, journal, run.arc)
    run.expect(checked, 'Archived')
    run.step('prepared-archive-resumed', checked, item['journal_path'])
    return journal


def _archive(run):
    from . import directory_archive as engine
    from .directory_metrics import measure, evaluate
    request = run.value.get('request')
    if not isinstance(request, dict) or not isinstance(request.get('batches'), list) or not request['batches']:
        raise DirectoryError('INVALID_INPUT')
    if 'measure_before' not in run.value:
        # The workflow receipt is already present. Its fixed records root is
        # included on both sides; later report writes are explicitly disclosed.
        run.value['measure_before'] = measure(run.profile, request, run.arc, run.records)
        run.checkpoint()
    batches = request['batches']
    if not run.value['batches']:
        run.value['batches'] = [{'source': b['source'], 'stage': 'New', 'pilot_done': False} for b in batches]
        run.checkpoint()
    if [b.get('source') for b in run.value['batches']] != [b.get('source') for b in batches]:
        raise DirectoryError('SOURCE_CHANGED')
    for index, (batch, item) in enumerate(zip(batches, run.value['batches'])):
        path = item.get('journal_path')
        current = None
        if path and run.journal_exists(path):
            current = run.load_journal(path)
            if current.get('state') not in ('Archived', 'Restored'):
                run.before_write()
                current = engine.recover(run.profile, current, run.arc, run.records)
            checked = engine.verify(run.profile, current, run.arc)
            run.expect(checked)
            if item['stage'] == 'Archived':
                run.expect(checked, 'Archived')
                continue
            if current['state'] == 'Restored':
                if index != 0 or item['stage'] not in ('PilotApplying', 'PilotRestoring', 'New') or item['stage'] == 'New' and not item['pilot_done']:
                    raise DirectoryError('PLAN_ALREADY_RESTORED')
                _finish_pilot(run, item)
                current = None
        elif path:
            # The workflow committed the exact plan before calling its engine.
            # If its initial journal is absent, retry that plan's preflight;
            # do not manufacture a new baseline from possibly changed sources.
            current = _resume_prepared_archive(run, batch, item)
        if index == 0 and not item['pilot_done']:
            if current is None:
                current = _new_archive(run, batch, item, 'PilotApplying')
            item['stage'] = 'PilotRestoring'
            run.checkpoint()
            _restore_one(run, item, current)
            _finish_pilot(run, item)
            current = None
        if current is None:
            current = _new_archive(run, batch, item, 'FinalApplying')
        else:
            # Fresh archives were just verified by _new_archive. Existing
            # operations still need this check, and every batch is checked
            # again below after all other batches have completed.
            run.expect(engine.verify(run.profile, current, run.arc), 'Archived')
        item['stage'] = 'Archived'
        run.checkpoint()
    # Recheck current terminal states, never reuse a superseded pilot receipt.
    for item in run.value['batches']:
        run.expect(engine.verify(run.profile, run.load_journal(item['journal_path']), run.arc), 'Archived')
    run.value['state'], run.value['status'] = 'Completed', 'Passed'
    run.value['completion'] = 'all_archived'
    run.checkpoint()
    after = measure(run.profile, request, run.arc, run.records)
    run.value['metrics'] = evaluate(run.value['measure_before'], after)
    run.value['metrics']['measurement_note'] = 'Observed before this final receipt update; subsequent record writes are not attributed or hidden.'


def _restore(run, supplied_journal):
    from . import directory_archive, search_view
    if supplied_journal is not None:
        path = supplied_journal.get('journal_path')
        if not path:
            raise DirectoryError('ARTIFACT_INVALID')
        targets = [{'journal_path': path}]
        run.value['restore_targets'] = targets
    else:
        targets = run.value.get('restore_targets') or list(reversed(run.value.get('batches', [])))
        if not targets and run.value.get('search_journal'):
            targets = [{'journal_path': run.value['search_journal']}]
    if not targets:
        raise DirectoryError('INVALID_INPUT')
    for item in targets:
        journal = run.load_journal(item['journal_path'])
        if journal.get('kind') == 'directory-archive':
            if run.arc is None:
                raise DirectoryError('EXTERNAL_ROOT_NOT_AUTHORIZED')
            if journal.get('state') not in ('Archived', 'Restored'):
                run.before_write()
                journal = directory_archive.recover(run.profile, journal, run.arc, run.records)
            if journal.get('state') != 'Restored':
                _restore_one(run, item, journal)
            run.expect(directory_archive.verify(run.profile, run.load_journal(item['journal_path']), run.arc), 'Restored')
        elif journal.get('kind') == 'search-config':
            if journal.get('state') == 'Restoring':
                run.before_write()
                journal = search_view.recover(run.profile, journal, run.records)
            if journal.get('state') != 'Restored':
                plan = search_view.restore_preview(run.profile, journal)
                item['restore_plan_path'] = run.save('search-restore-plan', plan)
                run.checkpoint()
                run.before_write()
                journal = search_view.restore(run.profile, plan, run.records)
            run.expect(search_view.verify(run.profile, journal), 'Restored')
        else:
            raise DirectoryError('DIRECTORY_FORMAT_UNSUPPORTED')
        item['stage'] = 'Restored'
        run.checkpoint()
    run.value['state'], run.value['status'] = 'Restored', 'Passed'
    run.value['completion'] = 'all_recovered'
    if run.value.get('measure_before') is not None and run.value.get('request') and run.arc is not None:
        from .directory_metrics import measure, evaluate
        if run.value.get('metrics') and 'archive_metrics_artifact' not in run.value:
            run.value['archive_metrics_artifact'] = run.save('archive-metrics', run.value['metrics'])
        run.checkpoint()
        run.value['metrics'] = evaluate(run.value['measure_before'], measure(run.profile, run.value['request'], run.arc, run.records))
        run.value['metrics']['measurement_note'] = 'Restored terminal observation before this final receipt update; later writes remain unmeasured.'


def workflow(profile, *, phase='inspect', request=None, plan=None, journal=None,
             archive_root=None, records_dir=None, resume=None):
    if phase not in ('inspect', 'search', 'archive', 'restore') or records_dir is None:
        raise DirectoryError('INVALID_INPUT')
    if phase == 'inspect' and resume:
        raise DirectoryError('INVALID_INPUT')
    if plan is not None and phase != 'search' or journal is not None and phase != 'restore':
        raise DirectoryError('INVALID_INPUT')
    if resume and (plan is not None or journal is not None):
        raise DirectoryError('INVALID_INPUT')
    initial_measure = None
    if phase == 'archive' and not resume:
        from .directory_metrics import measure
        initial_measure = measure(profile, request, archive_root, records_dir)
    run = _Run(profile, phase, records_dir, archive_root, request, resume)
    with root_lock(run.directory):
        previous_error = run.value.get('reason_code')
        if previous_error and (not run.value['steps'] or run.value['steps'][-1].get('reason_code') != previous_error):
            run.value['steps'].append({'step': 'previous-attempt-failure', 'status': 'Blocked',
                                       'state': run.value.get('state'), 'reason_code': previous_error, 'artifact': None})
        run.value['last_action'] = phase
        if initial_measure is not None:
            run.value['measure_before'] = initial_measure
        run.checkpoint()
        try:
            if phase == 'inspect':
                _inspect(run)
            elif phase == 'search':
                _search(run, plan)
            elif phase == 'archive':
                _archive(run)
            else:
                _restore(run, journal)
        except Exception as error:
            run.value['status'], run.value['state'] = 'Blocked', 'NeedsAttention'
            run.value['reason_code'] = getattr(error, 'reason_code', 'WORKFLOW_FAILED')
            run.value['completion'] = 'incomplete'
            run.value['next_action'] = 'Inspect this workflow receipt and its exact engine journal; recover only the recorded operation.'
            run.value['steps'].append({'step': phase + '-blocked', 'status': 'Blocked', 'state': 'NeedsAttention',
                                       'reason_code': run.value['reason_code'], 'artifact': None})
            run.checkpoint()
            return _public(run.value)
        if run.value.get('status') == 'Passed':
            run.value.pop('reason_code', None)
            run.value.pop('next_action', None)
        run.checkpoint()
        return _public(run.value)
