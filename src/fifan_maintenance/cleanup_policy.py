"""Data-only cleanup policy and read-only eligibility; never a deletion grant.

Inspect reads metadata only. Qualification scans retained consumers and explicit
proofs; same-approved-batch historical process logs can be omitted as consumers.
Relocations are an internal observation adapter, never accepted from task JSON.
"""
from __future__ import annotations

import copy
import fnmatch
import os
from pathlib import Path
import re
import stat
import time
from dataclasses import dataclass, field

from . import directory_common as dc
from .directory_census import _References, _references_to, _Walk

KINDS = {'old_build', 'completed_log', 'disposable_output'}
PROFILE_FIELDS = {'schema_version', 'project_root', 'preset', 'scan_roots', 'current', 'keep',
                  'protected', 'candidates', 'rules', 'reference_sources', 'streaming_references',
                  'quarantine_root', 'records_dir', 'require_no_open_handles', 'budgets', 'reference_batching'}
BUILD_FIELDS = {'platform', 'branch', 'configuration', 'purpose'}
HARD_ROOTS = {'src', 'source', 'scripts', 'tools', 'assets', 'resources', 'packages', 'projectsettings',
              'library', 'temp', 'obj', 'usersettings', 'node_modules', 'saves', 'savedata', 'userdata', 'data'}
CODE_SUFFIXES = {'.py', '.cs', '.cpp', '.c', '.h', '.hpp', '.js', '.ts', '.tsx', '.jsx', '.swift',
                 '.java', '.go', '.rs', '.sh', '.command', '.sql', '.save', '.sqlite', '.sqlite3', '.db'}


@dataclass
class CleanupProfile:
    root: Path
    config: dict
    data: dict
    sha256: str
    budgets: dict
    _root_identity: tuple = field(default=(), init=False, repr=False)
    _config_sha256: str = field(default='', init=False, repr=False)
    _control_sha256: str = field(default='', init=False, repr=False)
    _config_signature: tuple = field(default=(), init=False, repr=False)


def _fail(code='INVALID_INPUT', message='invalid cleanup data'):
    raise dc.DirectoryError(code, message)


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _sha(value):
    return isinstance(value, str) and bool(re.fullmatch('[0-9a-f]{64}', value))


def _within(path, parent):
    a, b = dc.path_key(path), dc.path_key(parent)
    return b == '.' or a == b or a.startswith(b + '/')


def _overlap(first, second):
    return _within(first, second) or _within(second, first)


def _paths(value, *, dot=False):
    if not isinstance(value, list):
        _fail()
    for path in value:
        dc.relative(path, allow_dot=dot)
    if len({dc.path_key(path) for path in value}) != len(value):
        _fail('PATH_ALIAS', 'duplicate cleanup path declaration')
    return copy.deepcopy(value)


def _evidence(value, *, required=False):
    if not isinstance(value, list) or len(value) > 100 or required and not value:
        _fail()
    seen = set()
    for proof in value:
        if not isinstance(proof, dict) or set(proof) != {'path', 'sha256'} or not _sha(proof['sha256']):
            _fail()
        dc.relative(proof['path'])
        key = dc.path_key(proof['path'])
        if key in seen:
            _fail('PATH_ALIAS')
        seen.add(key)
    return copy.deepcopy(value)


def _build(value):
    if not isinstance(value, dict) or set(value) != BUILD_FIELDS or any(not _text(v) or v.casefold() == 'unknown' for v in value.values()):
        _fail('BUILD_GROUP_UNKNOWN', 'build group requires explicit platform, branch, configuration and purpose')
    return copy.deepcopy(value)


def _retained_originals(profile):
    return (profile.data['current'] + [item['path'] for item in profile.data['keep']]
            + [item['path'] for item in profile.data['reference_sources'] if item['role'] == 'current'])


def _old_build_code_child(profile, path):
    # Comparison keys are never authority to enter a build subtree. Preserve
    # exact component spelling, including Unicode, from the declared namespace.
    for item in profile.data['candidates']:
        source = item['path']
        if item['kind'] != 'old_build' or not path.startswith(source + '/'):
            continue
        if (dc.protected(profile, source, archive=True) or dc.path_key(source).split('/')[0] in HARD_ROOTS
                or Path(dc.path_key(source)).suffix in CODE_SUFFIXES
                or any(_overlap(source, kept) for kept in _retained_originals(profile) + profile.data['protected'])):
            continue
        try:
            dc.validate_path_spelling(profile.root, path, allow_missing=True)
            try:
                info = dc.stat_entry(profile.root, source)
            except FileNotFoundError:
                # A moved original is a semantic namespace, not a new IO grant.
                # Operations separately prove the owned relocated manifest.
                return True
            if stat.S_ISDIR(info.st_mode):
                return True
        except (OSError, ValueError):
            continue
    return False


def _hard_protected(profile, path):
    key = dc.path_key(path)
    if key == '.':
        return True
    if dc.protected(profile, path, archive=True):
        return True
    if (key.split('/')[0] in HARD_ROOTS or key == '.fifan-maintenance.json'
            or any(_overlap(path, item) for item in profile.data['protected'])):
        return True
    suffix = Path(key).suffix
    # Saved/production-data formats never become runtime-code exceptions.
    if suffix in {'.save', '.sqlite', '.sqlite3', '.db'}:
        return True
    return suffix in CODE_SUFFIXES and not _old_build_code_child(profile, path)


def protected(profile, rel):
    dc.relative(rel, allow_dot=True)
    retained = _retained_originals(profile)
    return _hard_protected(profile, rel) or any(_overlap(rel, path) for path in retained)


def _configuration_signature(root):
    try:
        info = dc.stat_entry(root, '.fifan-maintenance.json')
    except FileNotFoundError:
        return ('Missing',)
    if not stat.S_ISREG(info.st_mode):
        _fail('PROTECTED_PATH', 'project configuration is not an ordinary file')
    return dc._stable(info)


def validate_profile_root(profile):
    if not isinstance(profile, CleanupProfile):
        _fail()
    # Validate pure control data before using any possibly changed path.
    if (profile.sha256 != profile._control_sha256 or dc.digest(profile.data) != profile.sha256 or profile.budgets != profile.data.get('budgets')
            or dc.digest(profile.config) != profile._config_sha256
            or str(profile.root) != profile.data.get('project_root')):
        _fail('PROFILE_CONFLICT', 'cleanup control data changed after loading')
    info = dc.stat_entry(profile.root, '.')
    if not profile._root_identity or (info.st_dev, info.st_ino) != profile._root_identity:
        _fail('SOURCE_CHANGED', 'cleanup project root was replaced')
    if _configuration_signature(profile.root) != profile._config_signature:
        _fail('SOURCE_CHANGED', 'project configuration changed; load a fresh profile')


def load_profile(root, config, path_or_dict):
    root = dc.safe_root(root)
    if not isinstance(config, dict):
        _fail()
    if isinstance(path_or_dict, dict):
        if len(dc.canonical(path_or_dict)) > dc.MAX_PROFILE_BYTES:
            _fail('BUDGET_EXHAUSTED', 'cleanup profile exceeds 256KiB')
        data = copy.deepcopy(path_or_dict)
    else:
        path = dc.canonical_destination(path_or_dict)
        if path.is_relative_to(root):
            _fail('PROFILE_CONFLICT', 'cleanup profile must be outside project')
        data = dc.load_artifact(path, dc.MAX_PROFILE_BYTES)
    if set(data) - PROFILE_FIELDS or type(data.get('schema_version')) is not int or data['schema_version'] != 1:
        _fail()
    if not isinstance(data.get('project_root'), str) or data['project_root'] != str(root):
        _fail('PROFILE_CONFLICT')
    if data.get('preset', 'generic') not in ('generic', 'unity'):
        _fail()
    result = {'schema_version': 1, 'project_root': str(root), 'preset': data.get('preset', 'generic')}
    for key in ('scan_roots', 'current', 'protected', 'streaming_references'):
        result[key] = _paths(data.get(key, ['.'] if key == 'scan_roots' else []), dot=key == 'scan_roots')
    if not result['scan_roots']:
        _fail()
    if any(not path.lower().endswith(('.log', '.txt')) for path in result['streaming_references']):
        _fail('INVALID_INPUT', 'streaming references must be explicit log/txt files')
    if any(not isinstance(data.get(key, []), list) for key in ('keep', 'candidates', 'rules')):
        _fail()
    result['keep'] = []
    for item in data.get('keep', []):
        if (not isinstance(item, dict) or set(item) - {'path', 'reason', 'build', 'evidence', 'sha256'}
                or not {'path', 'reason'} <= set(item) or not _text(item['reason'])):
            _fail()
        dc.relative(item['path'])
        value = copy.deepcopy(item)
        if 'build' in value:
            value['build'] = _build(value['build'])
        value['evidence'] = _evidence(value.get('evidence', []))
        if 'sha256' in value and not _sha(value['sha256']):
            _fail()
        result['keep'].append(value)
    _paths([item['path'] for item in result['keep']])
    result['candidates'] = []
    for item in data.get('candidates', []):
        if (not isinstance(item, dict) or set(item) - {'path', 'kind', 'disposal_policy'}
                or not {'path', 'kind'} <= set(item) or not isinstance(item.get('kind'), str) or item.get('kind') not in KINDS):
            _fail()
        dc.relative(item['path'])
        if 'disposal_policy' in item and (item['kind'] != 'old_build' or item['disposal_policy'] != 'generated_artifact'):
            _fail('INVALID_INPUT', 'generated disposal policy requires an exact old_build candidate')
        result['candidates'].append(copy.deepcopy(item))
    _paths([item['path'] for item in result['candidates']])
    result['rules'] = []
    for item in data.get('rules', []):
        if (not isinstance(item, dict) or set(item) != {'kind', 'glob', 'reason'} or not isinstance(item.get('kind'), str) or item.get('kind') not in KINDS
                or not _text(item.get('reason'))):
            _fail()
        dc.relative(item['glob'])
        result['rules'].append(copy.deepcopy(item))
    references = data.get('reference_sources', [])
    if not isinstance(references, list):
        _fail()
    for entry in references:
        if not isinstance(entry, dict) or set(entry) != {'path', 'role'} or entry.get('role') not in ('current', 'historical'):
            _fail()
        dc.relative(entry['path'])
    _paths([item['path'] for item in references])
    result['reference_sources'] = copy.deepcopy(references)
    if type(data.get('require_no_open_handles', True)) is not bool:
        _fail()
    result['require_no_open_handles'] = data.get('require_no_open_handles', True)
    for key in ('quarantine_root', 'records_dir'):
        if key in data:
            result[key] = str(dc._absolute(data[key]))  # Syntax only; runtime roots grant IO later.
    budgets = data.get('budgets', {})
    if not isinstance(budgets, dict) or set(budgets) - set(dc.DEFAULT_BUDGETS):
        _fail()
    for key, value in budgets.items():
        if type(value) is not int or not (0 if key == 'max_depth' else 1) <= value <= dc.HARD_BUDGETS[key]:
            _fail('BUDGET_EXHAUSTED')
    result['budgets'] = {**dc.DEFAULT_BUDGETS, **budgets}
    if 'reference_batching' in data:
        from .reference_batches import validate_options
        result['reference_batching'] = validate_options(data['reference_batching'])
    profile = CleanupProfile(root, copy.deepcopy(config), result, dc.digest(result), copy.deepcopy(result['budgets']))
    info = dc.stat_entry(root, '.')
    profile._root_identity = (info.st_dev, info.st_ino)
    profile._config_sha256 = dc.digest(profile.config)
    profile._control_sha256 = profile.sha256
    profile._config_signature = _configuration_signature(root)
    return profile


def runtime_roots(profile, quarantine_root, records_dir):
    validate_profile_root(profile)
    if quarantine_root is None or records_dir is None:
        _fail('BODY_NOT_AUTHORIZED', 'runtime quarantine and record roots must be explicit')
    q, rec = dc.safe_root(quarantine_root), dc.safe_root(records_dir)
    if any(not profile.data.get(key) or profile.data[key] != str(path)
           for key, path in (('quarantine_root', q), ('records_dir', rec))):
        _fail('PROFILE_CONFLICT', 'runtime cleanup roots must match profile')
    roots = (profile.root, q, rec)
    if any(dc.roots_overlap(a, b) for index, a in enumerate(roots) for b in roots[index + 1:]):
        _fail('PROTECTED_PATH', 'project, quarantine and records roots must not overlap')
    return q, rec


def validate_request(profile, request):
    if (not isinstance(request, dict) or set(request) != {'schema_version', 'approval', 'items'}
            or type(request.get('schema_version')) is not int or request['schema_version'] != 1):
        _fail()
    if len(dc.canonical(request)) > profile.budgets['max_artifact_bytes']:
        _fail('BUDGET_EXHAUSTED')
    approval = request['approval']
    if (not isinstance(approval, dict) or set(approval) != {'reference', 'actions'} or not _text(approval['reference'])
            or not isinstance(approval['actions'], list) or not approval['actions']
            or any(action not in ('quarantine', 'purge') for action in approval['actions'])
            or len(set(approval['actions'])) != len(approval['actions'])):
        _fail('APPROVAL_INVALID')
    items = request['items']
    if not isinstance(items, list) or not 1 <= len(items) <= 100:
        _fail()
    result, seen = copy.deepcopy(request), []
    candidates = {dc.path_key(item['path']): item for item in profile.data['candidates']}
    keep = {dc.path_key(item['path']) for item in profile.data['keep']}
    for item in result['items']:
        fields = {'source', 'kind', 'reason', 'closure', 'loss', 'retained', 'build', 'disposition', 'dynamic_reference_resolutions', 'generated_disposal'}
        if not isinstance(item, dict) or set(item) - fields or not {'source', 'kind', 'reason', 'closure', 'loss', 'retained'} <= set(item):
            _fail()
        source = dc.relative(item['source'])
        declared = candidates.get(dc.path_key(source))
        if declared is None or declared['path'] != source or declared['kind'] != item['kind']:
            _fail('CANDIDATE_NOT_DECLARED')
        if item['kind'] not in KINDS or not _text(item['reason']):
            _fail()
        if any(_overlap(source, previous) for previous in seen):
            _fail('PATH_ALIAS', 'cleanup items overlap')
        seen.append(source)
        item.setdefault('disposition', 'quarantine')
        if item['disposition'] not in ('quarantine', 'purge'):
            _fail()
        closure = item['closure']
        if (not isinstance(closure, dict) or set(closure) != {'decision', 'reason', 'evidence'}
                or closure['decision'] != 'closed' or not _text(closure['reason'])):
            _fail('CLOSURE_NOT_SUPPORTED')
        closure['evidence'] = _evidence(closure['evidence'], required=True)
        loss = item['loss']
        if (not isinstance(loss, dict) or set(loss) != {'accepted', 'rebuildable', 'unique_evidence', 'description'}
                or type(loss['accepted']) is not bool or type(loss['unique_evidence']) is not bool
                or type(loss['rebuildable']) is not bool and loss['rebuildable'] != 'Unknown' or not _text(loss['description'])):
            _fail()
        item['retained'] = _paths(item['retained'])
        if any(dc.path_key(path) not in keep for path in item['retained']):
            _fail('RETAINED_NOT_DECLARED')
        if 'generated_disposal' in item:
            grant = item['generated_disposal']
            if (item['kind'] != 'old_build' or declared.get('disposal_policy') != 'generated_artifact'
                    or not isinstance(grant, dict) or set(grant) != {'generated_only', 'reason'}
                    or grant['generated_only'] is not True or not _text(grant['reason'])
                    or not loss['accepted'] or loss['unique_evidence']):
                _fail('GENERATED_BUILD_APPROVAL_REQUIRED', 'generated build disposal requires exact policy, attestation and explicit loss acceptance')
            build = item.get('build', {})
            if (not isinstance(build, dict) or set(build) - BUILD_FIELDS
                    or any(not _text(value) for value in build.values())):
                _fail('BUILD_GROUP_UNKNOWN', 'provided build metadata must remain explicit text')
            item['build'] = copy.deepcopy(build)
        elif item['kind'] == 'old_build' or 'build' in item:
            item['build'] = _build(item.get('build'))
        resolutions = item.setdefault('dynamic_reference_resolutions', [])
        if not isinstance(resolutions, list) or len(resolutions) > 100000:
            _fail()
        identities = set()
        for entry in resolutions:
            fields = {'source', 'path', 'sha256', 'line', 'column', 'line_sha256', 'expression_sha256', 'reason', 'evidence'}
            if (not isinstance(entry, dict) or set(entry) != fields or entry['source'] != source
                    or type(entry['line']) is not int or entry['line'] < 1 or type(entry['column']) is not int or entry['column'] < 1
                    or not _text(entry['reason']) or any(not _sha(entry[k]) for k in ('sha256', 'line_sha256', 'expression_sha256'))):
                _fail('DYNAMIC_RESOLUTION_MISMATCH')
            dc.relative(entry['path'])
            entry['evidence'] = _evidence(entry['evidence'], required=True)
            key = tuple(entry[k] for k in ('path', 'line', 'column', 'expression_sha256'))
            if key in identities:
                _fail('DYNAMIC_RESOLUTION_MISMATCH')
            identities.add(key)
    return result


def _read_adapter(profile):
    # Read-only derivation, not an archive profile or external-root permission.
    data = {'preset': profile.data['preset'], 'reference_sources': profile.data['reference_sources'],
            'streaming_references': profile.data['streaming_references'], 'classifications': [],
            'critical_paths': profile.data['current'], 'scan_roots': profile.data['scan_roots']}
    if 'reference_batching' in profile.data:
        data['reference_batching'] = profile.data['reference_batching']
    config = copy.deepcopy(profile.config)
    config['protected'] = config.get('protected', []) + profile.data['protected']
    value = dc.DirectoryProfile(profile.root, config, data, profile.sha256, profile.budgets)
    value._root_identity = profile._root_identity
    return value


class _RetainedReferences(_References):
    def __init__(self, profile, items, relocations=None):
        super().__init__(_read_adapter(profile), tuple(item['source'] for item in items))
        self.cleanup_profile, self.items, self.skipped = profile, items, set()
        self.relocations = relocations or {}
        self.source_metadata = {}
        self.active_roots = []

    def discarded(self, path):
        return (not protected(self.cleanup_profile, path)
                and any(not item['loss']['unique_evidence'] and _within(path, item['source'])
                        and (item['kind'] == 'completed_log' or path.lower().endswith(('.log', '.txt')))
                        for item in self.items)
                and not any(entry['role'] == 'current' and _overlap(path, entry['path'])
                            for entry in self.cleanup_profile.data['reference_sources']))

    def reference_roots(self):
        declarations = self.profile.data['reference_sources']
        roots = []
        for declaration in declarations:
            moved_discard = (declaration['role'] == 'historical'
                             and not protected(self.cleanup_profile, declaration['path'])
                             and any(item['source'] in self.relocations and not item['loss']['unique_evidence']
                                     and _within(declaration['path'], item['source']) for item in self.items))
            if declaration['role'] == 'historical' and self.discarded(declaration['path']) or moved_discard:
                self.skipped.add(declaration['path'])
            else:
                roots.append(declaration['path'])
        self.active_roots = roots
        return roots

    def load_all(self):
        declarations = self.profile.data['reference_sources']
        roots = self.reference_roots()
        if 'reference_batching' in self.profile.data:
            from .reference_batches import load_all
            load_all(self, roots)
            return
        try:
            for path, _ in self.walk.walk(roots):
                try:
                    self.read(path)
                except (OSError, ValueError) as error:
                    self.failures[path] = getattr(error, 'reason_code', 'REFERENCE_UNAVAILABLE')
        except dc.DirectoryError as error:
            self.walk.gap('.', error.reason_code)
        if not declarations:
            self.walk.gap('.', 'REFERENCE_SCOPE_EMPTY')

    def read(self, path):
        if self.discarded(path):
            self.skipped.add(path)
            return {'sha256': None, 'bytes': 0, 'role': 'discarded-same-approved-batch'}
        if path in self.cache:
            return self.cache[path]
        before = dc.stat_entry(self.profile.root, path)
        value = super().read(path)
        after = dc.stat_entry(self.profile.root, path)
        if dc._stable(before) != dc._stable(after):
            _fail('SOURCE_CHANGED')
        self.source_metadata[path] = before
        return value


def _reference_snapshot(profile, request, relocations=None):
    items = request['items'] if request else []
    reader = _RetainedReferences(profile, items, relocations)
    current_roots = profile.data['current'] + [entry['path'] for entry in profile.data['reference_sources'] if entry['role'] == 'current']
    reader.load_all()
    # Enumerate necessary current originals independently of body permission.
    # A second walk has its own seen identities but shares remaining work/time.
    adapter = _read_adapter(profile)
    adapter.budgets = {**profile.budgets, 'max_entries': max(0, profile.budgets['max_entries'] - reader.walk.work_entries)}
    current_walk = _Walk(adapter, started=reader.walk.started)
    current_paths, reference_paths = set(), set()
    changed = False
    try:
        for path, info in current_walk.walk(current_roots + reader.active_roots):
            if any(_within(path, scope) for scope in current_roots):
                current_paths.add(path)
            authorized = any(_within(path, entry['path']) and (path == entry['path'] or path.startswith(entry['path'] + '/'))
                             for entry in profile.data['reference_sources'])
            if authorized and not reader.discarded(path):
                reference_paths.add(path)
                old = reader.source_metadata.get(path)
                if old is None or dc._stable(old) != dc._stable(info):
                    changed = True
    except dc.DirectoryError as error:
        current_walk.gap('.', error.reason_code)
    if reference_paths != set(reader.cache):
        changed = True
    missing_scope = [path for path in current_paths if not any(entry['role'] == 'current' and _within(path, entry['path'])
                      and (path == entry['path'] or path.startswith(entry['path'] + '/')) for entry in profile.data['reference_sources'])]
    unknowns = []
    if changed:
        unknowns.append({'reason_code': 'REFERENCE_SET_OR_STATE_CHANGED'})
    if not current_roots:
        unknowns.append({'reason_code': 'CURRENT_SCOPE_EMPTY'})
    if missing_scope:
        unknowns.append({'reason_code': 'CURRENT_REFERENCE_SCOPE_MISSING', 'paths': sorted(missing_scope)})
    fingerprints = [{'path': path, 'sha256': value['sha256'], 'role': value['role'],
                     'identity': {'device': reader.source_metadata[path].st_dev, 'inode': reader.source_metadata[path].st_ino,
                                  'mode': stat.S_IMODE(reader.source_metadata[path].st_mode)}}
                    for path, value in sorted(reader.cache.items()) if path in reader.source_metadata]
    coverage = reader.coverage()
    coverage['current_coverage'] = current_walk.coverage()
    coverage['complete'] = coverage['complete'] and current_walk.complete and not changed
    coverage['count_is_lower_bound'] = not coverage['complete']
    coverage['work_entries'] += current_walk.work_entries
    if not coverage['complete']:
        unknowns.append({'reason_code': 'REFERENCE_COVERAGE_INCOMPLETE'})
    return reader, sorted(current_paths), fingerprints, coverage, unknowns


def _retained_snapshot(profile, paths, *, started=None):
    budget = dc.HashBudget(profile.budgets)
    if started is not None:
        budget.started = started
    declared = {dc.path_key(item['path']): item for item in profile.data['keep']}
    snapshots, failures = [], []
    manifest_bytes = 0
    def append(entries, value):
        nonlocal manifest_bytes
        manifest_bytes += len(dc.canonical(value))
        if manifest_bytes > profile.budgets['max_artifact_bytes']:
            _fail('BUDGET_EXHAUSTED')
        entries.append(value)
    def state(info):
        return {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode),
                'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns, 'nlink': info.st_nlink}
    def visit(path, base, depth, entries):
        budget.check_time()
        if depth > profile.budgets['max_depth']:
            _fail('BUDGET_EXHAUSTED')
        dc.validate_path_spelling(profile.root, path)
        info = dc.stat_entry(profile.root, path)
        rel = '.' if path == base else path[len(base) + 1:]
        if stat.S_ISDIR(info.st_mode):
            budget.charge_entry()
            append(entries, {'path': rel, 'kind': 'directory', **state(info)})
            with dc.open_dir(profile.root, path) as fd:
                before = os.fstat(fd)
                if dc._stable(before) != dc._stable(info):
                    _fail('SOURCE_CHANGED')
                with os.scandir(fd) as iterator:
                    for entry in iterator:
                        budget.check_time()
                        visit(path + '/' + entry.name, base, depth + 1, entries)
                after = os.fstat(fd)
                named = dc.stat_entry(profile.root, path)
                if dc._stable(before) != dc._stable(after) or dc._stable(before) != dc._stable(named):
                    _fail('SOURCE_CHANGED')
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            if dc.protected(_read_adapter(profile), path):
                _fail('PROTECTED_PATH')
            value = dc.stream_hash(_read_adapter(profile), path, budget)
            attributes = {key: value[key] for key in ('device', 'inode', 'mode', 'mtime_ns', 'ctime_ns', 'nlink')}
            if attributes != state(info) or value['bytes'] != info.st_size:
                _fail('SOURCE_CHANGED')
            append(entries, {'path': rel, 'kind': 'file', 'bytes': value['bytes'], 'sha256': value['sha256'], **attributes})
        else:
            _fail('RETAINED_UNSUPPORTED')
    for path in paths:
        declaration = declared[dc.path_key(path)]
        entries = []
        try:
            visit(path, path, 0, entries)
            entries.sort(key=lambda item: item['path'])
            # Keep the existing content/permission fingerprint separate from
            # identity/state. Retained originals are not moved by cleanup, so
            # their real inode and timestamps must remain bound, not restored.
            content = [{key: entry[key] for key in ('path', 'kind', 'mode', 'bytes', 'sha256') if key in entry}
                       for entry in entries]
            observed = entries[0]['sha256'] if len(entries) == 1 and entries[0]['kind'] == 'file' else dc.digest(content)
            if declaration.get('sha256') and declaration['sha256'] != observed:
                _fail('SOURCE_CHANGED')
            info = dc.stat_entry(profile.root, path)
            if state(info) != {key: entries[0][key] for key in state(info)}:
                _fail('SOURCE_CHANGED')
            snapshots.append({'path': path, 'sha256': observed, 'state_sha256': dc.digest(entries), 'manifest': entries, 'build': declaration.get('build'), 'entries': len(entries),
                              'identity': {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode)},
                              'runtime_validation': 'Not run'})
        except (OSError, ValueError) as error:
            failures.append({'path': path, 'reason_code': getattr(error, 'reason_code', 'RETAINED_UNAVAILABLE')})
    return snapshots, failures, budget.snapshot()


def _proofs(reader, proofs, discard):
    verified, failures = [], []
    for proof in proofs:
        path = proof['path']
        if any(_overlap(path, source) for source in discard):
            failures.append({'path': path, 'reason_code': 'EVIDENCE_IN_DISCARD'})
            continue
        try:
            observed = reader.read(path)
            if observed['sha256'] != proof['sha256']:
                _fail('SOURCE_CHANGED')
            verified.append({'path': path, 'sha256': observed['sha256']})
        except (OSError, ValueError) as error:
            failures.append({'path': path, 'reason_code': getattr(error, 'reason_code', 'EVIDENCE_UNAVAILABLE')})
    return verified, failures


def _validate_relocations(profile, request, relocations):
    if relocations is not None:
        if not isinstance(relocations, dict) or set(relocations) - {item['source'] for item in request['items']}:
            _fail('INVALID_INPUT', 'invalid internal candidate relocation observation')
        for source, value in relocations.items():
            if value is not None and (not isinstance(value, dict) or set(value) != {'root', 'path'}
                                      or str(dc.safe_root(value['root'])) != profile.data.get('quarantine_root')):
                _fail('PROFILE_CONFLICT')
            if value is not None:
                dc.relative(value['path'])


def rebaseline(profile, request=None, *, relocations=None):
    validate_profile_root(profile)
    request = validate_request(profile, request) if request is not None else None
    if relocations is not None and request is None:
        _fail('INVALID_INPUT', 'internal relocation requires an exact approved request')
    if request is not None:
        _validate_relocations(profile, request, relocations)
    reader, paths, fingerprints, coverage, unknowns = _reference_snapshot(profile, request, relocations)
    retained, failures, hash_usage = _retained_snapshot(profile, [item['path'] for item in profile.data['keep']], started=reader.walk.started)
    material = {'root': str(profile.root), 'profile_sha256': profile.sha256,
                'current_paths': paths, 'reference_fingerprints': fingerprints, 'retained': retained,
                'discarded_historical_log_scopes': [item['source'] for item in (request['items'] if request else [])
                                                  if not item['loss']['unique_evidence'] and not protected(profile, item['source'])],
                'skipped_discarded_references': sorted(item['source'] for item in (request['items'] if request else [])
                                                       if item['kind'] == 'completed_log' and not item['loss']['unique_evidence']
                                                       and not protected(profile, item['source']))}
    result = {'format': 'fifan-cleanup-report', 'schema_version': 1, 'kind': 'rebaseline', 'root': str(profile.root),
              'profile_sha256': profile.sha256, 'status': 'Passed' if not unknowns and not failures else 'Unknown',
              'material': material, 'material_sha256': dc.digest(material), 'coverage': coverage,
              'unknowns': unknowns + failures, 'reference_bytes_read': coverage['reference_bytes_read'],
              'retained_hash_usage': hash_usage, 'model_calls': 0, 'model_usage': 'Unknown'}
    validate_profile_root(profile)
    if len(dc.canonical(result)) > profile.budgets['max_artifact_bytes']:
        _fail('BUDGET_EXHAUSTED')
    return dc.seal(result)


def qualify(profile, request, *, relocations=None):
    validate_profile_root(profile)
    request = validate_request(profile, request)
    _validate_relocations(profile, request, relocations)
    reader, current_paths, fingerprints, coverage, scope_unknowns = _reference_snapshot(profile, request, relocations)
    discard = [item['source'] for item in request['items']]
    keep_lookup = {dc.path_key(item['path']): item for item in profile.data['keep']}
    retained_paths = sorted({path for item in request['items'] for path in item['retained']})
    snapshots, keep_failures, hash_usage = _retained_snapshot(profile, retained_paths, started=reader.walk.started)
    retained_map = {dc.path_key(item['path']): item for item in snapshots}
    results, material_items, identities = [], [], set()
    artifact_bytes = 0
    for item in request['items']:
        source, blockers, unknowns = item['source'], [], list(scope_unknowns)
        if protected(profile, source):
            blockers.append({'reason_code': 'CURRENT_KEEP_OR_PROTECTED'})
        if 'quarantine' not in request['approval']['actions']:
            blockers.append({'reason_code': 'QUARANTINE_NOT_APPROVED'})
        if item['loss']['unique_evidence']:
            blockers.append({'reason_code': 'UNIQUE_EVIDENCE'})
        source_identity = None
        try:
            if relocations is not None and source in relocations:
                target = relocations[source]
                if target is None:
                    info = None
                else:
                    dc.validate_path_spelling(Path(target['root']), target['path'])
                    info = dc.stat_entry(Path(target['root']), target['path'])
            else:
                dc.validate_path_spelling(profile.root, source)
                info = dc.stat_entry(profile.root, source)
            if info is not None:
                if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                    _fail('SOURCE_UNSUPPORTED')
                inode = (info.st_dev, info.st_ino)
                if inode in identities:
                    _fail('DUPLICATE_SOURCE_IDENTITY')
                identities.add(inode)
                source_identity = {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
                                   'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
        except (OSError, ValueError) as error:
            blockers.append({'reason_code': getattr(error, 'reason_code', 'SOURCE_UNAVAILABLE')})
        closure, failures = _proofs(reader, item['closure']['evidence'], discard)
        blockers.extend(failure for failure in failures if failure['reason_code'] != 'BUDGET_EXHAUSTED')
        unknowns.extend(failure for failure in failures if failure['reason_code'] == 'BUDGET_EXHAUSTED')
        retained = []
        for path in item['retained']:
            declaration = keep_lookup[dc.path_key(path)]
            if any(_overlap(path, candidate) for candidate in discard):
                blockers.append({'path': path, 'reason_code': 'RETAINED_IN_DISCARD'})
            if dc.path_key(path) not in retained_map:
                blockers.extend(failure for failure in keep_failures if dc.path_key(failure['path']) == dc.path_key(path))
                continue
            proofs, failures = _proofs(reader, declaration['evidence'], discard)
            blockers.extend(failures)
            retained.append({**retained_map[dc.path_key(path)], 'evidence': proofs})
        if item['kind'] == 'old_build' and 'generated_disposal' not in item and (not retained or not any(value.get('build') == item['build'] for value in retained)):
            blockers.append({'reason_code': 'RETAINED_BUILD_GROUP_MISSING'})
        resolutions = {}
        fields = ('path', 'sha256', 'line', 'column', 'line_sha256', 'expression_sha256')
        dynamic = {tuple(entry.get(key) for key in fields)
                   for path in reader.cache for entry in _references_to(reader, path, source)[1]
                   if entry.get('reason_code') == 'DYNAMIC_REFERENCE_UNKNOWN'}
        for entry in item['dynamic_reference_resolutions']:
            proof, failures = _proofs(reader, entry['evidence'], discard)
            blockers.extend(failures)
            if tuple(entry[key] for key in fields) not in dynamic or failures:
                blockers.append({'path': entry['path'], 'reason_code': 'DYNAMIC_RESOLUTION_MISMATCH'})
            else:
                resolutions[(entry['path'], entry['line'], entry['column'], entry['expression_sha256'])] = entry
        dependencies = []
        for path in reader.cache:
            found, unresolved = _references_to(reader, path, source)
            dependencies.extend(found)
            unknowns.extend(entry for entry in unresolved if entry.get('reason_code') != 'DYNAMIC_REFERENCE_UNKNOWN'
                            or (entry['path'], entry['line'], entry['column'], entry['expression_sha256']) not in resolutions)
        if any(_within(path, source) for path in reader.cache):
            blockers.append({'reason_code': 'RETAINED_REFERENCE_ORIGINAL_IN_DISCARD'})
        if dependencies:
            blockers.append({'reason_code': 'RETAINED_DEPENDENCIES'})
        status = 'Blocked' if blockers else 'Unknown' if unknowns else 'Passed'
        value = {'source': source, 'kind': item['kind'], 'status': status, 'eligible': status == 'Passed',
                 'source_identity': source_identity, 'blockers': blockers, 'unknowns': unknowns,
                 'retained_dependencies': dependencies, 'closure_evidence': closure, 'retained': retained,
                 'purge_authorized': 'purge' in request['approval']['actions'] and item['disposition'] == 'purge' and item['loss']['accepted'],
                 'payload_manifest_validation': 'Not run', 'retained_runtime_validation': 'Not run',
                 'rebuildability': item['loss']['rebuildable']}
        if 'generated_disposal' in item:
            missing = sorted(key for key in BUILD_FIELDS if key not in item['build'] or item['build'][key].casefold() == 'unknown')
            value['build_provenance'] = {'status': 'Unknown' if missing else 'Known',
                                         'metadata': copy.deepcopy(item['build']), 'missing_fields': missing}
            value['retention_comparison'] = 'WaivedByExplicitLossApproval'
            value['generated_disposal'] = copy.deepcopy(item['generated_disposal'])
        results.append(value)
        material_items.append({'source': source, 'kind': item['kind'], 'closure_evidence': closure, 'retained': retained,
                               'current_paths': current_paths, 'reference_fingerprints': fingerprints,
                               'discarded_historical_log_scopes': [entry['source'] for entry in request['items']
                                                                 if not entry['loss']['unique_evidence'] and not protected(profile, entry['source'])],
                               'skipped_discarded_references': sorted(item['source'] for item in (request['items'] if request else [])
                                                       if item['kind'] == 'completed_log' and not item['loss']['unique_evidence']
                                                       and not protected(profile, item['source']))})
        if 'generated_disposal' in item:
            material_items[-1].update({key: copy.deepcopy(value[key]) for key in
                                      ('build_provenance', 'retention_comparison', 'generated_disposal')})
        artifact_bytes += len(dc.canonical(value)) + len(dc.canonical(material_items[-1]))
        if artifact_bytes > profile.budgets['max_artifact_bytes']:
            _fail('BUDGET_EXHAUSTED', 'qualification retained state exceeds artifact budget')
    # Proof reads can add fingerprints; all observed bytes are bound, not elapsed counters.
    fingerprints = [{'path': path, 'sha256': value['sha256'], 'role': value['role'],
                     'identity': {'device': reader.source_metadata[path].st_dev, 'inode': reader.source_metadata[path].st_ino,
                                  'mode': stat.S_IMODE(reader.source_metadata[path].st_mode)}}
                    for path, value in sorted(reader.cache.items()) if path in reader.source_metadata]
    for item in material_items:
        item['reference_fingerprints'] = fingerprints
    final_coverage = reader.coverage()
    final_coverage['current_coverage'] = coverage['current_coverage']
    final_coverage['complete'] = final_coverage['complete'] and coverage['complete']
    final_coverage['count_is_lower_bound'] = not final_coverage['complete']
    final_coverage['work_entries'] += coverage['current_coverage']['work_entries']
    coverage = final_coverage
    if not coverage['complete']:
        for item in results:
            item['unknowns'].append({'reason_code': 'REFERENCE_COVERAGE_INCOMPLETE'})
            if item['status'] == 'Passed':
                item.update(status='Unknown', eligible=False)
    material = {'root': str(profile.root), 'profile_sha256': profile.sha256, 'request_sha256': dc.digest(request),
                'approval_sha256': dc.digest(request['approval']), 'items': material_items}
    status = 'Blocked' if any(item['status'] == 'Blocked' for item in results) else 'Unknown' if any(item['status'] == 'Unknown' for item in results) else 'Passed'
    report = {'format': 'fifan-cleanup-report', 'schema_version': 1, 'kind': 'qualification', 'root': str(profile.root),
              'profile_sha256': profile.sha256, 'request_sha256': dc.digest(request), 'approval_sha256': dc.digest(request['approval']),
              'status': status, 'items': results, 'material': material, 'material_sha256': dc.digest(material),
              'coverage': coverage, 'reference_bytes_read': coverage['reference_bytes_read'], 'retained_hash_usage': hash_usage,
              'candidate_hash_bytes': 0, 'model_calls': 0, 'model_usage': 'Unknown',
              'global_no_dependencies': 'Unknown', 'semantic_acceptance': 'Not run'}
    validate_profile_root(profile)
    if len(dc.canonical(report)) > profile.budgets['max_artifact_bytes']:
        _fail('BUDGET_EXHAUSTED')
    return dc.seal(report)


def inspect(profile, request=None):
    validate_profile_root(profile)
    request = validate_request(profile, request) if request is not None else None
    requested = {dc.path_key(item['source']) for item in request['items']} if request else set()
    unique_evidence = [item['source'] for item in request['items'] if item['loss']['unique_evidence']] if request else []
    counts, logical_bytes, work, gaps, samples = {'R': 0, 'D': 0, 'U': 0}, 0, 0, [], []
    started = time.monotonic()
    gap_count = 0
    rule_groups, matching_rules, matched_paths = {}, set(), 0
    def hint(path):
        raw = path.encode('utf-8')
        return raw[:128].decode('utf-8', errors='ignore') + ('...' if len(raw) > 128 else '')
    def gap(value):
        nonlocal gap_count
        gap_count += 1
        if len(gaps) < 8:
            gaps.append({**value, **({'path': hint(value['path'])} if 'path' in value else {})})
    def charge():
        nonlocal work
        if work >= profile.budgets['max_entries'] or time.monotonic() - started >= profile.budgets['max_seconds']:
            _fail('BUDGET_EXHAUSTED')
        work += 1
    candidates = {dc.path_key(item['path']): item for item in profile.data['candidates']}
    def visit(path, depth, charged=False):
        nonlocal logical_bytes, matched_paths
        if not charged:
            charge()
        role = ('R' if protected(profile, path) or any(_overlap(path, source) for source in unique_evidence)
                else 'D' if any(_within(path, source) for source in requested) else 'U')
        counts[role] += 1
        matched = False
        # Reuse this walk's namespace and budget. Globs only explain metadata
        # clues; they never feed requested/D or qualification eligibility.
        for index, rule in enumerate(profile.data['rules']):
            charge()
            if not fnmatch.fnmatchcase(path, rule['glob']):
                continue
            if not matched:
                matched_paths += 1
                matched = True
            matching_rules.add(index)
            if index not in rule_groups and len(rule_groups) < 8:
                rule_groups[index] = {'rule_index': index, 'kind': rule['kind'], 'glob': hint(rule['glob']),
                                      'reason': hint(rule['reason']), 'matched_count': 0, 'samples': []}
            group = rule_groups.get(index)
            if group is not None:
                group['matched_count'] += 1
                if len(group['samples']) < 8:
                    group['samples'].append({'path': hint(path), 'classification': role})
        if len(samples) < 10:
            samples.append({'path': hint(path), 'classification': role, 'kind': candidates.get(dc.path_key(path), {}).get('kind')})
        if dc.protected(_read_adapter(profile), path):
            gap({'path': path, 'reason_code': 'PROTECTED_PATH'})
            return
        try:
            info = dc.stat_entry(profile.root, path)
            if stat.S_ISREG(info.st_mode):
                logical_bytes += info.st_size
            elif stat.S_ISDIR(info.st_mode):
                if depth > profile.budgets['max_depth']:
                    gap({'path': path, 'reason_code': 'DEPTH_LIMIT'})
                    return
                with dc.open_dir(profile.root, path) as fd:
                    with os.scandir(fd) as iterator:
                        while True:
                            charge()
                            try:
                                entry = next(iterator)
                            except StopIteration:
                                break
                            visit(entry.name if path == '.' else path + '/' + entry.name, depth + 1, True)
            else:
                gap({'path': path, 'reason_code': 'SYMLINK_OR_SPECIAL'})
        except (OSError, ValueError) as error:
            if getattr(error, 'reason_code', None) == 'BUDGET_EXHAUSTED':
                raise
            gap({'path': path, 'reason_code': getattr(error, 'reason_code', 'METADATA_UNAVAILABLE')})
    roots = []
    for path in sorted(profile.data['scan_roots'], key=lambda p: (p.count('/'), p)):
        if not any(_within(path, root) for root in roots):
            roots.append(path)
    try:
        for path in roots:
            visit(path, 0)
    except dc.DirectoryError as error:
        gap({'reason_code': error.reason_code})
    groups_truncated = len(matching_rules) > len(rule_groups)
    for group in rule_groups.values():
        group['samples_truncated'] = group['matched_count'] > len(group['samples'])
    hints_truncated = groups_truncated or any(group['samples_truncated'] for group in rule_groups.values())
    report = {'format': 'fifan-cleanup-report', 'schema_version': 1, 'kind': 'inspect', 'root': str(profile.root),
              'profile_sha256': profile.sha256, 'status': 'Unknown' if gap_count or hints_truncated else 'Passed', 'counts': counts,
              'scan_roots_count': len(roots), 'scan_root_hints': [hint(path) for path in roots[:8]],
              'scope': 'declared scan roots only; hints and samples are display-only',
              'observed_logical_bytes': logical_bytes, 'body_bytes_read': 0, 'candidate_hash_bytes': 0,
              'work_entries': work, 'coverage': {'complete': not gap_count, 'count_is_lower_bound': bool(gap_count),
                                               'gaps': gaps, 'gap_count': gap_count, 'gaps_truncated': gap_count > len(gaps)},
              'rule_hints': {'groups': [rule_groups[index] for index in sorted(rule_groups)],
                             'matching_rules_count': len(matching_rules), 'matched_paths_count': matched_paths,
                             'groups_truncated': groups_truncated, 'complete': not gap_count and not hints_truncated,
                             'counts_are_lower_bounds': bool(gap_count), 'groups_limited_to': 8, 'samples_limited_to': 8},
              'samples': samples, 'samples_are_display_only': True, 'samples_limited_to': 10, 'candidate_is_execution_approval': False, 'rules_are_hints_only': True,
              'model_calls': 0, 'model_usage': 'Unknown', 'semantic_acceptance': 'Not run'}
    validate_profile_root(profile)
    if len(dc.canonical(report)) > profile.budgets['max_artifact_bytes']:
        _fail('BUDGET_EXHAUSTED')
    return dc.seal(report)


def reference_inspection(profile, request=None, *, resume=None, expected_fingerprint=None, estimate_only=False, max_batches=1):
    """Request-bound inspection only; operation entry points always rescan."""
    from .reference_batches import estimate, advance
    validate_profile_root(profile)
    request = validate_request(profile, request) if request is not None else None
    reader = _RetainedReferences(profile, request['items'] if request else [])
    roots = reader.reference_roots()
    if estimate_only:
        return estimate(reader, roots)
    result = advance(reader, roots, resume=resume, expected_fingerprint=expected_fingerprint, max_batches=max_batches)
    validate_profile_root(profile)
    return result
