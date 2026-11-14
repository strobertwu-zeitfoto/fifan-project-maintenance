"""Opt-in bounded reference batches; inspection receipts never authorize writes.

A caller retaining a receipt fingerprint may resume exact parse facts after fresh
namespace/state/hash checks. Seals detect corruption, not hostile authorship.
Mutation paths always create their own scan rather than consume these receipts.
"""
from __future__ import annotations

import hashlib
from copy import deepcopy
import time
from pathlib import Path

from . import directory_common as dc

LIMITS = {'max_batches': 1000, 'max_total_bytes': 8 * dc.GiB,
          'max_total_files': 1000000, 'max_total_seconds': 3600}


def validate_options(value):
    if not isinstance(value, dict) or set(value) != set(LIMITS):
        raise dc.DirectoryError('INVALID_INPUT', 'reference_batching requires four explicit aggregate limits')
    for key, maximum in LIMITS.items():
        if type(value[key]) is not int or not 1 <= value[key] <= maximum:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'invalid aggregate reference limit: ' + key)
    return dict(value)


def _engine():
    # Bind persisted facts to the parser and batching implementation actually
    # installed, including local patches, rather than a manually bumped label.
    base = Path(__file__).parent
    return dc.digest({name: hashlib.sha256((base / name).read_bytes()).hexdigest()
                      for name in ('directory_census.py', 'reference_batches.py', 'dynamic_review.py',
                                   'adapters/markdown.py', 'jsonc_edit.py', 'selection.py') if (base / name).is_file()})


def _inventory(reader, roots):
    from .directory_census import _Walk
    dc.validate_profile_root(reader.profile)
    walk = _Walk(reader.profile)
    entries, infos, keys = [], {}, {}
    inventory_bytes = 0
    for path, info in walk.walk(roots):
        if hasattr(reader, 'discarded') and reader.discarded(path):
            reader.skipped.add(path)
            continue
        key = dc.path_key(path)
        if key in keys and keys[key] != path:
            raise dc.DirectoryError('PATH_ALIAS')
        keys[key] = path
        overlay = reader.reference_overlay.get(path) or b''
        entry = {'path': path, 'state': list(dc._stable(info)), 'bytes': info.st_size,
                 'analysis_bytes': info.st_size + len(overlay)}
        entries.append(entry)
        inventory_bytes += len(dc.canonical(entry)) + 1
        infos[path] = info
        if inventory_bytes > reader.profile.budgets['max_artifact_bytes'] // 2:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'reference inventory exceeds artifact budget')
    if not roots:
        walk.gap('.', 'REFERENCE_SCOPE_EMPTY')
    if not walk.complete:
        raise dc.DirectoryError('REFERENCE_COVERAGE_INCOMPLETE', 'reference inventory is incomplete')
    return sorted(entries, key=lambda x: x['path']), infos, walk


def _partition(profile, entries, options):
    limits = profile.budgets
    if (len(entries) > options['max_total_files']
            or sum(item['analysis_bytes'] for item in entries) > options['max_total_bytes']):
        raise dc.DirectoryError('BUDGET_EXHAUSTED', 'aggregate reference budget is insufficient')
    groups, group, size = [], [], 0
    for item in entries:
        path, amount = item['path'], item['analysis_bytes']
        file_limit = limits['max_reference_bytes'] if path in profile.data.get('streaming_references', []) else limits['max_reference_file_bytes']
        if item['bytes'] > file_limit or amount > limits['max_reference_bytes']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'a reference cannot fit a single batch: ' + path)
        if group and (len(group) >= limits['max_reference_files'] or size + amount > limits['max_reference_bytes']):
            groups.append(group)
            group, size = [], 0
        group.append(path)
        size += amount
    if group:
        groups.append(group)
    if len(groups) > options['max_batches']:
        raise dc.DirectoryError('BUDGET_EXHAUSTED', 'aggregate batch count is insufficient')
    return groups


def estimate(reader, roots):
    """Metadata-only preflight, before any reference body is read."""
    started = time.monotonic()
    options = validate_options(reader.profile.data.get('reference_batching'))
    entries, _, _ = _inventory(reader, roots)
    groups = _partition(reader.profile, entries, options)
    return dc.seal({'schema_version': 1, 'kind': 'reference-estimate', 'status': 'Passed',
                    'project_root': str(reader.profile.root), 'profile_sha256': reader.profile.sha256,
                    'reference_files': len(entries), 'estimated_parse_bytes': sum(e['bytes'] for e in entries),
                    'estimated_analysis_bytes': sum(e['analysis_bytes'] for e in entries),
                    'estimated_resume_validation_bytes': sum(e['bytes'] for e in entries),
                    'batch_count': len(groups), 'batch_paths': groups,
                    'single_batch_limits': dict(reader.profile.budgets), 'aggregate_limits': options,
                    'body_bytes_read': 0, 'elapsed_seconds': time.monotonic() - started})


def advance(reader, roots, *, resume=None, expected_fingerprint=None, max_batches=1):
    """Advance an inspection session. Partial is never complete coverage.

    max_batches=None is reserved for an in-memory full scan by qualification.
    The caller must retain a trusted fingerprint when resuming external JSON.
    """
    from .directory_census import _References
    started = time.monotonic()
    if reader.reference_overlay and resume is not None:
        raise dc.DirectoryError('ARTIFACT_INVALID', 'overlay projections cannot resume persisted reference sessions')
    options = validate_options(reader.profile.data.get('reference_batching'))
    if max_batches is not None and (type(max_batches) is not int or not 1 <= max_batches <= options['max_batches']):
        raise dc.DirectoryError('INVALID_INPUT', 'invalid batch advance count')
    entries, infos, walk = _inventory(reader, roots)
    groups = _partition(reader.profile, entries, options)
    inventory_seconds = time.monotonic() - started
    binding = {'root': str(reader.profile.root), 'root_identity': list(reader.profile._root_identity),
               'profile_sha256': reader.profile.sha256, 'config_sha256': dc.digest(reader.profile.config),
               'engine_sha256': _engine(), 'sources': list(reader.sources), 'roots': sorted(roots),
               'inventory': entries, 'batch_paths': groups}
    chunks = []
    if resume is not None:
        if not isinstance(resume, dict) or len(dc.canonical(resume)) > reader.profile.budgets['max_artifact_bytes']:
            raise dc.DirectoryError('ARTIFACT_INVALID')
        dc.validate_seal(resume)
        if not expected_fingerprint or resume['fingerprint'] != expected_fingerprint:
            raise dc.DirectoryError('ARTIFACT_INVALID', 'resume requires the exact retained receipt fingerprint')
        if (resume.get('kind') != 'reference-session' or resume.get('binding') != binding
                or not isinstance(resume.get('batches'), list)):
            raise dc.DirectoryError('SOURCE_CHANGED', 'reference session scope, engine or file state changed')
        chunks = deepcopy(resume['batches'])
        if (len(chunks) > len(groups) or resume.get('next_batch') != len(chunks)
                or resume.get('batch_count') != len(groups)):
            raise dc.DirectoryError('ARTIFACT_INVALID')
        expected_status = 'Passed' if len(chunks) == len(groups) else 'Partial'
        if resume.get('status') != expected_status or resume.get('complete') is not (expected_status == 'Passed'):
            raise dc.DirectoryError('ARTIFACT_INVALID', 'inconsistent session completeness')
    parse_bytes = validation_bytes = 0
    previous_elapsed = resume.get('cumulative_elapsed_seconds', 0) if resume else 0
    if type(previous_elapsed) not in (int, float) or previous_elapsed < 0:
        raise dc.DirectoryError('ARTIFACT_INVALID')

    def check_total():
        if previous_elapsed + time.monotonic() - started >= options['max_total_seconds']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'aggregate reference time exhausted')

    validation_started = time.monotonic()
    # No external facts enter the live reader until every old chunk validates.
    for index, chunk in enumerate(chunks):
        check_total()
        dc.validate_seal(chunk)
        if (set(chunk) != {'index', 'paths', 'facts', 'elapsed_seconds', 'reference_bytes_read', 'reference_bytes_charged', 'fingerprint'}
                or type(chunk.get('index')) is not int
                or any(type(chunk.get(key)) is not int or chunk[key] < 0 for key in ('reference_bytes_read', 'reference_bytes_charged'))):
            raise dc.DirectoryError('ARTIFACT_INVALID', 'invalid batch accounting')
        if chunk.get('index') != index or chunk.get('paths') != groups[index] or set(chunk.get('facts', {})) != set(groups[index]):
            raise dc.DirectoryError('ARTIFACT_INVALID', 'missing, duplicated or reordered batch')
        for path in groups[index]:
            fact = chunk['facts'][path]
            if (not isinstance(fact, dict) or not isinstance(fact.get('analysis'), list)
                    or len(fact['analysis']) != len(reader.sources)
                    or not isinstance(fact.get('value'), dict)):
                raise dc.DirectoryError('ARTIFACT_INVALID', 'invalid reference facts')
        budget = dc.HashBudget(dc.reference_hash_limits(reader.profile))
        for path in groups[index]:
            value = dc.stream_reference_hash(reader.profile, path, budget, reference_path=path)
            validation_bytes += value['bytes']
            if value['sha256'] != chunk['facts'][path]['value']['sha256']:
                raise dc.DirectoryError('SOURCE_CHANGED')
    validation_seconds = time.monotonic() - validation_started
    parse_started = time.monotonic()
    stop = len(groups) if max_batches is None else min(len(groups), len(chunks) + max_batches)
    for index in range(len(chunks), stop):
        check_total()
        batch_started = time.monotonic()
        batch = _References(reader.profile, reader.sources, reference_overlay=reader.reference_overlay)
        facts = {}
        for path in groups[index]:
            value = batch.read(path)
            facts[path] = {'value': value, 'analysis': [batch.analysis[(path, source)] for source in reader.sources]}
        # _scan_text can conservatively return a budget unknown instead of
        # raising; it remains unknown in the original qualification gates.
        chunks.append(dc.seal({'index': index, 'paths': groups[index], 'facts': facts,
                               'elapsed_seconds': time.monotonic() - batch_started,
                               'reference_bytes_read': batch.returned_bytes, 'reference_bytes_charged': batch.bytes}))
        parse_bytes += batch.returned_bytes
        if len(dc.canonical(chunks)) > reader.profile.budgets['max_artifact_bytes'] // 2:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'aggregate parse facts exceed artifact budget')
    parse_seconds = time.monotonic() - parse_started
    check_total()
    # Re-enumerate the namespace, detecting files added while parsing, state
    # changes, aliases and protected/special paths before claiming completion.
    final_started = time.monotonic()
    final_entries, _, final_walk = _inventory(reader, roots)
    check_total()
    if final_entries != entries:
        raise dc.DirectoryError('SOURCE_CHANGED')
    if walk.work_entries + final_walk.work_entries + len(entries) * 2 > reader.profile.budgets['max_entries']:
        raise dc.DirectoryError('BUDGET_EXHAUSTED', 'aggregate reference metadata work exhausted')
    complete = len(chunks) == len(groups)
    result = dc.seal({'schema_version': 1, 'kind': 'reference-session', 'binding': binding,
                      'status': 'Passed' if complete else 'Partial', 'complete': complete,
                      'batches': chunks, 'next_batch': len(chunks), 'batch_count': len(groups),
                      'inspection_only': True, 'mutation_authorized': False,
                      'cumulative_elapsed_seconds': previous_elapsed + time.monotonic() - started,
                      'usage': {'reference_bytes_read': parse_bytes, 'validation_bytes_read': validation_bytes,
                                'reference_bytes_charged': sum(c['reference_bytes_charged'] for c in chunks),
                                'parsed_files': sum(len(c['paths']) for c in chunks),
                                'phase_seconds': {'inventory': inventory_seconds, 'resume_validation': validation_seconds,
                                                  'parse': parse_seconds, 'final_inventory': time.monotonic() - final_started},
                                'elapsed_seconds': time.monotonic() - started}})
    if len(dc.canonical(result)) > reader.profile.budgets['max_artifact_bytes']:
        raise dc.DirectoryError('BUDGET_EXHAUSTED')
    # Hydrate only fully checked in-memory facts. A Partial reader explicitly
    # fails coverage and cannot pass any existing qualification gate.
    reader.cache.clear()
    reader.cache_keys.clear()
    reader.analysis.clear()
    reader.failures.clear()
    if hasattr(reader, 'source_metadata'):
        reader.source_metadata.clear()
    reader.walk = walk
    reader.walk.work_entries += final_walk.work_entries + len(entries) * 2
    reader.walk.started = time.monotonic()  # next qualification phase has its own unchanged time budget
    if not complete:
        reader.walk.gap('.', 'REFERENCE_BATCHES_INCOMPLETE')
    reader.batch_coverage = {key: result[key] for key in ('status', 'complete', 'next_batch', 'batch_count', 'usage')}
    reader.batch_coverage['estimated_parse_bytes'] = sum(e['bytes'] for e in entries)
    for chunk in chunks:
        for path, fact in chunk['facts'].items():
            reader.cache[path] = fact['value']
            reader.cache_keys[dc.path_key(path)] = path
            for source, analysis in zip(reader.sources, fact['analysis']):
                reader.analysis[(path, source)] = analysis
            if hasattr(reader, 'source_metadata'):
                reader.source_metadata[path] = infos[path]
    reader.files = sum(len(c['paths']) for c in chunks)
    reader.bytes = sum(c['reference_bytes_charged'] for c in chunks)
    reader.returned_bytes = parse_bytes + validation_bytes
    return result


def load_all(reader, roots):
    """Full fresh bounded scan for qualification, never external receipt reuse."""
    started = time.monotonic()
    try:
        advance(reader, roots, max_batches=None)
    except (OSError, ValueError) as error:
        reader.walk.gap('.', getattr(error, 'reason_code', 'REFERENCE_UNAVAILABLE'))
        # A failed stage may have consumed bytes before its current batch
        # could publish facts. Never misreport that work as a zero-byte scan.
        reader.read_bytes_unknown = True
        reader.batch_coverage = {'status': 'Unknown', 'complete': False,
                                 'elapsed_seconds': time.monotonic() - started}


class ReferenceHasher:
    """Fresh mutation-proof IO, split at the same explicit batch boundaries."""
    def __init__(self, profile):
        self.profile = profile
        self.options = validate_options(profile.data['reference_batching']) if 'reference_batching' in profile.data else None
        self.started = time.monotonic()
        self.total_bytes = self.total_files = 0
        self.batch_count = 1
        self.budget = dc.HashBudget(dc.reference_hash_limits(profile))

    def read(self, rel, *, reference_path, root=None):
        if self.options is not None:
            info = dc.stat_entry(self.profile.root if root is None else root, rel)
            if (self.total_files >= self.options['max_total_files']
                    or self.total_bytes + info.st_size > self.options['max_total_bytes']
                    or time.monotonic() - self.started >= self.options['max_total_seconds']):
                raise dc.DirectoryError('BUDGET_EXHAUSTED', 'aggregate reference proof budget exhausted')
            limits = self.profile.budgets
            if self.budget.entries >= limits['max_reference_files'] or self.budget.bytes + info.st_size > limits['max_reference_bytes']:
                self.batch_count += 1
                if self.batch_count > self.options['max_batches']:
                    raise dc.DirectoryError('BUDGET_EXHAUSTED', 'reference proof batch count exhausted')
                self.budget = dc.HashBudget(dc.reference_hash_limits(self.profile))
        value = dc.stream_reference_hash(self.profile, rel, self.budget, reference_path=reference_path, root=root)
        if self.options is not None and time.monotonic() - self.started >= self.options['max_total_seconds']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED', 'aggregate reference proof time exhausted')
        self.total_files += 1
        self.total_bytes += value['bytes']
        return value
