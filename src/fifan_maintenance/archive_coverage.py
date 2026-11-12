"""Read-only exact archive coverage and source-bound, non-textual proofs.

Request v1: {version:1, allowed_external_roots?:[absolute root], items:[{
 source:{path,selector,expected_sha256?,root?},
 archive:{path,selector,expected_sha256?,root?,reference_base,classification_basis}}]}.
Selectors are documented by selection.select_bytes. Relative paths never choose
an external root implicitly. Proofs contain byte ranges and hashes, not snippets.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import time

from .models import Context
from .project import fingerprint, project_root, relative_parts
from .selection import SelectionError, select_bytes

MAX_ITEMS = 100


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


def _hash_string(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-fA-F0-9]{64}', value))


class _Reader:
    def __init__(self, root, config, external_roots):
        self.root, self.config = root, config
        self.roots = {str(root): root}
        if not isinstance(external_roots, list) or len(external_roots) > 100:
            raise SelectionError('REQUEST_INVALID')
        for value in external_roots:
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise SelectionError('EXTERNAL_ROOT_NOT_ALLOWED')
            declared = Path(value).absolute()
            if any(path.is_symlink() for path in (declared, *declared.parents)) or not declared.is_dir():
                raise SelectionError('EXTERNAL_ROOT_NOT_ALLOWED')
            resolved = declared.resolve(strict=True)
            if resolved.is_relative_to(root) or root.is_relative_to(resolved):
                # The project already has an implicit root. Its descendants
                # must retain project scope, and its parents cannot grant broad
                # new access merely by being declared as an external root.
                raise SelectionError('EXTERNAL_ROOT_NOT_ALLOWED')
            self.roots[value] = resolved
            self.roots[str(resolved)] = resolved
        self.contexts, self.cache = {}, {}
        self.read_bytes = 0
        self.started = time.monotonic()

    def time_remaining(self):
        return time.monotonic() - self.started < self.config.get('max_seconds', 60)

    def endpoint(self, item, archive=False):
        if not self.time_remaining():
            raise SelectionError('BUDGET_EXHAUSTED')
        fields = {'root', 'path', 'selector', 'expected_sha256'} | ({'reference_base', 'classification_basis'} if archive else set())
        if not isinstance(item, dict) or set(item) - fields or not {'path', 'selector'} <= set(item):
            raise SelectionError('REQUEST_INVALID')
        rel = item['path']
        relative_parts(rel)
        chosen_root = item.get('root', str(self.root))
        if not isinstance(chosen_root, str) or chosen_root not in self.roots:
            raise SelectionError('EXTERNAL_ROOT_NOT_ALLOWED')
        chosen_root = self.roots[chosen_root]
        key = (str(chosen_root), rel)
        if key not in self.cache:
            if len(self.cache) >= self.config.get('max_files', 20000):
                raise SelectionError('BUDGET_EXHAUSTED')
            if not self.time_remaining():
                raise SelectionError('BUDGET_EXHAUSTED')
            if str(chosen_root) not in self.contexts:
                config = dict(self.config)
                config.pop('_overlay', None)  # Proofs bind real originals, never a preview overlay.
                if chosen_root != self.root:
                    config.pop('_task', None)  # Separate explicit external root, same protection rules.
                self.contexts[str(chosen_root)] = Context(chosen_root, {}, config)
            ctx = self.contexts[str(chosen_root)]
            ctx.resolve(rel)
            if not ctx.body_allowed(rel):
                raise SelectionError('BODY_NOT_AUTHORIZED')
            remaining = self.config.get('max_total_bytes', 64 * 1024 * 1024) - self.read_bytes
            size = ctx.metadata(rel).st_size
            if remaining <= 0 or size > min(remaining, self.config['max_file_bytes']):
                raise SelectionError('BUDGET_EXHAUSTED')
            ctx.config['max_total_bytes'] = ctx._read_total + remaining
            data = ctx.read_bytes(rel)
            self.read_bytes += len(data)
            self.cache[key] = data
        raw = self.cache[key]
        full_hash = _sha(raw)
        expected = item.get('expected_sha256')
        if expected is not None and (not _hash_string(expected) or expected.lower() != full_hash):
            raise SelectionError('SOURCE_CHANGED' if _hash_string(expected) else 'REQUEST_INVALID')
        start, end = select_bytes(raw, item['selector'])
        if not self.time_remaining():
            raise SelectionError('BUDGET_EXHAUSTED')
        selected = raw[start:end]
        public = {'root': str(chosen_root), 'path': rel, 'file_sha256': full_hash, 'file_bytes': len(raw),
                  'start_byte': start, 'end_byte': end, 'selected_sha256': _sha(selected), 'selected_bytes': len(selected)}
        return public, selected


def _unknown_result(index, reason, result='Unknown'):
    return {'index': index, 'result': result, 'reason_code': reason}


def _proof_item(source, archive, reference_hash, classification_hash):
    def endpoint(item):
        return {'root': item['root'], 'path': item['path'], 'expected_sha256': item['file_sha256'],
                'selector': {'kind': 'bytes', 'start_byte': item['start_byte'], 'end_byte': item['end_byte']},
                'selected_sha256': item['selected_sha256']}
    return {'source': endpoint(source), 'archive': endpoint(archive), 'reference_base_sha256': reference_hash,
            'classification_basis_sha256': classification_hash}


def archive_coverage(root, config, request):
    root = project_root(root)
    if (not isinstance(request, dict) or set(request) - {'version', 'allowed_external_roots', 'items'}
            or type(request.get('version')) is not int or request['version'] != 1 or not isinstance(request.get('items'), list) or not request['items']):
        raise SelectionError('REQUEST_INVALID')
    reader = _Reader(root, config, request.get('allowed_external_roots', []))
    results, proof_items = [], []
    items = request['items']
    item_limit = min(MAX_ITEMS, config.get('max_files', MAX_ITEMS))
    for index, item in enumerate(items):
        if index >= item_limit or not reader.time_remaining():
            break
        if not isinstance(item, dict) or set(item) != {'source', 'archive'}:
            results.append(_unknown_result(index, 'REQUEST_INVALID'))
            continue
        archive = item['archive']
        if not isinstance(archive, dict) or not all(isinstance(archive.get(name), str) and archive[name].strip() for name in ('reference_base', 'classification_basis')):
            results.append(_unknown_result(index, 'ARCHIVE_CONTEXT_MISSING'))
            continue
        try:
            source, before = reader.endpoint(item['source'])
            archived, after = reader.endpoint(archive, archive=True)
            reference_hash = _sha(archive['reference_base'].encode('utf-8'))
            classification_hash = _sha(archive['classification_basis'].encode('utf-8'))
            same = before == after
            results.append({'index': index, 'result': 'Exact' if same else 'Different', 'source': source, 'archive': archived,
                            'reference_base_sha256': reference_hash, 'classification_basis_sha256': classification_hash,
                            'semantic_acceptance': 'Not run'})
            if same:
                proof_items.append(_proof_item(source, archived, reference_hash, classification_hash))
        except FileNotFoundError:
            results.append(_unknown_result(index, 'ORIGINAL_MISSING', 'Missing'))
        except SelectionError as exc:
            state = 'Ambiguous' if exc.reason_code == 'SELECTOR_AMBIGUOUS' else 'Missing' if exc.reason_code in ('HEADING_NOT_FOUND', 'SELECTOR_MISSING') else 'Unknown'
            results.append(_unknown_result(index, exc.reason_code, state))
        except UnicodeError:
            results.append(_unknown_result(index, 'ENCODING_UNSUPPORTED'))
        except (OSError, ValueError):
            results.append(_unknown_result(index, 'READ_UNAVAILABLE'))
    checked = len(results)
    complete = checked == len(items) and all(item['result'] in ('Exact', 'Different', 'Missing', 'Ambiguous') for item in results)
    exact = complete and all(item['result'] == 'Exact' for item in results)
    report = {'schema_version': 1, 'request_sha256': _sha(_canonical(request)), 'root': str(root), 'config_sha256': fingerprint(config), 'status': 'Passed' if exact else 'Failed' if complete else 'Unknown',
              'complete': complete, 'item_total': len(items), 'checked_items': checked, 'results': results,
              'unchecked': None if checked == len(items) else {'start_index': checked, 'count': len(items) - checked, 'reason_code': 'BUDGET_EXHAUSTED'},
              'read_bytes': reader.read_bytes, 'elapsed_seconds': round(time.monotonic() - reader.started, 6),
              'semantic_acceptance': 'Not run', 'proof': None}
    if exact:
        proof = {'version': 1, 'root': str(root), 'config_sha256': fingerprint(config),
                 'allowed_external_roots': sorted({item[side]['root'] for item in proof_items for side in ('source', 'archive') if item[side]['root'] != str(root)}),
                 'items': proof_items}
        proof['proof_sha256'] = _sha(_canonical(proof))
        report['proof'] = proof
        report['write_precondition'] = 'Blocked' if proof['allowed_external_roots'] else 'Requires bound source writers and compiled v2 guards'
    return report


def _validate_proof(root, config, proof):
    root = project_root(root)
    fields = {'version', 'root', 'config_sha256', 'allowed_external_roots', 'items', 'proof_sha256'}
    if (not isinstance(proof, dict) or set(proof) != fields or type(proof.get('version')) is not int or proof['version'] != 1 or proof.get('root') != str(root)
            or proof.get('config_sha256') != fingerprint(config) or not isinstance(proof.get('items'), list) or not proof['items']
            or not _hash_string(proof.get('proof_sha256'))):
        raise SelectionError('PROOF_BINDING_MISMATCH')
    if _sha(_canonical({key: value for key, value in proof.items() if key != 'proof_sha256'})) != proof['proof_sha256']:
        raise SelectionError('PROOF_BINDING_MISMATCH')
    for item in proof['items']:
        if not isinstance(item, dict) or set(item) != {'source', 'archive', 'reference_base_sha256', 'classification_basis_sha256'}:
            raise SelectionError('PROOF_BINDING_MISMATCH')
        if not all(_hash_string(item[name]) for name in ('reference_base_sha256', 'classification_basis_sha256')):
            raise SelectionError('PROOF_BINDING_MISMATCH')
        for side in ('source', 'archive'):
            endpoint = item[side]
            if (not isinstance(endpoint, dict) or set(endpoint) != {'root', 'path', 'selector', 'expected_sha256', 'selected_sha256'}
                    or not _hash_string(endpoint['expected_sha256']) or not _hash_string(endpoint['selected_sha256'])
                    or not isinstance(endpoint['selector'], dict) or endpoint['selector'].get('kind') != 'bytes'):
                raise SelectionError('PROOF_BINDING_MISMATCH')
    return root


def _verified_reader(root, config, proof):
    root = _validate_proof(root, config, proof)
    reader = _Reader(root, config, proof['allowed_external_roots'])
    if len(proof['items']) > min(MAX_ITEMS, config.get('max_files', MAX_ITEMS)):
        raise SelectionError('BUDGET_EXHAUSTED')
    for item in proof['items']:
        if not isinstance(item, dict) or set(item) != {'source', 'archive', 'reference_base_sha256', 'classification_basis_sha256'}:
            raise SelectionError('PROOF_BINDING_MISMATCH')
        values = []
        for side in ('source', 'archive'):
            endpoint = item[side]
            if not isinstance(endpoint, dict) or set(endpoint) != {'root', 'path', 'selector', 'expected_sha256', 'selected_sha256'}:
                raise SelectionError('PROOF_BINDING_MISMATCH')
            public, raw = reader.endpoint({key: value for key, value in endpoint.items() if key != 'selected_sha256'})
            if public['selected_sha256'] != endpoint['selected_sha256']:
                raise SelectionError('PROOF_BINDING_MISMATCH')
            values.append(raw)
        if values[0] != values[1]:
            raise SelectionError('PROOF_BINDING_MISMATCH')
    return reader


def verify_archive_proof(root, config, proof):
    """Re-read exact byte ranges and both complete-file fingerprints."""
    reader = _verified_reader(root, config, proof)
    return {'status': 'Passed', 'complete': True, 'checked_items': len(proof['items']), 'read_bytes': reader.read_bytes, 'proof_sha256': proof['proof_sha256']}


def compile_v2_guards(root, config, proof):
    """Internal only: guards contain originals. Caller MUST bind source writers.

    Each source must be a replace/replace_many writer with the exact full SHA
    returned in source_bindings. External proofs cannot enter v2 persistence.
    """
    root = _validate_proof(root, config, proof)
    if proof['allowed_external_roots'] or any(item.get(side, {}).get('root') != str(root) for item in proof['items'] for side in ('source', 'archive')):
        raise SelectionError('EXTERNAL_PROOF_NOT_PERSISTABLE')
    reader = _verified_reader(root, config, proof)
    guards, bindings, archive_bindings = {}, {}, {}
    for item in proof['items']:
        source, archive = item['source'], item['archive']
        bindings[source['path']] = source['expected_sha256']
        if archive['path'] not in guards:
            raw = reader.cache[(str(root), archive['path'])]
            if _sha(raw) != archive['expected_sha256']:
                raise SelectionError('SOURCE_CHANGED')
            archive_bindings[archive['path']] = archive['expected_sha256']
            guards[archive['path']] = {'kind': 'snippet', 'path': archive['path'], 'value': raw.decode('utf-8')}
    return {'guards': list(guards.values()), 'archive_bindings': [{'path': path, 'expected_sha256': sha} for path, sha in sorted(archive_bindings.items())], 'source_bindings': [{'path': path, 'expected_sha256': sha} for path, sha in sorted(bindings.items())],
            'proof_sha256': proof['proof_sha256']}
