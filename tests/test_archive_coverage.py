from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from fifan_maintenance.archive_coverage import archive_coverage, verify_archive_proof, compile_v2_guards
from fifan_maintenance.project import DEFAULT_CONFIG
from fifan_maintenance.selection import SelectionError


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def config():
    return deepcopy(DEFAULT_CONFIG)


def item(source_selector, archive_selector=None, source='source.md', archive='archive.md'):
    return {'source': {'path': source, 'selector': source_selector},
            'archive': {'path': archive, 'selector': archive_selector or source_selector,
                        'reference_base': 'source.md', 'classification_basis': 'explicit approved historical copy'}}


def request(*items, roots=None):
    return {'version': 1, 'allowed_external_roots': roots or [], 'items': list(items)}


def test_heading_table_snippet_and_bytes_exact_no_original_output(tmp_path, config):
    raw = b'# Keep\r\nprivate marker\r\n\r\n| A | B |\r\n| - | - |\r\n| 1 | 2 |\r\n'
    (tmp_path / 'source.md').write_bytes(raw)
    (tmp_path / 'archive.md').write_bytes(raw)
    req = request(item({'kind': 'heading', 'value': 'Keep'}), item({'kind': 'table', 'index': 1}),
                  item({'kind': 'snippet', 'value': 'private marker'}), item({'kind': 'bytes', 'start_byte': 0, 'end_byte': len(raw)}))
    result = archive_coverage(tmp_path, config, req)
    assert result['status'] == 'Passed' and result['complete']
    assert [entry['result'] for entry in result['results']] == ['Exact'] * 4
    output = json.dumps(result)
    assert 'private marker' not in output and '| A | B |' not in output
    assert result['read_bytes'] == 2 * len(raw)
    assert result['proof']
    assert verify_archive_proof(tmp_path, config, result['proof'])['status'] == 'Passed'
    compiled = compile_v2_guards(tmp_path, config, result['proof'])
    assert len(compiled['guards']) == 1
    assert compiled['guards'][0]['value'].encode() == raw
    assert compiled['source_bindings'] == [{'path': 'source.md', 'expected_sha256': sha(raw)}]
    assert compiled['archive_bindings'] == [{'path': 'archive.md', 'expected_sha256': sha(raw)}]


def test_different_crlf_missing_ambiguous_and_metadata_unknown(tmp_path, config):
    (tmp_path / 'source.md').write_bytes(b'# Same\r\ntext\r\n')
    (tmp_path / 'archive.md').write_bytes(b'# Same\ntext\n')
    first = item({'kind': 'heading', 'value': 'Same'})
    missing = item({'kind': 'snippet', 'value': 'absent'})
    ambiguous = item({'kind': 'snippet', 'value': 'aa'}, source='repeated.md')
    (tmp_path / 'repeated.md').write_text('aaa')
    no_context = item({'kind': 'heading', 'value': 'Same'})
    del no_context['archive']['reference_base']
    result = archive_coverage(tmp_path, config, request(first, missing, ambiguous, no_context))
    assert [entry['result'] for entry in result['results']] == ['Different', 'Missing', 'Ambiguous', 'Unknown']
    assert result['status'] == 'Unknown' and not result['complete'] and result['proof'] is None
    result = archive_coverage(tmp_path, config, request(first, missing, ambiguous))
    assert result['status'] == 'Failed' and result['complete']


def test_duplicate_headings_tables_and_explicit_pairing(tmp_path, config):
    text = '# Same\nbody\n# Same\nbody\n'
    (tmp_path / 'source.md').write_text(text)
    (tmp_path / 'archive.md').write_text(text)
    result = archive_coverage(tmp_path, config, request(item({'kind': 'heading', 'value': 'Same'})))
    assert result['results'][0]['result'] == 'Ambiguous'
    result = archive_coverage(tmp_path, config, request(item({'kind': 'heading', 'value': '#same-1'})))
    assert result['results'][0]['result'] == 'Exact'
    tables = '| A |\n| - |\n| 1 |\n\n| A |\n| - |\n| 1 |\n'
    (tmp_path / 'source.md').write_text(tables)
    (tmp_path / 'archive.md').write_text(tables)
    assert archive_coverage(tmp_path, config, request(item({'kind': 'table'})))['results'][0]['result'] == 'Ambiguous'
    assert archive_coverage(tmp_path, config, request(item({'kind': 'table', 'index': 2})))['results'][0]['result'] == 'Exact'


def test_expected_sha_proof_drift_tampering_and_utf8_ranges(tmp_path, config):
    raw = '汉字\r\n'.encode()
    (tmp_path / 'source.md').write_bytes(raw)
    (tmp_path / 'archive.md').write_bytes(raw)
    exact = item({'kind': 'bytes', 'start_byte': 0, 'end_byte': len(raw)})
    result = archive_coverage(tmp_path, config, request(exact))
    proof = result['proof']
    tampered = deepcopy(proof)
    tampered['items'][0]['source']['selector']['start_byte'] = 1
    with pytest.raises(SelectionError):
        verify_archive_proof(tmp_path, config, tampered)
    broken = item({'kind': 'bytes', 'start_byte': 1, 'end_byte': len(raw)})
    assert archive_coverage(tmp_path, config, request(broken))['results'][0]['reason_code'] == 'SELECTOR_UTF8_BOUNDARY'
    exact['source']['expected_sha256'] = '0' * 64
    assert archive_coverage(tmp_path, config, request(exact))['results'][0]['reason_code'] == 'SOURCE_CHANGED'
    (tmp_path / 'archive.md').write_bytes(raw + b'changed')
    with pytest.raises(SelectionError) as error:
        verify_archive_proof(tmp_path, config, proof)
    assert error.value.reason_code == 'SOURCE_CHANGED'
    with pytest.raises(SelectionError):
        compile_v2_guards(tmp_path, config, proof)


def test_external_roots_are_independent_protected_and_not_persistable(tmp_path, config):
    project = tmp_path / 'project'
    external = tmp_path / 'external'
    project.mkdir()
    external.mkdir()
    (project / 'source.md').write_text('safe original')
    (external / 'archive.md').write_text('safe original')
    pair = item({'kind': 'snippet', 'value': 'safe original'})
    pair['archive']['root'] = str(external)
    assert archive_coverage(project, config, request(pair))['results'][0]['reason_code'] == 'EXTERNAL_ROOT_NOT_ALLOWED'
    report = archive_coverage(project, config, request(pair, roots=[str(external)]))
    assert report['results'][0]['result'] == 'Exact' and report['write_precondition'] == 'Blocked'
    assert verify_archive_proof(project, config, report['proof'])['status'] == 'Passed'
    with pytest.raises(SelectionError) as error:
        compile_v2_guards(project, config, report['proof'])
    assert error.value.reason_code == 'EXTERNAL_PROOF_NOT_PERSISTABLE'
    (external / '.env').write_text('safe original')
    pair['archive']['path'] = '.env'
    assert archive_coverage(project, config, request(pair, roots=[str(external)]))['results'][0]['result'] == 'Unknown'
    pair['archive']['path'] = 'link.md'
    (external / 'link.md').symlink_to(external / 'archive.md')
    assert archive_coverage(project, config, request(pair, roots=[str(external)]))['results'][0]['result'] == 'Unknown'


def test_budget_scope_and_unknown_encoding_do_not_claim_coverage(tmp_path, config):
    (tmp_path / 'source.md').write_text('payload')
    (tmp_path / 'archive.md').write_text('payload')
    pair = item({'kind': 'snippet', 'value': 'payload'})
    limited = {**config, 'max_total_bytes': 8}
    result = archive_coverage(tmp_path, limited, request(pair))
    assert result['results'][0]['reason_code'] == 'BUDGET_EXHAUSTED' and result['status'] == 'Unknown'
    limited = {**config, 'max_files': 1}
    result = archive_coverage(tmp_path, limited, request(pair, pair))
    assert result['checked_items'] == 1 and result['unchecked']['count'] == 1
    assert result['read_bytes'] == len('payload')  # max_files counts actual unique files too
    assert result['proof'] is None and result['status'] == 'Unknown'
    scoped = {**config, '_task': {'sources': ['source.md'], 'reference_bodies': [], 'views': []}}
    result = archive_coverage(tmp_path, scoped, request(pair))
    assert result['results'][0]['reason_code'] == 'BODY_NOT_AUTHORIZED'
    (tmp_path / 'source.md').write_bytes(b'\xff')
    assert archive_coverage(tmp_path, config, request(pair))['results'][0]['reason_code'] == 'ENCODING_UNSUPPORTED'


def test_unknown_requests_and_out_of_scope_paths_never_echo_snippets(tmp_path, config):
    pair = item({'kind': 'snippet', 'value': 'password=PRIVATE'})
    pair['source']['path'] = '../outside.md'
    result = archive_coverage(tmp_path, config, request(pair))
    assert result['results'][0]['result'] == 'Unknown'
    assert 'PRIVATE' not in json.dumps(result)
    with pytest.raises(SelectionError):
        archive_coverage(tmp_path, config, {'version': True, 'items': [pair]})


def test_missing_original_missing_table_and_invalid_ranges_are_distinct(tmp_path, config):
    (tmp_path / 'source.md').write_text('plain text')
    (tmp_path / 'archive.md').write_text('plain text')
    req = request(item({'kind': 'snippet', 'value': 'plain'}, source='missing.md'),
                  item({'kind': 'table', 'index': 1}),
                  item({'kind': 'bytes', 'start_byte': 0, 'end_byte': 200}))
    result = archive_coverage(tmp_path, config, req)
    assert [entry['result'] for entry in result['results']] == ['Missing', 'Missing', 'Unknown']
    assert result['results'][2]['reason_code'] == 'SELECTOR_OUT_OF_RANGE'


def test_proof_configuration_binding_and_schema_are_validated(tmp_path, config):
    (tmp_path / 'source.md').write_text('payload')
    (tmp_path / 'archive.md').write_text('payload')
    proof = archive_coverage(tmp_path, config, request(item({'kind': 'snippet', 'value': 'payload'})))['proof']
    with pytest.raises(SelectionError) as error:
        verify_archive_proof(tmp_path, {**config, 'max_findings': 10}, proof)
    assert error.value.reason_code == 'PROOF_BINDING_MISMATCH'
    invalid = deepcopy(proof)
    invalid['items'][0]['archive']['selector'] = {'kind': 'snippet', 'value': 'payload'}
    invalid['proof_sha256'] = sha(json.dumps({key: value for key, value in invalid.items() if key != 'proof_sha256'}, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode())
    with pytest.raises(SelectionError):
        compile_v2_guards(tmp_path, config, invalid)


def test_external_root_symlink_and_symlink_ancestor_are_rejected(tmp_path, config):
    project = tmp_path / 'project'
    actual = tmp_path / 'actual'
    project.mkdir()
    (actual / 'nested').mkdir(parents=True)
    (project / 'source.md').write_text('payload')
    (actual / 'nested' / 'archive.md').write_text('payload')
    alias = tmp_path / 'alias'
    alias.symlink_to(actual, target_is_directory=True)
    direct_alias = tmp_path / 'direct-alias'
    direct_alias.symlink_to(actual / 'nested', target_is_directory=True)
    for declared in (direct_alias, alias / 'nested'):
        pair = item({'kind': 'snippet', 'value': 'payload'})
        pair['archive']['root'] = str(declared)
        with pytest.raises(SelectionError) as error:
            archive_coverage(project, config, request(pair, roots=[str(declared)]))
        assert error.value.reason_code == 'EXTERNAL_ROOT_NOT_ALLOWED'


def test_external_roots_cannot_overlap_project_or_grant_parent_files(tmp_path, config):
    project = tmp_path / 'project'
    child = project / 'child'
    child.mkdir(parents=True)
    (project / 'source.md').write_text('payload')
    (tmp_path / 'archive.md').write_text('payload')
    for declared in (project, child, tmp_path, Path('/')):
        pair = item({'kind': 'snippet', 'value': 'payload'})
        pair['archive']['root'] = str(declared)
        with pytest.raises(SelectionError) as error:
            archive_coverage(project, config, request(pair, roots=[str(declared)]))
        assert error.value.reason_code == 'EXTERNAL_ROOT_NOT_ALLOWED'
