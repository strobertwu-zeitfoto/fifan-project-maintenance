"""Isolated behavior tests for offline specialist checks."""
from __future__ import annotations

import hashlib
import os
import subprocess
import time
from pathlib import Path

import pytest

from fifan_maintenance.models import Context, FileRecord
from fifan_maintenance.checks import configs, dependencies, repository, assets, evidence, scripts


class FixtureContext(Context):
    """Explicit fixture-only scope, independent of the CLI's file scanner."""
    def resolve(self, rel):
        path = (self.root / rel).resolve()
        if Path(rel).is_absolute() or not path.is_relative_to(self.root):
            raise ValueError('outside fixture')
        return path

    def read_bytes(self, rel):
        if rel not in self.files:
            raise ValueError('not in fixture inventory')
        content = self.resolve(rel).read_bytes()
        if len(content) > self.config['max_file_bytes']:
            raise ValueError('size limit')
        return content


def context(tmp_path, files=None, **config):
    records = {}
    for path, value in (files or {}).items():
        content = value.encode() if isinstance(value, str) else value
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        records[path] = FileRecord(path, len(content), hashlib.sha256(content).hexdigest(), destination.stat().st_mtime_ns)
    return FixtureContext(tmp_path.resolve(), records, {'max_file_bytes': 1048576, **config})


def codes(findings):
    return {item.code for item in findings}


def test_configuration_formats_and_safe_custom_tags(tmp_path):
    ctx = context(tmp_path, {'duplicate.json': '{"a":1,"a":2}', 'nan.json': '{"v": NaN}',
                             'multi.yaml': 'a: 1\n---\na: 2\n', 'custom.yaml': 'a: !Something value\n',
                             'good.toml': 'answer = 42\n'})
    found = configs.run(ctx)
    assert {f.path for f in found if f.code == 'invalid_format'} == {'duplicate.json', 'nan.json'}
    assert [(f.path, f.status) for f in found if f.code == 'custom_tag'] == [('custom.yaml', 'Unknown')]
    assert not any(f.path in ('multi.yaml', 'good.toml') for f in found)


def test_tag_cannot_hide_later_yaml_syntax_error(tmp_path):
    ctx = context(tmp_path, {'bad.yaml': 'a: !Custom value\n---\n[broken\n'})
    assert 'invalid_format' in codes(configs.run(ctx))


def test_equality_pointer_types_and_bad_declarations(tmp_path):
    ctx = context(tmp_path, {'a.json': '{"a/b": {"~v": true}, "n": 1}', 'b.json': '{"x": 1}'},
                  equalities=[{'left': 'a.json#/a~1b/~0v', 'right': 'b.json#/x'},
                              {'left': 'a.json#/n', 'right': 'b.json#/x'},
                              {'left': '../outside.json#/x', 'right': 'b.json#/x'}], paths=['../escape'])
    found = configs.run(ctx)
    assert codes(found) == {'unequal', 'equality_unknown', 'unsafe_path'}
    assert len([f for f in found if f.code == 'unequal']) == 1
    ctx.config['paths'] = {'x': 'bad'}
    ctx.config['equalities'] = None
    assert 'invalid_declaration' in codes(configs.run(ctx))


def test_read_limit_is_unknown_not_invalid_format(tmp_path):
    ctx = context(tmp_path, {'large.json': '{"value": 123456789}'}, max_file_bytes=4)
    found = configs.run(ctx)
    assert [(f.code, f.status) for f in found] == [('unreadable', 'Unknown')]


def test_yaml_alias_comparison_is_bounded(tmp_path):
    ctx = context(tmp_path, {'cycle.yaml': '&x [*x]', 'a.json': '[]'}, equalities=[{'left': 'cycle.yaml#', 'right': 'a.json#'}])
    assert 'equality_unknown' in codes(configs.run(ctx))


def test_node_lock_exact_ranges_and_unsupported_format(tmp_path):
    ctx = context(tmp_path, {'package.json': '{"dependencies":{"a":"1.0.0","b":"^2","c":"3.0.0"}}',
                             'package-lock.json': '{"packages":{"":{"dependencies":{"a":"1.1.0","b":"~2"}}}}'})
    assert codes(dependencies.run(ctx)) == {'version_mismatch', 'version_unknown', 'missing_locked_dependency', 'lock_format_unknown'}
    (tmp_path / 'package-lock.json').write_text('{"lockfileVersion": 1}')
    assert codes(dependencies.run(ctx)) == {'lock_format_unknown'}


def test_unity_direct_and_python_pins(tmp_path):
    ctx = context(tmp_path, {'Packages/manifest.json': '{"dependencies":{"a":"1.0.0","b":"2.0.0"}}',
                             'Packages/packages-lock.json': '{"dependencies":{"a":{"version":"1.0.0","depth":0},"b":{"version":"2.0.0","depth":1}}}',
                             'pyproject.toml': '[project]\ndependencies = ["My_Pkg==1.0.0", "dynamic>=2"]\n',
                             'requirements.txt': 'my-pkg==2.0.0\n-r external.txt\n'})
    found = dependencies.run(ctx)
    assert {'not_direct', 'version_mismatch', 'version_unknown'} == codes(found)


def test_evidence_requires_real_original_and_matching_hash(tmp_path):
    ctx = context(tmp_path, {'report.md': 'Passed', 'candidate.bin': b'candidate'}, evidence_bindings=[
        {'report': 'report.md', 'candidate': 'candidate.bin', 'sha256': hashlib.sha256(b'candidate').hexdigest()},
        {'report': 'report.md', 'candidate': 'candidate.bin', 'sha256': '0' * 64},
        {'report': '../outside', 'candidate': 'candidate.bin', 'sha256': '0' * 64}, {}])
    found = evidence.run(ctx)
    assert codes(found) == {'binding_verified', 'candidate_mismatch', 'original_unavailable', 'invalid_binding'}
    assert [f.status for f in found if f.code == 'binding_verified'] == ['Passed']
    assert '验收' in next(f.message for f in found if f.code == 'binding_verified')


def test_asset_duplicates_sources_and_age_only_advisory(tmp_path):
    ctx = context(tmp_path, {'image.png': b'123', 'other.png': b'123', 'backup/old.log': 'log'},
                  asset_sources={'image.png': 'missing-source.md'}, artifact_age_days=30)
    ctx.files['backup/old.log'].mtime_ns = time.time_ns() - 60 * 86400000000000
    before = {p: (tmp_path / p).read_bytes() for p in ctx.files}
    findings = assets.run(ctx)
    assert codes(findings) == {'duplicate_hash', 'source_unknown', 'missing_source_record', 'old_artifact', 'directory_distribution'}
    distribution = next(f for f in findings if f.code == 'directory_distribution')
    assert distribution.evidence['groups']['unclassified'] == {'files': 2, 'bytes': 6}
    assert before == {p: (tmp_path / p).read_bytes() for p in ctx.files}


def test_entries_waivers_modes_and_no_script_execution(tmp_path):
    ctx = context(tmp_path, {'bad.sh': '#!/bin/sh\ntouch MUST_NOT_EXIST\n./missing-tool\n',
                             'executable.py': 'print(1)\n'}, entrypoints=['missing.sh'], checks=['../external'],
                  waivers=[{'id': 'old', 'expires': '2000-01-01'}, {'id': 'bad', 'expires': 'bad'},
                           {'id': 'future', 'expires': '2999-01-01'}])
    (tmp_path / 'executable.py').chmod(0o755)
    found = scripts.run(ctx)
    assert {'missing_entrypoints', 'path_unknown', 'expired_waiver', 'invalid_waiver', 'shebang_mode', 'literal_path_unknown'} == codes(found)
    assert len([f for f in found if f.code == 'shebang_mode']) == 2
    assert not (tmp_path / 'MUST_NOT_EXIST').exists()


def test_repository_ancestor_scope_newline_names_and_no_hooks(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    child = tmp_path / 'child'
    child.mkdir()
    ctx = context(child, {'node_modules/line\nbreak.js': 'code\n', 'conflict.txt': '<<<<<<< ours\nx\n=======\ny\n>>>>>>> theirs\n'})
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules' / 'external.js').write_text('external')
    subprocess.run(['git', '-C', str(tmp_path), 'add', '--', '.'], check=True)
    before = subprocess.check_output(['git', '-C', str(tmp_path), 'diff', '--cached', '--raw', '-z', '--', '.'])
    found = repository.run(ctx)
    tracked = [f.path for f in found if f.code == 'tracked_generated']
    assert tracked == ['node_modules/line\nbreak.js']
    assert len([f for f in found if f.code == 'conflict_marker']) == 3
    assert before == subprocess.check_output(['git', '-C', str(tmp_path), 'diff', '--cached', '--raw', '-z', '--', '.'])


def test_configured_symlink_escape_not_read(tmp_path):
    outside = tmp_path / 'outside.json'
    outside.write_text('{"secret": 1}')
    child = tmp_path / 'child'
    child.mkdir()
    ctx = context(child, {'a.json': '{}'}, paths=['escape.json'], evidence_bindings=[
        {'report': 'a.json', 'candidate': 'escape.json', 'sha256': '0' * 64}])
    (child / 'escape.json').symlink_to(outside)
    assert 'unsafe_path' in codes(configs.run(ctx))
    assert 'original_unavailable' in codes(evidence.run(ctx))


def test_explicit_artifact_rules_and_malformed_thresholds(tmp_path):
    ctx = context(tmp_path, {'Exports/release.zip': b'zip'}, artifacts=[
        {'pattern': 'Exports/**', 'age_days': 3}, {'pattern': '../outside/**', 'age_days': 0},
        {'pattern': ['bad'], 'age_days': 0}, {'pattern': 'x/**', 'age_days': float('nan')}])
    ctx.files['Exports/release.zip'].mtime_ns = time.time_ns() - 4 * 86400000000000
    found = assets.run(ctx)
    assert len([f for f in found if f.code == 'invalid_artifacts']) == 3
    assert len([f for f in found if f.code == 'old_artifact']) == 1
    assert (tmp_path / 'Exports/release.zip').exists()
    ctx.config['artifacts'] = 'bad'
    ctx.config['artifact_age_days'] = float('inf')
    assert {'invalid_artifacts', 'invalid_threshold'} <= codes(assets.run(ctx))


def test_specialists_use_production_context_for_scope_and_limits(tmp_path):
    outside = tmp_path / 'external'
    outside.write_bytes(b'secret')
    child = tmp_path / 'project'
    child.mkdir()
    fixture = context(child, {'a.json': '{"value": 1}', 'report.md': 'Passed'}, max_file_bytes=4,
                      paths=['../external'], evidence_bindings=[{'report': 'report.md', 'candidate': 'escape', 'sha256': '0' * 64}])
    (child / 'escape').symlink_to(outside)
    ctx = Context(child.resolve(), fixture.files, fixture.config)
    found = configs.run(ctx)
    assert {'unreadable', 'unsafe_path'} <= codes(found)
    assert 'original_unavailable' in codes(evidence.run(ctx))


def test_tracked_generated_outside_inventory_respects_explicit_excludes(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    ctx = context(tmp_path, {'Library/cache.bin': b'not-readable', 'node_modules/hidden.js': b'not-readable',
                             'Temp/skip.bin': b'not-readable', 'Obj/generated.bin': b'not-readable'},
                  exclude=['node_modules/**', 'Temp/'])
    subprocess.run(['git', '-C', str(tmp_path), 'add', '--', '.'], check=True)
    from fifan_maintenance.inventory import collect
    from fifan_maintenance.project import DEFAULT_CONFIG
    ctx = Context(tmp_path.resolve(), {}, {**DEFAULT_CONFIG, 'exclude': ctx.config['exclude']}, inventory=True)
    collect(ctx)
    assert not ctx.files  # Real inventory omits all the generated directories.
    found = repository.run(ctx)
    assert {f.path for f in found if f.code == 'tracked_generated'} == {'Obj/generated.bin'}


def test_setext_title_is_not_a_merge_conflict(tmp_path):
    ctx = context(tmp_path, {'guide.md': '合法标题\n=======\n正文\n>>>>>>> unrelated\n'})
    assert 'conflict_marker' not in codes(repository.run(ctx))
    (tmp_path / 'guide.md').write_text('合法标题\n=======\n<<<<<<< ours\nunfinished\n')
    found = [f for f in repository.run(ctx) if f.code == 'conflict_marker']
    assert [f.line for f in found] == [3]


def test_absolute_script_paths_are_unknown_and_never_resolved(tmp_path):
    ctx = context(tmp_path, {'paths.sh': 'echo /Volumes/旧盘/项目\necho /Users/某人/工作\necho C:\\旧盘\\项目\necho /usr/bin/python3\n'})
    resolved = []
    original_resolve = ctx.resolve

    def local_only(path):
        resolved.append(path)
        assert path == 'paths.sh', 'absolute migration clues must not be resolved'
        return original_resolve(path)

    ctx.resolve = local_only
    found = [f for f in scripts.run(ctx) if f.code == 'absolute_path_unknown']
    assert [f.line for f in found] == [1, 2, 3]
    assert all(f.status == 'Unknown' for f in found)
    assert resolved == ['paths.sh', 'paths.sh']  # read_bytes and permission inspection


@pytest.mark.parametrize('lock_version', [2, 3])
def test_node_checks_resolved_direct_entries_not_only_root(tmp_path, lock_version):
    import json
    package = {'dependencies': {'a': '1.0.0', '@scope/b': '2.0.0'}}
    lock = {'lockfileVersion': lock_version, 'packages': {'': package,
            'node_modules/a': {'version': '2.0.0'}, 'node_modules/@scope/b': {'version': '2.0.0'}}}
    ctx = context(tmp_path, {'package.json': json.dumps(package), 'package-lock.json': json.dumps(lock)})
    found = dependencies.run(ctx)
    assert [(f.code, f.status, f.evidence.get('dependency')) for f in found] == [('resolved_version_mismatch', 'Failed', 'a')]


def test_node_resolved_unknown_boundaries_and_missing_required(tmp_path):
    import json
    package = {'dependencies': {'required': '1.0.0', 'ranged': '^1.0.0', 'linked': '1.0.0',
                               'source': '1.0.0', 'badversion': '1.0.0', 'optional': '1.0.0'},
               'optionalDependencies': {'optional': '1.0.0'}, 'peerDependencies': {'peer': '1.0.0'}}
    lock = {'lockfileVersion': 3, 'packages': {'': package,
            'node_modules/ranged': {'version': '1.0.0'}, 'node_modules/linked': {'link': True, 'version': '2.0.0'},
            'node_modules/source': {'version': '2.0.0', 'resolved': 'git+https://example.invalid/repo'},
            'node_modules/badversion': {'version': 'not-version'}}}
    ctx = context(tmp_path, {'package.json': json.dumps(package), 'package-lock.json': json.dumps(lock)})
    found = dependencies.run(ctx)
    assert [(f.evidence['dependency'], f.status) for f in found if f.code == 'resolved_dependency_missing'] == [('required', 'Failed')]
    unknown = {f.evidence['dependency'] for f in found if f.status == 'Unknown'}
    assert unknown == {'ranged', 'linked', 'source', 'badversion', 'optional', 'peer'}


def test_node_unknown_lock_version_cannot_claim_resolved_coverage(tmp_path):
    ctx = context(tmp_path, {'package.json': '{"dependencies":{"a":"1.0.0"}}',
                             'package-lock.json': '{"lockfileVersion":99,"packages":{"":{"dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0"}}}'})
    assert 'lock_format_unknown' in codes(dependencies.run(ctx))


@pytest.mark.parametrize('declared', ['1.0', '1.0.0-01', '1.0.0-.'])
def test_node_partial_or_invalid_semver_is_unknown(tmp_path, declared):
    import json
    package = {'dependencies': {'a': declared}}
    lock = {'lockfileVersion': 3, 'packages': {'': package, 'node_modules/a': {'version': '1.0.0'}}}
    ctx = context(tmp_path, {'package.json': json.dumps(package), 'package-lock.json': json.dumps(lock)})
    found = dependencies.run(ctx)
    assert [(f.code, f.status) for f in found] == [('resolved_dependency_unknown', 'Unknown')]


def test_json_registry_required_pointers_and_explicit_path_fields(tmp_path):
    import json
    registry = {'items': [{'id': 0, 'file': 'Assets/valid.png', 'a/b': {'~name': None}},
                          {'file': 'Assets/missing.png'}, {'id': False, 'file': '../outside'},
                          {'id': None, 'file': 3}]}
    ctx = context(tmp_path, {'registry.json': json.dumps(registry), 'Assets/valid.png': b'png'},
                  json_contracts=[{'path': 'registry.json', 'records': '/items',
                                   'required': ['/id', '/a~1b/~0name'], 'paths': ['/file']}])
    found = configs.run(ctx)
    assert len([f for f in found if f.code == 'json_required_missing']) == 4
    assert [(f.status, f.evidence['target']) for f in found if f.code == 'json_path_missing'] == [('Failed', 'Assets/missing.png')]
    assert [(f.status, f.evidence['target']) for f in found if f.code == 'json_path_unavailable'] == [('Unknown', '../outside')]
    assert len([f for f in found if f.code == 'json_path_field']) == 1
    assert not any(f.code == 'json_required_missing' and f.evidence['record_index'] == 0 for f in found)


def test_json_contract_does_not_infer_fields_or_business_values(tmp_path):
    ctx = context(tmp_path, {'registry.json': '{"items":[{"frames":-1,"path":"absent.png"}]}'})
    assert configs.run(ctx) == []
    ctx.config['json_contracts'] = [{'path': 'registry.json', 'records': '/items', 'required': ['/frames']}]
    assert configs.run(ctx) == []  # Presence is the contract; no implicit frame-count semantics.


def test_json_contract_failures_and_scope_are_explicit(tmp_path):
    ctx = context(tmp_path, {'a.json': '{"items":[7]}', 'bad.json': '{'}, json_contracts=[
        {'path': 'a.json', 'records': '/items', 'required': ['/id']},
        {'path': 'a.json', 'records': '/absent'}, {'path': '../outside.json'},
        {'path': 'a.json', 'required': ['id']}, {'path': 'a.json', 'plugin': 'execute.py'},
        {'path': 'bad.json'}])
    found = configs.run(ctx)
    assert {'json_record_type', 'json_records_missing', 'json_contract_unavailable', 'invalid_json_contract', 'invalid_format'} <= codes(found)
    assert all(f.status == 'Unknown' for f in found if f.code == 'json_contract_unavailable')
    assert not (tmp_path / 'execute.py').exists()


def test_json_contracts_share_run_local_parse_and_recheck_changes(tmp_path):
    ctx = context(tmp_path, {'registry.json': '{"id": 1}'},
                  json_contracts=[{'path': 'registry.json', 'required': ['/id']},
                                  {'path': 'registry.json', 'required': ['/id']}])
    reads = []
    original = ctx.read_bytes

    def counted(path):
        reads.append(path)
        return original(path)

    ctx.read_bytes = counted
    assert configs.run(ctx) == []
    assert reads == ['registry.json']
    (tmp_path / 'registry.json').write_text('{}')
    assert len([f for f in configs.run(ctx) if f.code == 'json_required_missing']) == 2
    assert reads == ['registry.json', 'registry.json']


def test_json_contract_paths_accept_validated_overlay_metadata(tmp_path):
    import base64
    fixture = context(tmp_path, {'registry.json': '{"file":"archive/copy.png"}'})
    ctx = Context(tmp_path.resolve(), fixture.files,
                  {**fixture.config, 'json_contracts': [{'path': 'registry.json', 'paths': ['/file']}],
                   '_task': {'sources': ['registry.json'], 'reference_bodies': []},
                   '_overlay': {'archive/copy.png': base64.b64encode(b'candidate').decode()}})
    assert configs.run(ctx) == []
    assert not (tmp_path / 'archive/copy.png').exists()
