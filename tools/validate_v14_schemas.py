#!/usr/bin/env python3
"""Validate v1.4 schemas and retained synthetic JSON using jsonschema.

Development-only: run with evidence/validation/v1.3/schema-env/bin/python.
Only fixture top-level JSON and records JSON are inspected. Embedded paths
are never followed; project/quarantine payloads and business projects are not
read. Summary objects keep Unknown rather than impersonating full artifacts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'evidence/validation/v1.4'
DEFAULT_FIXTURES = ['cleanup-small-contract-r6', 'cleanup-workflow-r1']
SCHEMAS = ['cleanup-profile', 'cleanup-request', 'cleanup-plan', 'cleanup-journal',
           'cleanup-report', 'maintenance-workflow']
VARIANTS = {'profile', 'request', 'plan:quarantine', 'plan:restore', 'plan:purge',
            'journal', 'workflow'} | {'report:' + k for k in (
                'inspect', 'qualification', 'rebaseline', 'verification',
                'measurement', 'evaluation', 'history', 'after-metrics')}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def identify(data):
    fmt = data.get('format')
    if fmt == 'fifan-cleanup-plan' and 'roots' in data:
        return 'cleanup-plan', 'plan:' + str(data.get('kind'))
    if fmt == 'fifan-cleanup-journal' and 'quarantine_plan' in data:
        return 'cleanup-journal', 'journal'
    if fmt == 'fifan-cleanup-report' and 'profile_sha256' in data:
        return 'cleanup-report', 'report:' + str(data.get('kind'))
    if fmt == 'fifan-maintenance-workflow' and 'measurement_data' in data:
        return 'maintenance-workflow', 'workflow'
    if fmt is None and data.get('schema_version') == 1:
        if 'project_root' in data and 'candidates' in data:
            return 'cleanup-profile', 'profile'
        if 'approval' in data and 'items' in data:
            return 'cleanup-request', 'request'
    return None


def walk(data, pointer=''):
    if isinstance(data, dict):
        match = identify(data)
        if match or 'format' in data:
            yield pointer, data, match
        for key, value in data.items():
            escaped = str(key).replace('~', '~0').replace('/', '~1')
            yield from walk(value, pointer + '/' + escaped)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from walk(value, pointer + '/' + str(index))


def safe_errors(errors):
    # Default engine messages may contain an entire private instance.
    return [{'validator': e.validator, 'instance_path': list(e.absolute_path),
             'schema_path': list(e.absolute_schema_path)} for e in errors[:30]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', action='append', default=[],
                        help='Additional retained fixture under v1.4/forward')
    parser.add_argument('--driver-fixture',
                        help='Replace early defaults with one retained driver: only its '
                             'approved-batch/quarantine-only/workflow JSON and records/commands JSON')
    parser.add_argument('--artifact', type=Path, action='append', default=[],
                        help='Explicit additional JSON under v1.4 validation evidence')
    parser.add_argument('--output', type=Path, default=BASE / 'schema-validation.json')
    args = parser.parse_args()
    paths = [ROOT / 'schemas' / (name + '.schema.json') for name in SCHEMAS]

    def offline(uri):
        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=offline)
    documents = {p.stem.removesuffix('.schema'): json.loads(p.read_bytes()) for p in paths}
    for path in paths:
        registry = registry.with_resource(path.as_uri(), Resource.from_contents(documents[path.stem.removesuffix('.schema')]))
    validators, schema_checks = {}, []
    for name, path in zip(SCHEMAS, paths):
        row = {'path': str(path.relative_to(ROOT)), 'sha256': sha(path.read_bytes())}
        try:
            Draft202012Validator.check_schema(documents[name])
            bound = {**documents[name], '$id': path.as_uri()}
            validators[name] = Draft202012Validator(bound, registry=registry)
            row['status'] = 'Passed'
        except Exception as error:
            row.update(status='Failed', error_type=type(error).__name__)
        schema_checks.append(row)

    inputs = []
    for name in ([] if args.driver_fixture else DEFAULT_FIXTURES) + args.fixture:
        fixture = BASE / 'forward' / name
        if fixture.resolve().parent != (BASE / 'forward').resolve() or not fixture.is_dir():
            raise ValueError('fixture must be an existing immediate forward child')
        inputs.extend(sorted(fixture.glob('*.json')))
        inputs.extend(sorted((fixture / 'records').rglob('*.json')))
    if args.driver_fixture:
        driver = BASE / 'forward' / args.driver_fixture
        if driver.resolve().parent != (BASE / 'forward').resolve() or not driver.is_dir():
            raise ValueError('driver fixture must be an immediate forward child')
        for name in ('approved-batch', 'quarantine-only', 'workflow'):
            fixture = driver / name
            if fixture.is_symlink() or not fixture.is_dir():
                raise ValueError('driver fixture requires three real fixed subdirectories')
            inputs.extend(sorted(fixture.glob('*.json')))
            inputs.extend(sorted((fixture / 'records').rglob('*.json')))
            inputs.extend(sorted((fixture / 'commands').glob('*.json')))
    for artifact in args.artifact:
        if artifact.is_symlink():
            raise ValueError('additional artifact cannot be a symlink')
        path = artifact.resolve()
        if (not path.is_relative_to(BASE.resolve()) or not path.is_file()
                or {'project', 'quarantine'} & set(path.relative_to(BASE.resolve()).parts)):
            raise ValueError('additional artifact must be retained v1.4 evidence')
        inputs.append(path)
    # Source data examples are inputs, never grants to follow placeholder paths.
    inputs.extend(sorted((ROOT / 'examples').glob('cleanup-*.example.json')))
    if any(path.is_symlink() for path in inputs):
        raise ValueError('fixture artifacts cannot be symlinks')
    inputs = sorted(set(p.resolve() for p in inputs))
    checks, unselected, sources, first_request, first_snapshot = [], [], [], None, None
    first_after_metrics = None
    for path in inputs:
        example = path.parent == ROOT / 'examples' and path.name.startswith('cleanup-')
        if path.is_symlink() or not (path.is_relative_to(BASE.resolve()) or example):
            raise ValueError('fixture material must stay inside v1.4 evidence')
        raw = path.read_bytes()
        source = {'path': str(path.relative_to(ROOT)), 'sha256': sha(raw), 'bytes': len(raw)}
        sources.append(source)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            checks.append({**source, 'status': 'Failed', 'error_type': type(error).__name__})
            continue
        entries = list(walk(data))
        if not entries:
            unselected.append({**source, 'status': 'Unknown', 'reason': 'No matching cleanup contract'})
        for pointer, instance, match in entries:
            row = {**source, 'json_pointer': pointer, 'instance_sha256': sha(canonical(instance))}
            if match is None:
                unselected.append({**row, 'status': 'Unknown',
                                   'reason': 'Summary or unsupported format; not schema-validated'})
                continue
            name, variant = match
            if variant == 'report:after-metrics' and first_after_metrics is None:
                first_after_metrics = instance
            if variant == 'request' and first_request is None:
                first_request = instance
            if variant == 'report:qualification' and first_snapshot is None:
                for item in instance.get('material', {}).get('items', []):
                    if item.get('retained'):
                        first_snapshot = item['retained'][0]
                        break
            row.update(schema=name + '.schema.json', variant=variant)
            try:
                errors = list(validators[name].iter_errors(instance))
                row.update(status='Failed' if errors else 'Passed',
                           error_count=len(errors), errors=safe_errors(errors))
            except Exception as error:
                row.update(status='Failed', error_type=type(error).__name__)
            checks.append(row)

    controls = {'unknown_format_not_dispatched': identify({'format': 'unknown-cleanup-format'}) is None,
                'public_plan_summary_not_full_artifact': identify({'format': 'fifan-cleanup-plan', 'kind': 'quarantine'}) is None}
    if first_request is not None and 'cleanup-request' in validators:
        invalid = json.loads(canonical(first_request))
        invalid.pop('approval')
        controls['missing_approval_rejected'] = not validators['cleanup-request'].is_valid(invalid)
        invalid = {**first_request, 'unexpected_executable_callback': 'forbidden'}
        controls['extra_input_field_rejected'] = not validators['cleanup-request'].is_valid(invalid)
    if first_snapshot is not None:
        snapshot_validator = Draft202012Validator(
            {'$ref': (ROOT / 'schemas/cleanup-report.schema.json').as_uri()
                     + '#/$defs/retained_snapshot'}, registry=registry)
        controls['current_retained_snapshot_valid'] = snapshot_validator.is_valid(first_snapshot)
        for key in ('manifest', 'state_sha256'):
            invalid = {k: v for k, v in first_snapshot.items() if k != key}
            controls['missing_retained_' + key + '_rejected'] = not snapshot_validator.is_valid(invalid)
    if first_after_metrics is not None:
        invalid = json.loads(canonical(first_after_metrics))
        invalid['metrics'].pop('search')
        controls['missing_after_metrics_domain_rejected'] = not validators['cleanup-report'].is_valid(invalid)
        if first_after_metrics['metrics']['archive']['status'] == 'Passed':
            invalid = json.loads(canonical(first_after_metrics))
            invalid['metrics']['archive']['project_reduction_bytes'] = None
            controls['passed_archive_null_delta_rejected'] = not validators['cleanup-report'].is_valid(invalid)
            invalid = json.loads(canonical(first_after_metrics))
            invalid['metrics']['archive']['status'] = 'Unknown'
            for key in ('project_reduction_bytes', 'archive_increase_bytes',
                        'records_increase_bytes', 'combined_delta_bytes'):
                invalid['metrics']['archive'][key] = 0
            controls['unknown_archive_zero_deltas_rejected'] = not validators['cleanup-report'].is_valid(invalid)
    covered = {row.get('variant') for row in checks if row['status'] == 'Passed'}
    missing = sorted(VARIANTS - covered)
    failed = sum(row['status'] == 'Failed' for row in schema_checks + checks) + sum(not ok for ok in controls.values())
    report = {
        'schema_version': 1, 'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'Failed' if failed else ('Unknown' if missing else 'Passed'),
        'meaning': 'Schema conformance of matched synthetic JSON only. Unknown/unmatched outputs '
                   'are not counted as Passed. This does not grant approval or prove runtime/semantic acceptance.',
        'engine': {'name': 'jsonschema', 'version': version('jsonschema'), 'draft': '2020-12',
                   'python': sys.version, 'executable': sys.executable, 'argv': sys.argv,
                   'network_reference_retrieval': 'Disabled'},
        'validator_script': {'path': str(Path(__file__).resolve().relative_to(ROOT)),
                             'sha256': sha(Path(__file__).read_bytes())},
        'schemas': schema_checks, 'sources': sources, 'checks': checks, 'unselected_outputs': unselected,
        'directed_controls': controls,
        'coverage': {'schema_count': len(paths), 'expected_variant_count': len(VARIANTS),
                     'covered_variants': sorted(covered), 'missing_variants': missing,
                     'failed_checks': failed, 'unselected_outputs': len(unselected)},
    }
    output = args.output.resolve()
    if not output.is_relative_to(BASE.resolve()) or output in inputs:
        raise ValueError('report must be separate v1.4 evidence')
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        # Preserve every previous validation result, including failed attempts.
        old = output.read_bytes()
        previous = output.with_name(output.stem + '.previous-' + sha(old)[:16] + '.json')
        if not previous.exists():
            previous.write_bytes(old)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'coverage': report['coverage'],
                      'report': str(output.relative_to(ROOT))}))
    return 1 if failed else (2 if missing else 0)


if __name__ == '__main__':
    raise SystemExit(main())
