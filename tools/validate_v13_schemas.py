#!/usr/bin/env python3
"""Offline development validation of directory schemas and retained fixtures.

Run with evidence/validation/v1.3/schema-env/bin/python. This is not a
runtime dependency or a filesystem/semantic acceptance test. No target project
body is read: only the named fixture inputs and their results/records JSON.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'evidence/validation/v1.3'
DRIVERS = ('forward/small-driver-r5', 'forward/archive-driver-python39')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':')).encode('utf-8')


def identify(data):
    """Dispatch by actual artifact contract, never by a misleading filename."""
    fmt, kind = data.get('format'), data.get('kind')
    envelopes = {
        'fifan-directory-plan': 'plan',
        'fifan-directory-journal': 'journal',
        'fifan-directory-restore-plan': 'restore-plan',
    }
    if fmt in envelopes:
        family = {'search-config': 'search', 'directory-archive': 'archive'}.get(kind)
        if family is None:
            return []
        suffix = envelopes[fmt]
        return ['directory-' + family + '-' + suffix + '.schema.json',
                'directory-' + suffix + '.schema.json']
    by_format = {
        'fifan-directory-workflow': 'workflow',
        'fifan-directory-metrics': 'metrics',
        'fifan-directory-metrics-evaluation': 'metrics-evaluation',
    }
    if fmt in by_format:
        return ['directory-' + by_format[fmt] + '.schema.json']
    if fmt is not None:
        return []
    if kind in ('directory-census', 'directory-impact'):
        return [kind + '.schema.json']
    if kind == 'directory-archive' and 'resolution' in data:
        return ['directory-location.schema.json']
    if data.get('schema_version') == 1 and 'project_root' in data and kind is None and 'status' not in data:
        return ['directory-profile.schema.json']
    if data.get('schema_version') == 1 and 'batches' in data and kind is None and 'status' not in data:
        return ['directory-request.schema.json']
    return []


def nested_artifacts(data, pointer=''):
    if isinstance(data, dict):
        schemas = identify(data)
        if schemas:
            yield pointer, data, schemas
        # Only descend retained JSON, never follow its paths or references.
        for key, value in data.items():
            escaped = str(key).replace('~', '~0').replace('/', '~1')
            yield from nested_artifacts(value, pointer + '/' + escaped)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from nested_artifacts(value, pointer + '/' + str(index))


def safe_error(error):
    # jsonschema's default message can embed private config/body values.
    return {'validator': error.validator,
            'instance_path': list(error.absolute_path),
            'schema_path': list(error.absolute_schema_path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=BASE / 'schema-validation.json')
    args = parser.parse_args()
    schema_paths = sorted((ROOT / 'schemas').glob('directory-*.json'))
    schemas = {p.name: json.loads(p.read_bytes()) for p in schema_paths}

    def deny_remote(uri):
        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=deny_remote)
    for path in schema_paths:
        registry = registry.with_resource(path.as_uri(), Resource.from_contents(schemas[path.name]))
    validators = {}
    schema_results = []
    for path in schema_paths:
        data = schemas[path.name]
        row = {'path': str(path.relative_to(ROOT)), 'sha256': sha(path.read_bytes())}
        try:
            Draft202012Validator.check_schema(data)
            # Explicit base URI makes sibling $refs resolve locally; no web fetch.
            bound = dict(data)
            bound['$id'] = path.as_uri()
            validators[path.name] = Draft202012Validator(bound, registry=registry)
            row['status'] = 'Passed'
        except Exception as error:
            row.update(status='Failed', error_type=type(error).__name__)
        schema_results.append(row)

    inputs = []
    for name in DRIVERS:
        directory = BASE / name
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        inputs.extend(directory / n for n in ('directory-profile.json', 'directory-request.json'))
        for subdir in ('results', 'records'):
            inputs.extend(sorted((directory / subdir).rglob('*.json')))
    supplement = BASE / 'schema-metrics-fixture/metrics.json'
    if supplement.exists():
        inputs.append(supplement)

    checks, unselected, source_files = [], [], []
    for path in inputs:
        raw = path.read_bytes()
        source = str(path.relative_to(ROOT))
        file_sha = sha(raw)
        source_files.append({'path': source, 'sha256': file_sha, 'bytes': len(raw)})
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            checks.append({'path': source, 'sha256': file_sha, 'status': 'Failed',
                           'error_type': type(error).__name__})
            continue
        selected = list(nested_artifacts(data))
        if not selected:
            unselected.append({'path': source, 'sha256': file_sha, 'status': 'Unknown',
                               'reason': 'No matching directory schema; not counted as validated',
                               'format': data.get('format') if isinstance(data, dict) else None,
                               'kind': data.get('kind') if isinstance(data, dict) else None})
        for pointer, artifact, names in selected:
            for name in names:
                row = {'path': source, 'sha256': file_sha, 'json_pointer': pointer,
                       'instance_sha256': sha(canonical(artifact)), 'schema': name}
                try:
                    errors = list(validators[name].iter_errors(artifact))
                    row.update(status='Failed' if errors else 'Passed',
                               error_count=len(errors), errors=[safe_error(e) for e in errors[:30]])
                except Exception as error:
                    row.update(status='Failed', error_type=type(error).__name__)
                checks.append(row)

    covered = {row.get('schema') for row in checks if row['status'] == 'Passed'}
    missing = sorted(set(schemas) - covered)
    inventory_complete = len(schemas) == 17
    failed = sum(row['status'] == 'Failed' for row in schema_results + checks)
    log_names = ['schema-env-create.log', 'schema-env-install.log', 'schema-env-commands.json',
                 'schema-metrics-generate.py', 'schema-metrics-generate.log']
    logs = [{'path': str((BASE / name).relative_to(ROOT)),
             'sha256': sha((BASE / name).read_bytes())} for name in log_names if (BASE / name).is_file()]
    report = {
        'schema_version': 1, 'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': 'Failed' if failed else ('Unknown' if missing or not inventory_complete else 'Passed'),
        'meaning': 'Standard schema conformance of selected retained fixture artifacts only; '
                   'unmapped outputs remain Unknown, not validated. No runtime or semantic acceptance.',
        'engine': {'name': 'jsonschema', 'version': version('jsonschema'),
                   'draft': '2020-12', 'python': sys.version, 'executable': sys.executable,
                   'argv': sys.argv, 'network_reference_retrieval': 'Disabled'},
        'validator_script': {'path': str(Path(__file__).resolve().relative_to(ROOT)),
                             'sha256': sha(Path(__file__).read_bytes())},
        'schemas': schema_results, 'source_files': source_files, 'checks': checks,
        'unselected_outputs': unselected,
        'coverage': {'schema_count': len(schemas), 'schemas_with_passing_artifacts': len(covered),
                     'expected_schema_count': 17, 'schema_inventory_complete': inventory_complete,
                     'missing_artifact_types': missing, 'failed_checks': failed,
                     'unselected_outputs': len(unselected)},
        'provenance_logs': logs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'coverage': report['coverage'],
                      'report': str(args.output.relative_to(ROOT))}, ensure_ascii=True))
    return 1 if failed else (2 if missing or not inventory_complete else 0)


if __name__ == '__main__':
    raise SystemExit(main())
