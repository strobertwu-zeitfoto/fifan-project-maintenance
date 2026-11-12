#!/usr/bin/env python3
"""Offline, real-wheel 1.2 -> 1.3 compatibility on fresh isolated fixtures.

Default only prepares inputs. Root must identify the final 1.3 wheel before
--run. Every attempt keeps its fixtures, command stdout/stderr and failures.
No editable/source import, project commands, network or dependency upgrade.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import uuid

import validate_v12 as previous

ROOT = previous.ROOT
BASE = ROOT / 'evidence/validation/v1.3'
OLD_WHEEL = ROOT / 'evidence/validation/v1.2/wheels/fifan_project_maintenance-1.2.0-py3-none-any.whl'
NEW_WHEEL = BASE / 'wheels/fifan_project_maintenance-1.3.0-py3-none-any.whl'
PYTHONS = [ROOT / '.venv39/bin/python', ROOT / '.venv/bin/python']
OFFLINE_DIRS = previous.OFFLINE_WHEEL_DIRS
write_json = previous.write_json
sha256_file = previous.sha256_file
require = previous._assert


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def prepare(run_root):
    project, records = run_root / 'project', run_root / 'records'
    project.mkdir(parents=True)
    records.mkdir()
    (project / 'archive').mkdir()
    files = {
        'README.md': b'# Fixture\n\nSee [guide](guide.md#guide).\n',
        'guide.md': '# Guide\n\n普通 Unicode 原文。\n'.encode('utf-8'),
        'chain.md': '# Chain\r\n\r\nphase-original 中文\r\n'.encode('utf-8'),
        'standalone-v1.md': b'# Standalone v1\n\nold-one\n',
        'standalone-v2.md': b'# Standalone v2\n\nold-two\n',
    }
    for path, data in files.items():
        (project / path).write_bytes(data)
    write_json(project / '.fifan-maintenance.json', {
        'schema_version': 1, 'include': ['*.md', 'archive/**'],
        'exclude': [], 'protected': ['.git/**', '.venv/**', '.venv39/**'],
    })
    sources = list(files)
    profile1 = {'schema_version': 1, 'sources': sources, 'reference_bodies': [],
                'historical_roots': [], 'views': [], 'checks': ['links'], 'budgets': {}}
    parent2 = {**profile1, 'schema_version': 2, 'goal': 'navigation'}
    write_json(records / 'profile1.json', profile1)
    write_json(records / 'parent-profile2.json', parent2)
    for label, path, old, new in (
        ('standalone-v1', 'standalone-v1.md', 'old-one', 'new-one'),
        ('chain-v1', 'chain.md', 'phase-original', 'phase-first'),
    ):
        write_json(records / (label + '-request.json'), {
            'operations': [{'type': 'replace', 'path': path, 'old': old, 'new': new}],
        })
    manifest = {'fixture': 'synthetic-v13-real-wheel-compat', 'project': str(project),
                'original_sha256': {path.relative_to(project).as_posix(): sha256_file(path)
                                    for path in project.iterdir() if path.is_file()},
                'sources': sources, 'profile1': str(records / 'profile1.json'),
                'parent_profile2': str(records / 'parent-profile2.json'),
                'generated_by_driver': ['fixture source bytes', 'schema1 input profile',
                                        'schema2 parent input', 'v1 request inputs', 'session selection manifest'],
                'must_be_generated_by_actual_v12': ['derived schema2 profile', 'v1/v2 plans and journals',
                                                   'check reports', 'session report/verify/recovery-preview']}
    write_json(records / 'fixture-manifest.json', manifest)
    return project, records, manifest


def command(argv, records, label, *, expected=(0,)):
    return previous.run_logged([str(item) for item in argv], records, label,
                               env={'PYTHONDONTWRITEBYTECODE': '1'}, expected_codes=list(expected))


def install(python, wheel, records, label, *, upgrade=False):
    args = [python, '-I', '-B', '-m', 'pip', '--isolated', 'install', '--no-index',
            '--no-cache-dir', '--disable-pip-version-check']
    for directory in OFFLINE_DIRS:
        require(directory.is_dir(), 'offline wheel directory is missing')
        args.extend(['--find-links', directory])
    if upgrade:
        args.append('--upgrade')
    args.append(wheel)
    return command(args, records, label)


def provenance(python, venv, records, version, label):
    result = command([python, '-I', '-B', '-c',
                      'import json,sys,pathlib,fifan_maintenance as p; '
                      'print(json.dumps({"version":p.__version__,"module":str(pathlib.Path(p.__file__).resolve()),'
                      '"prefix":sys.prefix,"python":list(sys.version_info[:3])}))'], records, label)
    value = json.loads(result['stdout'])
    require(value['version'] == version, 'fresh environment imported the wrong package version')
    require(Path(value['module']).is_relative_to(venv), 'package was imported from outside the fresh wheel environment')
    require(Path(value['prefix']) == venv, 'wrong isolated interpreter prefix')
    return value


def execute(python, run_root, old_wheel, new_wheel, *, resume=False):
    if resume:
        project, records = run_root / 'project', run_root / 'records'
        manifest = read_json(records / 'fixture-manifest.json')
    else:
        project, records, manifest = prepare(run_root)
    logs = records if not resume else records / ('resume-' + uuid.uuid4().hex[:10])
    logs.mkdir(exist_ok=True)
    venv = run_root / 'venv'
    steps = []
    wheel_python, tool = venv / 'bin/python', venv / 'bin/fifan-maintain'
    if not resume:
        command([python, '-I', '-B', '-m', 'venv', venv], records, 'create-fresh-venv')
        install(wheel_python, old_wheel, records, 'install-real-v12')
        old_provenance = provenance(wheel_python, venv, records, '1.2.0', 'v12-package-provenance')

    def cli(label, args, expected=(0,)):
        result = command([wheel_python, '-I', '-B', tool, *args], logs, label, expected=expected)
        steps.append({'name': label, 'returncode': result['returncode'], 'passed': result['passed']})
        return json.loads(result['stdout'])

    common = ['--project', str(project)]
    if not resume:
        derived = records / 'v12-derived-profile2.json'
        cli('v12-derive-profile2', ['profile', 'derive', *common, '--from', str(records / 'parent-profile2.json'),
                                 '--sources', 'README.md', 'guide.md', '--checks', 'links', '--output', str(derived)])
        require(read_json(derived).get('schema_version') == 2, '1.2 did not emit a real schema2 derived profile')
        require('parent_binding' in read_json(derived), 'old derived profile lacks parent binding')

        old_report = records / 'v12-check-report.json'
        cli('v12-check-schema1', ['check', *common, '--task-profile', str(records / 'profile1.json'),
                                '--checks', 'links', '--format', 'json', '--output', str(old_report)])
        require(read_json(old_report).get('tool_version') == '1.2.0', 'old report was not generated by the old wheel')

        journals = {}
        def apply_old(label, request):
            request_path = records / (label + '-request.json')
            if request is not None:
                write_json(request_path, request)
            plan_path, operations = records / (label + '-plan.json'), records / (label + '-operations')
            cli('v12-preview-' + label, ['preview', *common, '--request', str(request_path), '--plan', str(plan_path)])
            cli('v12-apply-' + label, ['apply', *common, '--plan', str(plan_path), '--operations-dir', str(operations)])
            found = list(operations.glob('*.json'))
            require(len(found) == 1, 'old apply did not emit exactly one journal')
            journal = found[0]
            require(read_json(journal)['plan']['version'] == (2 if label.endswith('v2') else 1), 'wrong old record version')
            require(cli('v12-verify-' + label, ['verify', *common, '--journal', str(journal)])['status'] == 'Passed',
                    'old applied record did not verify')
            journals[label] = journal
            return journal

        def v2_request(path, destination, old, new):
            return {'version': 2, 'operations': [
                {'kind': 'snapshot', 'path': path, 'destination': destination,
                 'expected_sha256': sha256_file(project / path),
                 'origin': {'reference_base': '.', 'classification_basis': 'synthetic old-wheel compatibility snapshot'}},
                {'type': 'replace', 'path': path, 'old': old, 'new': new},
            ], 'guards': []}

        apply_old('standalone-v1', None)
        apply_old('standalone-v2', v2_request('standalone-v2.md', 'archive/standalone-before.md', 'old-two', 'new-two'))
        apply_old('chain-v1', None)
        apply_old('chain-v2', v2_request('chain.md', 'archive/chain-before.md', 'phase-first', 'phase-second'))
        session = records / 'v12-session.json'
        write_json(session, {'schema_version': 1, 'root': str(project),
                            'journals': [str(journals['chain-v1']), str(journals['chain-v2'])],
                            'reports': [str(old_report)],
                            'profiles': [{'path': str(records / 'profile1.json'), 'root': str(project)},
                                         {'path': str(derived), 'root': str(project)}]})
        old_recovery = records / 'v12-recovery-plan.json'
        for action in ('report', 'verify', 'recovery-preview'):
            output = old_recovery if action == 'recovery-preview' else records / ('v12-session-' + action + '.json')
            value = cli('v12-session-' + action, ['session', action, *common, '--session', str(session), '--output', str(output)])
            require(value.get('status') == 'Passed', 'old wheel did not validate the selected session')
        require([step['path'] for step in read_json(old_recovery)['steps']] ==
                [str(journals['chain-v2']), str(journals['chain-v1'])], 'old recovery plan is not in reverse dependency order')
        preserved = [derived, old_report, old_recovery, session, records / 'profile1.json']
        old_material_hashes = {str(path): sha256_file(path) for path in preserved}
        write_json(records / 'v12-material-provenance.json', {
            'wheel_sha256': sha256_file(old_wheel), 'package': old_provenance,
            'journals': {label: {'path': str(path), 'sha256': sha256_file(path)} for label, path in journals.items()},
            'selected_material_sha256': old_material_hashes,
        })

    else:
        material = read_json(records / 'v12-material-provenance.json')
        require(material['wheel_sha256'] == sha256_file(old_wheel), 'resume old wheel changed')
        old_provenance = material['package']
        old_material_hashes = material['selected_material_sha256']
        require(all(sha256_file(Path(path)) == sha for path, sha in old_material_hashes.items()),
                'cannot resume after old selected material changes')
        journals = {label: Path(item['path']) for label, item in material['journals'].items()}
        for path in journals.values():
            journal = read_json(path)
            require(journal['status'] == 'applied', 'resume only supports the safe pre-recovery checkpoint')
            for operation in journal['plan']['operations']:
                if operation['path'] == 'chain.md' and path == journals['chain-v1']:
                    continue  # The second old journal supersedes this terminal value.
                if operation.get('kind', operation.get('type')) == 'snapshot':
                    selected_path = project / operation['destination']
                else:
                    selected_path = project / operation['path']
                require(sha256_file(selected_path) == operation['after_sha256'], 'resume terminal source changed')
        derived = records / 'v12-derived-profile2.json'
        old_report = records / 'v12-check-report.json'
        old_recovery = records / 'v12-recovery-plan.json'
        session = records / 'v12-session.json'
    if not resume:
        install(wheel_python, new_wheel, records, 'upgrade-to-real-v13', upgrade=True)
    new_provenance = provenance(wheel_python, venv, logs, '1.3.0', 'v13-package-provenance')
    for name, profile in (('schema1', records / 'profile1.json'), ('derived-schema2', derived)):
        outline = cli('v13-read-' + name, ['read', *common, '--file', 'README.md', '--outline', '--task-profile', str(profile)])
        require(outline.get('sha256') == sha256_file(project / 'README.md'), 'upgraded read did not bind the real source bytes')
        report = logs / ('v13-check-' + name + '.json')
        cli('v13-check-' + name, ['check', *common, '--task-profile', str(profile), '--checks', 'links',
                                '--format', 'json', '--output', str(report)])
        require(read_json(report).get('tool_version') == '1.3.0', 'upgraded check imported a source/old package')
        checked, selected = read_json(report), set(read_json(profile)['sources'])
        # Both real 1.2 and 1.3 default JSON render intentionally omit files.
        # Scope + observed count + source anchor identities prove this selection.
        require(set(checked['scope']['sources']) == selected and checked['file_count'] == len(selected)
                and set(checked['anchors']) == selected, 'upgraded check expanded or lost old profile scope')
    cli('v13-read-old-report', ['report', *common, '--input', str(old_report)])
    for label in ('standalone-v1', 'standalone-v2', 'chain-v2'):
        require(cli('v13-verify-' + label, ['verify', *common, '--journal', str(journals[label])])['status'] == 'Passed',
                'upgraded wheel could not verify the applied old journal')
    for label in ('standalone-v1', 'standalone-v2'):
        recovered = cli('v13-recover-' + label, ['recover', *common, '--journal', str(journals[label])])
        require(recovered.get('status') == 'recovered', 'standalone old journal recovery did not finish')
        require(cli('v13-reverify-' + label, ['verify', *common, '--journal', str(journals[label])])['status'] == 'Passed',
                'recovered standalone journal did not verify')
    new_recovery = logs / 'v13-recovery-plan.json'
    cli('v13-session-verify', ['session', 'verify', *common, '--session', str(session), '--output', str(logs / 'v13-session-verify.json')])
    cli('v13-session-preview', ['session', 'recovery-preview', *common, '--session', str(session), '--output', str(new_recovery)])
    require(read_json(new_recovery) == read_json(old_recovery), 'upgrade changed the still-valid old recovery-plan contract')
    result = cli('v13-session-recover-old-plan', ['session', 'recover', *common, '--session', str(session),
                                               '--recovery-plan', str(old_recovery), '--output', str(logs / 'v13-recovery-result.json')])
    require(result.get('status') == 'Passed' and result.get('completion') == 'all_recovered', 'reverse session recovery did not complete')
    require(result.get('restored') == [read_json(journals['chain-v2'])['plan']['operation_id'],
                                     read_json(journals['chain-v1'])['plan']['operation_id']], 'session restored journals out of reverse order')
    require(cli('v13-session-final-verify', ['session', 'verify', *common, '--session', str(session)])['status'] == 'Passed',
            'fully recovered session did not verify')
    require(cli('v13-session-final-report', ['session', 'report', *common, '--session', str(session)])['completion'] == 'all_recovered',
            'final session report did not retain actual recovered state')
    require(cli('v13-final-v1-verify', ['verify', *common, '--journal', str(journals['chain-v1'])])['status'] == 'Passed',
            'first journal baseline was not restored')
    require(cli('v13-final-v2-verify-superseded-baseline', ['verify', *common, '--journal', str(journals['chain-v2'])], expected=(1,))['status'] == 'Failed',
            'later journal must retain individual semantics after an earlier baseline is restored')
    restored = {path.relative_to(project).as_posix(): sha256_file(path) for path in project.rglob('*') if path.is_file()}
    require(restored == manifest['original_sha256'], 'original project file set or exact source SHA was not restored')
    require(all(sha256_file(Path(path)) == sha for path, sha in old_material_hashes.items()), 'upgrade/recovery modified immutable old profile/report/session evidence')
    return {'status': 'Passed', 'old_package': old_provenance, 'new_package': new_provenance,
            'v12_wheel_sha256': sha256_file(old_wheel), 'v13_wheel_sha256': sha256_file(new_wheel),
            'original_sha256': manifest['original_sha256'], 'restored_sha256': restored,
            'reverse_session_order_verified': True, 'old_recovery_plan_consumed': True,
            'journal_formats': [1, 2], 'profile_schemas': [1, 2], 'steps': steps,
            'expected_individual_v2_verify_after_reverse_chain': 'Failed; v1 baseline supersedes v2 baseline',
            'evidence_directory': str(records), 'latest_logs': str(logs), 'resumed_after_driver_assertion': resume}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--v12-wheel', type=Path, default=OLD_WHEEL)
    parser.add_argument('--v13-wheel', type=Path, default=NEW_WHEEL)
    parser.add_argument('--python-executable', type=Path, action='append', dest='pythons')
    parser.add_argument('--results', type=Path)
    parser.add_argument('--resume', type=Path, help='continue a preserved failed pre-recovery checkpoint without regenerating old data')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--run', action='store_true')
    mode.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    require(not args.resume or args.run and not args.results, '--resume requires --run and no --results')
    results = args.resume or args.results or BASE / ('compat-' + ('run-' if args.run else 'prepared-') + uuid.uuid4().hex[:12])
    results = results.absolute()
    require(results.parent == BASE and results.name.startswith('compat-'), 'results must be a new v1.3/compat-* evidence directory')
    require(not results.is_symlink(), 'compatibility evidence must not be a symlink')
    if args.resume:
        require(results.is_dir() and (results / 'summary.json').is_file(), 'resume evidence is missing')
        failed = read_json(results / 'summary.json')
        require(failed['status'] == 'Failed', 'only a preserved failed run can resume')
    else:
        require(not results.exists(), 'do not overwrite any previous compatibility evidence')
        results.mkdir(parents=True)
    summary_path = results / ('resume-summary-' + uuid.uuid4().hex[:10] + '.json' if args.resume else 'summary.json')
    summary = {'status': 'Not run', 'mode': 'run' if args.run else 'prepare-only',
               'driver_sha256': sha256_file(Path(__file__)), 'results': str(results), 'environments': []}
    try:
        old, new = args.v12_wheel.absolute(), args.v13_wheel.absolute()
        require(old.is_file(), 'real 1.2 wheel is unavailable')
        if args.run:
            require(new.is_file(), 'final 1.3 wheel is unavailable')
        if args.resume:
            require(sha256_file(new) == failed['v13_wheel_sha256'], 'resume wheel differs from preserved installed candidate')
        summary.update(v12_wheel=str(old), v12_wheel_sha256=sha256_file(old), v13_wheel=str(new))
        if new.is_file():
            summary['v13_wheel_sha256'] = sha256_file(new)
        for index, python in enumerate(args.pythons or PYTHONS):
            require(python.is_file(), 'requested Python interpreter is unavailable')
            run_root = results / ('environment-' + str(index + 1))
            run_root.mkdir(exist_ok=bool(args.resume))
            if args.run:
                reuse = bool(args.resume and (run_root / 'records/v12-material-provenance.json').is_file())
                value = execute(python.absolute(), run_root, old, new, resume=reuse)
            else:
                project, records, manifest = prepare(run_root)
                value = {'status': 'Prepared', 'python_executable': str(python), 'manifest': manifest,
                         'evidence_directory': str(records), 'old_cli_execution': 'Not run', 'upgrade': 'Not run'}
            write_json(run_root / 'summary.json', value)
            summary['environments'].append(value)
        summary['status'] = 'Passed' if args.run else 'Prepared'
    except Exception as error:
        summary.update(status='Failed', error_type=type(error).__name__, error=str(error))
    write_json(summary_path, summary)
    print(json.dumps({'status': summary['status'], 'results': str(results),
                      'summary': str(summary_path), 'environments_completed': len(summary['environments']),
                      'error': summary.get('error')}, ensure_ascii=True))
    return 0 if summary['status'] in {'Passed', 'Prepared'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
