"""Exercise real shell selection, argument forwarding and failure propagation."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.fixture
def launcher(tmp_path):
    root = tmp_path / 'tool with spaces'
    (root / 'bin').mkdir(parents=True)
    target = root / 'bin/fifan-maintain'
    shutil.copy2(Path(__file__).resolve().parents[1] / 'bin/fifan-maintain', target)
    return root, target


def python_stub(root, version, status=0):
    names = {'315': '.venv315', '39': '.venv39', '312': '.venv'}
    executable = root / names[version] / 'bin/python'
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nprintf '%s\\n' '" + version + "'\nprintf '%s\\n' \"$@\"\nexit " + str(status) + '\n')
    executable.chmod(0o755)


def launch(target, runtime=None):
    env = os.environ.copy()
    env.pop('FIFAN_MAINTAIN_RUNTIME', None)
    if runtime is not None:
        env['FIFAN_MAINTAIN_RUNTIME'] = runtime
    return subprocess.run([str(target), 'check', '--project', '目标 目录', '--files', '带 空格.md'],
                          capture_output=True, text=True, env=env, timeout=5)


@pytest.mark.parametrize('available,runtime,expected', [
    (['315', '39', '312'], None, '312'),
    (['315', '39'], None, '315'),
    (['39'], None, '39'),
    (['312'], None, '312'),
    (['315', '39', '312'], '315', '315'),
    (['315', '39', '312'], '39', '39'),
    (['315', '39', '312'], '312', '312'),
])
def test_launcher_selects_expected_runtime_and_preserves_arguments(launcher, available, runtime, expected):
    root, target = launcher
    for version in available:
        python_stub(root, version)
    result = launch(target, runtime)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [expected, '-B', '-m', 'fifan_maintenance.cli',
                                         'check', '--project', '目标 目录', '--files', '带 空格.md']


@pytest.mark.parametrize('selected,available', [('315', '39'), ('312', '315'), ('39', '312')])
def test_explicit_missing_runtime_cannot_silently_fall_back(launcher, selected, available):
    root, target = launcher
    python_stub(root, available)
    result = launch(target, selected)
    assert result.returncode == 2 and result.stdout == ''
    assert 'environment missing' in result.stderr


@pytest.mark.parametrize('runtime', ['unknown', '/bin/sh', '315; echo injected'])
def test_launcher_rejects_unsupported_or_executable_runtime_values(launcher, runtime):
    root, target = launcher
    python_stub(root, '315')
    result = launch(target, runtime)
    assert result.returncode == 2 and result.stdout == ''
    assert 'Unknown FIFAN_MAINTAIN_RUNTIME' in result.stderr


def test_broken_preferred_runtime_does_not_hide_error_with_old_runtime(launcher):
    root, target = launcher
    python_stub(root, '312', status=23)
    python_stub(root, '315')
    python_stub(root, '39')
    result = launch(target)
    assert result.returncode == 23
    assert result.stdout.splitlines()[0] == '312'


@pytest.mark.parametrize('failure', ['missing-python', 'not-executable'])
def test_present_but_unusable_preferred_environment_cannot_silently_fall_back(launcher, failure):
    root, target = launcher
    python_stub(root, '39')
    python_stub(root, '315')
    (root / '.venv/bin').mkdir(parents=True)
    if failure == 'not-executable':
        (root / '.venv/bin/python').write_text('#!/bin/sh\nexit 0\n')
    result = launch(target)
    assert result.returncode == 2 and result.stdout == ''
    assert 'environment unavailable' in result.stderr


def test_missing_all_environments_reports_error(launcher):
    _, target = launcher
    result = launch(target)
    assert result.returncode == 2 and result.stdout == ''
    assert 'environment missing' in result.stderr
