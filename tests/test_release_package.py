"""Public release builder tests use synthetic trees/wheels only."""
import base64
import csv
import hashlib
import importlib.util
import io
import os
import posixpath
import re
from pathlib import Path
import zipfile

import pytest

spec = importlib.util.spec_from_file_location('build_release', Path(__file__).parents[1] / 'tools/build_release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


NOTICE = b'Notices: [licenses](docs/licenses) and [dependencies](docs/DEPENDENCIES.md)\n'


def write_wheel(path, runtime, notice=NOTICE, *, version='1.5.0', extra=None, bad_record=False):
    dist = release.DIST_INFO
    members = {**runtime,
        dist + 'METADATA': ('Metadata-Version: 2.1\nName: fifan-project-maintenance\nVersion: ' + version + '\n').encode(),
        dist + 'WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        dist + 'entry_points.txt': b'[console_scripts]\nfifan-maintain = fifan_maintenance.cli:main\n',
        dist + 'top_level.txt': b'fifan_maintenance\n', dist + 'licenses/NOTICE.md': notice}
    members.update(extra or {})
    output = io.StringIO()
    writer = csv.writer(output, lineterminator='\n')
    for name, data in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        writer.writerow((name, 'sha256=' + digest, len(data)))
    writer.writerow((dist + 'RECORD', '', ''))
    members[dist + 'RECORD'] = b'forged RECORD\n' if bad_record else output.getvalue().encode()
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)


@pytest.fixture
def candidate(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    for name in release.FILES:
        (root / name).write_text('Synthetic ' + name + '\n')
    (root / 'NOTICE.md').write_bytes(NOTICE)
    (root / 'pyproject.toml').write_text('[project]\nname = "fifan-project-maintenance"\nversion = "1.5.0"\n')
    for name in release.DIRECTORIES:
        (root / name).mkdir(parents=True, exist_ok=True)
    runtime = {'fifan_maintenance/__init__.py': b'__version__ = "1.5.0"\n',
               'fifan_maintenance/cli.py': b'def main():\n    return 0\n'}
    for name, data in runtime.items():
        (root / 'src' / name).write_bytes(data)
    (root / 'bin/fifan-maintain').write_text('#!/bin/sh\nexit 0\n')
    (root / 'skill/SKILL.md').write_text('---\nname: fifan-project-maintenance\n---\nSynthetic Skill\n')
    (root / 'skill/references').mkdir()
    (root / 'skill/references/usage.md').write_text('Reference usage\n')
    (root / 'docs/USAGE.md').write_text('Synthetic public usage\n')
    (root / 'docs/DEPENDENCIES.md').write_text('[License](licenses/upstream.txt) and [NOTICE](../NOTICE.md)\n')
    (root / 'docs/licenses').mkdir()
    (root / 'docs/licenses/upstream.txt').write_text('Synthetic upstream license text\n')
    (root / 'schemas/input.schema.json').write_text('{}\n')
    (root / 'examples/request.json').write_text('{}\n')
    (root / 'tools/helper.py').write_text('# synthetic helper\n')
    (root / 'tests/test_example.py').write_text('def test_example(): pass\n')
    # Outside the closed roots: must never inspect this symlink or its body.
    (root / '.venv').symlink_to(tmp_path / 'missing-private-environment', target_is_directory=True)
    (root / '.git').mkdir()
    (root / '.git/private-state').write_text('not public\n')
    (root / 'outside-closed-roots.txt').write_text('not public\n')
    wheel = tmp_path / ('fifan_project_maintenance-1.5.0-py3-none-any.whl')
    write_wheel(wheel, runtime)
    return root, wheel, runtime


def test_three_assets_notices_checksums_contents_and_fixed_metadata(candidate, tmp_path):
    root, wheel, _ = candidate
    output = tmp_path / 'release'
    result = release.build_release(root, output, wheel)
    expected = {'fifan-project-maintenance-1.5.0.zip', 'fifan-project-maintenance-skill-1.5.0.zip', wheel.name, 'SHA256SUMS'}
    assert {name.name for name in output.iterdir()} == expected
    assert result['runtime_python_files_verified'] == 2
    assert (output / wheel.name).read_bytes() == wheel.read_bytes()
    for line in (output / 'SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ')
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == checksum
    assert len((output / 'SHA256SUMS').read_text().splitlines()) == 3
    with zipfile.ZipFile(output / 'fifan-project-maintenance-1.5.0.zip') as archive:
        names = archive.namelist()
        prefix = 'fifan-project-maintenance-1.5.0/'
        assert names == sorted(names)
        assert all(name.startswith(prefix) for name in names)
        assert prefix + 'src/fifan_maintenance/cli.py' in names
        assert prefix + 'tools/helper.py' in names
        assert prefix + 'tests/test_example.py' in names
        assert prefix + 'INSTALL.md' in names
        assert prefix + 'NOTICE.md' in names
        assert all('.venv' not in name and '.git/' not in name and 'outside-closed-roots' not in name for name in names)
        assert archive.getinfo(prefix + 'bin/fifan-maintain').external_attr >> 16 & 0o777 == 0o755
        assert all(entry.date_time == (1980, 1, 1, 0, 0, 0) for entry in archive.infolist())
    with zipfile.ZipFile(output / 'fifan-project-maintenance-skill-1.5.0.zip') as archive:
        assert archive.namelist() == ['fifan-project-maintenance/' + name for name in
            ('NOTICE.md', 'SKILL.md', 'docs/DEPENDENCIES.md', 'docs/licenses/upstream.txt', 'references/usage.md')]
        for name in ('NOTICE.md', 'docs/DEPENDENCIES.md', 'docs/licenses/upstream.txt'):
            assert archive.read('fifan-project-maintenance/' + name) == (root / name).read_bytes()
        for document in ('NOTICE.md', 'docs/DEPENDENCIES.md'):
            name = 'fifan-project-maintenance/' + document
            for link in re.findall(r'\[[^\]]+\]\(([^)]+)\)', archive.read(name).decode()):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
                assert target in archive.namelist() or any(item.startswith(target + '/') for item in archive.namelist())
        assert archive.read('fifan-project-maintenance/NOTICE.md') == (root / 'NOTICE.md').read_bytes()


def test_deterministic_ignores_source_mtimes_modes_and_output_name(candidate, tmp_path):
    root, wheel, _ = candidate
    first, second = tmp_path / 'first', tmp_path / 'second'
    release.build_release(root, first, wheel)
    (root / 'README.md').chmod(0o600)
    os.utime(root / 'README.md', ns=(1000000000000000000, 1000000000000000000))
    release.build_release(root, second, wheel)
    assert {p.name: p.read_bytes() for p in first.iterdir()} == {p.name: p.read_bytes() for p in second.iterdir()}


@pytest.mark.parametrize('name', ['.env', '.env.local', 'secret.key', 'cert.pem', 'secrets.json', 'credentials.json', '__pycache__', 'module.egg-info', 'evidence', 'build', 'dist'])
def test_excludes_sensitive_filenames_and_non_source_artifacts(candidate, tmp_path, name):
    root, wheel, _ = candidate
    target = root / 'docs' / name
    if name in ('__pycache__', 'module.egg-info', 'evidence', 'build', 'dist'):
        target.mkdir()
        (target / 'private.txt').write_text('must not enter archive')
    else:
        target.write_text('must not enter archive')
    out = tmp_path / 'out'
    release.build_release(root, out, wheel)
    with zipfile.ZipFile(out / 'fifan-project-maintenance-1.5.0.zip') as archive:
        assert all('/docs/' + name not in path for path in archive.namelist())


@pytest.mark.parametrize('kind', ['source-link', 'source-fifo', 'source-root-link', 'output-parent-link', 'wheel-link'])
def test_rejects_symlinks_specials_and_aliased_roots(candidate, tmp_path, kind):
    root, wheel, _ = candidate
    out = tmp_path / 'out'
    if kind == 'source-link':
        (root / 'docs/linked.txt').symlink_to(root / 'README.md')
    elif kind == 'source-fifo':
        os.mkfifo(root / 'docs/pipe')
    elif kind == 'source-root-link':
        alias = tmp_path / 'source-alias'
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    elif kind == 'output-parent-link':
        alias = tmp_path / 'output-alias'
        alias.symlink_to(tmp_path, target_is_directory=True)
        out = alias / 'out'
    elif kind == 'wheel-link':
        alias = tmp_path / 'alias.whl'
        alias.symlink_to(wheel)
        wheel = alias
    with pytest.raises((release.ReleaseError, OSError)):
        release.build_release(root, out, wheel)
    assert not out.exists()


@pytest.mark.parametrize('where', ['source', 'source-child', 'existing-dir', 'existing-file', 'existing-link'])
def test_output_overlap_and_existing_destinations_never_overwrite(candidate, tmp_path, where):
    root, wheel, _ = candidate
    out = tmp_path / 'out'
    sentinel = None
    if where == 'source':
        out = root
    elif where == 'source-child':
        out = root / 'release'
    elif where == 'existing-dir':
        out.mkdir()
        sentinel = out / 'preserved'
        sentinel.write_text('preserve')
    elif where == 'existing-file':
        out.write_text('preserve')
        sentinel = out
    else:
        out.symlink_to(root, target_is_directory=True)
    with pytest.raises((release.ReleaseError, OSError)):
        release.build_release(root, out, wheel)
    if sentinel:
        assert sentinel.read_text() == 'preserve'
    assert (root / 'README.md').is_file()


@pytest.mark.parametrize('forgery', ['stale-python', 'missing-python', 'extra-python', 'metadata-version', 'record', 'traversal', 'notice', 'wrong-name'])
def test_rejects_stale_same_version_and_forged_wheels(candidate, tmp_path, forgery):
    root, wheel, runtime = candidate
    runtime = dict(runtime)
    kwargs = {}
    if forgery == 'stale-python':
        runtime['fifan_maintenance/cli.py'] = b'# stale version1.5.0 implementation\n'
    elif forgery == 'missing-python':
        runtime.pop('fifan_maintenance/cli.py')
    elif forgery == 'extra-python':
        runtime['fifan_maintenance/unapproved.py'] = b'# extra\n'
    elif forgery == 'metadata-version':
        kwargs['version'] = '1.4.2'
    elif forgery == 'record':
        kwargs['bad_record'] = True
    elif forgery == 'traversal':
        kwargs['extra'] = {'../escape.py': b'# escape\n'}
    elif forgery == 'notice':
        kwargs['notice'] = b'forged or missing third-party credit\n'
    write_wheel(wheel, runtime, **kwargs)
    if forgery == 'wrong-name':
        replacement = wheel.with_name('other-1.5.0-py3-none-any.whl')
        wheel.rename(replacement)
        wheel = replacement
    out = tmp_path / 'out'
    with pytest.raises((release.ReleaseError, OSError)):
        release.build_release(root, out, wheel)
    assert not out.exists()


@pytest.mark.parametrize('file,text', [('pyproject.toml', '[project]\nversion = "1.4.2"\n'),
    ('src/fifan_maintenance/__init__.py', '__version__ = "1.4.2"\n')])
def test_rejects_source_version_disagreement(candidate, tmp_path, file, text):
    root, wheel, _ = candidate
    (root / file).write_text(text)
    with pytest.raises(release.ReleaseError):
        release.build_release(root, tmp_path / 'out', wheel)


def test_install_doc_is_optional_and_source_is_not_executed(candidate, tmp_path):
    root, wheel, _ = candidate
    (root / 'INSTALL.md').unlink()
    (root / 'tools/helper.py').write_text('raise RuntimeError("source must never execute")\n')
    release.build_release(root, tmp_path / 'out', wheel)


def test_source_drift_during_package_build_is_rejected(candidate, tmp_path, monkeypatch):
    root, wheel, _ = candidate
    original = release._zip
    def changed(*args):
        result = original(*args)
        (root / 'README.md').write_text('changed after snapshot\n')
        return result
    monkeypatch.setattr(release, '_zip', changed)
    with pytest.raises(release.ReleaseError):
        release.build_release(root, tmp_path / 'out', wheel)
    assert not (tmp_path / 'out').exists()


def test_new_source_file_after_snapshot_is_rejected(candidate, tmp_path, monkeypatch):
    root, wheel, _ = candidate
    original = release._zip
    def changed(*args):
        result = original(*args)
        (root / 'src/fifan_maintenance/added.py').write_text('# new runtime file after inventory\n')
        return result
    monkeypatch.setattr(release, '_zip', changed)
    with pytest.raises(release.ReleaseError):
        release.build_release(root, tmp_path / 'out', wheel)
    assert not (tmp_path / 'out').exists()


def test_wheel_symlink_member_is_rejected(candidate, tmp_path):
    root, wheel, _ = candidate
    with zipfile.ZipFile(wheel) as archive:
        entries = [(entry, archive.read(entry)) for entry in archive.infolist()]
    with zipfile.ZipFile(wheel, 'w') as archive:
        for entry, data in entries:
            if entry.filename == 'fifan_maintenance/cli.py':
                entry.create_system = 3
                entry.external_attr = (0o120777 << 16)
            archive.writestr(entry, data)
    with pytest.raises(release.ReleaseError):
        release.build_release(root, tmp_path / 'out', wheel)
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('missing', ['dependencies', 'licenses'])
def test_skill_notice_dependencies_must_not_be_silently_missing(candidate, tmp_path, missing):
    root, wheel, _ = candidate
    if missing == 'dependencies':
        (root / 'docs/DEPENDENCIES.md').unlink()
    else:
        (root / 'docs/licenses/upstream.txt').unlink()
    with pytest.raises(release.ReleaseError, match='dependency documentation and license notices'):
        release.build_release(root, tmp_path / 'out', wheel)
    assert not (tmp_path / 'out').exists()
