#!/usr/bin/env python3
"""Build the three offline 1.5.0 public assets; never publish or install them.

Only closed source roots enter the source ZIP. Filename exclusions are not a
secret-content scanner: public prose/fixtures still need the owner's review.
"""
from __future__ import annotations

import argparse
import ast
import base64
from contextlib import contextmanager
import csv
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zipfile

VERSION = '1.5.0'
NAME = 'fifan-project-maintenance'
FILES = ('README.md', 'README.en.md', 'INSTALL.md', 'NOTICE.md', 'requirements.txt',
         'pyproject.toml', '.gitignore', 'AGENTS.md')
DIRECTORIES = ('bin', 'src/fifan_maintenance', 'schemas', 'examples', 'skill', 'docs', 'tests', 'tools')
EXCLUDED = {'.git', '.venv', 'venv', '__pycache__', 'build', 'dist', 'evidence',
            'secrets', 'secrets.json', 'credentials', 'credentials.json', 'credentials.toml',
            '.netrc', '.pypirc', '.ssh', '.aws', '.gnupg', '.ds_store', '.pytest_cache'}
DIST_INFO = 'fifan_project_maintenance-' + VERSION + '.dist-info/'
DIST_FILES = {'METADATA', 'WHEEL', 'entry_points.txt', 'top_level.txt', 'RECORD', 'licenses/NOTICE.md'}


class ReleaseError(ValueError):
    pass


def _parts(path):
    if not isinstance(path, str) or not path or '\\' in path or '\x00' in path or path.startswith('/') or any(p in ('', '.', '..') for p in path.split('/')):
        raise ReleaseError('invalid relative archive path: ' + repr(path))
    return path.split('/')


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode


def _state(info):
    return (*_identity(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _directory(path):
    """Pin each absolute directory component without following aliases."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ReleaseError('absolute canonical directory required')
    handles, nodes = [], []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append(fd)
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            handles.append(child)
            expected = _identity(os.fstat(child))
            nodes.append((fd, name, expected))
            fd = child
        def check():
            for parent, name, expected in nodes:
                if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected:
                    raise ReleaseError('directory identity drift')
        check()
        yield fd, check
        check()
    finally:
        for fd in reversed(handles):
            os.close(fd)


def _read(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReleaseError('source must be a unique regular file: ' + name)
        data = bytearray()
        while len(data) < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - len(data)))
            if not block:
                raise ReleaseError('source shrank while reading')
            data.extend(block)
        if os.read(fd, 1) or _state(before) != _state(os.fstat(fd)) or _state(before) != _state(os.stat(name, dir_fd=parent, follow_symlinks=False)):
            raise ReleaseError('source drift while reading')
        return bytes(data), _state(before)
    finally:
        os.close(fd)


def _excluded(name):
    lower = name.casefold()
    return (lower in EXCLUDED or lower.endswith(('.egg-info', '.pyc', '.pyo', '.pem', '.key', '.p12', '.pfx', '.keystore'))
            or lower == '.env' or lower.startswith('.env.') or lower in ('id_rsa', 'id_ed25519'))


def _source_files(source):
    result, states = {}, {}
    with _directory(source) as (root, check):
        root_state = _state(os.fstat(root))
        def visit(parent, name, rel):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
                raise ReleaseError('symlink or special source path: ' + rel)
            if _excluded(name):
                return
            if stat.S_ISREG(before.st_mode):
                data, observed = _read(parent, name)
                result[rel], states[rel] = data, observed
                return
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                if _identity(before) != _identity(os.fstat(fd)):
                    raise ReleaseError('source directory drift')
                for child in sorted(os.listdir(fd)):
                    _parts(child)
                    visit(fd, child, rel + '/' + child)
                after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _state(before) != _state(after) or _state(before) != _state(os.fstat(fd)):
                    raise ReleaseError('source directory changed while reading')
                states[rel + '/'] = _state(before)
            finally:
                os.close(fd)
        for name in FILES:
            try:
                visit(root, name, name)
            except FileNotFoundError:
                if name != 'INSTALL.md':
                    raise ReleaseError('missing required release file: ' + name)
        for rel in DIRECTORIES:
            names = _parts(rel)
            if len(names) == 1:
                visit(root, rel, rel)
            else:
                with _directory(source / names[0]) as (parent, parent_check):
                    visit(parent, names[1], rel)
                    parent_check()
        check()
        if _state(os.fstat(root)) != root_state:
            raise ReleaseError('source root namespace changed while reading')
        states['.'] = root_state
    return result, states


def _validate_snapshot(source, states):
    for rel, expected in states.items():
        if rel == '.':
            with _directory(source) as (root, check):
                if _state(os.fstat(root)) != expected:
                    raise ReleaseError('source root changed after snapshot')
                check()
            continue
        names = _parts(rel.rstrip('/'))
        with _directory(source.joinpath(*names[:-1])) as (parent, check):
            if _state(os.stat(names[-1], dir_fd=parent, follow_symlinks=False)) != expected:
                raise ReleaseError('source changed after snapshot: ' + rel)
            check()


def _versions(files):
    text = files['pyproject.toml'].decode('utf-8')
    section = re.search(r'^\[project\]\s*\n(.*?)(?=^\[|\Z)', text, re.M | re.S)
    matches = re.findall(r'^version\s*=\s*[\'\"]([^\'\"]+)[\'\"]\s*(?:#.*)?$', section.group(1), re.M) if section else []
    assignments = [node for node in ast.parse(files['src/fifan_maintenance/__init__.py']).body
                   if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '__version__' for target in node.targets)]
    values = [ast.literal_eval(node.value) for node in assignments]
    if matches != [VERSION] or values != [VERSION]:
        raise ReleaseError('pyproject and runtime __version__ must both equal ' + VERSION)


def _wheel(raw, files, filename):
    if filename != 'fifan_project_maintenance-' + VERSION + '-py3-none-any.whl':
        raise ReleaseError('unexpected wheel filename')
    expected_python = {key[len('src/'):]: value for key, value in files.items()
                       if key.startswith('src/fifan_maintenance/') and key.endswith('.py')}
    if not expected_python:
        raise ReleaseError('runtime Python source set is empty')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries, contents = {}, {}
        for entry in archive.infolist():
            name = entry.filename
            _parts(name[:-1] if name.endswith('/') else name)
            mode = entry.external_attr >> 16
            if name in entries or entry.flag_bits & 1 or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ReleaseError('duplicate, encrypted or special wheel member')
            if entry.is_dir():
                continue
            if name not in expected_python and not (name.startswith(DIST_INFO) and name[len(DIST_INFO):] in DIST_FILES):
                raise ReleaseError('unexpected wheel member: ' + name)
            if entry.file_size > max(1024 * 1024, len(expected_python.get(name, b''))):
                raise ReleaseError('oversized wheel metadata/member')
            entries[name] = entry
            contents[name] = archive.read(entry)
        if set(contents) != set(expected_python) | {DIST_INFO + name for name in DIST_FILES}:
            raise ReleaseError('wheel runtime or metadata set differs from approved source')
        for name, expected in expected_python.items():
            if contents[name] != expected:
                raise ReleaseError('stale same-version wheel runtime: ' + name)
        metadata = BytesParser().parsebytes(contents[DIST_INFO + 'METADATA'])
        if metadata.get_all('Name') != [NAME] or metadata.get_all('Version') != [VERSION]:
            raise ReleaseError('wheel project/version mismatch')
        wheel = BytesParser().parsebytes(contents[DIST_INFO + 'WHEEL'])
        if wheel.get_all('Root-Is-Purelib') != ['true'] or wheel.get_all('Tag') != ['py3-none-any']:
            raise ReleaseError('wheel must be pure Python py3-none-any')
        if contents[DIST_INFO + 'licenses/NOTICE.md'] != files['NOTICE.md']:
            raise ReleaseError('wheel third-party notice differs from source')
        record = list(csv.reader(io.StringIO(contents[DIST_INFO + 'RECORD'].decode('utf-8'))))
        rows = {}
        for row in record:
            if len(row) != 3 or row[0] in rows:
                raise ReleaseError('invalid wheel RECORD')
            rows[row[0]] = row[1:]
        if set(rows) != set(contents) or rows[DIST_INFO + 'RECORD'] != ['', '']:
            raise ReleaseError('incomplete wheel RECORD')
        for name, value in contents.items():
            if name == DIST_INFO + 'RECORD':
                continue
            digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b'=').decode('ascii')
            if rows[name] != ['sha256=' + digest, str(len(value))]:
                raise ReleaseError('wheel RECORD mismatch: ' + name)
    return len(expected_python)


def _zip(prefix, files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for rel in sorted(files):
            _parts(rel)
            entry = zipfile.ZipInfo(prefix + '/' + rel, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | (0o755 if rel.startswith('bin/') else 0o644)) << 16
            archive.writestr(entry, files[rel])
    return output.getvalue()


def build_release(source, output, wheel):
    source, output, wheel = (Path(os.path.abspath(os.path.expanduser(str(value)))) for value in (source, output, wheel))
    if source == output or source in output.parents or output in source.parents or output == wheel or output in wheel.parents:
        raise ReleaseError('output overlaps source or wheel input')
    # Validate the external output parent before inspecting source bodies.
    with _directory(output.parent) as (parent, parent_check):
        try:
            os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ReleaseError('output must be a NEW directory')
        files, snapshot = _source_files(source)
        _versions(files)
        with _directory(wheel.parent) as (wheel_parent, wheel_check):
            wheel_raw, _ = _read(wheel_parent, wheel.name)
            wheel_check()
        runtime_count = _wheel(wheel_raw, files, wheel.name)
        skill = {'NOTICE.md': files['NOTICE.md']}
        for rel, data in files.items():
            if rel == 'skill/SKILL.md' or rel.startswith('skill/references/'):
                skill[rel[len('skill/'):]] = data
            elif rel == 'docs/DEPENDENCIES.md' or rel.startswith('docs/licenses/'):
                # NOTICE uses these same relative paths in every distribution.
                skill[rel] = data
        if 'SKILL.md' not in skill or not any(name.startswith('references/') for name in skill):
            raise ReleaseError('Skill entry and references are required')
        if 'docs/DEPENDENCIES.md' not in skill or not any(name.startswith('docs/licenses/') for name in skill):
            raise ReleaseError('Skill dependency documentation and license notices are required')
        assets = {NAME + '-' + VERSION + '.zip': _zip(NAME + '-' + VERSION, files),
                  NAME + '-skill-' + VERSION + '.zip': _zip(NAME, skill), wheel.name: wheel_raw}
        checksums = ''.join(hashlib.sha256(assets[name]).hexdigest() + '  ' + name + '\n' for name in sorted(assets))
        _validate_snapshot(source, snapshot)
        parent_check()
        os.mkdir(output.name, mode=0o755, dir_fd=parent)  # Exclusive publication; never reuse output.
        fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            created = _identity(os.fstat(fd))
            for name, data in {**assets, 'SHA256SUMS': checksums.encode('ascii')}.items():
                parent_check()
                if _identity(os.stat(output.name, dir_fd=parent, follow_symlinks=False)) != created:
                    raise ReleaseError('output directory identity drift')
                leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=fd)
                try:
                    view = memoryview(data)
                    while view:
                        amount = os.write(leaf, view)
                        if amount <= 0:
                            raise ReleaseError('short release write')
                        view = view[amount:]
                    os.fsync(leaf)
                finally:
                    os.close(leaf)
            os.fsync(fd)
            parent_check()
            if _identity(os.stat(output.name, dir_fd=parent, follow_symlinks=False)) != created:
                raise ReleaseError('output directory identity drift')
        finally:
            os.close(fd)
    return {'version': VERSION, 'output': str(output), 'assets': sorted(assets),
            'runtime_python_files_verified': runtime_count, 'source_files': len(files),
            'privacy_scope': 'closed roots and filename exclusions; owner content review remains required'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='External NEW output directory; parent must already exist')
    parser.add_argument('--wheel', required=True, help='Existing source-matched 1.5.0 pure Python wheel')
    args = parser.parse_args(argv)
    result = build_release(Path(__file__).absolute().parents[1], args.output, args.wheel)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
