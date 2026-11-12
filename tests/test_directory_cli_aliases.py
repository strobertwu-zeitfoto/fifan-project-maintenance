import json

import pytest

from test_directory_cli import case, call


@pytest.mark.parametrize('kind', ['plan', 'output'])
def test_case_alias_cannot_publish_private_or_public_artifact_in_project(case, capsys, kind):
    root, _, records, _ = case
    alias = root.with_name(root.name.upper())
    if not alias.exists():
        pytest.skip('requires case-insensitive fixture volume')
    destination = alias / 'unexpected.json'
    arguments = ['--plan', destination if kind == 'plan' else records / 'plan.json']
    if kind == 'output':
        arguments.extend(['--output', destination])
    code, result = call(case, capsys, 'search-preview', *arguments)
    assert code == 2 and result['reason_code'] == 'OUTPUT_INSIDE_PROJECT'
    assert not destination.exists()
    assert not (records / 'plan.json').exists()


def test_output_alias_cannot_overwrite_profile(case, capsys):
    _, _, records, profile = case
    alias = profile.with_name(profile.name.upper())
    if not alias.exists():
        pytest.skip('requires case-insensitive fixture volume')
    before = profile.read_bytes()
    code, result = call(case, capsys, 'search-preview', '--plan', records / 'plan.json', '--output', alias)
    assert code == 2 and result['reason_code'] == 'OUTPUT_INPUT_CONFLICT'
    assert profile.read_bytes() == before
    assert not (records / 'plan.json').exists()


@pytest.mark.parametrize('via_link', [False, True])
def test_search_does_not_execute_engine_selected_from_project(case, monkeypatch, via_link):
    from fifan_maintenance import search_view
    from fifan_maintenance.directory_common import DirectoryError, load_profile
    from fifan_maintenance.project import load_config
    root, _, records, profile_path = case
    executable = root / 'rg'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    selected = executable
    if via_link:
        selected = records / 'external-rg'
        selected.symlink_to(executable)
    monkeypatch.setattr(search_view.shutil, 'which', lambda _: str(selected))
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError('attempted to execute a project-owned engine')
    monkeypatch.setattr(search_view.subprocess, 'run', forbidden)
    monkeypatch.setattr(search_view.subprocess, 'Popen', forbidden)
    profile = load_profile(root, load_config(root), profile_path)
    with pytest.raises(DirectoryError) as error:
        search_view._rg(profile)
    assert error.value.reason_code == 'ENGINE_UNAVAILABLE'
    assert calls == []
