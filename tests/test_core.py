from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from fifan_maintenance.engine import compare_state, run
from fifan_maintenance.models import Context
from fifan_maintenance.project import load_config, read_bytes
from fifan_maintenance.cli import main


def test_descriptor_read_and_escape(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "secret"
    outside.write_text("private")
    (root / "good.md").write_bytes(b"a\r\nb\r\n")
    (root / "bad.md").symlink_to(outside)
    assert read_bytes(root, "good.md", 20) == b"a\r\nb\r\n"
    for path in ["../secret", str(outside), "bad.md"]:
        with pytest.raises((OSError, ValueError)):
            read_bytes(root, path, 20)
    with pytest.raises(ValueError):
        read_bytes(root, "good.md", 2)


def test_real_context_protects_secrets_and_excludes(tmp_path):
    (tmp_path / ".env").write_text("SECRET=x")
    (tmp_path / "excluded.md").write_text("hidden")
    (tmp_path / "excluded").mkdir()
    (tmp_path / "excluded/private.md").write_text("hidden")
    config = load_config(tmp_path)
    config["exclude"] = ["excluded.md", "excluded"]
    ctx = Context(tmp_path, {}, config)
    for rel in [".env", "excluded.md", "excluded/private.md", "./excluded.md", "./.env", "a//file", "Library/../excluded.md"]:
        with pytest.raises(ValueError):
            ctx.read_text(rel)


def test_config_rejects_executable_unknown_and_duplicate_keys(tmp_path):
    for text in ['{"command":"touch test"}', '{"max_files":1,"max_files":2}', '{"max_files":true}', '{"documents":{"large_bytes":0}}']:
        (tmp_path / ".fifan-maintenance.json").write_text(text)
        with pytest.raises(ValueError):
            load_config(tmp_path)


def test_engine_real_context_rechecks_target(tmp_path):
    (tmp_path / "README.md").write_text("[go](docs/target.md#标题)\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/target.md").write_text("# 标题\n")
    report = run(tmp_path, checks=["links", "configs"])
    assert not any(f["code"] == "missing-anchor" for f in report["findings"])
    (tmp_path / "docs/target.md").write_text("# changed\n")
    after = run(tmp_path, checks=["links", "configs"])
    assert any(f["code"] == "missing-anchor" for f in after["findings"])
    assert compare_state(after, report)["changed_files"] == 1


def test_cli_cycle_preserves_crlf_and_does_not_mutate_on_check(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    doc = root / "README.md"
    original = b"# Title\r\nold text\r\n"
    doc.write_bytes(original)
    assert main(["check", "--project", str(root), "--checks", "links,configs", "--format", "json"]) == 0
    assert doc.read_bytes() == original
    capsys.readouterr()
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"operations": [{"type": "replace", "path": "README.md", "old": "old text", "new": "new text"}]}))
    plan = tmp_path / "plan.json"
    assert main(["preview", "--project", str(root), "--request", str(request), "--plan", str(plan)]) == 0
    capsys.readouterr()
    assert main(["apply", "--project", str(root), "--plan", str(plan), "--operations-dir", str(tmp_path / "operations")]) == 0
    output = json.loads(capsys.readouterr().out)
    journal = output["journal"]
    assert doc.read_bytes() == original.replace(b"old text", b"new text")
    assert main(["verify", "--project", str(root), "--journal", journal]) == 0
    capsys.readouterr()
    assert main(["recover", "--project", str(root), "--journal", journal]) == 0
    assert doc.read_bytes() == original


def test_report_output_cannot_modify_inspected_project(tmp_path):
    doc = tmp_path / "README.md"
    doc.write_text("keep")
    assert main(["check", "--project", str(tmp_path), "--checks", "links", "--output", str(doc)]) == 2
    assert doc.read_text() == "keep"


def test_secret_file_cannot_be_modified_by_change_engine(tmp_path):
    from fifan_maintenance.changes import preview
    (tmp_path / ".env.local").write_text("credential=value")
    with pytest.raises(ValueError):
        preview(tmp_path, {"operations": [{"type": "replace", "path": ".env.local", "old": "value", "new": "changed"}]}, load_config(tmp_path))


def test_partial_nested_configuration_keeps_other_defaults(tmp_path):
    (tmp_path / ".fifan-maintenance.json").write_text('{"documents":{"large_bytes":123}}')
    config = load_config(tmp_path)
    assert config["documents"]["large_bytes"] == 123
    assert config["documents"]["paragraph_chars"] == 1000


@pytest.mark.parametrize('linked', [False, True])
def test_git_from_inspected_project_is_never_executed(tmp_path, monkeypatch, linked):
    from fifan_maintenance.project import identity
    from fifan_maintenance.checks import repository
    root = tmp_path / 'project'
    (root / 'bin').mkdir(parents=True)
    marker = root / 'executed'
    script = root / 'bin/git'
    script.write_text('#!/bin/sh\nprintf invoked >> "' + str(marker) + '"\nexit 1\n')
    script.chmod(0o755)
    directory = root / 'bin'
    if linked:
        directory = tmp_path / 'tools'
        directory.mkdir()
        (directory / 'git').symlink_to(script)
    monkeypatch.setenv('PATH', str(directory))
    assert identity(root)['git']['status'] == 'Unknown'
    ctx = Context(root, {}, load_config(root))
    assert any(f.status == 'Unknown' and f.code == 'git_unavailable' for f in repository.run(ctx))
    assert not marker.exists()


def test_documents_only_cli_rejects_project_git(tmp_path, monkeypatch, capsys):
    root = tmp_path / 'project'
    (root / 'bin').mkdir(parents=True)
    (root / 'README.md').write_text('# Current\n')
    marker = root / 'executed'
    script = root / 'bin/git'
    script.write_text('#!/bin/sh\nprintf invoked >> "' + str(marker) + '"\nexit 1\n')
    script.chmod(0o755)
    monkeypatch.setenv('PATH', str(root / 'bin'))
    assert main(['check', '--project', str(root), '--files', 'README.md', '--checks', 'documents', '--format', 'json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['identity']['git']['status'] == 'Unknown'
    assert not marker.exists()
