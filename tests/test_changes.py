import copy
import json
import os
from pathlib import Path

import pytest

from fifan_maintenance import changes as c


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_bytes(b"one\r\ntwo\r\n")
    os.chmod(root / "README.md", 0o640)
    (root / "old.md").write_text("history", encoding="utf-8")
    return root, tmp_path / "records", {"protected": ["private"], "version": 1}


def request():
    return {"operations": [{"type": "replace", "path": "README.md", "old": "one", "new": "new"},
                           {"type": "move", "path": "old.md", "destination": "docs/archive/old.md"}]}


def test_roundtrip(setup):
    root, out, cfg = setup
    plan = c.preview(root, request(), cfg)
    assert not out.exists()
    rec = c.apply(root, plan, cfg, out)
    assert (root / "README.md").read_bytes() == b"new\r\ntwo\r\n"
    assert not (root / "old.md").exists()
    assert c.verify(root, rec, cfg)["status"] == "Passed"
    restored = c.recover(root, Path(rec["journal_path"]), cfg)
    assert (root / "README.md").read_bytes() == b"one\r\ntwo\r\n"
    assert (root / "README.md").stat().st_mode & 0o777 == 0o640
    assert (root / "old.md").read_text() == "history"
    assert not (root / "docs").exists()
    assert c.verify(root, restored, cfg)["status"] == "Passed"


@pytest.mark.parametrize("path", ["../x", "/tmp/x", ".git/config", ".venv/x", "private/x", "docs/../x"])
def test_escape(setup, path):
    root, _, cfg = setup
    req = {"operations": [{"type": "replace", "path": path, "old": "x", "new": "y"}]}
    with pytest.raises((ValueError, OSError)):
        c.preview(root, req, cfg)


def test_ambiguity_empty_encoding_and_directory(setup):
    root, _, cfg = setup
    for content, old in [(b"one one", "one"), (b"one", ""), (b"\xff", "one")]:
        (root / "README.md").write_bytes(content)
        with pytest.raises(ValueError):
            c.preview(root, {"operations": [{"type": "replace", "path": "README.md", "old": old, "new": "x"}]}, cfg)
    (root / "folder").mkdir()
    with pytest.raises(ValueError):
        c.preview(root, {"operations": [{"type": "move", "path": "folder", "destination": "new"}]}, cfg)


def test_preview_concurrent_and_config_changes(setup):
    root, out, cfg = setup
    plan = c.preview(root, request(), cfg)
    (root / "old.md").write_text("changed")
    with pytest.raises(ValueError):
        c.apply(root, plan, cfg, out)
    assert not out.exists()
    assert (root / "README.md").read_bytes().startswith(b"one")
    with pytest.raises(ValueError):
        c.apply(root, plan, {**cfg, "version": 2}, out)


def test_symlink_destination_and_output(setup, tmp_path):
    root, out, cfg = setup
    (root / "docs").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        c.preview(root, request(), cfg)
    (root / "docs").unlink()
    plan = c.preview(root, request(), cfg)
    out.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        c.apply(root, plan, cfg, out)


def test_late_destination_is_not_overwritten(setup, monkeypatch):
    root, out, cfg = setup
    plan = c.preview(root, request(), cfg)
    original = c._move
    def raced(root, source, dest, expected, config):
        (root / dest).write_text("other work")
        return original(root, source, dest, expected, config)
    monkeypatch.setattr(c, "_move", raced)
    with pytest.raises(FileExistsError):
        c.apply(root, plan, cfg, out)
    journal = next(out.glob("*.json"))
    record = json.loads(journal.read_text())
    assert record["completed"] == [0]
    assert record["intent"] == 1
    assert (root / "docs/archive/old.md").read_text() == "other work"
    with pytest.raises(ValueError):
        c.recover(root, journal, cfg)
    assert (root / "README.md").read_bytes().startswith(b"new")


def test_interrupted_after_write_before_receipt(setup, monkeypatch):
    root, out, cfg = setup
    plan = c.preview(root, request(), cfg)
    original = c._atomic
    def interrupted(*args):
        original(*args)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, "_atomic", interrupted)
    with pytest.raises(KeyboardInterrupt):
        c.apply(root, plan, cfg, out)
    journal = next(out.glob("*.json"))
    assert json.loads(journal.read_text())["intent"] == 0
    monkeypatch.setattr(c, "_atomic", original)
    restored = c.recover(root, journal, cfg)
    assert restored["status"] == "recovered"
    assert (root / "README.md").read_bytes().startswith(b"one")


def test_recovery_refuses_subsequent_work(setup):
    root, out, cfg = setup
    rec = c.apply(root, c.preview(root, request(), cfg), cfg, out)
    (root / "docs/archive/old.md").write_text("subsequent edit")
    with pytest.raises(ValueError):
        c.recover(root, Path(rec["journal_path"]), cfg)
    assert (root / "README.md").read_bytes().startswith(b"new")
    assert c.verify(root, rec, cfg)["status"] == "Failed"


def test_tampering_and_unknown_records(setup):
    root, out, cfg = setup
    plan = c.preview(root, request(), cfg)
    altered = copy.deepcopy(plan)
    altered["operations"][0]["new"] = "evil"
    with pytest.raises(ValueError):
        c.apply(root, altered, cfg, out)
    rec = c.apply(root, plan, cfg, out)
    journal = Path(rec["journal_path"])
    for change in [lambda r: r.update(extra=True), lambda r: r["backups"].__setitem__(0, "b3RoZXI="),
                   lambda r: r["plan"]["operations"][0].update(path="../outside")]:
        modified = copy.deepcopy(rec)
        change(modified)
        c._seal(modified["plan"], "operation_id")
        c._seal(modified, "record_sha256")
        journal.write_text(json.dumps(modified))
        with pytest.raises((ValueError, KeyError)):
            c.recover(root, journal, cfg)


def test_interrupted_move_duplicate_link(setup, monkeypatch):
    root, out, cfg = setup
    plan = c.preview(root, request(), cfg)
    original = c._move
    def linked(root, source, dest, expected, config):
        os.link(root / source, root / dest)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, "_move", linked)
    with pytest.raises(KeyboardInterrupt):
        c.apply(root, plan, cfg, out)
    monkeypatch.setattr(c, "_move", original)
    restored = c.recover(root, next(out.glob("*.json")), cfg)
    assert restored["status"] == "recovered"
    assert (root / "old.md").read_text() == "history"
    assert not (root / "docs").exists()


def test_recovery_keeps_other_work_in_created_directory(setup):
    root, out, cfg = setup
    rec = c.apply(root, c.preview(root, request(), cfg), cfg, out)
    (root / "docs/archive/other.md").write_text("keep")
    c.recover(root, Path(rec["journal_path"]), cfg)
    assert (root / "docs/archive/other.md").read_text() == "keep"


def test_permission_and_symlink_changes_block_recovery(setup):
    root, out, cfg = setup
    rec = c.apply(root, c.preview(root, request(), cfg), cfg, out)
    os.chmod(root / "README.md", 0o600)
    with pytest.raises(ValueError):
        c.recover(root, Path(rec["journal_path"]), cfg)
    os.chmod(root / "README.md", 0o640)
    (root / "docs/archive/old.md").unlink()
    (root / "docs/archive/old.md").symlink_to(root / "README.md")
    with pytest.raises(OSError):
        c.recover(root, Path(rec["journal_path"]), cfg)


def test_apply_refuses_project_internal_journal(setup):
    root, _, cfg = setup
    plan = c.preview(root, request(), cfg)
    with pytest.raises(ValueError):
        c.apply(root, plan, cfg, root / "output")
    assert (root / "README.md").read_bytes().startswith(b"one")


def test_protected_config_globs(setup):
    root, _, cfg = setup
    (root / "Library").mkdir()
    (root / "Library/a.md").write_text("one")
    cfg["protected"] = ["Library/**"]
    with pytest.raises(ValueError):
        c.preview(root, {"operations": [{"type": "replace", "path": "Library/a.md", "old": "one", "new": "two"}]}, cfg)


def test_recomputed_plan_hash_cannot_hide_wrong_content(setup):
    root, out, cfg = setup
    plan = c.preview(root, request(), cfg)
    plan["operations"][0]["after_sha256"] = "0" * 64
    c._seal(plan, "operation_id")
    with pytest.raises(ValueError):
        c.apply(root, plan, cfg, out)
    assert not out.exists()


@pytest.mark.parametrize("action", ["apply", "recover"])
def test_cross_process_project_lock_rejects_overlapping_operations(setup, tmp_path, action):
    import subprocess
    import sys
    root, out, cfg = setup
    (root / "other.md").write_text("other")
    replace = {"operations": [request()["operations"][0]]}
    if action == "apply":
        rec = c.apply(root, c.preview(root, {"operations": [request()["operations"][1]]}, cfg), cfg, out)
        active = c.preview(root, replace, cfg)
    else:
        rec = c.apply(root, c.preview(root, replace, cfg), cfg, out)
        active = None
    other = c.preview(root, {"operations": [{"type": "replace", "path": "other.md", "old": "other", "new": "next"}]}, cfg)
    packet = tmp_path / "packet.json"
    packet.write_text(json.dumps({"root": str(root), "config": cfg, "plan": active,
                                  "record": rec, "output": str(tmp_path / "child-records")}))
    script = '''
import json,sys
from pathlib import Path
from fifan_maintenance import changes as c
p=json.loads(Path(sys.argv[1]).read_text())
original=c._atomic
def paused(*args):
    print("locked", flush=True)
    sys.stdin.readline()
    return original(*args)
c._atomic=paused
if sys.argv[2] == "apply":
    c.apply(Path(p["root"]),p["plan"],p["config"],Path(p["output"]))
else:
    c.recover(Path(p["root"]),Path(p["record"]["journal_path"]),p["config"])
'''
    env = dict(os.environ, PYTHONPATH=str(Path(c.__file__).resolve().parents[1]))
    child = subprocess.Popen([sys.executable, "-c", script, str(packet), action],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, env=env)
    try:
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(ValueError, match="project busy"):
            c.apply(root, other, cfg, tmp_path / "different-operation-dir")
        with pytest.raises(ValueError, match="project busy"):
            c.recover(root, Path(rec["journal_path"]), cfg)
        with pytest.raises(ValueError, match="project busy"):
            c.verify(root, rec, cfg)
        assert not (tmp_path / "different-operation-dir").exists()
    finally:
        stdout, stderr = child.communicate("continue\n", timeout=10)
        assert child.returncode == 0, stderr


@pytest.mark.parametrize("operation", [
    {"type": "replace", "path": ".fifan-maintenance.json", "old": "{}", "new": "{ }"},
    {"type": "move", "path": ".fifan-maintenance.json", "destination": "config-old.json"},
    {"type": "move", "path": "old.md", "destination": ".fifan-maintenance.json"},
])
def test_tool_configuration_is_always_protected(setup, operation):
    root, _, cfg = setup
    (root / ".fifan-maintenance.json").write_text("{}")
    with pytest.raises(ValueError, match="protected"):
        c.preview(root, {"operations": [operation]}, cfg)


def test_overlapping_replace_matches_are_ambiguous(setup):
    root, _, cfg = setup
    (root / "README.md").write_text("aaa")
    with pytest.raises(ValueError, match="exactly once"):
        c.preview(root, {"operations": [{"type": "replace", "path": "README.md", "old": "aa", "new": "b"}]}, cfg)


def test_move_detects_source_name_replacement_before_unlink(setup, monkeypatch):
    root, _, cfg = setup
    original = c._read
    calls = []
    def raced(root, rel, config):
        result = original(root, rel, config)
        calls.append(rel)
        if len(calls) == 3:
            (root / "other.md").write_text("same content, separate work")
            os.replace(root / "other.md", root / "old.md")
        return result
    monkeypatch.setattr(c, "_read", raced)
    with pytest.raises(ValueError, match="source name changed"):
        c._move(root, "old.md", "moved.md", c._hash(b"history"), cfg)
    assert (root / "old.md").read_text() == "same content, separate work"
    assert (root / "moved.md").read_text() == "history"


def v2_request(root, guards=None):
    # Deliberately put the replace first; the reviewable plan moves snapshots first.
    return {"version": 2, "operations": [request()["operations"][0],
            {"kind": "snapshot", "path": "README.md", "destination": "history/readme.md",
             "expected_sha256": c._hash((root / "README.md").read_bytes()),
             "origin": {"reference_base": ".", "classification_basis": "Explicitly approved historical original"}}],
            "guards": guards or []}


def test_v2_snapshot_overlay_apply_recover(setup):
    root, out, cfg = setup
    original = (root / "README.md").read_bytes()
    plan = c.preview(root, v2_request(root), cfg)
    assert plan["version"] == 2
    assert plan["operations"][0]["kind"] == "snapshot"
    candidate = c.overlay(root, plan, cfg)
    assert candidate == {"README.md": b"new\r\ntwo\r\n", "history/readme.md": original}
    assert not (root / "history").exists()
    record = c.apply(root, plan, cfg, out)
    assert record["completed"] == [0, 1]
    assert (root / "history/readme.md").read_bytes() == original
    assert c.verify(root, record, cfg)["status"] == "Passed"
    restored = c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "README.md").read_bytes() == original
    assert not (root / "history").exists()
    assert c.verify(root, restored, cfg)["status"] == "Passed"
    assert c.recover(root, Path(record["journal_path"]), cfg)["status"] == "recovered"


def test_v1_overlay_move_and_stale_source(setup):
    root, _, cfg = setup
    plan = c.preview(root, request(), cfg)
    assert c.overlay(root, plan, cfg)["old.md"] is None
    (root / "old.md").write_text("changed")
    with pytest.raises(ValueError):
        c.overlay(root, plan, cfg)


@pytest.mark.parametrize("stage", ["before_snapshot", "after_snapshot", "after_replace"])
def test_v2_interruption_recovery(setup, monkeypatch, stage):
    root, out, cfg = setup
    plan = c.preview(root, v2_request(root), cfg)
    snapshot, atomic = c._snapshot, c._atomic
    def interrupted_snapshot(*args):
        if stage != "before_snapshot":
            snapshot(*args)
        raise KeyboardInterrupt()
    def interrupted_atomic(*args):
        atomic(*args)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, "_atomic" if stage == "after_replace" else "_snapshot",
                        interrupted_atomic if stage == "after_replace" else interrupted_snapshot)
    with pytest.raises(KeyboardInterrupt):
        c.apply(root, plan, cfg, out)
    record = json.loads(next(out.glob("*.json")).read_text())
    assert record["status"] == "failed"
    if stage == "after_snapshot":
        assert (root / "README.md").read_bytes().startswith(b"one")
        assert (root / "history/readme.md").read_bytes().startswith(b"one")
    monkeypatch.setattr(c, "_atomic", atomic)
    monkeypatch.setattr(c, "_snapshot", snapshot)
    restored = c.recover(root, Path(record["journal_path"]), cfg)
    assert restored["status"] == "recovered"
    assert (root / "README.md").read_bytes().startswith(b"one")
    assert not (root / "history/readme.md").exists()


def test_v2_snapshot_publication_interruption_has_ownership(setup, monkeypatch):
    root, out, cfg = setup
    link = os.link
    def interrupted(*args, **kwargs):
        link(*args, **kwargs)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c.os, "link", interrupted)
    with pytest.raises(KeyboardInterrupt):
        c.apply(root, c.preview(root, v2_request(root), cfg), cfg, out)
    monkeypatch.setattr(c.os, "link", link)
    record = json.loads(next(out.glob("*.json")).read_text())
    assert record["created_files"][0]["path"] == "history/readme.md"
    c.recover(root, Path(record["journal_path"]), cfg)
    assert not (root / "history/readme.md").exists()


@pytest.mark.parametrize("change", ["edit", "same_bytes_new_inode"])
def test_v2_recovery_refuses_changed_archive(setup, change):
    root, out, cfg = setup
    rec = c.apply(root, c.preview(root, v2_request(root), cfg), cfg, out)
    archive = root / "history/readme.md"
    if change == "edit":
        archive.write_text("new work")
    else:
        other = root / "replacement.md"
        other.write_bytes(archive.read_bytes())
        os.replace(other, archive)
    with pytest.raises(ValueError):
        c.recover(root, Path(rec["journal_path"]), cfg)
    assert (root / "README.md").read_bytes().startswith(b"new")


def test_v2_preflight_drift_collision_origin_and_overlap(setup):
    root, out, cfg = setup
    req = v2_request(root)
    plan = c.preview(root, req, cfg)
    (root / "README.md").write_bytes(b"one\r\nchanged\r\n")
    with pytest.raises(ValueError):
        c.apply(root, plan, cfg, out)
    assert not out.exists()
    with pytest.raises(ValueError, match="fingerprint"):
        c.preview(root, req, cfg)
    req = v2_request(root)
    req["operations"][1]["origin"]["classification_basis"] = ""
    with pytest.raises(ValueError, match="origin"):
        c.preview(root, req, cfg)
    req = v2_request(root)
    req["operations"].append(request()["operations"][0])
    with pytest.raises(ValueError, match="multiple writes"):
        c.preview(root, req, cfg)
    req = v2_request(root)
    (root / "history").mkdir()
    (root / "history/readme.md").write_text("prior history")
    with pytest.raises(ValueError, match="destination exists"):
        c.preview(root, req, cfg)
    assert (root / "history/readme.md").read_text() == "prior history"


def test_v2_guards_exact_blocks_and_precise_exceptions(setup):
    root, out, cfg = setup
    text = "# Current\r\none\r\n\r\n## Contract\r\nKeep [doc](old.md)\r\n\r\n| Name | Value |\r\n| --- | --- |\r\n| size | 12 |\r\n\r\n<a id=\"stable\"></a>\r\n"
    (root / "README.md").write_bytes(text.encode())
    table = "| Name | Value |\r\n| --- | --- |\r\n| size | 12 |\r\n"
    guards = [{"kind": "snippet", "path": "README.md", "value": "size | 12"},
              {"kind": "heading", "path": "README.md", "value": "## Contract"},
              {"kind": "table", "path": "README.md", "value": table},
              {"kind": "anchor", "path": "README.md", "value": "stable"}]
    req = v2_request(root, guards)
    req["operations"][0].update(old="old.md", new="docs/new.md")
    with pytest.raises(ValueError, match="preservation"):
        c.preview(root, req, cfg)
    guards[1]["exceptions"] = [{"old": "old.md", "new": "docs/new.md"}]
    plan = c.preview(root, req, cfg)
    assert plan["guard_evidence"][1]["before_sha256"] != plan["guard_evidence"][1]["after_sha256"]
    rec = c.apply(root, plan, cfg, out)
    assert c.verify(root, rec, cfg)["status"] == "Passed"
    c.recover(root, Path(rec["journal_path"]), cfg)
    assert (root / "README.md").read_bytes() == text.encode()


@pytest.mark.parametrize("kind,value,text", [
    ("snippet", "aa", "aaa one"),
    ("heading", "## Same", "one\n## Same\na\n## Same\nb\n"),
    ("anchor", "same", 'one <a id="same"></a><b id="same"></b>'),
    ("table", "| A |\n| --- |\n| 1 |\n", "one\n\n| A |\n| --- |\n| 1 |\n\n| A |\n| --- |\n| 1 |\n"),
])
def test_v2_guard_ambiguity(setup, kind, value, text):
    root, _, cfg = setup
    (root / "README.md").write_text(text)
    req = v2_request(root, [{"kind": kind, "path": "README.md", "value": value}])
    with pytest.raises(ValueError, match="ambiguous"):
        c.preview(root, req, cfg)


def test_v2_guard_delete_and_whole_block_exception_refused(setup):
    root, _, cfg = setup
    (root / "README.md").write_text("one\n## Rules\nMust keep\n")
    req = v2_request(root, [{"kind": "heading", "path": "README.md", "value": "## Rules"}])
    req["operations"][0].update(old="Must keep", new="")
    with pytest.raises(ValueError, match="preservation"):
        c.preview(root, req, cfg)
    req["guards"][0]["exceptions"] = [{"old": "## Rules\nMust keep\n", "new": ""}]
    with pytest.raises(ValueError, match="entire block"):
        c.preview(root, req, cfg)


@pytest.mark.parametrize("version", [1, 2])
def test_old_records_survive_only_new_default_config_keys(setup, monkeypatch, version):
    from fifan_maintenance.project import DEFAULT_CONFIG
    root, out, cfg = setup
    req = request() if version == 1 else v2_request(root)
    record = c.apply(root, c.preview(root, req, cfg), cfg, out)
    monkeypatch.setitem(DEFAULT_CONFIG, "new_v11_default", {"enabled": False})
    added = {**cfg, "new_v11_default": {"enabled": False}}
    assert c.verify(root, record, added)["status"] == "Passed"
    c.recover(root, Path(record["journal_path"]), added)
    assert (root / "README.md").read_bytes().startswith(b"one")
    with pytest.raises(ValueError):
        c.verify(root, record, {**added, "new_v11_default": {"enabled": True}})
    with pytest.raises(ValueError):
        c.verify(root, record, {**added, "protected": ["README.md"]})


def test_v2_record_tampering_rehashed_rejected(setup):
    root, out, cfg = setup
    rec = c.apply(root, c.preview(root, v2_request(root), cfg), cfg, out)
    path = Path(rec["journal_path"])
    rec["plan"]["operations"][0]["origin"]["reference_base"] = "../outside"
    c._seal(rec["plan"], "operation_id")
    c._seal(rec, "record_sha256")
    path.write_text(json.dumps(rec))
    with pytest.raises(ValueError):
        c.recover(root, path, cfg)
    assert (root / "README.md").read_bytes().startswith(b"new")


def test_v2_guard_on_untouched_file_blocks_stale_plan_and_recovery(setup):
    root, out, cfg = setup
    (root / "rules.md").write_text("Must preserve rule")
    guard = {"kind": "snippet", "path": "rules.md", "value": "Must preserve rule"}
    plan = c.preview(root, v2_request(root, [guard]), cfg)
    (root / "rules.md").write_text("Rule changed")
    with pytest.raises(ValueError):
        c.overlay(root, plan, cfg)
    with pytest.raises(ValueError):
        c.apply(root, plan, cfg, out)
    assert not out.exists()
    (root / "rules.md").write_text("Must preserve rule")
    record = c.apply(root, plan, cfg, out)
    (root / "rules.md").write_text("Rule changed")
    with pytest.raises(ValueError):
        c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "README.md").read_bytes().startswith(b"new")
    assert (root / "history/readme.md").exists()


def test_v2_recovery_interrupted_during_reverse_replace_is_resumable(setup, monkeypatch):
    root, out, cfg = setup
    record = c.apply(root, c.preview(root, v2_request(root), cfg), cfg, out)
    atomic = c._atomic
    def interrupted(*args):
        atomic(*args)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, "_atomic", interrupted)
    with pytest.raises(KeyboardInterrupt):
        c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "README.md").read_bytes().startswith(b"one")
    assert (root / "history/readme.md").exists()
    monkeypatch.setattr(c, "_atomic", atomic)
    restored = c.recover(root, Path(record["journal_path"]), cfg)
    assert restored["status"] == "recovered"
    assert not (root / "history/readme.md").exists()


def test_v2_guard_exception_must_match_uniquely(setup):
    root, _, cfg = setup
    (root / "README.md").write_text("one\n## Rules\naaa\n")
    guard = {"kind": "heading", "path": "README.md", "value": "## Rules",
             "exceptions": [{"old": "aa", "new": "b"}]}
    with pytest.raises(ValueError, match="ambiguous"):
        c.preview(root, v2_request(root, [guard]), cfg)


def test_v2_binary_snapshot_and_unchanged_original(setup):
    root, out, cfg = setup
    original = b"\x00\xff\r\n"
    (root / "raw.bin").write_bytes(original)
    req = {"version": 2, "operations": [{"kind": "snapshot", "path": "raw.bin", "destination": "archive/raw.bin",
            "expected_sha256": c._hash(original), "origin": {"reference_base": ".", "classification_basis": "Explicit raw preservation"}}]}
    plan = c.preview(root, req, cfg)
    assert c.overlay(root, plan, cfg) == {"archive/raw.bin": original}
    record = c.apply(root, plan, cfg, out)
    assert (root / "raw.bin").read_bytes() == original
    assert c.verify(root, record, cfg)["status"] == "Passed"
    (root / "raw.bin").write_bytes(b"external change")
    with pytest.raises(ValueError, match="original subsequently changed"):
        c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "archive/raw.bin").read_bytes() == original


def test_preview_guard_encoding_is_incrementally_bounded(setup, monkeypatch):
    root, _, cfg = setup
    (root / "README.md").write_text("one" + "x" * 993 + "TAIL")
    guards = [{"kind": "snippet", "path": "README.md", "value": "TAIL"} for _ in range(10)]
    req = {"version": 2, "operations": [request()["operations"][0]], "guards": guards}
    encode = c.base64.b64encode
    encodings = []
    def counted(data):
        encodings.append(len(data))
        return encode(data)
    monkeypatch.setattr(c.base64, "b64encode", counted)
    monkeypatch.setattr(c, "MAX_BYTES", 7000)
    with pytest.raises(ValueError, match="Blocked: change journal budget"):
        c.preview(root, req, cfg)
    assert 0 < len(encodings) < len(guards)
    assert sum(encodings) < 7000


def test_repeated_snapshot_backups_budgeted_before_apply_encoding(setup, monkeypatch):
    root, out, cfg = setup
    (root / "README.md").write_text("one" + "x" * 997)
    snapshot = v2_request(root)["operations"][1]
    req = {"version": 2, "operations": [{**snapshot, "destination": "archive/copy-%s.md" % i} for i in range(10)]}
    plan = c.preview(root, req, cfg)
    encode = c.base64.b64encode
    encodings = []
    def counted(data):
        encodings.append(len(data))
        return encode(data)
    monkeypatch.setattr(c.base64, "b64encode", counted)
    monkeypatch.setattr(c, "MAX_BYTES", 7000)
    with pytest.raises(ValueError, match="Blocked: change journal budget"):
        c.preview(root, req, cfg)
    assert encodings == []
    with pytest.raises(ValueError, match="Blocked: change journal budget"):
        c.apply(root, plan, cfg, out)
    assert encodings == []
    assert not out.exists()


@pytest.mark.parametrize("version", [1, 2])
def test_partial_but_consistent_batch_verify_is_unknown(setup, monkeypatch, version):
    root, out, cfg = setup
    req = request() if version == 1 else v2_request(root)
    save = c._save
    interrupted = []
    def receipt_then_interrupt(path, record):
        save(path, record)
        if record["completed"] == [0] and record["intent"] is None and record["status"] == "applying" and not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt()
    monkeypatch.setattr(c, "_save", receipt_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        c.apply(root, c.preview(root, req, cfg), cfg, out)
    record = json.loads(next(out.glob("*.json")).read_text())
    assert record["completed"] == [0]
    assert record["intent"] is None
    result = c.verify(root, record, cfg)
    assert result["status"] == "Unknown"
    assert result["journal_consistency"] == "Passed"
    assert result["operation_status"] == "failed"
    assert result["issues"] == []
    restored = c.recover(root, Path(record["journal_path"]), cfg)
    assert c.verify(root, restored, cfg)["status"] == "Passed"


@pytest.mark.parametrize("interrupt_after_replace", [False, True])
def test_partial_guards_are_checked_for_both_observed_write_states(setup, monkeypatch, interrupt_after_replace):
    root, out, cfg = setup
    (root / "rules.md").write_text("Independent contract")
    guards = [{"kind": "snippet", "path": "rules.md", "value": "Independent contract"},
              {"kind": "snippet", "path": "README.md", "value": "two"}]
    plan = c.preview(root, v2_request(root, guards), cfg)
    save, atomic = c._save, c._atomic
    once = []
    def receipt_interrupt(path, record):
        save(path, record)
        if not interrupt_after_replace and record["completed"] == [0] and record["intent"] is None and record["status"] == "applying" and not once:
            once.append(True)
            raise KeyboardInterrupt()
    def write_interrupt(*args):
        atomic(*args)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, "_save", receipt_interrupt)
    if interrupt_after_replace:
        monkeypatch.setattr(c, "_atomic", write_interrupt)
    with pytest.raises(KeyboardInterrupt):
        c.apply(root, plan, cfg, out)
    record = json.loads(next(out.glob("*.json")).read_text())
    assert record["completed"] == [0]
    assert record["intent"] == (1 if interrupt_after_replace else None)
    verified = c.verify(root, record, cfg)
    # Intent-after-write remains an incomplete/uncertain receipt, never Passed.
    assert verified["status"] in ("Unknown", "Failed")
    if not interrupt_after_replace:
        assert verified["journal_consistency"] == "Passed"
    (root / "rules.md").write_text("Later independent work")
    drifted = c.verify(root, record, cfg)
    assert drifted["status"] == "Failed"
    assert any(issue.get("check") == "guards/snapshot sources" for issue in drifted["issues"])
    monkeypatch.setattr(c, "_atomic", atomic)
    with pytest.raises(ValueError, match="guard source subsequently changed"):
        c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "history/readme.md").exists()
    assert (root / "rules.md").read_text() == "Later independent work"
    assert (root / "README.md").read_bytes().startswith(b"new" if interrupt_after_replace else b"one")


def many_request(root, patches, path="README.md"):
    return {"version": 3, "operations": [{"type": "replace_many", "path": path,
            "expected_sha256": c._hash((root / path).read_bytes()), "patches": patches}]}


def test_v3_many_single_write_unicode_crlf_snapshot_and_recovery(setup, monkeypatch):
    root, out, cfg = setup
    before = "# 合同\r\n旧甲\r\n保留\r\n旧乙\r\n".encode()
    (root / "README.md").write_bytes(before)
    second = before.index("旧乙".encode())
    req = many_request(root, [{"old": "旧甲", "new": "新甲 longer"},
                       {"old_locator": {"sha256": c._hash(before), "start_byte": second, "end_byte": second + len("旧乙".encode())}, "new": "新乙"}])
    req["operations"].append(v2_request(root)["operations"][1])
    prepared = c.prepare_request(root, req, cfg)
    plan = prepared["plan"]
    assert plan == c.preview(root, req, cfg)
    assert plan["version"] == 2
    assert set(plan) == {"version", "root", "config_sha256", "config_snapshot", "config_contract", "operations", "guards", "guard_evidence", "operation_id"}
    assert c._kind(plan["operations"][0]) == "snapshot"
    compiled = prepared["request"]["operations"][0]
    assert compiled == {"type": "replace", "path": "README.md", "old": before.decode(), "new": "# 合同\r\n新甲 longer\r\n保留\r\n新乙\r\n"}
    assert "旧甲" not in json.dumps(prepared["compilation"], ensure_ascii=False)
    writes = []
    atomic = c._atomic
    def counted(*args):
        writes.append(args[1])
        return atomic(*args)
    monkeypatch.setattr(c, "_atomic", counted)
    record = c.apply(root, plan, cfg, out)
    assert writes == ["README.md"]
    assert (root / "README.md").read_bytes() == compiled["new"].encode()
    assert (root / "history/readme.md").read_bytes() == before
    assert c.verify(root, record, cfg)["status"] == "Passed"
    c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "README.md").read_bytes() == before


@pytest.mark.parametrize("patches,code", [
    ([{"old": "one", "new": "new"}, {"old": "missing", "new": "x"}], "PATCH_NOT_FOUND"),
    ([{"old": "one", "new": "new"}, {"old": "one\r\ntwo", "new": "x"}], "PATCH_OVERLAP"),
    ([{"old": "one", "new": "new"}, {"old": "one", "new": "other"}], "PATCH_OVERLAP"),
    ([{"old": "", "new": "x"}], "INVALID_REQUEST"),
])
def test_v3_many_invalid_patch_never_writes(setup, patches, code):
    root, out, cfg = setup
    before = (root / "README.md").read_bytes()
    with pytest.raises(c.ChangeRequestError) as failure:
        c.preview(root, many_request(root, patches), cfg)
    assert failure.value.reason_code == code
    assert failure.value.details["operation_index"] == 0
    assert (root / "README.md").read_bytes() == before
    assert not out.exists()


def test_v3_same_baseline_not_sequential_and_overlapping_occurrences(setup):
    root, _, cfg = setup
    req = many_request(root, [{"old": "one", "new": "inserted"}, {"old": "inserted", "new": "other"}])
    with pytest.raises(c.ChangeRequestError) as failure:
        c.preview(root, req, cfg)
    assert failure.value.reason_code == "PATCH_NOT_FOUND"
    (root / "README.md").write_text("aaa")
    with pytest.raises(c.ChangeRequestError) as failure:
        c.preview(root, many_request(root, [{"old": "aa", "new": "b"}]), cfg)
    assert failure.value.reason_code == "SELECTOR_AMBIGUOUS"


@pytest.mark.parametrize("start,end", [(1, 2), (False, 3), (-1, 3), (0, 999), (0, 0)])
def test_v3_locator_rejects_bad_unicode_ranges(setup, start, end):
    root, _, cfg = setup
    before = "甲 one".encode()
    (root / "README.md").write_bytes(before)
    req = many_request(root, [{"old_locator": {"sha256": c._hash(before), "start_byte": start, "end_byte": end}, "new": "x"}])
    with pytest.raises(c.ChangeRequestError) as failure:
        c.preview(root, req, cfg)
    assert failure.value.reason_code == "PATCH_RANGE_INVALID"


def test_v3_source_and_locator_drift(setup):
    root, _, cfg = setup
    req = many_request(root, [{"old": "one", "new": "new"}])
    (root / "README.md").write_bytes(b"one\r\nchanged\r\n")
    with pytest.raises(c.ChangeRequestError) as failure:
        c.preview(root, req, cfg)
    assert failure.value.reason_code == "SOURCE_CHANGED"
    req = many_request(root, [{"old_locator": {"sha256": "0" * 64, "start_byte": 0, "end_byte": 3}, "new": "x"}])
    with pytest.raises(c.ChangeRequestError) as failure:
        c.preview(root, req, cfg)
    assert failure.value.reason_code == "SOURCE_CHANGED"


def test_v3_mixed_independent_writer_rejected_even_if_many_noop(setup):
    root, _, cfg = setup
    req = many_request(root, [{"old": "one", "new": "one"}])
    req["operations"].append(request()["operations"][0])
    with pytest.raises(c.ChangeRequestError) as failure:
        c.prepare_request(root, req, cfg)
    assert failure.value.reason_code == "MULTIPLE_WRITES"


def test_v3_noop_is_reported_without_plan_or_journal(setup):
    root, out, cfg = setup
    req = many_request(root, [{"old": "one", "new": "one"}, {"old": "two", "new": "two"}])
    prepared = c.prepare_request(root, req, cfg)
    assert prepared["plan"] is None
    assert prepared["request"]["operations"] == []
    assert prepared["compilation"]["status"] == "NoChange"
    assert all(p["status"] == "NoChange" for p in prepared["compilation"]["operations"][0]["patches"])
    with pytest.raises(c.ChangeRequestError) as failure:
        c.preview(root, req, cfg)
    assert failure.value.reason_code == "NO_CHANGES"
    assert not out.exists()


def test_v3_many_budget_and_protected_source(setup, monkeypatch):
    root, _, cfg = setup
    (root / "README.md").write_text("one" + "x" * 997)
    req = many_request(root, [{"old": "one", "new": "new"}])
    monkeypatch.setattr(c, "MAX_BYTES", 1500)
    with pytest.raises(ValueError, match="journal budget"):
        c.preview(root, req, cfg)
    (root / ".fifan-maintenance.json").write_text("one")
    req = many_request(root, [{"old": "one", "new": "new"}], ".fifan-maintenance.json")
    with pytest.raises(ValueError, match="protected"):
        c.preview(root, req, cfg)


def exact_archive_proof(root, cfg):
    from fifan_maintenance.archive_coverage import archive_coverage
    (root / "archive.md").write_bytes(b"Archived original\r\ntwo\r\n")
    request = {"version": 1, "items": [{"source": {"path": "README.md", "selector": {"kind": "snippet", "value": "two\r\n"}},
               "archive": {"path": "archive.md", "selector": {"kind": "snippet", "value": "two\r\n"},
                           "reference_base": ".", "classification_basis": "Declared retained history"}}]}
    report = archive_coverage(root, cfg, request)
    assert report["status"] == "Passed"
    return report["proof"]


def test_v3_archive_proof_compile_bindings_and_apply_revalidation(setup):
    from fifan_maintenance.project import DEFAULT_CONFIG
    root, out, _ = setup
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    proof = exact_archive_proof(root, cfg)
    # A standard v3 replace is promoted to complete-source replacement too.
    req = {"version": 3, "operations": [{"type": "replace", "path": "README.md", "old": "two\r\n", "new": ""}], "archive_proofs": [proof]}
    prepared = c.prepare_request(root, req, cfg)
    compiled = prepared["request"]["operations"][0]
    assert compiled["old"] == "one\r\ntwo\r\n"
    assert compiled["new"] == "one\r\n"
    assert prepared["compilation"]["archive_proofs"][0]["archive_bindings"][0]["path"] == "archive.md"
    plan = prepared["plan"]
    original = (root / "archive.md").read_bytes()
    (root / "archive.md").write_bytes(original + b"appended other work")
    with pytest.raises(ValueError):
        c.apply(root, plan, cfg, out)
    assert not out.exists()
    (root / "archive.md").write_bytes(original)
    record = c.apply(root, plan, cfg, out)
    assert (root / "README.md").read_bytes() == b"one\r\n"
    assert c.verify(root, record, cfg)["status"] == "Passed"
    c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "README.md").read_bytes() == b"one\r\ntwo\r\n"
    assert (root / "archive.md").read_bytes() == original


@pytest.mark.parametrize("participant", ["README.md", "archive.md"])
def test_v3_proof_compile_to_plan_race_is_rejected(setup, monkeypatch, participant):
    from fifan_maintenance import archive_coverage as coverage
    from fifan_maintenance.project import DEFAULT_CONFIG
    root, out, _ = setup
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    proof = exact_archive_proof(root, cfg)
    original = coverage.compile_v2_guards
    def raced(*args):
        result = original(*args)
        target = root / participant
        target.write_bytes(target.read_bytes() + b"concurrent appendix")
        return result
    monkeypatch.setattr(coverage, "compile_v2_guards", raced)
    req = {"version": 3, "operations": [{"type": "replace", "path": "README.md", "old": "two\r\n", "new": ""}], "archive_proofs": [proof]}
    with pytest.raises(c.ChangeRequestError) as failure:
        c.prepare_request(root, req, cfg)
    assert failure.value.reason_code == "SOURCE_CHANGED"
    assert not out.exists()
    assert b"two\r\n" in (root / "README.md").read_bytes()


def test_v3_proof_requires_bound_source_writer(setup):
    from fifan_maintenance.project import DEFAULT_CONFIG
    root, _, _ = setup
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    proof = exact_archive_proof(root, cfg)
    req = {"version": 3, "operations": [request()["operations"][1]], "archive_proofs": [proof]}
    with pytest.raises(c.ChangeRequestError) as failure:
        c.prepare_request(root, req, cfg)
    assert failure.value.reason_code == "SOURCE_BINDING_MISSING"


def test_v3_snapshot_many_write_interruption_uses_unchanged_v2_recovery(setup, monkeypatch):
    root, out, cfg = setup
    req = many_request(root, [{"old": "one", "new": "new1"}, {"old": "two", "new": "new2"}])
    req["operations"].append(v2_request(root)["operations"][1])
    atomic = c._atomic
    def interrupted(*args):
        atomic(*args)
        raise KeyboardInterrupt()
    monkeypatch.setattr(c, "_atomic", interrupted)
    with pytest.raises(KeyboardInterrupt):
        c.apply(root, c.preview(root, req, cfg), cfg, out)
    record = json.loads(next(out.glob("*.json")).read_text())
    assert record["version"] == 2
    assert record["completed"] == [0]
    assert record["intent"] == 1
    monkeypatch.setattr(c, "_atomic", atomic)
    c.recover(root, Path(record["journal_path"]), cfg)
    assert (root / "README.md").read_bytes() == b"one\r\ntwo\r\n"
    assert not (root / "history/readme.md").exists()


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('names', [('A.md', 'a.md'), ('é.md', 'e\u0301.md'), ('one.md', 'linked.md')])
def test_batch_aliases_rejected_before_publication(setup, version, names):
    root, out, cfg = setup
    first, second = names
    (root / first).write_text('old')
    if not (root / second).exists():
        os.link(root / first, root / second)
    assert (root / first).stat().st_ino == (root / second).stat().st_ino
    req = {'operations': [{'type': 'replace', 'path': first, 'old': 'old', 'new': 'one'},
                          {'type': 'replace', 'path': second, 'old': 'old', 'new': 'two'}]}
    if version == 2:
        req['version'] = 2
    with pytest.raises(ValueError, match='alias'):
        c.preview(root, req, cfg)
    assert (root / first).read_text() == (root / second).read_text() == 'old'
    assert not out.exists()


def test_guard_commonmark_line_coordinates_and_roundtrip(setup):
    root, out, cfg = setup
    text = '```\nprefix\u2028more\u2028## Contract\n```\n## Contract\nMust keep\nExtra\n## Next\nAfter\n'
    (root / 'README.md').write_text(text)
    req = {'version': 2, 'operations': [{'type': 'replace', 'path': 'README.md', 'old': 'Must keep', 'new': ''}],
           'guards': [{'path': 'README.md', 'kind': 'heading', 'value': '## Contract'}]}
    with pytest.raises(ValueError):
        c.preview(root, req, cfg)
    assert (root / 'README.md').read_text() == text and not out.exists()
    req['operations'][0].update(old='After', new='Changed')
    rec = c.apply(root, c.preview(root, req, cfg), cfg, out)
    assert c.verify(root, rec, cfg)['status'] == 'Passed'
    restored = c.recover(root, Path(rec['journal_path']), cfg)
    assert c.verify(root, restored, cfg)['status'] == 'Passed'
    assert (root / 'README.md').read_text() == text


@pytest.mark.parametrize('version', [1, 2])
def test_identical_replace_verifies_recovers_and_rejects_drift(setup, version):
    root, out, cfg = setup
    req = {'operations': [{'type': 'replace', 'path': 'README.md', 'old': 'one', 'new': 'one'}]}
    if version == 2:
        req['version'] = 2
    rec = c.apply(root, c.preview(root, req, cfg), cfg, out)
    assert c.verify(root, rec, cfg)['status'] == 'Passed'
    restored = c.recover(root, Path(rec['journal_path']), cfg)
    assert c.verify(root, restored, cfg)['status'] == 'Passed'
    again = c.recover(root, Path(rec['journal_path']), cfg)
    assert c.verify(root, again, cfg)['status'] == 'Passed'
    (root / 'README.md').write_text('external')
    assert c.verify(root, again, cfg)['status'] == 'Failed'
    with pytest.raises(ValueError):
        c.recover(root, Path(rec['journal_path']), cfg)


@pytest.mark.parametrize('version', [1, 2])
def test_apply_rechecks_aliases_even_for_old_preview(setup, version, monkeypatch):
    root, out, cfg = setup
    (root / 'A.md').write_text('old')
    if not (root / 'a.md').exists():
        os.link(root / 'A.md', root / 'a.md')
    req = {'operations': [{'type': 'replace', 'path': 'A.md', 'old': 'old', 'new': 'one'},
                          {'type': 'replace', 'path': 'a.md', 'old': 'old', 'new': 'two'}]}
    if version == 2:
        req['version'] = 2
    # A sealed plan generated by the old string-only preview is still valid JSON;
    # the current apply must reject it before making a journal or changing files.
    with monkeypatch.context() as patch:
        patch.setattr(c, '_check_operation_aliases', lambda *args: None)
        plan = c.preview(root, req, cfg)
    with pytest.raises(ValueError, match='alias'):
        c.apply(root, plan, cfg, out)
    assert (root / 'A.md').read_text() == (root / 'a.md').read_text() == 'old'
    assert not out.exists()


def test_table_guard_uses_commonmark_lines_after_unicode_separator(setup):
    root, out, cfg = setup
    table = '| A | B |\r\n| --- | --- |\r\n| keep | value |\r\n'
    original = '```\r\nprefix\u2028extra\r\n```\r\n' + table + '\r\noutside\r\n'
    (root / 'README.md').write_bytes(original.encode())
    req = {'version': 2, 'operations': [{'type': 'replace', 'path': 'README.md', 'old': 'keep', 'new': 'removed'}],
           'guards': [{'path': 'README.md', 'kind': 'table', 'value': table}]}
    with pytest.raises(ValueError):
        c.preview(root, req, cfg)
    req['operations'][0].update(old='outside', new='changed')
    rec = c.apply(root, c.preview(root, req, cfg), cfg, out)
    assert c.verify(root, rec, cfg)['status'] == 'Passed'
    restored = c.recover(root, Path(rec['journal_path']), cfg)
    assert c.verify(root, restored, cfg)['status'] == 'Passed'
    assert (root / 'README.md').read_bytes() == original.encode()
