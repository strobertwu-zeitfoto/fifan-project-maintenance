from __future__ import annotations

import json
from pathlib import Path

from fifan_maintenance.cli import main
from fifan_maintenance.engine import run
from fifan_maintenance.project import read_bytes


def test_truncated_report_preserves_full_counts_and_failure(tmp_path, capsys):
    (tmp_path / ".fifan-maintenance.json").write_text(json.dumps({"max_findings": 1}))
    for number in range(8):
        (tmp_path / (str(number) + ".json")).write_text("{")
    report = run(tmp_path, checks=["configs"])
    assert report["finding_counts"]["configs/invalid_format"] == 8
    assert report["finding_total"] == 9
    assert report["has_failures"]
    assert len(report["findings"]) == 1
    assert report["findings_truncated"]
    assert main(["check", "--project", str(tmp_path), "--checks", "configs", "--format", "json"]) == 1


def test_oversize_file_does_not_become_passed(tmp_path):
    (tmp_path / ".fifan-maintenance.json").write_text(json.dumps({"max_file_bytes": 256}))
    (tmp_path / "README.md").write_text("x" * 512)
    report = run(tmp_path, checks=["documents"])
    assert any(f["status"] == "Unknown" for f in report["findings"])
    assert next(c for c in report["coverage"] if c["check"] == "documents")["status"] == "Unknown"


def test_incomplete_worker_is_not_success(monkeypatch, tmp_path):
    import subprocess
    from fifan_maintenance import engine
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("worker", 0.001)
    monkeypatch.setattr(engine, "run_bounded", timeout)
    report = run(tmp_path, checks=["configs"])
    assert next(c for c in report["coverage"] if c["check"] == "configs")["status"] == "Unknown"
    assert report["findings"][0]["code"] == "worker_incomplete"


def test_state_changed_target_with_identical_source(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("[target](target.txt)")
    (root / "target.txt").write_text("hello")
    state = tmp_path / "state.json"
    args = ["check", "--project", str(root), "--checks", "links", "--format", "json", "--state", str(state)]
    assert main(args) == 0
    capsys.readouterr()
    (root / "target.txt").unlink()
    assert main(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert any(f["code"] == "missing-target" for f in report["findings"])
    assert report["delta"]["new_findings"] > 0


def test_fifo_not_read(tmp_path):
    import os
    import pytest
    if not hasattr(os, "mkfifo"):
        pytest.skip("requires POSIX FIFO")
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ValueError):
        read_bytes(tmp_path, "pipe", 100)


def test_history_is_not_daily_work_and_inventory_does_not_promote_it(tmp_path):
    (tmp_path / "README.md").write_text("# Current")
    (tmp_path / "docs/history").mkdir(parents=True)
    (tmp_path / "docs/history/old.md").write_text("[old](missing.md)")
    (tmp_path / ".fifan-maintenance.json").write_text(json.dumps({"historical_sources": ["docs/history/**"]}))
    daily = run(tmp_path, checks=["links"])
    assert "docs/history/old.md" not in daily["files"]
    full = run(tmp_path, checks=["links"], inventory=True)
    assert "docs/history/old.md" in full["files"]
    assert any(f["code"] == "missing-target" and f["status"] == "Unknown" for f in full["findings"])


def test_explicit_include_can_select_current_evidence_and_report(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence/current.md").write_text("[current](missing.md)")
    (tmp_path / ".fifan-maintenance.json").write_text(json.dumps({"include": ["evidence/**"]}))
    report = run(tmp_path, checks=["links"])
    assert "evidence/current.md" in report["files"]
    assert any(f["code"] == "missing-target" and f["status"] == "Failed" for f in report["findings"])


def test_unused_reference_definition_is_checked(tmp_path):
    (tmp_path / "README.md").write_text("[unused]: missing.md\n")
    report = run(tmp_path, checks=["links"])
    assert any(f["code"] == "missing-target" for f in report["findings"])


def test_state_redacts_and_has_stable_delta(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("[x](missing.md?token=SECRET_VALUE)")
    state = tmp_path / "state.json"
    args = ["check", "--project", str(root), "--checks", "links", "--format", "json", "--state", str(state)]
    assert main(args) == 1
    capsys.readouterr()
    assert "SECRET_VALUE" not in state.read_text()
    assert main(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["delta"]["new_findings"] == 0
    assert report["delta"]["resolved_findings"] == 0


def test_stream_transport_caps_before_collecting_full_output():
    import sys
    import pytest
    from fifan_maintenance.process import run_bounded
    with pytest.raises(ValueError):
        run_bounded([sys.executable, "-c", "import sys; sys.stdout.write('x' * 2000000)"], input=b"", timeout=3, output_limit=1024)


def test_generation_cap_reports_unknown(tmp_path):
    (tmp_path / "README.md").write_text("[x](missing.md)\n\n" * 4200)
    report = run(tmp_path, checks=["links"])
    assert next(c for c in report["coverage"] if c["check"] == "links")["generation_limited"]
    assert next(c for c in report["coverage"] if c["check"] == "links")["status"] == "Unknown"
    assert any(f["code"] == "generation_limit" for f in report["findings"]) or report["findings_truncated"]
    assert report["has_failures"]


def test_empty_directory_iteration_obeys_budget(tmp_path, monkeypatch):
    from fifan_maintenance import inventory
    from fifan_maintenance.models import Context
    from fifan_maintenance.project import load_config
    for name in ["a", "b", "c"]:
        (tmp_path / name).mkdir()
    config = load_config(tmp_path)
    config["max_seconds"] = 1
    ticks = iter(range(100))
    monkeypatch.setattr(inventory.time, "monotonic", lambda: next(ticks))
    findings = inventory.collect(Context(tmp_path, {}, config, True))
    assert any(f.code == "scan_limit" for f in findings)


def test_growth_is_measured_not_inferred(tmp_path):
    (tmp_path / "README.md").write_text("old")
    before = run(tmp_path, checks=[])
    (tmp_path / "README.md").write_text("old + new")
    after = run(tmp_path, checks=[])
    from fifan_maintenance.engine import compare_state
    assert compare_state(after, before)["growth"][0]["growth_bytes"] == 6


def test_html_source_and_explicit_anchor(tmp_path):
    (tmp_path / "index.html").write_text('<html><a href="target.html#section">go</a><img src="missing.png"></html>')
    (tmp_path / "target.html").write_text('<div id="section">target</div>')
    report = run(tmp_path, checks=["links"])
    assert any(f["code"] == "missing-target" for f in report["findings"])
    assert not any(f["code"] == "missing-anchor" for f in report["findings"])


def test_state_file_identity_containing_secret_keyword(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    file = root / "password-policy.md"
    file.write_text("public policy")
    state = tmp_path / "state.json"
    args = ["check", "--project", str(root), "--checks", "documents", "--format", "json", "--state", str(state)]
    assert main(args) == 0
    capsys.readouterr()
    file.write_text("public policy updated")
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["delta"]["growth"][0]["path"] == "password-policy.md"


def test_long_credential_is_redacted_before_evidence_truncation(tmp_path, capsys):
    root = tmp_path / "project"
    root.mkdir()
    secret = "PASSWORD_FRAGMENT_" * 120
    (root / "README.md").write_text("[x](missing.md?next=https://user:" + secret + "@host)")
    state = tmp_path / "state.json"
    assert main(["check", "--project", str(root), "--checks", "links", "--format", "json", "--state", str(state)]) == 1
    assert "PASSWORD_FRAGMENT_" not in state.read_text()
    output = capsys.readouterr().out
    assert "PASSWORD_FRAGMENT_" not in output
    finding = next(f for f in json.loads(output)["findings"] if f["code"] == "missing-target")
    assert "[REDACTED]" in finding["evidence"]["target"]


def test_inventory_finding_generation_is_bounded(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    for number in range(4020):
        (root / ("link" + str(number))).symlink_to(outside, target_is_directory=True)
    report = run(root, checks=[], inventory=True)
    coverage = next(c for c in report["coverage"] if c["check"] == "inventory")
    assert coverage["generation_limited"] and coverage["status"] == "Unknown"
    assert report["finding_counts"]["inventory/symlink_not_followed"] == 4000
    assert report["findings_truncated"]


def test_skipped_file_iteration_obeys_budget(tmp_path, monkeypatch):
    from fifan_maintenance import inventory
    from fifan_maintenance.models import Context
    from fifan_maintenance.project import load_config
    for number in range(10):
        (tmp_path / (str(number) + ".ignored")).write_text("ignored")
    config = load_config(tmp_path)
    config["max_seconds"] = 2
    ticks = iter(range(100))
    monkeypatch.setattr(inventory.time, "monotonic", lambda: next(ticks))
    context = Context(tmp_path, {}, config)
    findings = inventory.collect(context)
    assert any(f.code == "scan_limit" for f in findings)
    assert context.files == {}


def test_sensitive_evidence_key_is_redacted_before_key_truncation():
    from fifan_maintenance.models import Finding
    finding = Finding("test", "sensitive", "test", evidence={"x" * 110 + "password": "CREDENTIAL_VALUE"})
    assert "CREDENTIAL_VALUE" not in json.dumps(finding.to_dict())
    assert "[REDACTED]" in json.dumps(finding.to_dict())


def test_finding_byte_limit_is_enforced_before_count_limit():
    import pytest
    from fifan_maintenance.models import Finding, FindingLimit, finding_budget
    with finding_budget(10) as budget:
        with pytest.raises(FindingLimit):
            for number in range(4001):
                Finding("test", "bytes", "test", evidence={"detail": "例" * 1000})
    assert budget["bytes"] >= 4 * 1024 * 1024
    assert budget["count"] < 4000
