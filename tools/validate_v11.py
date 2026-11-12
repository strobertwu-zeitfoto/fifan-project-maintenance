#!/usr/bin/env python3
"""Repeatable isolated end-to-end validation for the 1.1 maintenance CLI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOOL = ROOT / ".venv39/bin/fifan-maintain"
DEFAULT_RESULTS = ROOT / "evidence/validation/v1.1/forward"


class ValidationError(RuntimeError):
    pass


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(tool: Path, project: Path, results: Path, name: str, args: List[str],
        expected: Optional[List[int]] = None) -> Dict[str, Any]:
    expected = expected or [0]
    command = [str(tool), *args]
    completed = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True)
    record = {
        "name": name,
        "argv": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "expected_returncodes": expected,
        "passed": completed.returncode in expected,
    }
    write_json(results / (name + ".command.json"), record)
    if completed.returncode not in expected:
        raise ValidationError("{} returned {} (expected {}): {}".format(
            name, completed.returncode, expected, completed.stderr[-1200:]))
    return record


def parse_json_output(record: Dict[str, Any]) -> Any:
    try:
        return json.loads(record["stdout"])
    except (ValueError, TypeError) as exc:
        raise ValidationError("{} stdout was not JSON: {}".format(record["name"], exc))


def cli_json(tool: Path, project: Path, results: Path, name: str,
             args: List[str], output_path: Path) -> Any:
    record = run(tool, project, results, name, args + ["--output", str(output_path)])
    if not output_path.is_file():
        raise ValidationError("{} did not create report {}".format(name, output_path))
    return json.loads(output_path.read_text(encoding="utf-8"))


def create_fixture(project: Path) -> Dict[str, Any]:
    project.mkdir(parents=True)
    (project / "docs").mkdir()
    (project / "history").mkdir()
    (project / "archive").mkdir()
    (project / "README.md").write_text(
        "# Fixture\n\n入口见[计划](ENGINEERING_PLAN.md)。\n\n" +
        "当前说明：初始摘要。\n\n# 历史\n\n必须保留的决定。\n", encoding="utf-8")
    (project / "PROJECT_MEMORY.md").write_text(
        "# 导航\n\n当前信息见[计划](ENGINEERING_PLAN.md)和[决定](DECISIONS.md)。\n", encoding="utf-8")
    (project / "ENGINEERING_PLAN.md").write_text(
        "# 唯一计划\n\n- 待办：触屏验收。\n", encoding="utf-8")
    (project / "DECISIONS.md").write_text(
        "# 决定\n\n统一餐盘已批准，接入待执行。\n", encoding="utf-8")
    # Large UTF-8 document for outline, byte-bounded reads, and cursor continuation.
    (project / "docs/INDEX.md").write_text("# 索引\n\n入口清单。\n", encoding="utf-8")
    body = "# 大文档\n\n## 当前说明\n\n" + ("保留中文段落；cursor续读必须无缺口。\n" * 11000)
    (project / "archive/LARGE.md").write_text(body, encoding="utf-8")
    for idx in range(1200):
        (project / "history" / ("REPORT_{:04d}.md".format(idx))).write_text(
            "# 历史 {:04d}\n\n旧材料仅作机械元数据范围。\n".format(idx), encoding="utf-8")
    write_json(project / ".fifan-maintenance.json", {
        "schema_version": 1,
        "include": ["*.md", "docs/**", "history/**"],
        "checks": ["documents", "links"],
    })
    profile = {
        "schema_version": 1,
        "sources": ["README.md", "PROJECT_MEMORY.md", "ENGINEERING_PLAN.md",
                    "DECISIONS.md", "docs/INDEX.md"],
        "reference_bodies": [],
        "historical_roots": ["history"],
        "checks": ["documents", "links"],
        "views": [
            {"name": "current", "path": "README.md", "start_line": 1,
             "end_line": 4, "kind": "current"},
            {"name": "historical", "path": "README.md", "start_line": 6,
             "end_line": 8, "kind": "historical"},
        ],
        "budgets": {"max_files": 2000, "max_file_bytes": 4194304,
                    "max_total_bytes": 67108864, "max_seconds": 60,
                    "max_findings": 200},
    }
    write_json(project.parent / "task-profile.json", profile)
    read_profile = dict(profile)
    read_profile["sources"] = list(profile["sources"]) + ["archive/LARGE.md"]
    write_json(project.parent / "read-task-profile.json", read_profile)
    return profile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", type=Path, default=DEFAULT_TOOL)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--keep-project", action="store_true",
                        help="keep isolated fixture under results/work for inspection")
    args = parser.parse_args()
    tool = args.tool.resolve()
    results = args.results.resolve()
    if not tool.is_file():
        raise ValidationError("CLI executable not found: {}".format(tool))
    results.mkdir(parents=True, exist_ok=True)
    work = results / "work"
    work.mkdir(exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="run-", dir=str(work)))
    project = run_root / "project"
    reports = run_root / "reports"
    reports.mkdir()
    records: List[Dict[str, Any]] = []
    try:
        create_fixture(project)
        project = project.resolve()
        profile = (project.parent / "task-profile.json").resolve()
        read_profile = (project.parent / "read-task-profile.json").resolve()

        # Capture the legacy default scan on the same unchanged 5-key-file fixture.
        project_config = project / ".fifan-maintenance.json"
        project_config_sha = sha256(project_config)
        legacy_baseline = cli_json(tool, project, reports, "legacy-baseline-check",
            ["check", "--project", str(project), "--checks", "documents,links", "--format", "json"],
            reports / "legacy-baseline-check.json")

        # The profile is explicit: exactly five primary sources and 1,200 history files.
        common = ["--project", str(project), "--task-profile", str(profile)]
        preflight = cli_json(tool, project, reports, "preflight",
            ["check", *common, "--preflight", "--format", "json"], reports / "preflight.json")
        records.append({"phase": "preflight", "primary_files": len(preflight.get("sources", [])),
                        "coverage": preflight.get("coverage"), "findings": preflight.get("finding_total")})
        if len(preflight.get("sources", [])) != 5:
            raise ValidationError("preflight did not report exactly five primary files")
        if preflight.get("body_bytes_read") != 0:
            raise ValidationError("preflight unexpectedly read document bodies")

        before = cli_json(tool, project, reports, "check-before",
            ["check", *common, "--historical-roots", "history", "--checks", "documents,links", "--format", "json"],
            reports / "check-before.json")
        records.append({"phase": "check-before", "file_count": before.get("file_count"),
                        "file_bytes": before.get("file_bytes"), "coverage": before.get("coverage")})
        if (before.get("model_calls") != 0 or before.get("historical_metadata", {}).get("file_count") != 1200
                or before.get("historical_metadata", {}).get("body_bytes_read") != 0):
            raise ValidationError("scoped check did not preserve metadata-only historical scope")
        summary_record = run(tool, project, reports, "summary",
            ["check", *common, "--historical-roots", "history", "--format", "summary",
             "--max-output-bytes", "4096"])
        records.append({"phase": "summary", "stdout_bytes": len(summary_record["stdout"].encode("utf-8"))})
        report_record = run(tool, project, reports, "report-summary",
            ["report", "--project", str(project), "--input", str(reports / "check-before.json"),
             "--max-output-bytes", "4096"])
        report_summary = parse_json_output(report_record)
        if report_summary.get("output_truncated"):
            raise ValidationError("report summary unexpectedly truncated")
        records.append({"phase": "report", "stdout_bytes": len(report_record["stdout"].encode("utf-8")),
                        "file_count": report_summary.get("file_count"),
                        "finding_total": report_summary.get("finding_total"),
                        "findings_truncated": report_summary.get("findings_truncated")})
        read_common = ["read", "--project", str(project), "--task-profile", str(read_profile)]
        outline_record = run(tool, project, reports, "outline",
            [*read_common, "--file", "archive/LARGE.md", "--outline", "--max-output-bytes", "4096"])
        outline = parse_json_output(outline_record)
        read_current_record = run(tool, project, reports, "read-view-current",
            [*read_common, "--file", "README.md", "--view", "current", "--max-output-bytes", "1024"])
        read_history_record = run(tool, project, reports, "read-view-historical",
            [*read_common, "--file", "README.md", "--view", "historical", "--max-output-bytes", "1024"])
        first_read_record = run(tool, project, reports, "read-cursor-first",
            [*read_common, "--file", "archive/LARGE.md", "--heading", "大文档",
             "--max-output-bytes", "4096"])
        first_read = parse_json_output(first_read_record)
        cursor = first_read.get("next_cursor") or first_read.get("cursor")
        if not cursor:
            raise ValidationError("large read did not return a continuation cursor")
        changed_selector = run(tool, project, reports, "read-cursor-changed-heading",
            [*read_common, "--file", "archive/LARGE.md", "--heading", "当前说明", "--cursor", cursor,
             "--max-output-bytes", "4096"], expected=[2])
        cursor_record = run(tool, project, reports, "read-cursor-next",
            [*read_common, "--file", "archive/LARGE.md", "--heading", "大文档", "--cursor", cursor,
             "--max-output-bytes", "4096"])
        records.append({"phase": "read", "outline_keys": list(outline)[:12],
                        "current_bytes": len(read_current_record["stdout"].encode("utf-8")),
                        "historical_bytes": len(read_history_record["stdout"].encode("utf-8")),
                        "cursor_bytes": len(cursor_record["stdout"].encode("utf-8")),
                        "changed_heading_blocked_expected": changed_selector["passed"]})

        current_path = project / "README.md"
        initial_sha = sha256(current_path)
        (reports / "fixture-original-readme.bin").write_bytes(current_path.read_bytes())
        request = {
            "version": 2,
            "operations": [
                {"kind": "snapshot", "path": "README.md", "destination": "archive/README.before.md",
                 "expected_sha256": initial_sha,
                 "origin": {"reference_base": ".", "classification_basis": "isolated test fixture historical snapshot"}},
                {"type": "replace", "path": "README.md", "old": "当前说明：初始摘要。",
                 "new": "当前说明：治理后摘要。"},
            ],
            "guards": [
                {"kind": "heading", "path": "README.md", "value": "# 历史"},
                {"kind": "snippet", "path": "README.md", "value": "必须保留的决定。"},
            ],
        }
        request_path = reports / "request-v2.json"
        write_json(request_path, request)
        plan_path, diff_path = reports / "plan-v2.json", reports / "bounded.diff"
        preview_record = run(tool, project, reports, "preview-v2",
            ["preview", "--project", str(project), "--request", str(request_path),
             "--plan", str(plan_path), "--diff-output", str(diff_path), "--max-output-bytes", "512"])
        if not plan_path.is_file() or not diff_path.is_file():
            raise ValidationError("v2 preview did not create plan and full diff")
        if len(preview_record["stdout"].encode("utf-8")) > 512:
            raise ValidationError("preview stdout exceeded requested byte bound")
        overlay = reports / "compare-overlay.json"
        run(tool, project, reports, "compare-overlay",
            ["compare", *common, "--historical-roots", "history",
             "--before", str(reports / "check-before.json"),
             "--plan", str(plan_path), "--max-output-bytes", "4096", "--output", str(overlay)])
        overlay_result = json.loads(overlay.read_text(encoding="utf-8"))
        if not overlay_result.get("compatible") or not overlay_result.get("complete"):
            raise ValidationError("compare overlay was incomplete: {}".format(overlay_result.get("reasons")))
        records.append({"phase": "preview", "stdout_bytes": len(preview_record["stdout"].encode("utf-8")),
                        "diff_bytes": diff_path.stat().st_size, "snapshot_source_sha256": initial_sha})

        operations_dir = reports / "operations"
        run(tool, project, reports, "apply-v2",
            ["apply", "--project", str(project), "--plan", str(plan_path),
             "--operations-dir", str(operations_dir)])
        journal_files = sorted(operations_dir.glob("*.json"))
        if len(journal_files) != 1:
            raise ValidationError("expected one v2 recovery journal, got {}".format(len(journal_files)))
        journal = journal_files[0]
        verify = run(tool, project, reports, "verify-v2",
            ["verify", "--project", str(project), "--journal", str(journal)])
        verify_result = parse_json_output(verify)
        if verify_result.get("status") != "Passed" or verify_result.get("journal_consistency") != "Passed":
            raise ValidationError("v2 verify did not report a consistent applied journal: {}".format(verify_result))
        after = cli_json(tool, project, reports, "check-after",
            ["check", *common, "--historical-roots", "history", "--checks", "documents,links", "--format", "json"],
            reports / "check-after.json")
        before_after = reports / "compare-after.json"
        run(tool, project, reports, "compare-after",
            ["compare", *common, "--historical-roots", "history",
             "--before", str(reports / "check-before.json"),
             "--after", str(reports / "check-after.json"), "--max-output-bytes", "4096",
             "--output", str(before_after)])
        after_comparison = json.loads(before_after.read_text(encoding="utf-8"))
        if not after_comparison.get("compatible") or not after_comparison.get("complete"):
            raise ValidationError("before/after comparison was incomplete: {}".format(after_comparison.get("reasons")))
        snapshot_path = project / "archive/README.before.md"
        if snapshot_path.read_bytes() != (reports / "fixture-original-readme.bin").read_bytes():
            raise ValidationError("snapshot bytes differ from fixture original")
        records.append({"phase": "apply", "verify_passed": verify["passed"],
                        "after_file_count": after.get("file_count"),
                        "snapshot_exists": snapshot_path.is_file(), "snapshot_sha256": sha256(snapshot_path)})
        before_metrics = legacy_baseline.get("metrics", {})
        scoped_metrics = before.get("metrics", {})
        summary_record = next((item for item in records if item.get("phase") == "summary"), {})
        records.append({"phase": "range-read-comparison",
                        "legacy_default": {"file_count": legacy_baseline.get("file_count"),
                            "inventory_read_bytes": before_metrics.get("inventory_read_bytes"),
                            "worker_read_bytes": before_metrics.get("worker_read_bytes"),
                            "model_calls": legacy_baseline.get("model_calls")},
                        "scoped_five_plus_history_metadata": {"file_count": before.get("file_count"),
                            "historical_file_count": before.get("historical_metadata", {}).get("file_count"),
                            "historical_body_bytes_read": before.get("historical_metadata", {}).get("body_bytes_read"),
                            "inventory_read_bytes": scoped_metrics.get("inventory_read_bytes"),
                            "worker_read_bytes": scoped_metrics.get("worker_read_bytes"),
                            "model_calls": before.get("model_calls")},
                        "scoped_summary_stdout_bytes": summary_record.get("stdout_bytes"),
                        "functions_are_equivalent": False})
        if (legacy_baseline.get("file_count") != 1205 or before.get("file_count") != 5
                or legacy_baseline.get("model_calls") != 0 or before.get("model_calls") != 0):
            raise ValidationError("range comparison did not bind the intended files or stay model-free")
        records.append({"phase": "compare-status", "overlay": overlay_result.get("status"),
                        "overlay_complete": overlay_result.get("complete"),
                        "after": after_comparison.get("status"),
                        "after_complete": after_comparison.get("complete"),
                        "no_new_issues": after_comparison.get("no_new_issues")})
        if sha256(project_config) != project_config_sha:
            raise ValidationError("fixture project config changed during checks")
        records.append({"phase": "fixture-config-integrity", "before_sha256": project_config_sha,
                        "after_sha256": sha256(project_config), "unchanged": True})

        run(tool, project, reports, "recover-v2",
            ["recover", "--project", str(project), "--journal", str(journal)])
        recover_verify = run(tool, project, reports, "verify-recovered-v2",
            ["verify", "--project", str(project), "--journal", str(journal)])
        recover_verify_result = parse_json_output(recover_verify)
        if recover_verify_result.get("status") != "Passed" or recover_verify_result.get("journal_consistency") != "Passed":
            raise ValidationError("recovered v2 verify did not report consistency: {}".format(recover_verify_result))
        if sha256(current_path) != initial_sha:
            raise ValidationError("recover did not restore source fingerprint")
        records.append({"phase": "recover", "verify_passed": recover_verify["passed"],
                        "restored_sha256": sha256(current_path), "initial_sha256": initial_sha})

        # old_locator expands the exact original byte range into the plan, never into CLI stdout.
        locator_path = project / "locator.md"
        locator_source = "# Locator\n\npassword=fixture-only-not-real\n"
        locator_path.write_text(locator_source, encoding="utf-8")
        secret = "password=fixture-only-not-real"
        locator_raw = locator_path.read_bytes()
        start_byte = locator_raw.index(secret.encode("utf-8"))
        locator_request = reports / "request-locator.json"
        write_json(locator_request, {"version": 2, "operations": [{"type": "replace", "path": "locator.md",
            "new": "credential removed", "old_locator": {"sha256": sha256(locator_path),
                "start_byte": start_byte, "end_byte": start_byte + len(secret.encode("utf-8"))}}]})
        locator_plan = reports / "plan-locator.json"
        locator_preview = run(tool, project, reports, "preview-old-locator",
            ["preview", "--project", str(project), "--request", str(locator_request),
             "--plan", str(locator_plan), "--max-output-bytes", "4096"])
        expanded_plan = json.loads(locator_plan.read_text(encoding="utf-8"))
        expanded_old = expanded_plan["operations"][0].get("old")
        if expanded_old != secret or secret in locator_preview["stdout"]:
            raise ValidationError("old_locator did not expand privately to exact source bytes")
        locator_ops = reports / "operations-locator"
        run(tool, project, reports, "apply-old-locator",
            ["apply", "--project", str(project), "--plan", str(locator_plan), "--operations-dir", str(locator_ops)])
        locator_journal = sorted(locator_ops.glob("*.json"))[0]
        run(tool, project, reports, "verify-old-locator",
            ["verify", "--project", str(project), "--journal", str(locator_journal)])
        run(tool, project, reports, "recover-old-locator",
            ["recover", "--project", str(project), "--journal", str(locator_journal)])
        if locator_path.read_bytes() != locator_raw:
            raise ValidationError("old_locator recovery did not restore original bytes")
        records.append({"phase": "old-locator", "source_sha256": sha256(locator_path),
                        "byte_range": [start_byte, start_byte + len(secret.encode("utf-8"))],
                        "plan_exact_old": expanded_old, "secret_in_stdout": secret in locator_preview["stdout"]})

        # A changed-after-apply file is reported as drift; recovery returns the known before state.
        drift_a, drift_b = project / "drift-a.md", project / "drift-b.md"
        drift_a.write_text("before-a\n", encoding="utf-8")
        drift_b.write_text("before-b\n", encoding="utf-8")
        drift_request = reports / "request-post-edit-drift.json"
        write_json(drift_request, {"version": 2, "operations": [
            {"type": "replace", "path": "drift-a.md", "old": "before-a", "new": "after-a"},
            {"type": "replace", "path": "drift-b.md", "old": "before-b", "new": "after-b"},
        ]})
        drift_plan = reports / "plan-post-edit-drift.json"
        run(tool, project, reports, "preview-post-edit-drift",
            ["preview", "--project", str(project), "--request", str(drift_request), "--plan", str(drift_plan)])
        drift_ops = reports / "operations-post-edit-drift"
        run(tool, project, reports, "apply-post-edit-drift",
            ["apply", "--project", str(project), "--plan", str(drift_plan), "--operations-dir", str(drift_ops)])
        drift_journal = sorted(drift_ops.glob("*.json"))[0]
        drift_a.write_text("before-a\n", encoding="utf-8")
        drift_verify = run(tool, project, reports, "verify-post-edit-drift",
            ["verify", "--project", str(project), "--journal", str(drift_journal)], expected=[1])
        drift_result = parse_json_output(drift_verify)
        if drift_result.get("status") != "Failed" or drift_result.get("journal_consistency") != "Failed":
            raise ValidationError("post-edit drift was not identified as inconsistent: {}".format(drift_result))
        run(tool, project, reports, "recover-post-edit-drift",
            ["recover", "--project", str(project), "--journal", str(drift_journal)])
        drift_recovered = run(tool, project, reports, "verify-recovered-post-edit-drift",
            ["verify", "--project", str(project), "--journal", str(drift_journal)])
        records.append({"phase": "post-edit-drift", "verify_status": drift_result.get("status"),
                        "journal_consistency": drift_result.get("journal_consistency"),
                        "recover_verify_passed": drift_recovered["passed"]})

        # Legacy v1 request -> preview/apply/verify/recover and old default check remain usable.
        (project / "legacy.md").write_text("# Legacy\n\nold phrase\n", encoding="utf-8")
        legacy_before = sha256(project / "legacy.md")
        legacy_request = reports / "request-v1.json"
        write_json(legacy_request, {"operations": [{"type": "replace", "path": "legacy.md",
                     "old": "old phrase", "new": "new phrase"}]})
        legacy_plan = reports / "plan-v1.json"
        run(tool, project, reports, "preview-v1",
            ["preview", "--project", str(project), "--request", str(legacy_request), "--plan", str(legacy_plan)])
        legacy_ops = reports / "operations-v1"
        run(tool, project, reports, "apply-v1",
            ["apply", "--project", str(project), "--plan", str(legacy_plan), "--operations-dir", str(legacy_ops)])
        legacy_journal = sorted(legacy_ops.glob("*.json"))[0]
        run(tool, project, reports, "verify-v1",
            ["verify", "--project", str(project), "--journal", str(legacy_journal)])
        run(tool, project, reports, "recover-v1",
            ["recover", "--project", str(project), "--journal", str(legacy_journal)])
        run(tool, project, reports, "verify-recovered-v1",
            ["verify", "--project", str(project), "--journal", str(legacy_journal)])
        if sha256(project / "legacy.md") != legacy_before:
            raise ValidationError("v1 recover did not restore source fingerprint")
        legacy_check = cli_json(tool, project, reports, "legacy-default-check",
            ["check", "--project", str(project), "--checks", "documents,links", "--format", "json"],
            reports / "legacy-default-check.json")
        records.append({"phase": "legacy-v1", "default_check_files": legacy_check.get("file_count"),
                        "restored_sha256": sha256(project / "legacy.md")})

        summary = {
            "status": "Passed",
            "tool": str(tool),
            "project_fixture": "temporary isolated project; removed after run unless --keep-project",
            "primary_source_count": 5,
            "history_metadata_files": 1200,
            "phases": records,
            "reports_directory": str(results / "run-results" / run_root.name),
        }
        persisted = results / "run-results" / run_root.name
        shutil.copytree(reports, persisted, dirs_exist_ok=True)
        write_json(results / "summary.json", summary)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        if args.keep_project:
            print("fixture_project=" + str(project))
        return 0
    except Exception as exc:
        failure = {"status": "Failed", "error": str(exc), "reports_directory": str(reports)}
        if reports.exists():
            persisted = results / "run-results" / run_root.name
            persisted.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(reports, persisted, dirs_exist_ok=True)
            failure["reports_directory"] = str(persisted)
        write_json(results / "summary.json", failure)
        print(json.dumps(failure, ensure_ascii=False, indent=2))
        return 1
    finally:
        if not args.keep_project:
            # The isolated project and its sibling profile/reports are owned by this run.
            shutil.rmtree(run_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
