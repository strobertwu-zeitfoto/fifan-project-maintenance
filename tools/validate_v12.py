#!/usr/bin/env python3
"""Isolated end-to-end fixture and driver for the 1.2 CLI acceptance matrix.

The fixture is synthetic and contains no project/game data. --prepare-only is
safe while the 1.2 CLI surface is being integrated; --run is filled only after
module owners confirm the exact public command contracts.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOOL = ROOT / "bin/fifan-maintain"
DEFAULT_WHEEL_11 = ROOT / "evidence/validation/v1.1/wheels/fifan_project_maintenance-1.1.0-py3-none-any.whl"
DEFAULT_WHEEL_12 = ROOT / "evidence/validation/v1.2/wheels/fifan_project_maintenance-1.2.0-py3-none-any.whl"
DEFAULT_RESULTS = ROOT / "evidence/validation/v1.2/forward"
OFFLINE_WHEEL_DIRS = [ROOT / "evidence/validation/wheels",
                      ROOT / "evidence/validation/v1.2/dependencies"]


class ValidationError(RuntimeError):
    pass


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _write(path: Path, content: str, *, crlf: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.replace("\n", "\r\n") if crlf else content
    path.write_bytes(data.encode("utf-8"))


def build_fixture(project: Path, history_files: int = 20005) -> Dict[str, Any]:
    """Build a deterministic, isolated synthetic project; never reads external roots."""
    if history_files < 0:
        raise ValueError("history_files must be nonnegative")
    if project.exists() and any(project.iterdir()):
        raise ValidationError("fixture project path must be empty: {}".format(project))
    project.mkdir(parents=True, exist_ok=True)
    for name in ("docs/current", "docs/archive", "archive", "history/deep/level2", "private", "sessions"):
        (project / name).mkdir(parents=True, exist_ok=True)

    source_paths = [
        "README.md", "PROJECT_MEMORY.md", "ENGINEERING_PLAN.md", "DECISIONS.md",
        "docs/current/policy.md", "docs/current/budget.md", "docs/current/history.md",
        "docs/current/links.md", "docs/current/table.md", "docs/current/operations.md",
        "docs/current/assets.md", "docs/current/ux.md", "docs/current/appendix.md",
    ]
    active_readme = (
        "# Synthetic maintenance fixture\n\n"
        "入口见[唯一计划](ENGINEERING_PLAN.md)，决定见[决定记录](DECISIONS.md)。\n\n"
        "当前摘要：" + ("细节已收录在本次授权的正文段落中；" * 30) + "\n\n"
        "## 历史快照\n\n旧摘要必须按原样保留。\n"
    )
    _write(project / "README.md", active_readme)
    _write(project / "PROJECT_MEMORY.md",
           "# Project navigation\n\nSee [the plan](ENGINEERING_PLAN.md) and [decisions](DECISIONS.md).\n")
    _write(project / "ENGINEERING_PLAN.md",
           "# Unique plan\n\n- TODO: touch experience remains unaccepted.\n")
    _write(project / "DECISIONS.md",
           "# Decisions\n\nApproved: use one shared plate; integration remains pending.\n")
    _write(project / "docs/current/budget.md",
           "# Budget notes\n\nThe source grouping cross-links [appendix](appendix.md#shared-rule).\n")
    _write(project / "docs/current/history.md",
           "# History rules\n\nHistorical contents remain immutable unless separately authorized.\n")
    _write(project / "docs/current/links.md",
           "# Link coverage\n\n"
           "Local [plan](../../ENGINEERING_PLAN.md#unique-plan).\n"
           "Broken [target](missing-target.md#not-there).\n"
           "External [reference](https://example.invalid/reference).\n")
    _write(project / "docs/current/unknown-links.md",
           "# Unknown syntax fixture\n\nUnknown syntax: [[wiki-style]].\n")
    table_text = (
        "# Multi-patch source\n\n"
        "## shared-rule\n\n"
        "摘要甲：旧值一。\n\n"
        "摘要乙：旧值二。\n\n"
        "## Data table\n\n"
        "| Name | Value |\n"
        "| --- | --- |\n"
        "| A | Original |\n\n"
        "api_token=fixture-secret-not-real\n"
    )
    _write(project / "docs/current/table.md", table_text, crlf=True)
    _write(project / "docs/current/operations.md",
           "# Operations\n\nUse [policy](policy.md#policy-01).\n")
    _write(project / "docs/current/assets.md", "# Assets\n\nSynthetic asset inventory.\n")
    _write(project / "docs/current/ux.md", "# UX\n\nTouch acceptance is pending.\n")
    _write(project / "docs/current/appendix.md",
           "# Appendix\n\n## shared-rule\n\nCross-group anchor target.\n\n"
           "## api_token=fixture-title-secret\n\nSynthetic secret-title content.\n")

    # 27 section pairs: exactly 23 byte-identical, four intentionally different.
    current_parts: List[str] = ["# Current policy\n"]
    archive_parts: List[str] = ["# Archived policy\n"]
    for idx in range(1, 28):
        heading = "## Policy {:02d}".format(idx)
        original = "Requirement {:02d}: preserve this exact sentence.\n".format(idx)
        current_parts.extend(["\n", heading, "\n\n", original])
        archived = original if idx <= 23 else "Historical requirement {:02d}: wording differs.\n".format(idx)
        archive_parts.extend(["\n", heading, "\n\n", archived])
    current_parts.extend(["\n## Repeated heading\n\nFirst occurrence.\n",
                          "\n## Repeated heading\n\nSecond occurrence.\n"])
    _write(project / "docs/current/policy.md", "".join(current_parts))
    _write(project / "docs/archive/policy.md", "".join(archive_parts))
    _write(project / "docs/archive/table.md", table_text, crlf=True)
    _write(project / "docs/archive/table-lf.md", table_text)

    restricted = "# Restricted\n\n## private-rule\n\nfixture-private-body\n"
    _write(project / "private/restricted.md", restricted)
    for idx in range(history_files):
        _write(project / "history/REPORT_{:05d}.md".format(idx), "metadata fixture\n")
    for idx in range(5):
        _write(project / "history/deep/level2/REPORT_DEEP_{:02d}.md".format(idx), "deep metadata\n")

    # Real 1.1 request inputs are generated here and applied later using the actual 1.1 wheel.
    _write(project / "legacy-v1.md", "# Legacy v1\n\nold-1.1-v1-value\n")
    config = {
        "schema_version": 1,
        "include": ["*.md", "docs/**", "history/**", "private/**", "sessions/**"],
        "exclude": [],
        "protected": [".git/**", ".venv/**", ".venv39/**", "private/**"],
    }
    write_json(project / ".fifan-maintenance.json", config)
    return {
        "project": str(project.resolve()),
        "source_paths": source_paths,
        "source_count": len(source_paths),
        "profile_groups": {"parent": source_paths, "child_11": source_paths[:11], "child_2": source_paths[11:]},
        "history_files_flat": history_files,
        "history_files_nested": 5,
        "coverage_exact_sections": 23,
        "coverage_different_sections": 4,
        "duplicate_heading": "Repeated heading",
        "crlf_patch_file": "docs/current/table.md",
        "protected_path": "private/restricted.md",
        "config_sha256": sha256_file(project / ".fifan-maintenance.json"),
        "readme_sha256": sha256_file(project / "README.md"),
        "patch_source_sha256": sha256_file(project / "docs/current/table.md"),
    }


def write_prepared_inputs(project: Path, result_dir: Path,
                          manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Write external requests from exact fixture bytes; no CLI or project writes."""
    legacy_v1 = {"operations": [{"type": "replace", "path": "legacy-v1.md",
                  "old": "old-1.1-v1-value", "new": "step-1-value"}]}
    write_json(result_dir / "legacy-v1-request.json", legacy_v1)
    # v2 request is written only after the 1.1 wheel has applied v1 to the same file.

    policy_sha = sha256_file(project / "docs/current/policy.md")
    archived_policy_sha = sha256_file(project / "docs/archive/policy.md")
    coverage_items: List[Dict[str, Any]] = []
    for idx in range(1, 28):
        heading = "Policy {:02d}".format(idx)
        coverage_items.append({
            "source": {"path": "docs/current/policy.md", "selector": {"kind": "heading", "value": heading},
                       "expected_sha256": policy_sha},
            "archive": {"path": "docs/archive/policy.md", "selector": {"kind": "heading", "value": heading},
                        "expected_sha256": archived_policy_sha, "reference_base": "docs/archive",
                        "classification_basis": "explicit synthetic current-to-history comparison fixture"},
        })
    coverage_items.extend([
        {"source": {"path": "docs/current/policy.md", "selector": {"kind": "heading", "value": "Repeated heading"},
                     "expected_sha256": policy_sha},
         "archive": {"path": "docs/archive/policy.md", "selector": {"kind": "heading", "value": "Repeated heading"},
                     "expected_sha256": archived_policy_sha, "reference_base": "docs/archive",
                     "classification_basis": "duplicate heading ambiguity case"}},
        {"source": {"path": "docs/current/policy.md", "selector": {"kind": "snippet", "value": "Requirement 01: preserve this exact sentence."},
                     "expected_sha256": policy_sha},
         "archive": {"path": "docs/archive/missing.md", "selector": {"kind": "snippet", "value": "Requirement 01: preserve this exact sentence."},
                     "reference_base": "docs/archive", "classification_basis": "missing archive case"}},
    ])
    table_sha = sha256_file(project / "docs/current/table.md")
    archive_table_sha = sha256_file(project / "docs/archive/table.md")
    coverage_items.extend([
        {"source": {"path": "docs/current/table.md", "selector": {"kind": "table", "index": 1},
                     "expected_sha256": table_sha},
         "archive": {"path": "docs/archive/table.md", "selector": {"kind": "table", "index": 1},
                     "expected_sha256": archive_table_sha, "reference_base": "docs/archive",
                     "classification_basis": "byte-identical synthetic table case"}},
        {"source": {"path": "docs/current/table.md", "selector": {"kind": "bytes", "start_byte": 0, "end_byte": 32},
                     "expected_sha256": table_sha},
         "archive": {"path": "docs/archive/table.md", "selector": {"kind": "bytes", "start_byte": 0, "end_byte": 32},
                     "expected_sha256": archive_table_sha, "reference_base": "docs/archive",
                     "classification_basis": "byte-range UTF-8 boundary case"}},
        {"source": {"path": "docs/current/table.md", "selector": {"kind": "table", "index": 1},
                     "expected_sha256": table_sha},
         "archive": {"path": "docs/archive/table-lf.md", "selector": {"kind": "table", "index": 1},
                     "expected_sha256": sha256_file(project / "docs/archive/table-lf.md"),
                     "reference_base": "docs/archive", "classification_basis": "CRLF/LF difference case"}},
        {"source": {"path": "private/restricted.md", "selector": {"kind": "heading", "value": "private-rule"},
                     "expected_sha256": sha256_file(project / "private/restricted.md")},
         "archive": {"path": "docs/archive/policy.md", "selector": {"kind": "snippet", "value": "Requirement 01: preserve this exact sentence."},
                     "expected_sha256": archived_policy_sha, "reference_base": "docs/archive",
                     "classification_basis": "protected source must remain unreadable"}},
    ])
    coverage_request = {"version": 1, "allowed_external_roots": [], "items": coverage_items}
    write_json(result_dir / "archive-coverage-request.json", coverage_request)

    patch_path = project / "docs/current/table.md"
    patch_raw = patch_path.read_bytes()
    secret = "api_token=fixture-secret-not-real".encode("utf-8")
    token_start = patch_raw.index(secret)
    readme_sha = sha256_file(project / "README.md")
    summary_detail = "细节已收录在本次授权的正文段落中；" * 30
    v3_request = {
        "version": 3,
        "operations": [
            {"kind": "snapshot", "path": "README.md", "destination": "docs/archive/README.before.md",
             "expected_sha256": readme_sha,
             "origin": {"reference_base": ".", "classification_basis": "body-slim fixture preserves source bytes"}},
            {"type": "replace", "path": "README.md", "old": summary_detail,
             "new": "细节见唯一计划与相关章节索引。"},
            {"type": "replace_many", "path": "docs/current/table.md", "expected_sha256": table_sha,
             "patches": [
                 {"old": "摘要甲：旧值一。", "new": "摘要甲：新值一。"},
                 {"old": "摘要乙：旧值二。", "new": "摘要乙：新值二。"},
                 {"old_locator": {"sha256": table_sha, "start_byte": token_start,
                                  "end_byte": token_start + len(secret)},
                  "new": "api_token=[REDACTED]"},
             ]},
        ],
        "guards": [
            {"kind": "heading", "path": "README.md", "value": "## 历史快照"},
            {"kind": "snippet", "path": "README.md", "value": "旧摘要必须按原样保留。"},
            {"kind": "table", "path": "docs/current/table.md",
             "value": "| Name | Value |\r\n| --- | --- |\r\n| A | Original |\r\n"},
        ],
    }
    write_json(result_dir / "replace-many-v3-request.json", v3_request)
    manifest["prepared_requests"] = {
        "legacy_v1": "legacy-v1-request.json", "legacy_v2": "generated after v1 apply",
        "archive_coverage_items": len(coverage_items), "replace_many_v3": "replace-many-v3-request.json",
        "v3_source_sha256": table_sha, "v3_locator_bytes": [token_start, token_start + len(secret)],
    }
    return manifest


def write_profile2_parent(result_dir: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Create the authorized profile-2 parent; child narrowing is done by public CLI."""
    sources = manifest["source_paths"]
    current_view = {"name": "current", "path": "README.md", "start_line": 1,
                    "end_line": 5, "kind": "current"}
    historical_view = {"name": "historical", "path": "README.md", "start_line": 7,
                       "end_line": 8, "kind": "historical"}
    profile = {
        "schema_version": 2,
        "sources": sources,
        "reference_bodies": ["docs/current/appendix.md", "docs/archive/*.md"],
        "historical_roots": ["history"],
        "checks": ["documents", "links"],
        "views": [current_view, historical_view],
        "budgets": {"max_files": 100, "max_file_bytes": 4194304,
                    "max_total_bytes": 16777216, "max_seconds": 60,
                    "max_findings": 500},
        "goal": {"kind": "body-slim", "each_file": False,
                 "minimum_reduction_bytes": 1, "exceptions": []},
        "history_budget": {"max_files": 20000, "max_seconds": 60, "max_depth": 1,
                           "per_root_max_files": {"history": 20000},
                           "max_output_entries": 20},
        "measurement": {"version": 1, "active": sources,
                        "views": [current_view], "reused_archives": [],
                        "new_archives": ["docs/archive/README.before.md"],
                        "external_roots": [], "external_records": [],
                        "allow_absent": [{"role": "new_archives",
                                          "path": "docs/archive/README.before.md"}]},
    }
    path = result_dir / "task-profile2-parent.json"
    write_json(path, profile)
    minimal = dict(profile)
    minimal["sources"] = sources[:3]
    minimal["views"] = [current_view, historical_view]
    minimal["measurement"] = dict(profile["measurement"], active=sources[:3])
    write_json(result_dir / "task-profile2-three-key.json", minimal)
    manifest["profile2_parent"] = {"path": path.name, "source_count": 13,
                                    "child_groups": [11, 2],
                                    "three_key_profile": "task-profile2-three-key.json",
                                    "history_budget_max_files": 20000,
                                    "history_files_requested": manifest["history_files_flat"]}
    return manifest


def write_legacy_v2_after_v1(project: Path, result_dir: Path) -> Path:
    """Bind the real v1.1 v2 request to the post-v1 file bytes and serialize externally."""
    path = project / "legacy-v1.md"
    if "step-1-value" not in path.read_text(encoding="utf-8"):
        raise ValidationError("v1.1 wheel has not applied its expected v1 record")
    request = {"version": 2, "operations": [
        {"kind": "snapshot", "path": "legacy-v1.md", "destination": "archive/legacy-v1.before-v2.md",
         "expected_sha256": sha256_file(path),
         "origin": {"reference_base": ".", "classification_basis": "same-file 1.1 v1 then v2 journal chain"}},
        {"type": "replace", "path": "legacy-v1.md", "old": "step-1-value", "new": "step-2-value"},
    ], "guards": [{"kind": "heading", "path": "legacy-v1.md", "value": "# Legacy v1",
                   "exceptions": [{"old": "step-1-value", "new": "step-2-value"}]}]}
    output = result_dir / "legacy-v2-request.json"
    write_json(output, request)
    return output


def run_command(tool: Path, args: List[str], result_dir: Path, name: str,
                expected_codes: Optional[List[int]] = None,
                env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Capture exact CLI argv/stdout/stderr/exit; intended for final stable CLI run."""
    expected_codes = expected_codes or [0]
    command = [str(tool), *args]
    process_env = os.environ.copy()
    process_env.update(env or {})
    process_env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(command, cwd=str(ROOT), env=process_env,
                               capture_output=True, text=True)
    record = {"name": name, "argv": command, "returncode": completed.returncode,
              "stdout": completed.stdout, "stderr": completed.stderr,
              "expected_returncodes": expected_codes,
              "passed": completed.returncode in expected_codes}
    write_json(result_dir / (name + ".command.json"), record)
    if not record["passed"]:
        raise ValidationError("{} returned {}; expected {}: {}".format(
            name, completed.returncode, expected_codes, completed.stderr[-1600:]))
    return record


def run_logged(argv: List[str], log_dir: Path, name: str,
               env: Optional[Dict[str, str]] = None,
               expected_codes: Optional[List[int]] = None) -> Dict[str, Any]:
    """Capture setup/CLI commands without shell interpolation or network fallback."""
    expected_codes = expected_codes or [0]
    process_env = os.environ.copy()
    process_env.update(env or {})
    process_env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(argv, cwd=str(ROOT), env=process_env,
                               capture_output=True, text=True)
    record = {"name": name, "argv": argv, "returncode": completed.returncode,
              "stdout": completed.stdout, "stderr": completed.stderr,
              "expected_returncodes": expected_codes,
              "passed": completed.returncode in expected_codes}
    write_json(log_dir / (name + ".command.json"), record)
    if not record["passed"]:
        raise ValidationError("{} returned {}; expected {}: {}".format(
            name, completed.returncode, expected_codes, completed.stderr[-2000:]))
    return record


def create_fresh_compat_venv(python: Path, run_root: Path, old_wheel: Path,
                             result_dir: Path) -> Dict[str, Path]:
    """Install the real 1.1 wheel using only approved offline wheels."""
    python = python.resolve()
    old_wheel = old_wheel.resolve()
    if not python.is_file() or not old_wheel.is_file():
        raise ValidationError("required Python interpreter or 1.1 wheel is missing")
    venv_dir = run_root / "compat-venv"
    run_logged([str(python), "-m", "venv", str(venv_dir)], result_dir, "create-compat-venv")
    wheel_python = venv_dir / "bin/python"
    pip_args = [str(wheel_python), "-m", "pip", "install", "--no-index", "--no-cache-dir"]
    for wheel_dir in OFFLINE_WHEEL_DIRS:
        if wheel_dir.is_dir():
            pip_args.extend(["--find-links", str(wheel_dir)])
    pip_args.append(str(old_wheel))
    run_logged(pip_args, result_dir, "install-v11-wheel",
               {"PIP_NO_INDEX": "1", "PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    tool = venv_dir / "bin/fifan-maintain"
    version = run_logged([str(tool), "--version"], result_dir, "v11-wheel-version")
    if version["stdout"].strip() != "1.1.0":
        raise ValidationError("fresh wheel environment did not run the actual 1.1.0 package")
    return {"venv": venv_dir, "python": wheel_python, "tool": tool}


def upgrade_compat_venv_to_v12(venv_info: Dict[str, Path], new_wheel: Path,
                              result_dir: Path) -> Path:
    """Upgrade the same isolated venv offline after 1.1 journals are created."""
    new_wheel = new_wheel.resolve()
    if not new_wheel.is_file():
        raise ValidationError("1.2 wheel is unavailable: {}".format(new_wheel))
    pip_args = [str(venv_info["python"]), "-m", "pip", "install", "--no-index", "--no-cache-dir", "--upgrade"]
    for wheel_dir in OFFLINE_WHEEL_DIRS:
        if wheel_dir.is_dir():
            pip_args.extend(["--find-links", str(wheel_dir)])
    pip_args.append(str(new_wheel))
    run_logged(pip_args, result_dir, "upgrade-v12-wheel",
               {"PIP_NO_INDEX": "1", "PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    version = run_logged([str(venv_info["tool"]), "--version"], result_dir, "v12-wheel-version")
    if version["stdout"].strip() != "1.2.0":
        raise ValidationError("upgraded compatibility environment did not run version 1.2.0")
    return venv_info["tool"]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _compact_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"name": step["name"], "returncode": step["returncode"],
             "passed": step["passed"]} for step in steps]


def execute_source_workflow(tool: Path, project: Path, result_dir: Path,
                            manifest: Dict[str, Any],
                            stop_after_preview: bool = False) -> Dict[str, Any]:
    """Exercise the 1.2 public CLI contract on one synthetic project."""
    common = ["--project", str(project)]
    parent = result_dir / "task-profile2-parent.json"
    three_key = result_dir / "task-profile2-three-key.json"
    source_paths = manifest["source_paths"]
    empty_records = result_dir / "records-before"
    empty_records.mkdir(exist_ok=True)
    history_before = run_command(tool, ["history", "--project", str(project),
        "--records-dir", str(empty_records), "--max-records", "30",
        "--max-record-bytes", "67108864", "--output", str(result_dir / "history-before.json"),
        "--max-output-bytes", "8192"], result_dir, "history-before")
    history_before_json = _load_json(result_dir / "history-before.json")
    _assert(history_before_json.get("status") == "Passed" and not history_before_json.get("records") and
            history_before_json.get("coverage", {}).get("project_document_coverage") == "Unknown",
            "empty explicit history directory was mistaken for proof of no project governance")
    child_profile = result_dir / "task-profile2-child.json"
    profile_derive = run_command(tool, ["profile", "derive", *common,
        "--from", str(parent), "--sources", *source_paths[:11], "--checks", "documents,links",
        "--output", str(child_profile)], result_dir, "profile-derive")
    derived = _load_json(child_profile)
    _assert(set(derived.get("sources", [])) == set(source_paths[:11]),
            "profile derive did not preserve the requested 11-source child scope")
    child_two_path = result_dir / "task-profile2-child-2.json"
    child_two_run = run_command(tool, ["profile", "derive", *common,
        "--from", str(parent), "--sources", *source_paths[11:], "--checks", "documents,links",
        "--output", str(child_two_path)], result_dir, "profile-derive-two-source-child")
    child_two = _load_json(child_two_path)
    first_group, second_group = set(derived.get("sources", [])), set(child_two.get("sources", []))
    _assert(second_group == set(source_paths[11:]) and not (first_group & second_group) and
            first_group | second_group == set(source_paths),
            "derived 11+2 child profiles do not partition the exact 13-source parent")
    second_references = child_two.get("reference_bodies", [])
    _assert(all(any(fnmatch.fnmatchcase(path, pattern) for pattern in second_references)
                for path in source_paths[:11]),
            "2-source child did not preserve parent-authorized reference bodies from its sibling group")

    preflight = run_command(tool, ["check", *common, "--task-profile", str(three_key),
        "--preflight", "--format", "json", "--output", str(result_dir / "preflight.json")],
        result_dir, "preflight")
    preflight_json = _load_json(result_dir / "preflight.json")
    _assert(preflight_json.get("source_count") == 3 or
            len(preflight_json.get("sources", [])) == 3,
            "preflight report did not bind the three-source profile")
    unknown_report = result_dir / "unknown-syntax-check.json"
    unknown_check = run_command(tool, ["check", *common, "--files", "docs/current/unknown-links.md",
        "--checks", "links", "--format", "json", "--output", str(unknown_report)],
        result_dir, "unknown-syntax-check")
    unknown_json = _load_json(unknown_report)
    _assert("UNSUPPORTED_SYNTAX" in unknown_json.get("coverage_domains", {})
            .get("local_targets", {}).get("unknown_reasons", []),
            "unknown link syntax did not preserve a local-target coverage gap")

    baseline_report = result_dir / "baseline-report.json"
    baseline = run_command(tool, ["check", *common, "--task-profile", str(parent),
        "--format", "json", "--output", str(baseline_report)], result_dir, "baseline-check",
        expected_codes=[1])
    baseline_json = _load_json(baseline_report)
    _assert(baseline_json.get("tool_version", "").startswith("1.2"),
            "baseline report is not bound to the 1.2 candidate")
    _assert(baseline_json.get("file_count") == 13,
            "parent profile check did not cover its complete 13-source scope")
    _assert(baseline_json.get("model_calls") == 0,
            "offline CLI report unexpectedly records model calls")
    _assert(baseline_json.get("has_failures") is True and
            any(item.get("check") == "links" and item.get("code") == "missing-target"
                and item.get("status") == "Failed" for item in baseline_json.get("findings", [])),
            "expected missing-target finding was not retained in the baseline report")
    history_roots = baseline_json.get("historical_metadata", {}).get("roots", [])
    _assert(history_roots and history_roots[0].get("complete") is False and
            "DEPTH_LIMIT" in history_roots[0].get("reasons", []),
            "history metadata did not retain the depth-pruned lower-bound result")
    if manifest["history_files_flat"] + 2 >= 20000:
        _assert(history_roots[0].get("entry_count") == 20000 and
                "FILE_BUDGET" in history_roots[0].get("reasons", []),
                "history metadata did not retain the bounded 20,000-entry lower-bound result")
    else:
        _assert(history_roots[0].get("entry_count") == manifest["history_files_flat"] + 2,
                "small history fixture did not count observed files and directory entries")
    _assert(baseline_json.get("metrics", {}).get("reference_body_bytes") == 0,
            "history/reference fixture bodies were unexpectedly read during the check")
    summary = run_command(tool, ["check", *common, "--task-profile", str(three_key),
        "--format", "summary", "--max-output-bytes", "8192"], result_dir, "summary")
    report_input = run_command(tool, ["report", *common, "--input", str(baseline_report),
        "--max-output-bytes", "8192"], result_dir, "report-input")

    # I5: bounded outline, filtered/deep outline, section-id, lines, and selector-bound cursor.
    outline_path = result_dir / "outline.json"
    outline = run_command(tool, ["read", *common, "--task-profile", str(parent),
        "--file", "docs/current/policy.md", "--outline", "--max-depth", "2",
        "--heading-filter", "Policy", "--max-output-bytes", "1024"], result_dir, "read-outline")
    outline_json = json.loads(outline["stdout"])
    headings = outline_json.get("headings", outline_json.get("sections", []))
    _assert(headings, "filtered outline returned no policy headings")
    section_id = headings[0].get("section_id")
    _assert(section_id, "outline omitted source-bound section_id")
    _assert(outline_json.get("complete") is False and outline_json.get("next_cursor"),
            "bounded outline did not preserve an explicit continuation cursor")
    (result_dir / "read-outline.json").write_text(outline["stdout"], encoding="utf-8")
    section = run_command(tool, ["read", *common, "--task-profile", str(parent),
        "--file", "docs/current/policy.md", "--section-id", str(section_id),
        "--max-output-bytes", "8192"], result_dir, "read-section")
    section_json = json.loads(section["stdout"])
    _assert(section_json.get("complete") is True, "section-id read did not complete")
    line_read = run_command(tool, ["read", *common, "--task-profile", str(parent),
        "--file", "docs/current/table.md", "--lines", "1:5",
        "--max-output-bytes", "8192"], result_dir, "read-lines")
    _assert(isinstance(json.loads(line_read["stdout"]).get("content"), str),
            "line range response lacks its selected source text")
    cursor = outline_json.get("next_cursor")
    if cursor:
        changed_selector = run_command(tool, ["read", *common, "--task-profile", str(parent),
            "--file", "docs/current/policy.md", "--cursor", cursor,
            "--max-depth", "3", "--heading-filter", "Policy",
            "--max-output-bytes", "8192"], result_dir, "cursor-changed-selector",
            expected_codes=[2])
        _assert(any(code in (changed_selector["stdout"] + changed_selector["stderr"]).upper()
                    for code in ("BINDING", "SELECTOR_CONFLICT")),
                "changed cursor selector was rejected without a binding diagnostic")

    coverage_path = result_dir / "archive-coverage.json"
    coverage = run_command(tool, ["archive-coverage", *common,
        "--request", str(result_dir / "archive-coverage-request.json"),
        "--output", str(coverage_path), "--max-output-bytes", "32768"],
        result_dir, "archive-coverage")
    coverage_json = _load_json(coverage_path)
    outcomes = [item.get("result") for item in coverage_json.get("results", [])]
    _assert(outcomes.count("Exact") == 25, "archive coverage Exact count differs from fixture")
    _assert(outcomes.count("Different") == 5, "archive coverage Different count differs from fixture")
    _assert(outcomes.count("Ambiguous") == 1, "duplicate heading was not Ambiguous")
    _assert(outcomes.count("Missing") == 1, "missing archive was not Missing")
    _assert(outcomes.count("Unknown") == 1 and coverage_json.get("proof") is None,
            "protected source case or mixed-proof boundary differs from fixture")
    _assert(coverage_json.get("status") == "Unknown" and coverage_json.get("complete") is False,
            "mixed archive coverage did not retain its incomplete overall state")
    raw_coverage_request = _load_json(result_dir / "archive-coverage-request.json")
    proof_request = {"version": 1, "allowed_external_roots": [],
                     "items": [raw_coverage_request["items"][29]]}
    proof_request_path = result_dir / "archive-proof-request.json"
    write_json(proof_request_path, proof_request)
    proof_run = run_command(tool, ["archive-coverage", *common,
        "--request", str(proof_request_path), "--output", str(result_dir / "archive-proof.json"),
        "--max-output-bytes", "32768"], result_dir, "archive-proof")
    proof_json = _load_json(result_dir / "archive-proof.json")
    proof = proof_json.get("proof")
    _assert(proof_json.get("status") == "Passed" and proof is not None,
            "all-Exact in-project archive coverage did not produce a proof")
    request = _load_json(result_dir / "replace-many-v3-request.json")
    request["archive_proofs"] = [proof]
    compiled_request = result_dir / "replace-many-v3-with-proofs.json"
    write_json(compiled_request, request)

    child_profile_json = _load_json(child_profile)
    measure_request = dict(child_profile_json["measurement"])
    measure_request["allow_absent"] = [{"role": "new_archives",
                                         "path": "docs/archive/README.before.md"}]
    measure_input = result_dir / "measure-request.json"
    write_json(measure_input, measure_request)
    measure = run_command(tool, ["report", *common, "--measure-request", str(measure_input),
        "--output", str(result_dir / "measure.json"), "--max-output-bytes", "8192"],
        result_dir, "report-measure")
    measure_json = _load_json(result_dir / "measure.json")
    _assert(measure_json.get("contract") == "goals-v1" and
            "active" in measure_json.get("domains", {}),
            "measure report omitted goals-v1 domains")

    plan_path = result_dir / "v3-plan.json"
    diff_path = result_dir / "v3-preview.diff"
    receipt_path = result_dir / "v3-receipt.json"
    change_baseline = run_command(tool, ["check", *common, "--task-profile", str(child_profile),
        "--format", "json", "--output", str(result_dir / "change-before.json")],
        result_dir, "change-before", expected_codes=[1])
    preview = run_command(tool, ["preview", *common, "--request", str(compiled_request),
        "--plan", str(plan_path), "--diff-output", str(diff_path),
        "--task-profile", str(child_profile), "--receipt", str(receipt_path),
        "--max-output-bytes", "8192"], result_dir, "preview-v3", expected_codes=[0, 1])
    plan_json = _load_json(plan_path)
    _assert(plan_json.get("version") == 2, "v3 request did not compile to standard v2 plan")
    _assert("api_token=fixture-secret-not-real" not in preview["stdout"],
            "preview leaked the locator-selected secret to stdout")
    receipt_json = _load_json(receipt_path)
    goal_preview = receipt_json.get("goal_preview", {})
    _assert(goal_preview.get("goal_result") == "Passed" and goal_preview.get("candidate") == "Preview",
            "body-slim preview did not pass on the actual overlay measurement")
    _assert(goal_preview.get("measurement_coverage", {}).get("before", {}).get("new_archives") == "Passed",
            "preview did not honor the predeclared, safely absent future archive")
    if stop_after_preview:
        return {"status": "PreviewPassed", "steps": _compact_steps([history_before, profile_derive,
            child_two_run, preflight, baseline, summary, report_input, outline, section, line_read,
            unknown_check, coverage, proof_run,
            measure, change_baseline, preview]),
            "plan_version": plan_json.get("version"), "receipt": str(receipt_path)}
    compare_before = run_command(tool, ["compare", *common, "--task-profile", str(child_profile),
        "--before", str(result_dir / "change-before.json"), "--plan", str(plan_path),
        "--output", str(result_dir / "compare-overlay.json"), "--max-output-bytes", "8192"],
        result_dir, "compare-before-overlay")
    overlay_json = _load_json(result_dir / "compare-overlay.json")
    local_targets_overlay = overlay_json.get("domains", {}).get("local_targets", {})
    _assert(local_targets_overlay.get("complete") is True and
            local_targets_overlay.get("no_new_issues") is True,
            "complete local-target overlay comparison did not conclude no new issues")
    preview_before_measure = result_dir / "measure-preview-before.json"
    preview_candidate_measure = result_dir / "measure-preview-candidate.json"
    write_json(preview_before_measure, receipt_json["measurements"]["before"])
    write_json(preview_candidate_measure, receipt_json["measurements"]["candidate"])
    goal_eval = run_command(tool, ["report", *common, "--before", str(preview_before_measure),
        "--after", str(preview_candidate_measure), "--goal-profile", str(child_profile),
        "--output", str(result_dir / "goal-overlay.json"), "--max-output-bytes", "8192"],
        result_dir, "goal-evaluate-overlay")
    goal_overlay_json = _load_json(result_dir / "goal-overlay.json")
    _assert(goal_overlay_json.get("goal_result") == "Passed" and
            goal_overlay_json.get("candidate") == "Preview",
            "receipt-backed overlay goal evaluation was not Passed/Preview")

    apply = run_command(tool, ["apply", *common, "--plan", str(plan_path),
        "--operations-dir", str(result_dir / "operations")], result_dir, "apply-v3")
    apply_json = json.loads(apply["stdout"])
    _assert(apply_json.get("status") == "applied",
            "apply did not report an applied v3 plan")
    journal_path = Path(apply_json.get("journal", apply_json.get("journal_path", "")))
    _assert(journal_path.is_file(), "apply omitted an existing journal path")
    verify = run_command(tool, ["verify", *common, "--journal", str(journal_path)],
                         result_dir, "verify-v3", expected_codes=[0])
    _assert(json.loads(verify["stdout"]).get("status") == "Passed",
            "applied v3 journal did not verify Passed")
    after_report = result_dir / "after-report.json"
    after = run_command(tool, ["check", *common, "--task-profile", str(child_profile),
        "--format", "json", "--output", str(after_report)], result_dir, "after-check",
        expected_codes=[1])
    after_json = _load_json(after_report)
    _assert(after_json.get("has_failures") is True and
            any(item.get("check") == "links" and item.get("code") == "missing-target"
                and item.get("status") == "Failed" for item in after_json.get("findings", [])),
            "expected missing-target finding did not persist after the candidate changes")
    measure_after = run_command(tool, ["report", *common, "--measure-request", str(measure_input),
        "--output", str(result_dir / "measure-after.json"), "--max-output-bytes", "8192"],
        result_dir, "report-measure-after")
    measure_before_json = _load_json(result_dir / "measure.json")
    measure_after_json = _load_json(result_dir / "measure-after.json")
    before_archive = measure_before_json["domains"]["new_archives"]["items"][0]
    after_archive = measure_after_json["domains"]["new_archives"]["items"][0]
    _assert(before_archive.get("presence") == "Absent" and
            before_archive.get("absence_authorized") is True and before_archive.get("bytes") == 0 and
            after_archive.get("presence") == "Present" and after_archive.get("bytes", 0) > 0,
            "authorized absent-to-present archive cohort was not measured on both sides")
    _assert(measure_after_json.get("storage", {}).get("bytes", 0) >
            measure_before_json.get("storage", {}).get("bytes", 0),
            "snapshot growth was hidden by the active-body shrink")
    compare_after = run_command(tool, ["compare", *common, "--task-profile", str(child_profile),
        "--before", str(result_dir / "change-before.json"), "--after", str(after_report),
        "--output", str(result_dir / "compare-after.json"), "--max-output-bytes", "8192"],
        result_dir, "compare-after")
    compare_after_json = _load_json(result_dir / "compare-after.json")
    local_targets_after = compare_after_json.get("domains", {}).get("local_targets", {})
    _assert(local_targets_after.get("complete") is True and
            local_targets_after.get("no_new_issues") is True,
            "complete local-target disk comparison did not conclude no new issues")
    goal_after = run_command(tool, ["report", *common, "--before", str(result_dir / "measure.json"),
        "--after", str(result_dir / "measure-after.json"), "--goal-profile", str(child_profile),
        "--output", str(result_dir / "goal-after.json"), "--max-output-bytes", "8192"],
        result_dir, "goal-evaluate-after")
    goal_after_json = _load_json(result_dir / "goal-after.json")
    _assert(goal_after_json.get("goal_result") == "Passed" and goal_after_json.get("candidate") == "Disk",
            "disk body-slim evaluation did not pass on the applied candidate")
    _assert(measure_after_json.get("config_sha256") == measure_before_json.get("config_sha256"),
            "measurement before/after config binding changed during the operation")
    _assert(sha256_file(project / ".fifan-maintenance.json") == manifest["config_sha256"],
            "project config bytes changed during the operation")

    history = run_command(tool, ["history", *common, "--records-dir", str(result_dir / "operations"),
        "--max-records", "30", "--max-record-bytes", "67108864",
        "--output", str(result_dir / "history.json"), "--max-output-bytes", "8192"],
        result_dir, "history")
    history_json = _load_json(result_dir / "history.json")
    _assert(history_json.get("status") == "Passed" and history_json.get("records"),
            "history report did not identify the applied journal")
    session_manifest = {"schema_version": 1, "root": str(project.resolve()),
                        "journals": [str(journal_path.resolve())], "reports": [], "profiles": []}
    session_path = result_dir / "session.json"
    write_json(session_path, session_manifest)
    session_report = run_command(tool, ["session", "report", *common, "--session", str(session_path),
        "--output", str(result_dir / "session-report.json"), "--max-output-bytes", "8192"],
        result_dir, "session-report")
    session_report_json = _load_json(result_dir / "session-report.json")
    _assert(session_report_json.get("status") == "Passed" and
            session_report_json.get("completion") == "all_applied",
            "session report did not describe a complete applied session")
    session_verify = run_command(tool, ["session", "verify", *common, "--session", str(session_path),
        "--output", str(result_dir / "session-verify.json"), "--max-output-bytes", "8192"],
        result_dir, "session-verify")
    session_verify_json = _load_json(result_dir / "session-verify.json")
    _assert(session_verify_json.get("status") == "Passed",
            "session verify did not report a consistent applied journal")
    recovery_preview = run_command(tool, ["session", "recovery-preview", *common,
        "--session", str(session_path), "--output", str(result_dir / "recovery-plan.json"),
        "--max-output-bytes", "8192"], result_dir, "session-recovery-preview",
        expected_codes=[0])
    recovery_plan_json = _load_json(result_dir / "recovery-plan.json")
    _assert(recovery_plan_json.get("status") == "Passed",
            "session recovery preview did not report a complete recovery plan")
    recovery_plan_path = result_dir / "recovery-plan.json"
    recover = run_command(tool, ["session", "recover", *common, "--session", str(session_path),
        "--recovery-plan", str(recovery_plan_path), "--output", str(result_dir / "session-recover.json"),
        "--max-output-bytes", "8192"], result_dir, "session-recover")
    recover_json = _load_json(result_dir / "session-recover.json")
    _assert(recover_json.get("status") in ("Recovered", "Passed"),
            "session recovery did not report a successful recovery state")
    recovered_verify = run_command(tool, ["verify", *common, "--journal", str(journal_path)],
        result_dir, "verify-recovered", expected_codes=[0])
    _assert(json.loads(recovered_verify["stdout"]).get("status") == "Passed",
            "recovered journal did not verify Passed")
    # Recover must restore original README/table bytes and remove the created snapshot.
    _assert(sha256_file(project / "README.md") == manifest["readme_sha256"],
            "session recover did not restore original README bytes")
    _assert(sha256_file(project / "docs/current/table.md") == manifest["patch_source_sha256"],
            "session recover did not restore original multi-patch source bytes")
    _assert(not (project / "docs/archive/README.before.md").exists(),
            "session recover left the created snapshot behind")

    return {"status": "Passed", "steps": _compact_steps([history_before, profile_derive, child_two_run, preflight, baseline, summary,
        report_input, outline, section, line_read, unknown_check, coverage, proof_run, measure, change_baseline, preview, compare_before,
        goal_eval, apply, verify, after, measure_after, compare_after, goal_after, history, session_report,
        session_verify, recovery_preview, recover, recovered_verify]),
        "journal": str(journal_path), "archive_exact": outcomes.count("Exact"),
        "archive_different": outcomes.count("Different"), "history_status": history_json.get("status"),
        "report_status": baseline_json.get("status"), "recovered": True}


def execute_v11_upgrade_chain(python: Path, project: Path, run_root: Path,
                              result_dir: Path, old_wheel: Path,
                              new_wheel: Path) -> Dict[str, Any]:
    """Create real v1/v2 journals with 1.1, then verify and recover in upgraded 1.2."""
    before_sha = sha256_file(project / "legacy-v1.md")
    v11 = create_fresh_compat_venv(python, run_root, old_wheel, result_dir)
    v11_tool = v11["tool"]
    common = ["--project", str(project)]

    v1_request = result_dir / "legacy-v1-request.json"
    v1_plan = result_dir / "legacy-v1-plan.json"
    run_command(v11_tool, ["preview", *common, "--request", str(v1_request),
        "--plan", str(v1_plan)], result_dir, "v11-preview-v1")
    v1_ops = result_dir / "v11-operations-v1"
    run_command(v11_tool, ["apply", *common, "--plan", str(v1_plan),
        "--operations-dir", str(v1_ops)], result_dir, "v11-apply-v1")
    v1_journals = sorted(v1_ops.glob("*.json"))
    _assert(len(v1_journals) == 1, "1.1 v1 apply did not create exactly one journal")
    v1_journal = v1_journals[0]
    run_command(v11_tool, ["verify", *common, "--journal", str(v1_journal)],
        result_dir, "v11-verify-v1")

    v2_request = write_legacy_v2_after_v1(project, result_dir)
    v2_plan = result_dir / "legacy-v2-plan.json"
    run_command(v11_tool, ["preview", *common, "--request", str(v2_request),
        "--plan", str(v2_plan)], result_dir, "v11-preview-v2")
    v2_ops = result_dir / "v11-operations-v2"
    run_command(v11_tool, ["apply", *common, "--plan", str(v2_plan),
        "--operations-dir", str(v2_ops)], result_dir, "v11-apply-v2")
    v2_journals = sorted(v2_ops.glob("*.json"))
    _assert(len(v2_journals) == 1, "1.1 v2 apply did not create exactly one journal")
    v2_journal = v2_journals[0]
    run_command(v11_tool, ["verify", *common, "--journal", str(v2_journal)],
        result_dir, "v11-verify-v2")

    v12_tool = upgrade_compat_venv_to_v12(v11, new_wheel, result_dir)
    v2_latest_before_recovery = run_command(v12_tool, ["verify", *common,
        "--journal", str(v2_journal)], result_dir, "v12-verify-latest-v2-before-recovery",
        expected_codes=[0])
    _assert(json.loads(v2_latest_before_recovery["stdout"]).get("status") == "Passed",
            "1.2 did not verify the latest real 1.1 v2 journal before recovery")
    session_path = result_dir / "v11-generated-session.json"
    write_json(session_path, {"schema_version": 1, "root": str(project.resolve()),
        "journals": [str(v1_journal.resolve()), str(v2_journal.resolve())],
        "reports": [], "profiles": []})
    session_verify = run_command(v12_tool, ["session", "verify", *common,
        "--session", str(session_path), "--output", str(result_dir / "v11-session-verify.json"),
        "--max-output-bytes", "8192"], result_dir, "v12-verify-v11-session",
        expected_codes=[0])
    _assert(_load_json(result_dir / "v11-session-verify.json").get("status") == "Passed",
            "session verify did not report the valid 1.1 v1/v2 chain")
    recovery_preview = run_command(v12_tool, ["session", "recovery-preview", *common,
        "--session", str(session_path), "--output", str(result_dir / "v11-recovery-plan.json"),
        "--max-output-bytes", "8192"], result_dir, "v12-preview-v11-recovery",
        expected_codes=[0])
    recovery_plan_json = _load_json(result_dir / "v11-recovery-plan.json")
    _assert(recovery_plan_json.get("status") == "Passed",
            "1.1 session recovery preview did not report a complete plan")
    recover = run_command(v12_tool, ["session", "recover", *common,
        "--session", str(session_path), "--recovery-plan", str(result_dir / "v11-recovery-plan.json"),
        "--output", str(result_dir / "v11-recovery-result.json"), "--max-output-bytes", "8192"],
        result_dir, "v12-recover-v11-session", expected_codes=[0])
    recovery_result_json = _load_json(result_dir / "v11-recovery-result.json")
    _assert(recovery_result_json.get("status") == "Passed" and
            recovery_result_json.get("completion") == "all_recovered",
            "upgraded 1.2 did not complete the real 1.1 recovery chain")
    session_verify_after = run_command(v12_tool, ["session", "verify", *common,
        "--session", str(session_path), "--output", str(result_dir / "v11-session-verify-after.json"),
        "--max-output-bytes", "8192"], result_dir, "v12-verify-v11-session-after-recovery",
        expected_codes=[0])
    _assert(_load_json(result_dir / "v11-session-verify-after.json").get("status") == "Passed",
            "recovered session did not verify Passed")
    v2_verify = run_command(v12_tool, ["verify", *common, "--journal", str(v2_journal)],
        result_dir, "v12-verify-v11-v2-after-recovery", expected_codes=[1])
    v1_verify = run_command(v12_tool, ["verify", *common, "--journal", str(v1_journal)],
        result_dir, "v12-verify-v11-v1-after-recovery", expected_codes=[0])
    _assert(json.loads(v2_verify["stdout"]).get("status") == "Failed",
            "v2 standalone verify after reverse chain recovery was not the expected Failed")
    _assert(json.loads(v1_verify["stdout"]).get("status") == "Passed",
            "v1 standalone verify after reverse chain recovery did not return to its baseline")
    _assert(sha256_file(project / "legacy-v1.md") == before_sha,
            "upgraded 1.2 recovery did not restore the v1/v2 source chain")
    _assert(not (project / "archive/legacy-v1.before-v2.md").exists(),
            "upgraded 1.2 recovery left the 1.1-created snapshot behind")
    return {"status": "Passed", "v11_wheel_sha256": sha256_file(old_wheel),
            "v12_wheel_sha256": sha256_file(new_wheel), "v1_journal": str(v1_journal),
            "v2_journal": str(v2_journal), "steps": _compact_steps([v2_latest_before_recovery,
            session_verify, recovery_preview, recover, session_verify_after, v2_verify, v1_verify]),
            "restored_sha256": before_sha}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--tool", type=Path, default=DEFAULT_TOOL)
    parser.add_argument("--v11-wheel", type=Path, default=DEFAULT_WHEEL_11)
    parser.add_argument("--v12-wheel", type=Path, default=DEFAULT_WHEEL_12)
    parser.add_argument("--python-executable", type=Path, default=ROOT / ".venv39/bin/python")
    parser.add_argument("--history-files", type=int, default=20005)
    parser.add_argument("--prepare-only", action="store_true",
                        help="generate fixture/manifest only; do not call unstable CLI interfaces")
    parser.add_argument("--run", action="store_true",
                        help="execute the full integration only after Root announces CLI freeze")
    parser.add_argument("--compat-upgrade", action="store_true",
                        help="generate real 1.1 v1/v2 journals and upgrade the same fresh venv to 1.2")
    parser.add_argument("--preview-only", action="store_true",
                        help="stop after the v3 preview for focused contract diagnostics")
    parser.add_argument("--keep-fixture", action="store_true",
                        help="retain this run's synthetic project and sibling result directory")
    args = parser.parse_args()
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    work = results / "work"
    work.mkdir(exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="run-", dir=str(work)))
    project = run_root / "project"
    result_dir = run_root / "results"
    result_dir.mkdir()
    try:
        manifest = build_fixture(project, args.history_files)
        manifest = write_prepared_inputs(project, result_dir, manifest)
        manifest = write_profile2_parent(result_dir, manifest)
        manifest.update({"fixture_version": 1, "history_requested": args.history_files,
                         "tool_candidate": str(args.tool.resolve()),
                         "v11_wheel": str(args.v11_wheel.resolve()),
                         "v12_wheel": str(args.v12_wheel.resolve()),
                         "python_executable": str(args.python_executable.resolve()),
                         "mode": "awaiting-stable-cli" if args.run else "prepare-only"})
        write_json(result_dir / "fixture-manifest.json", manifest)
        if args.run:
            cli_result = execute_source_workflow(args.tool.resolve(), project, result_dir, manifest,
                                                 stop_after_preview=args.preview_only)
            compatibility = None
            if args.compat_upgrade:
                compatibility = execute_v11_upgrade_chain(args.python_executable.resolve(), project,
                    run_root, result_dir, args.v11_wheel.resolve(), args.v12_wheel.resolve())
            summary = {"status": cli_result["status"], "run_id": run_root.name,
                       "manifest": {"source_count": manifest["source_count"],
                           "history_files_flat": manifest["history_files_flat"],
                           "history_files_nested": manifest["history_files_nested"],
                           "config_sha256": manifest["config_sha256"]}, "workflow": cli_result,
                       "v11_compatibility": compatibility,
                       "results_directory": str(results / "run-results" / run_root.name)}
            persisted = results / "run-results" / run_root.name
            shutil.copytree(result_dir, persisted, dirs_exist_ok=True)
            write_json(results / "prepared-summary.json", summary)
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            return 0
        summary = {"status": "Prepared", "run_id": run_root.name, "manifest": manifest,
                   "results_directory": str(results / "run-results" / run_root.name)}
        persisted = results / "run-results" / run_root.name
        shutil.copytree(result_dir, persisted, dirs_exist_ok=True)
        write_json(results / "prepared-summary.json", summary)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        failure = {"status": "Failed", "error": str(exc), "run_id": run_root.name}
        if result_dir.exists():
            persisted = results / "run-results" / run_root.name
            persisted.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(result_dir, persisted, dirs_exist_ok=True)
        write_json(results / "prepare-failure.json", failure)
        print(json.dumps(failure, ensure_ascii=False, indent=2))
        return 1
    finally:
        if not args.keep_fixture:
            shutil.rmtree(run_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
