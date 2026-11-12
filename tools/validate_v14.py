#!/usr/bin/env python3
"""Synthetic v1.4 cleanup driver; writes only inside the authorized evidence tree.

This driver only creates project/Q/REC roots below evidence/validation/v1.4/forward.
It never invokes fixture project scripts and does not mutate production modules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Dict, Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
FORWARD = ROOT / "evidence/validation/v1.4/forward"
PROTECTED_FILES = (
    "current/README.md", "current/PLAN.md", "current/DECISIONS.md", "current/src/current.py",
    ".fifan-maintenance.json", ".env", ".git/HEAD", "current/keep.md",
    "Assets/fixture.asset", "Assets/fixture.asset.meta",
    "builds/keep.zip",
)
DISPOSABLE_FILES = (
    "builds/old/out.pkg", "builds/old/build.log",
    "logs/completed-run.log", "tmp/disposable.cache",
)
CLEANUP_CANDIDATES = ("builds/old", "logs/completed-run.log", "tmp/disposable.cache")
CURRENT_BUILD = {"platform": "mac", "branch": "main", "configuration": "release", "purpose": "rollback"}


class FixtureError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def _put(project: Path, rel: str, content: bytes) -> Path:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _root_snapshot(path: Path) -> Dict[str, Dict[str, Any]]:
    snapshot: Dict[str, Dict[str, Any]] = {}
    for item in sorted(path.rglob("*"), key=lambda entry: entry.relative_to(path).as_posix()):
        rel = item.relative_to(path).as_posix()
        info = item.lstat()
        snapshot[rel] = {
            "kind": "directory" if item.is_dir() else "file",
            "mode": info.st_mode & 0o777,
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "device": info.st_dev,
            "inode": info.st_ino,
            "sha256": sha256_file(item) if item.is_file() else None,
        }
    return snapshot


def prepare_fixture(workspace: Path, *, log_bytes: int = 4096) -> Dict[str, Any]:
    """Create a fresh, tiny, synthetic three-root project fixture."""
    workspace = workspace.absolute()
    if workspace.exists() and any(workspace.iterdir()):
        raise FixtureError("refusing to overwrite a non-empty fixture workspace")
    workspace.mkdir(parents=True, exist_ok=True)
    project, quarantine, records = (workspace / "project", workspace / "quarantine", workspace / "records")
    for root in (project, quarantine, records):
        root.mkdir()

    contents = {
        "current/README.md": "# Synthetic project\n\nCurrent entry [source](src/current.py).\n",
        "current/PLAN.md": "# Plan\n\nCurrent work remains protected.\n",
        "current/DECISIONS.md": "# Decision\n\nKeep current package and its evidence.\n",
        "current/src/current.py": "def current_entry():\n    return 'protected synthetic source'\n",
        "current/keep.md": "# Retained build evidence\n\nThis fixture documents a kept rollback build.\n",
        ".fifan-maintenance.json": json.dumps({"schema_version": 1, "include": ["**/*", "*.md"]},
                                               sort_keys=True) + "\n",
        ".env": "SYNTHETIC_MARKER=not-a-secret\n",
        ".git/HEAD": "ref: refs/heads/synthetic\n",
        "Assets/fixture.asset": "synthetic Unity asset payload\n",
        "Assets/fixture.asset.meta": "fileFormatVersion: 2\nguid: synthetic-only\n",
    }
    for rel, value in contents.items():
        _put(project, rel, value.encode("utf-8"))
    build_payload = b"synthetic retained rollback build artifact\n"
    current_build = _put(project, "builds/keep.zip", build_payload)
    _put(project, "builds/old/out.pkg", b"synthetic retired build\n")
    _put(project, "builds/old/build.log", b"synthetic old build log\n")
    _put(project, "logs/completed-run.log", b"synthetic completed log\n" + b"L" * log_bytes)
    _put(project, "tmp/disposable.cache", b"synthetic one-off output\n")
    closure = project / "closed-batch.md"
    _put(project, "closed-batch.md",
         b"# Closed fixture batch\n\nSynthetic process and build work is closed.\n")
    closure_sha = sha256_file(closure)

    profile = {
        "schema_version": 1, "project_root": str(project.resolve()), "preset": "generic",
        "scan_roots": ["."], "current": ["current"],
        "keep": [{"path": "builds/keep.zip", "reason": "current rollback baseline",
                  "build": CURRENT_BUILD,
                  "evidence": [{"path": "current/keep.md", "sha256": sha256_file(project / "current/keep.md")}],
                  "sha256": sha256_file(current_build)}],
        "protected": ["Assets/**", "Assets/**/*.meta", ".git/**", ".env"],
        "candidates": [{"path": "builds/old", "kind": "old_build"},
                       {"path": "logs/completed-run.log", "kind": "completed_log"},
                       {"path": "tmp/disposable.cache", "kind": "disposable_output"}],
        "rules": [],
        "reference_sources": [{"path": "current", "role": "current"},
                              {"path": "closed-batch.md", "role": "historical"}],
        "streaming_references": [], "quarantine_root": str(quarantine.resolve()),
        "records_dir": str(records.resolve()), "require_no_open_handles": True,
        "budgets": {},
    }
    items = [
        {"source": "builds/old", "kind": "old_build", "reason": "retired synthetic build",
         "disposition": "purge", "build": CURRENT_BUILD, "retained": ["builds/keep.zip"],
         "closure": {"decision": "closed", "reason": "finished fixture batch",
                     "evidence": [{"path": "closed-batch.md", "sha256": closure_sha}]},
         "loss": {"accepted": True, "rebuildable": "Unknown", "unique_evidence": False,
                  "description": "lose the original retired build snapshot"}},
        {"source": "logs/completed-run.log", "kind": "completed_log", "reason": "closed synthetic process log",
         "disposition": "purge",
         "closure": {"decision": "closed", "reason": "finished fixture batch",
                     "evidence": [{"path": "closed-batch.md", "sha256": closure_sha}]},
         "loss": {"accepted": True, "rebuildable": "Unknown", "unique_evidence": False,
                  "description": "lose the original completed process transcript"}, "retained": []},
        {"source": "tmp/disposable.cache", "kind": "disposable_output", "reason": "one-time fixture output",
         "disposition": "purge",
         "closure": {"decision": "closed", "reason": "finished fixture batch",
                     "evidence": [{"path": "closed-batch.md", "sha256": closure_sha}]},
         "loss": {"accepted": True, "rebuildable": "Unknown", "unique_evidence": False,
                  "description": "lose the one-time synthetic output"}, "retained": []},
    ]
    request = {"schema_version": 1,
               "approval": {"reference": "synthetic approved batch", "actions": ["quarantine", "purge"]},
               "items": items}
    quarantine_only_request = {
        "schema_version": 1,
        "approval": {"reference": "synthetic quarantine only", "actions": ["quarantine"]},
        "items": [{**item, "disposition": "quarantine",
                   "loss": {**item["loss"], "accepted": False}} for item in items],
    }
    write_json(workspace / "cleanup-profile.json", profile)
    write_json(workspace / "cleanup-request.json", request)
    write_json(workspace / "quarantine-only-request.json", quarantine_only_request)

    protected_hashes = {rel: sha256_file(project / rel) for rel in PROTECTED_FILES}
    disposable_hashes = {rel: sha256_file(project / rel) for rel in DISPOSABLE_FILES}
    roots = [project, quarantine, records]
    devices = {root.stat().st_dev for root in roots}
    if len(devices) != 1:
        raise FixtureError("synthetic project/quarantine/records roots are not on the same device")
    if any(root == project or project in root.parents or root in project.parents for root in (quarantine, records)):
        raise FixtureError("project and external roots must not contain one another")

    manifest: Dict[str, Any] = {
        "fixture": "synthetic-cleanup-v14",
        "roots": {"workspace": str(workspace), "project": str(project),
                  "quarantine_root": str(quarantine), "records_dir": str(records),
                  "closure_evidence": str(closure),
                  "closure_evidence_project_path": "closed-batch.md"},
        "counts": {"current_markdown": 3, "protected_files": len(PROTECTED_FILES),
                   "disposable_files": len(DISPOSABLE_FILES), "log_bytes": log_bytes},
        "protected_paths": list(PROTECTED_FILES), "disposable_paths": list(CLEANUP_CANDIDATES),
        "disposable_file_paths": list(DISPOSABLE_FILES),
        "current_build_sha256": sha256_file(current_build),
        "closure_evidence_sha256": closure_sha,
        "historical_evidence_sha256": {"closed-batch.md": closure_sha},
        "protected_sha256": protected_hashes, "disposable_sha256": disposable_hashes,
        "project_metadata_snapshot": _root_snapshot(project),
        "profile": str((workspace / "cleanup-profile.json").resolve()),
        "request": str((workspace / "cleanup-request.json").resolve()),
        "quarantine_only_request": str((workspace / "quarantine-only-request.json").resolve()),
        "profile_sha256": sha256_file(workspace / "cleanup-profile.json"),
        "request_sha256": sha256_file(workspace / "cleanup-request.json"),
        "quarantine_only_request_sha256": sha256_file(workspace / "quarantine-only-request.json"),
        "api_contract_status": "stable cleanup 1.4 CLI contract; synthetic fixture only",
    }
    write_json(workspace / "fixture-manifest.json", manifest)
    return manifest


def _call_cli(workspace: Path, cli: Path, label: str, args: list[str], *,
              expected_exit: int = 0, expected_status: Optional[str] = None) -> Dict[str, Any]:
    """Run one real CLI action and retain exact argv, exit code and JSON reply."""
    command_root = workspace / "commands"
    command_root.mkdir(parents=True, exist_ok=True)
    artifact = workspace / "artifacts" / (label + ".json")
    artifact.parent.mkdir(parents=True, exist_ok=True)
    if args and args[0] in {"cleanup", "directory"} and "--output" not in args:
        args = [*args, "--output", str(artifact)]
    argv = [str(cli), *args]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(argv, cwd=str(ROOT), capture_output=True, text=True, env=environment)
    try:
        payload = result.stdout.strip() or result.stderr.strip()
        output = json.loads(payload) if payload else None
    except json.JSONDecodeError:
        output = None
    record = {"label": label, "argv": argv, "exit_code": result.returncode,
              "stdout_json": output, "stdout": result.stdout, "stderr": result.stderr,
              "private_artifact": str(artifact) if artifact.is_file() else None,
              "private_artifact_sha256": sha256_file(artifact) if artifact.is_file() else None,
              "python_environment_removed": ["PYTHONPATH", "PYTHONHOME"]}
    write_json(command_root / (label + ".json"), record)
    if result.returncode != expected_exit:
        raise FixtureError("{} returned exit {}; expected {}".format(label, result.returncode, expected_exit))
    if expected_status is not None and (not isinstance(output, dict) or output.get("status") != expected_status):
        raise FixtureError("{} status was {!r}; expected {!r}".format(
            label, output.get("status") if isinstance(output, dict) else None, expected_status))
    return {"record": record, "json": output}


def _workspace_cli_paths(workspace: Path) -> Dict[str, str]:
    root = workspace.resolve()
    project = root / "project"
    return {"project": str(project), "profile": str(root / "cleanup-profile.json"),
            "request": str(root / "cleanup-request.json"),
            "quarantine_only_request": str(root / "quarantine-only-request.json"),
            "quarantine": str(root / "quarantine"), "records": str(root / "records")}


def _cleanup_sequence(workspace: Path, cli: Path, *, quarantine_only: bool = False) -> Dict[str, Any]:
    paths = _workspace_cli_paths(workspace)
    manifest = json.loads((workspace / "fixture-manifest.json").read_text(encoding="utf-8"))
    project = Path(paths["project"])
    profile = paths["profile"]
    request_key = "quarantine_only_request" if quarantine_only else "request"
    request = paths[request_key]
    request_data = json.loads(Path(request).read_text(encoding="utf-8"))
    plan_path = workspace / "quarantine-plan.json"
    preview = _call_cli(workspace, cli, "preview-quarantine", ["cleanup", "preview", "--project", paths["project"],
        "--profile", profile, "--request", request, "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--plan", str(plan_path)], expected_status="Preview")["json"]
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("kind") != "quarantine" or plan.get("fingerprint") != preview.get("fingerprint"):
        raise FixtureError("quarantine plan fingerprint or kind does not match the CLI receipt")
    opid = plan["operation_id"]
    journal_path = Path(paths["records"]) / ("cleanup-{}".format(opid)) / "journal.json"
    _call_cli(workspace, cli, "apply-quarantine", ["cleanup", "apply", "--project", paths["project"],
        "--profile", profile, "--plan", str(plan_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--approve-plan", plan["fingerprint"]],
        expected_status="Passed")
    verified = _call_cli(workspace, cli, "verify-quarantined", ["cleanup", "verify", "--project", paths["project"],
        "--profile", profile, "--journal", str(journal_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"]], expected_status="Passed")["json"]
    if verified.get("state") != "Quarantined" or verified.get("restore_possible") is not True:
        raise FixtureError("quarantined journal did not remain restorable")
    restore_plan_path = workspace / "restore-plan.json"
    restore_preview = _call_cli(workspace, cli, "preview-restore", ["cleanup", "restore-preview", "--project", paths["project"],
        "--profile", profile, "--journal", str(journal_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--plan", str(restore_plan_path)],
        expected_status="Preview")["json"]
    restore_plan = json.loads(restore_plan_path.read_text(encoding="utf-8"))
    if restore_plan.get("fingerprint") != restore_preview.get("fingerprint"):
        raise FixtureError("restore plan did not match its CLI receipt")
    _call_cli(workspace, cli, "restore", ["cleanup", "restore", "--project", paths["project"],
        "--profile", profile, "--plan", str(restore_plan_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--approve-plan", restore_plan["fingerprint"]],
        expected_status="Passed")
    restored = _call_cli(workspace, cli, "verify-restored", ["cleanup", "verify", "--project", paths["project"],
        "--profile", profile, "--journal", str(journal_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"]], expected_status="Passed")["json"]
    if restored.get("state") != "Restored":
        raise FixtureError("restored journal has an unexpected state")
    for rel, digest in manifest["protected_sha256"].items():
        if sha256_file(project / rel) != digest:
            raise FixtureError("protected source drifted after restore: {}".format(rel))
    for rel, digest in manifest["disposable_sha256"].items():
        if sha256_file(project / rel) != digest:
            raise FixtureError("disposable source was not exactly restored: {}".format(rel))
    restored_journal_path = journal_path
    fresh_plan_path = workspace / "fresh-after-restore-plan.json"
    fresh_preview = _call_cli(workspace, cli, "fresh-preview-after-restore", ["cleanup", "preview", "--project", paths["project"],
        "--profile", profile, "--request", request, "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--plan", str(fresh_plan_path)],
        expected_status="Preview")["json"]
    fresh_plan = json.loads(fresh_plan_path.read_text(encoding="utf-8"))
    if fresh_plan.get("operation_id") == plan.get("operation_id") or fresh_plan.get("fingerprint") != fresh_preview.get("fingerprint"):
        raise FixtureError("restored sources did not produce a fresh distinct cleanup operation")
    # A purge is a separate, explicit approval after restore. Reapply the new
    # quarantine plan first, then bind purge to this second live journal.
    fresh_apply = _call_cli(workspace, cli, "apply-fresh-quarantine-before-purge", ["cleanup", "apply", "--project", paths["project"],
        "--profile", profile, "--plan", str(fresh_plan_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--approve-plan", fresh_plan["fingerprint"]],
        expected_status="Passed")["json"]
    journal_path = Path(paths["records"]) / ("cleanup-{}".format(fresh_plan["operation_id"])) / "journal.json"
    fresh_verified = _call_cli(workspace, cli, "verify-fresh-quarantine-before-purge", ["cleanup", "verify",
        "--project", paths["project"], "--profile", profile, "--journal", str(journal_path),
        "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"]],
        expected_status="Passed")["json"]
    if (fresh_apply.get("state") != "Quarantined" or fresh_verified.get("state") != "Quarantined"
            or fresh_verified.get("restore_possible") is not True):
        raise FixtureError("fresh quarantine is not in a verified, restorable state")
    result = {"workspace": str(workspace.resolve()), "status": "FreshQuarantineReadyForPurge",
              "quarantine_only": quarantine_only, "request_sha256": sha256_file(Path(request)),
              "restored_journal": str(restored_journal_path),
              "first_quarantine_fingerprint": plan["fingerprint"],
              "purge_batch_quarantine_fingerprint": fresh_plan["fingerprint"], "journal": str(journal_path),
              "journal_state_after_restore": restored["state"],
              "fresh_operation_id": fresh_plan["operation_id"],
              "protected_sha256": manifest["protected_sha256"],
              "disposable_sha256": manifest["disposable_sha256"]}
    purge_plan_path = workspace / "purge-plan.json"
    if quarantine_only:
        _call_cli(workspace, cli, "purge-without-followup-approval", ["cleanup", "purge-preview", "--project", paths["project"],
            "--profile", profile, "--journal", str(journal_path), "--records-dir", paths["records"],
            "--quarantine-root", paths["quarantine"], "--plan", str(workspace / "denied-purge-plan.json")],
            expected_exit=2, expected_status="Blocked")
        approval_path = workspace / "follow-up-purge-approval.json"
        write_json(approval_path, {"quarantine_fingerprint": fresh_plan["fingerprint"],
                                   "reference": "synthetic follow-up purge approval", "loss_accepted": True})
        purge_preview = _call_cli(workspace, cli, "preview-purge-with-followup-approval", ["cleanup", "purge-preview",
            "--project", paths["project"], "--profile", profile, "--journal", str(journal_path),
            "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
            "--approval-file", str(approval_path), "--plan", str(purge_plan_path)], expected_status="Preview")["json"]
    else:
        purge_preview = _call_cli(workspace, cli, "preview-purge", ["cleanup", "purge-preview", "--project", paths["project"],
            "--profile", profile, "--journal", str(journal_path), "--records-dir", paths["records"],
            "--quarantine-root", paths["quarantine"], "--plan", str(purge_plan_path)],
            expected_status="Preview")["json"]
    purge_plan = json.loads(purge_plan_path.read_text(encoding="utf-8"))
    if purge_plan.get("fingerprint") != purge_preview.get("fingerprint"):
        raise FixtureError("purge plan did not match its CLI receipt")
    restore_after_purge_path = workspace / "restore-after-purge-preview-plan.json"
    restore_after_purge = _call_cli(workspace, cli, "restore-preview-after-purge-plan", ["cleanup", "restore-preview",
        "--project", paths["project"], "--profile", profile, "--journal", str(journal_path),
        "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
        "--plan", str(restore_after_purge_path)], expected_status="Preview")["json"]
    if restore_after_purge.get("kind") != "restore":
        raise FixtureError("persisted purge plan incorrectly removed restore eligibility")
    _call_cli(workspace, cli, "purge", ["cleanup", "purge", "--project", paths["project"],
        "--profile", profile, "--plan", str(purge_plan_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--approve-plan", purge_plan["fingerprint"]],
        expected_status="Passed")
    purged = _call_cli(workspace, cli, "verify-purged", ["cleanup", "verify", "--project", paths["project"],
        "--profile", profile, "--journal", str(journal_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"]], expected_status="Passed")["json"]
    if purged.get("state") != "Purged" or purged.get("restore_possible") is not False:
        raise FixtureError("purge final state does not match the irreversible contract")
    missing_restore = _call_cli(workspace, cli, "restore-refused-after-purge", ["cleanup", "restore-preview",
        "--project", paths["project"], "--profile", profile, "--journal", str(journal_path),
        "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
        "--plan", str(workspace / "restore-refused-after-purge-plan.json")], expected_exit=2,
        expected_status="Blocked")["json"]
    if missing_restore.get("reason_code") != "PURGE_NOT_RESTORABLE":
        raise FixtureError("purged journal returned the wrong restore refusal")
    for rel, digest in manifest["protected_sha256"].items():
        if sha256_file(project / rel) != digest:
            raise FixtureError("protected source drifted after purge: {}".format(rel))
    result.update({"status": "PurgedAndVerified", "purge_fingerprint": purge_plan["fingerprint"],
                   "purged_items": [item["source"] for item in purged.get("items", [])],
                   "restore_refusal": missing_restore.get("reason_code")})
    return result


def _workflow_sequence(workspace: Path, cli: Path, *, log_bytes: int) -> Dict[str, Any]:
    manifest = prepare_fixture(workspace, log_bytes=log_bytes)
    paths = _workspace_cli_paths(workspace)
    task_profile = workspace / "task-check-profile.json"
    after_descriptor = workspace / "after-task-check.json"
    write_json(task_profile, {"schema_version": 1, "sources": ["current/README.md"],
                              "checks": ["documents", "links"]})
    write_json(after_descriptor, {"kind": "task-check", "profile": str(task_profile.resolve())})
    profile = paths["profile"]
    inspect = _call_cli(workspace, cli, "workflow-inspect", ["maintenance", "workflow", "--project", paths["project"],
        "--profile", profile, "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
        "--mode", "inspect"], expected_status="Unknown")["json"]
    if inspect.get("state") != "Completed" or inspect.get("model_calls") != 0:
        raise FixtureError("inspect-only workflow did not remain read-only with global Unknown preserved")

    quarantine_plan_path = workspace / "workflow-quarantine-plan.json"
    quarantine_preview = _call_cli(workspace, cli, "workflow-quarantine-preview", ["cleanup", "preview",
        "--project", paths["project"], "--profile", profile, "--request", paths["request"],
        "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
        "--plan", str(quarantine_plan_path)], expected_status="Preview")["json"]
    quarantine_plan = json.loads(quarantine_plan_path.read_text(encoding="utf-8"))
    if quarantine_plan.get("fingerprint") != quarantine_preview.get("fingerprint"):
        raise FixtureError("workflow quarantine plan fingerprint does not match its receipt")
    workflow_q = _call_cli(workspace, cli, "workflow-quarantine", ["maintenance", "workflow", "--project", paths["project"],
        "--profile", profile, "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
        "--mode", "quarantine", "--request", paths["request"], "--plan", str(quarantine_plan_path),
        "--approve-plan", quarantine_plan["fingerprint"], "--after", str(after_descriptor)],
        expected_status="Unknown")["json"]
    if (workflow_q.get("cleanup_state") != "Quarantined" or workflow_q.get("cleanup_status") != "Passed"
            or workflow_q.get("after_action", {}).get("status") != "Passed"
            or workflow_q.get("after_action", {}).get("write_performed") is not False):
        raise FixtureError("workflow quarantine or task-check after-action did not match its contract")
    qjournal = Path(workflow_q["cleanup_journal"])
    restore_plan_path = workspace / "workflow-quarantine-restore-plan.json"
    restore_preview = _call_cli(workspace, cli, "workflow-quarantine-restore-preview", ["cleanup", "restore-preview",
        "--project", paths["project"], "--profile", profile, "--journal", str(qjournal),
        "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
        "--plan", str(restore_plan_path)], expected_status="Preview")["json"]
    restore_plan = json.loads(restore_plan_path.read_text(encoding="utf-8"))
    if restore_plan.get("fingerprint") != restore_preview.get("fingerprint"):
        raise FixtureError("workflow restore plan fingerprint does not match its receipt")
    _call_cli(workspace, cli, "workflow-quarantine-restore", ["cleanup", "restore", "--project", paths["project"],
        "--profile", profile, "--plan", str(restore_plan_path), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--approve-plan", restore_plan["fingerprint"]],
        expected_status="Passed")
    restored = _call_cli(workspace, cli, "workflow-quarantine-verify-restored", ["cleanup", "verify", "--project", paths["project"],
        "--profile", profile, "--journal", str(qjournal), "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"]], expected_status="Passed")["json"]
    if restored.get("state") != "Restored":
        raise FixtureError("workflow quarantine fixture did not restore cleanly")
    purge_source = workspace / "workflow-purge-plan.json"
    purge_preview = _call_cli(workspace, cli, "workflow-purge-preview", ["cleanup", "preview", "--project", paths["project"],
        "--profile", profile, "--request", paths["request"], "--records-dir", paths["records"],
        "--quarantine-root", paths["quarantine"], "--plan", str(purge_source)], expected_status="Preview")["json"]
    purge_source_data = json.loads(purge_source.read_text(encoding="utf-8"))
    if purge_source_data.get("fingerprint") != purge_preview.get("fingerprint"):
        raise FixtureError("workflow purge plan fingerprint does not match its preview")
    workflow_purge = _call_cli(workspace, cli, "workflow-purge", ["maintenance", "workflow", "--project", paths["project"],
        "--profile", profile, "--records-dir", paths["records"], "--quarantine-root", paths["quarantine"],
        "--mode", "purge", "--request", paths["request"], "--plan", str(purge_source),
        "--approve-plan", purge_source_data["fingerprint"], "--after", str(after_descriptor)],
        expected_status="Unknown")["json"]
    measurement_stages = [item.get("stage") for item in workflow_purge.get("measurements", [])]
    if (workflow_purge.get("state") != "Completed" or workflow_purge.get("cleanup_state") != "Purged"
            or workflow_purge.get("cleanup_status") != "Passed"
            or workflow_purge.get("after_action", {}).get("status") != "Passed"
            or workflow_purge.get("after_action", {}).get("write_performed") is not False
            or measurement_stages != ["T0", "T1", "T2", "T3"]
            or not all(item.get("status") == "Passed" for item in workflow_purge.get("measurements", []))
            or workflow_purge.get("global_coverage_status") != "Unknown"):
        raise FixtureError("workflow purge state, measured stages, or global Unknown changed unexpectedly")
    for rel, digest in manifest["protected_sha256"].items():
        if sha256_file(Path(paths["project"]) / rel) != digest:
            raise FixtureError("workflow changed protected path: {}".format(rel))
    remaining = [rel for rel in manifest["disposable_sha256"] if (Path(paths["project"]) / rel).exists()]
    if remaining:
        raise FixtureError("workflow purge left disposable sources behind: {}".format(remaining))
    return {"status": "Passed", "inspect_status": inspect["status"],
            "workflow_quarantine": workflow_q["status"], "workflow_quarantine_cleanup": workflow_q["cleanup_status"],
            "workflow_purge": workflow_purge["status"], "workflow_purge_cleanup": workflow_purge["cleanup_status"],
            "workflow_purge_global_coverage": workflow_purge["global_coverage_status"],
            "measurement_stages": measurement_stages, "after_task_check": workflow_purge["after_action"]["status"],
            "protected_sha256": manifest["protected_sha256"],
            "purge_journal": workflow_purge["cleanup_journal"]}


def run_small_contract(workspace: Path, cli: Path, *, log_bytes: int = 4096) -> Dict[str, Any]:
    workspace = workspace.absolute()
    if workspace.exists() and any(workspace.iterdir()):
        raise FixtureError("refusing to overwrite non-empty small-contract workspace")
    normal = workspace / "approved-batch"
    quarantine_only = workspace / "quarantine-only"
    workflow = workspace / "workflow"
    prepare_fixture(normal, log_bytes=log_bytes)
    prepare_fixture(quarantine_only, log_bytes=log_bytes)
    approved = _cleanup_sequence(normal, cli)
    followup = _cleanup_sequence(quarantine_only, cli, quarantine_only=True)
    workflow_result = _workflow_sequence(workflow, cli, log_bytes=log_bytes)
    summary = {"status": "Passed", "approved_batch": approved, "quarantine_only_followup": followup,
               "workflow": workflow_result,
               "execution": "real CLI; synthetic fixtures only", "model_calls": 0}
    write_json(workspace / "small-contract-summary.json", summary)
    return summary


def _new_workspace(workspace: Path) -> None:
    if workspace.exists() and any(workspace.iterdir()):
        raise FixtureError("refusing to overwrite a non-empty scenario workspace")
    workspace.mkdir(parents=True, exist_ok=True)


def _line_payload(path: Path, size: int) -> None:
    """Generate bounded-memory, valid plain-text logs for stream-reference checks."""
    block = b"synthetic completed process line with no consumer dependency\n" * 1024
    with path.open("wb") as stream:
        while size:
            part = block[:min(size, len(block))]
            stream.write(part)
            size -= len(part)


def _large_fixture(workspace: Path, log_bytes: int) -> Dict[str, Any]:
    manifest = prepare_fixture(workspace, log_bytes=0)
    project = Path(manifest["roots"]["project"])
    _line_payload(project / "logs/completed-run.log", log_bytes)
    _line_payload(project / "builds/old/out.pkg", max(1024, log_bytes // 45))
    profile = json.loads(Path(manifest["profile"]).read_text())
    profile["reference_sources"].append({"path": "logs/completed-run.log", "role": "historical"})
    write_json(Path(manifest["profile"]), profile)
    manifest["counts"]["log_bytes"] = log_bytes
    manifest["disposable_sha256"] = {rel: sha256_file(project / rel) for rel in DISPOSABLE_FILES}
    manifest["project_metadata_snapshot"] = _root_snapshot(project)
    manifest["profile_sha256"] = sha256_file(Path(manifest["profile"]))
    write_json(workspace / "fixture-manifest.json", manifest)
    return manifest


def _private(workspace: Path, label: str) -> Dict[str, Any]:
    return json.loads((workspace / "artifacts" / (label + ".json")).read_text())


def run_large_contract(workspace: Path, cli: Path, *, log_bytes: int = 45 * 1024 * 1024) -> Dict[str, Any]:
    """Real CLI D lifecycle and a retained-current full-stream read-only contrast."""
    _new_workspace(workspace)
    disposable, retained = workspace / "disposable", workspace / "retained-current"
    manifest = _large_fixture(disposable, log_bytes)
    paths = _workspace_cli_paths(disposable)
    _call_cli(disposable, cli, "inspect-large", ["cleanup", "inspect", "--project", paths["project"],
              "--profile", paths["profile"], "--request", paths["request"]], expected_status="Unknown")
    inspected = _private(disposable, "inspect-large")
    if inspected["body_bytes_read"] != 0 or inspected["candidate_hash_bytes"] != 0:
        raise FixtureError("inspect read/hash payload bodies")
    chain = _cleanup_sequence(disposable, cli)
    plan = json.loads((disposable / "quarantine-plan.json").read_text())
    qualification = plan["qualification"]
    if qualification["reference_bytes_read"] >= log_bytes or qualification["candidate_hash_bytes"] != 0:
        raise FixtureError("discarded D log was parsed as a retained consumer")
    # This log is explicitly declared historical. Skip metadata and retained
    # fingerprints distinguish deliberate D exclusion from absent permission.
    for item in qualification["material"]["items"]:
        if "logs/completed-run.log" not in item["skipped_discarded_references"]:
            raise FixtureError("D log skip evidence is absent")
        if any(entry["path"] == "logs/completed-run.log" for entry in item["reference_fingerprints"]):
            raise FixtureError("D log was included in retained consumer fingerprints")
    payload_bytes = sum(item["manifest"]["file_bytes"] for item in plan["items"])
    sha_coverage = {}
    for item in plan["items"]:
        for entry in item["manifest"]["entries"]:
            if entry["kind"] == "file":
                rel = item["source"] if entry["path"] == "." else item["source"] + "/" + entry["path"]
                if entry["sha256"] != manifest["disposable_sha256"][rel]:
                    raise FixtureError("CLI payload SHA does not match fixture baseline")
                sha_coverage[rel] = {"bytes": entry["bytes"], "sha256": entry["sha256"]}
    verify_usage = {label: _private(disposable, label)["hash_usage"] for label in
                    ("verify-quarantined", "verify-restored", "verify-fresh-quarantine-before-purge", "verify-purged")}
    for label in ("verify-quarantined", "verify-restored", "verify-fresh-quarantine-before-purge"):
        if verify_usage[label]["hash_bytes"] < payload_bytes:
            raise FixtureError("verify did not account full payload hash reads")

    retained_manifest = _large_fixture(retained, log_bytes)
    retained_paths = _workspace_cli_paths(retained)
    profile_path = Path(retained_paths["profile"])
    profile_data = json.loads(profile_path.read_text())
    profile_data["current"].append("logs/completed-run.log")
    profile_data["reference_sources"][-1]["role"] = "current"
    profile_data["streaming_references"] = ["logs/completed-run.log"]
    write_json(profile_path, profile_data)
    retained_before = {rel: sha256_file(Path(retained_paths["project"]) / rel)
                       for rel in (*PROTECTED_FILES, *DISPOSABLE_FILES)}
    # CLI does not expose inner qualification on rejection. This is the single
    # read-only API sample used for the retained large-file coverage evidence.
    from fifan_maintenance import cleanup_policy
    from fifan_maintenance.project import load_config
    project = Path(retained_paths["project"])
    profile = cleanup_policy.load_profile(project, load_config(project), profile_path)
    request = json.loads(Path(retained_paths["request"]).read_text())
    contrast = cleanup_policy.qualify(profile, request)
    write_json(retained / "qualification-api.json", contrast)
    write_json(retained / "qualification-api-command.json", {"execution": "single in-process read-only policy.qualify sample",
               "python": sys.executable, "python_version": sys.version, "profile": str(profile_path),
               "request": retained_paths["request"], "exit_code": 0,
               "source": str(Path(cleanup_policy.__file__).resolve()),
               "source_sha256": sha256_file(Path(cleanup_policy.__file__))})
    if contrast["status"] != "Blocked" or not contrast["coverage"]["complete"] or contrast["reference_bytes_read"] < log_bytes:
        raise FixtureError("retained current log did not get full authorized streaming coverage and block cleanup")
    _call_cli(retained, cli, "retained-current-preview", ["cleanup", "preview", "--project", retained_paths["project"],
              "--profile", str(profile_path), "--request", retained_paths["request"],
              "--records-dir", retained_paths["records"], "--quarantine-root", retained_paths["quarantine"],
              "--plan", str(retained / "forbidden-plan.json")], expected_exit=2, expected_status="Blocked")
    retained_after = {rel: sha256_file(project / rel) for rel in retained_before}
    if retained_before != retained_after:
        raise FixtureError("retained control changed")
    if list(Path(retained_paths["quarantine"]).iterdir()) or list(Path(retained_paths["records"]).iterdir()):
        raise FixtureError("retained control created cleanup records or Q payload")
    result = {"status": "Passed", "execution": "real CLI plus one explicitly labeled retained-only API qualification sample",
              "log_bytes": log_bytes, "payload_manifest_bytes": payload_bytes, "payload_sha_coverage": sha_coverage,
              "inspect_body_bytes_read": inspected["body_bytes_read"], "inspect_candidate_hash_bytes": inspected["candidate_hash_bytes"],
              "preview_payload_hash_usage": "Unknown (manifest SHA coverage is recorded separately)",
              "qualification_reference_bytes_read": qualification["reference_bytes_read"],
              "qualification_retained_hash_usage": qualification["retained_hash_usage"],
              "verify_hash_usage": verify_usage, "hash_accounting_is_os_physical_io": False,
              "retained_api_reference_bytes_read": contrast["reference_bytes_read"],
              "retained_api_coverage_complete": contrast["coverage"]["complete"],
              "retained_cli_status": "Blocked", "retained_sha256_before": retained_before,
              "retained_sha256_after": retained_after, "protected_sha256": manifest["protected_sha256"],
              "cleanup_chain": chain, "model_calls": 0}
    write_json(workspace / "large-contract-summary.json", result)
    return result


def run_metadata_contract(workspace: Path, cli: Path, *, files: int = 20005) -> Dict[str, Any]:
    """New bounded metadata set; excludes/dirs consume work, no default hashing."""
    _new_workspace(workspace)
    project = workspace / "project"
    project.mkdir()
    for index in range(files):
        rel = "history/g{:04d}/entry-{:06d}.log".format(index // 100, index)
        _put(project, rel, b"synthetic historical entry\n")
    (project / "history/empty").mkdir(parents=True)
    _put(project, "cache/unvisited.bin", b"excluded content")
    _put(project, ".git/HEAD", b"synthetic protected repository metadata")
    write_json(project / ".fifan-maintenance.json", {"exclude": ["cache/**", "cache"]})
    data = {"schema_version": 1, "project_root": str(project.resolve()), "scan_roots": ["history"],
            "classifications": [{"path": "history", "role": "historical", "reason": "explicit closed synthetic dataset"}],
            "budgets": {"max_entries": max(1000, files * 3 + 100), "max_seconds": 120}}
    profile_path = workspace / "directory-profile.json"
    write_json(profile_path, data)
    base = ["directory", "census", "--project", str(project), "--profile", str(profile_path)]
    _call_cli(workspace, cli, "metadata-complete", base, expected_status="Passed")
    complete = _private(workspace, "metadata-complete")
    if complete["file_count"] != files or complete["hash_coverage"]["hash_bytes"] != 0 or complete["body_bytes_sent"] != 0:
        raise FixtureError("metadata-only complete census count/hash/output mismatch")
    if complete["coverage"]["work_entries"] <= files + complete["directory_count"]:
        raise FixtureError("directory/iteration work was not charged")
    data["scan_roots"] = ["history", "cache", ".git"]
    write_json(workspace / "excluded-profile.json", data)
    excluded_args = ["directory", "census", "--project", str(project), "--profile", str(workspace / "excluded-profile.json")]
    _call_cli(workspace, cli, "metadata-excluded", excluded_args, expected_status="Unknown")
    excluded = _private(workspace, "metadata-excluded")
    if excluded["coverage"]["excluded_entries"] != 2 or excluded["coverage"]["work_entries"] < complete["coverage"]["work_entries"] + 2:
        raise FixtureError("excluded roots did not consume metadata budget")
    data["budgets"]["max_entries"] = max(2, min(1000, files // 2))
    write_json(workspace / "limited-profile.json", data)
    _call_cli(workspace, cli, "metadata-limited", ["directory", "census", "--project", str(project),
              "--profile", str(workspace / "limited-profile.json")], expected_status="Unknown")
    limited = _private(workspace, "metadata-limited")
    if not limited["coverage"]["count_is_lower_bound"] or limited["coverage"]["work_entries"] != data["budgets"]["max_entries"]:
        raise FixtureError("limited census did not retain Unknown/lower-bound work limit")
    # Cleanup inspect explicitly exposes body reads=0 on the same new metadata set.
    cleanup_data = {"schema_version": 1, "project_root": str(project), "scan_roots": ["history"],
                    "budgets": {"max_entries": max(1000, files * 3 + 100), "max_seconds": 120}}
    write_json(workspace / "cleanup-metadata-profile.json", cleanup_data)
    _call_cli(workspace, cli, "metadata-inspect", ["cleanup", "inspect", "--project", str(project),
              "--profile", str(workspace / "cleanup-metadata-profile.json")], expected_status="Passed")
    inspect = _private(workspace, "metadata-inspect")
    if inspect["body_bytes_read"] != 0 or inspect["candidate_hash_bytes"] != 0:
        raise FixtureError("metadata inspect read/hash bodies")
    summary = {"status": "Passed", "synthetic_files": files, "directory_count": complete["directory_count"],
               "complete_work_entries": complete["coverage"]["work_entries"],
               "excluded_entries": excluded["coverage"]["excluded_entries"], "excluded_work_entries": excluded["coverage"]["work_entries"],
               "limited_work_entries": limited["coverage"]["work_entries"], "limited_file_count": limited["file_count"],
               "limited_status": limited["status"], "limited_count_is_lower_bound": limited["coverage"]["count_is_lower_bound"],
               "body_bytes_read": inspect["body_bytes_read"], "default_hash_bytes": complete["hash_coverage"]["hash_bytes"],
               "body_bytes_sent": complete["body_bytes_sent"], "logical_bytes_are_physical_release": False}
    write_json(workspace / "metadata-contract-summary.json", summary)
    return summary


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--run-small-contract", action="store_true")
    mode.add_argument("--run-large-contract", action="store_true", help="D log lifecycle and retained-current streaming contrast; default 45MiB")
    mode.add_argument("--run-metadata-contract", action="store_true", help="bounded metadata-only set; default 20005 historical files")
    parser.add_argument("--workspace", type=Path, help="fresh workspace within authorized forward evidence")
    parser.add_argument("--cli", type=Path, default=ROOT / "bin/fifan-maintain", help="source or installed fifan-maintain executable")
    parser.add_argument("--log-bytes", type=int, default=None, help="large default45MiB, other modes default4096; tiny calibration may override")
    parser.add_argument("--metadata-files", type=int, default=20005)
    args = parser.parse_args(list(argv) if argv is not None else None)
    log_bytes = args.log_bytes if args.log_bytes is not None else (45 * 1024 * 1024 if args.run_large_contract else 4096)
    if log_bytes < 0 or (args.run_large_contract and log_bytes == 0) or log_bytes > 128 * 1024 * 1024 or not 1 <= args.metadata_files <= 100000:
        parser.error("log bytes must be 1..128MiB and metadata files 1..100000")
    FORWARD.mkdir(parents=True, exist_ok=True)
    prefix = "large-" if args.run_large_contract else "metadata-" if args.run_metadata_contract else "driver-checks-"
    workspace = args.workspace or Path(tempfile.mkdtemp(prefix=prefix, dir=str(FORWARD)))
    workspace = workspace.resolve()
    if workspace != FORWARD.resolve() and not workspace.is_relative_to(FORWARD.resolve()):
        parser.error("workspace must be inside authorized forward evidence")
    try:
        if not args.cli.is_file():
            raise FixtureError("selected CLI does not exist")
        if args.run_large_contract:
            summary = run_large_contract(workspace, args.cli, log_bytes=log_bytes)
            name = "large-contract-summary.json"
        elif args.run_metadata_contract:
            summary = run_metadata_contract(workspace, args.cli, files=args.metadata_files)
            name = "metadata-contract-summary.json"
        elif args.run_small_contract:
            summary = run_small_contract(workspace, args.cli, log_bytes=log_bytes)
            name = "small-contract-summary.json"
        else:
            summary = prepare_fixture(workspace, log_bytes=log_bytes)
            name = "fixture-manifest.json"
        print(json.dumps({"status": summary.get("status", "Prepared"), "summary": str(workspace / name)}, sort_keys=True))
        return 0
    except Exception as exc:
        write_json(workspace / "driver-failure.json", {"status": "Failed", "error_type": type(exc).__name__, "message": str(exc),
                   "python": sys.executable, "argv": list(argv) if argv is not None else sys.argv[1:]})
        parser.exit(2, "driver failed; evidence {}: {}\n".format(workspace, exc))


if __name__ == "__main__":
    raise SystemExit(main())
