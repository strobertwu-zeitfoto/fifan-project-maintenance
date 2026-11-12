#!/usr/bin/env python3
"""Prepare and run offline 1.3-origin compatibility against the v1.4 wheel.

Published 1.3 and the frozen current-1.3 snapshot are distinct origins. This
The --run path upgrades only the already-preserved synthetic 1.3 environments
in place and consumes their existing v1/v2/session/directory records. It never
recreates source material or invokes target project scripts.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Dict, Optional

import validate_v14 as fixture
import validate_v13_compat as legacy_driver

ROOT = fixture.ROOT
COMPAT_ROOT = ROOT / "evidence/validation/v1.4"
OLD_RELEASE_WHEEL = ROOT / "evidence/validation/v1.3/wheels-release/fifan_project_maintenance-1.3.0-py3-none-any.whl"
CURRENT_13_WHEEL = COMPAT_ROOT / "baseline-current13/wheels/fifan_project_maintenance-1.3.0-py3-none-any.whl"
CURRENT_13_MANIFEST = COMPAT_ROOT / "baseline-current13/manifest.json"
CURRENT_13_MATCH = COMPAT_ROOT / "baseline-current13/wheel-source-match.json"
OFFLINE_WHEEL_DIRS = [ROOT / "evidence/validation/wheels", ROOT / "evidence/validation/v1.2/dependencies"]
DEFAULT_PYTHONS = [ROOT / ".venv39/bin/python", ROOT / ".venv/bin/python"]


def sha256_file(path: Path) -> str:
    return fixture.sha256_file(path)


def write_json(path: Path, value: Any) -> None:
    fixture.write_json(path, value)


def _extend_compat_project(workspace: Path, origin: str, wheel: Path) -> Dict[str, Any]:
    manifest_path = workspace / "fixture-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    project = Path(manifest["roots"]["project"])
    extra = {
        "legacy-v1.md": b"# Legacy v1\n\nlegacy-v1-original\n",
        "legacy-v2.md": b"# Legacy v2\n\nlegacy-v2-original\n",
        "legacy-session.md": b"# Legacy session\n\nlegacy-session-original\n",
        "archive-source.md": b"# Archived source\n\narchive-content-original\n",
    }
    for rel, data in extra.items():
        fixture._put(project, rel, data)
    manifest["compatibility_origin"] = origin
    manifest["source_wheel"] = str(wheel.resolve())
    manifest["source_wheel_sha256"] = sha256_file(wheel)
    manifest["compatibility_sources"] = sorted(extra)
    manifest["compatibility_original_sha256"] = {
        rel: sha256_file(project / rel) for rel in sorted(extra)
    }
    manifest["protected_sha256"].update({
        rel: sha256_file(project / rel) for rel in fixture.PROTECTED_FILES
    })
    manifest["project_metadata_snapshot"] = fixture._root_snapshot(project)
    manifest["compatibility_status"] = "prepared; legacy wheel CLI generation not run"
    write_json(manifest_path, manifest)
    return manifest


def prepare(results: Path) -> Dict[str, Any]:
    if results.exists() and any(results.iterdir()):
        raise fixture.FixtureError("refusing to overwrite non-empty compat evidence")
    results.mkdir(parents=True, exist_ok=True)
    origins = []
    for name, wheel in (("published-v13", OLD_RELEASE_WHEEL), ("current-v13-baseline", CURRENT_13_WHEEL)):
        if not wheel.is_file():
            raise fixture.FixtureError("required real 1.3 wheel is missing: {}".format(wheel))
        workspace = results / name
        manifest = fixture.prepare_fixture(workspace)
        manifest = _extend_compat_project(workspace, name, wheel)
        origins.append({"origin": name, "wheel": str(wheel.resolve()),
                        "wheel_sha256": sha256_file(wheel),
                        "manifest": str((workspace / "fixture-manifest.json").resolve()),
                        "project": manifest["roots"]["project"],
                        "records": manifest["roots"]["records_dir"],
                        "quarantine": manifest["roots"]["quarantine_root"],
                        "legacy_records": "Not run"})
    snapshot_manifest = json.loads(CURRENT_13_MANIFEST.read_text(encoding="utf-8"))
    result = {"status": "Prepared", "schema_version": 1,
              "published_13_wheel_sha256": sha256_file(OLD_RELEASE_WHEEL),
              "current_13_wheel_sha256": sha256_file(CURRENT_13_WHEEL),
              "current_13_snapshot_manifest": str(CURRENT_13_MANIFEST.resolve()),
              "current_13_wheel_source_match": str(CURRENT_13_MATCH.resolve()),
              "current_13_wheel_source_match_sha256": sha256_file(CURRENT_13_MATCH),
              "current_13_source_version": snapshot_manifest.get("version"),
              "origins": origins,
              "required_old_materials": ["v1 plan/journal", "v2 plan/journal", "session and reverse recovery plan",
                                         "search journal", "archive journal", "restore plan"],
              "old_cli_material_generation": "Not run",
              "upgrade_to_final_14": "Not run"}
    write_json(results / "prepared-summary.json", result)
    return result


def _record_command(argv, log_dir: Path, label: str, *, expected=(0,)) -> Dict[str, Any]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PIP_NO_INDEX": "1",
                "PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    completed = subprocess.run([str(item) for item in argv], cwd=str(ROOT), env=env,
                               capture_output=True, text=True)
    record = {"name": label, "argv": [str(item) for item in argv],
              "exit_code": completed.returncode, "expected_exit_codes": list(expected),
              "stdout": completed.stdout, "stderr": completed.stderr,
              "passed": completed.returncode in expected}
    output = log_dir / (label + ".command.json")
    attempt = 1
    while output.exists():
        attempt += 1
        output = log_dir / (label + "-attempt-{}".format(attempt) + ".command.json")
    write_json(output, record)
    if not record["passed"]:
        raise fixture.FixtureError("{} returned {}; see {}".format(label, completed.returncode, log_dir))
    return record


def _run_cli(tool: Path, project: Path, records: Path, label: str, args, *, expected=(0,)) -> Dict[str, Any]:
    result = _record_command([tool, *args], records / "commands", label, expected=expected)
    try:
        result["json"] = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        raise fixture.FixtureError("{} stdout was not JSON".format(label)) from exc
    return result


def _legacy_file_governance(tool: Path, run_root: Path) -> Dict[str, Any]:
    project, records, manifest = legacy_driver.prepare(run_root / "file-governance")
    logs = records / "commands"
    logs.mkdir()
    common = ["--project", str(project.resolve())]
    profile1 = records / "profile1.json"
    parent2 = records / "parent-profile2.json"
    derived = records / "derived-profile2.json"
    _run_cli(tool, project, records, "derive-profile2", ["profile", "derive", *common,
              "--from", str(parent2), "--sources", "README.md", "guide.md",
              "--checks", "links", "--output", str(derived)])
    report = records / "legacy-check-report.json"
    _run_cli(tool, project, records, "check-report", ["check", *common, "--task-profile", str(profile1),
              "--checks", "links", "--format", "json", "--output", str(report)])

    journals: Dict[str, Path] = {}
    def apply_old(label, request_path: Path, request: Optional[Dict[str, Any]] = None):
        if request is not None:
            write_json(request_path, request)
        plan = records / (label + "-plan.json")
        operations = records / (label + "-operations")
        _run_cli(tool, project, records, label + "-preview", ["preview", *common,
                  "--request", str(request_path), "--plan", str(plan)])
        _run_cli(tool, project, records, label + "-apply", ["apply", *common,
                  "--plan", str(plan), "--operations-dir", str(operations)])
        found = sorted(operations.glob("*.json"))
        if len(found) != 1:
            raise fixture.FixtureError("{} did not create one journal".format(label))
        journal = found[0]
        version = json.loads(journal.read_text(encoding="utf-8"))["plan"]["version"]
        expected_version = 2 if label.endswith("v2") else 1
        if version != expected_version:
            raise fixture.FixtureError("{} emitted plan version {}, expected {}".format(label, version, expected_version))
        verify = _run_cli(tool, project, records, label + "-verify", ["verify", *common,
                            "--journal", str(journal)])
        if verify["json"].get("status") != "Passed":
            raise fixture.FixtureError("{} old journal did not verify".format(label))
        journals[label] = journal
        return journal

    def v2_request(path: str, destination: str, old: str, new: str):
        return {"version": 2, "operations": [
            {"kind": "snapshot", "path": path, "destination": destination,
             "expected_sha256": sha256_file(project / path),
             "origin": {"reference_base": ".", "classification_basis": "synthetic legacy 1.3 compatibility"}},
            {"type": "replace", "path": path, "old": old, "new": new},
        ], "guards": []}

    requests = {label: records / (label + "-request.json") for label in
                ("standalone-v1", "standalone-v2", "chain-v1", "chain-v2")}
    apply_old("standalone-v1", requests["standalone-v1"])
    apply_old("standalone-v2", requests["standalone-v2"],
              v2_request("standalone-v2.md", "archive/standalone-before.md", "old-two", "new-two"))
    apply_old("chain-v1", requests["chain-v1"])
    apply_old("chain-v2", requests["chain-v2"],
              v2_request("chain.md", "archive/chain-before.md", "phase-first", "phase-second"))
    session = records / "session.json"
    write_json(session, {"schema_version": 1, "root": str(project.resolve()),
                         "journals": [str(journals["standalone-v1"]), str(journals["standalone-v2"]),
                                      str(journals["chain-v1"]), str(journals["chain-v2"])],
                         "reports": [str(report)],
                         "profiles": [{"path": str(profile1), "root": str(project.resolve())},
                                      {"path": str(derived), "root": str(project.resolve())}]})
    recovery = records / "recovery-preview.json"
    for action in ("report", "verify", "recovery-preview"):
        output = recovery if action == "recovery-preview" else records / ("session-" + action + ".json")
        value = _run_cli(tool, project, records, "session-" + action,
                         ["session", action, *common, "--session", str(session), "--output", str(output)])
        if value["json"].get("status") != "Passed":
            raise fixture.FixtureError("legacy session {} did not pass".format(action))
    selected = json.loads(recovery.read_text(encoding="utf-8"))
    expected_order = [str(journals[label]) for label in
                      ("chain-v2", "chain-v1", "standalone-v2", "standalone-v1")]
    if [item["path"] for item in selected.get("steps", [])] != expected_order:
        raise fixture.FixtureError("legacy session recovery preview was not reverse-ordered")
    materials = {str(path): sha256_file(path) for path in
                 (derived, report, recovery, session, profile1, *journals.values())}
    return {"status": "Passed", "project": str(project.resolve()), "records": str(records.resolve()),
            "original_sha256": manifest["original_sha256"],
            "journal_paths": {label: str(path.resolve()) for label, path in journals.items()},
            "session": str(session.resolve()), "recovery_plan": str(recovery.resolve()),
            "recovery_plan_sha256": sha256_file(recovery), "material_sha256": materials,
            "state_before_upgrade": "Applied; recovery not yet run"}


def _legacy_directory_materials(tool: Path, run_root: Path) -> Dict[str, Any]:
    """Create one real 1.3 search journal and one archive journal plus restore plans."""
    project, archive, records = (run_root / name for name in ("project", "archive-root", "records"))
    results = run_root / "results"
    for root in (project, archive, records, results):
        root.mkdir(parents=True)
    contents = {
        "README.md": b"# Compatibility fixture\n\nSee [plan](PLAN.md) and [decision](DECISIONS.md).\n",
        "PLAN.md": b"# Plan\n\nKeep this synthetic fixture unchanged.\n",
        "DECISIONS.md": b"# Decision\n\nSynthetic fixture only.\n",
        "current.md": b"Current entry remains protected.\n",
        "closure.md": b"Explicitly closed synthetic archive batch.\n",
        ".ignore": b"# Existing user rule\n!README.md\n",
        ".vscode/settings.json": b'{\n  "search.exclude": {}\n}\n',
        "src/current_entry.py": b"# Synthetic entry; never execute.\n",
        "Assets/fixture.asset": b"Protected synthetic asset.\n",
        "Assets/fixture.asset.meta": b"fileFormatVersion: 2\nguid: synthetic-only\n",
        "history/closed/payload/nested.txt": b"Synthetic archived content.\n",
    }
    for rel, data in contents.items():
        fixture._put(project, rel, data)
    baseline = {rel: sha256_file(project / rel) for rel in
                ("README.md", "PLAN.md", "DECISIONS.md", "current.md", ".ignore",
                 ".vscode/settings.json", "src/current_entry.py", "Assets/fixture.asset",
                 "Assets/fixture.asset.meta", "history/closed/payload/nested.txt")}
    critical = ["README.md", "PLAN.md", "DECISIONS.md", "current.md", "src/current_entry.py"]
    profile = {
        "schema_version": 1, "project_root": str(project.resolve()), "preset": "generic",
        "scan_roots": ["."], "critical_paths": critical,
        "reference_sources": ([{"path": path, "role": "current"} for path in critical]
                              + [{"path": "closure.md", "role": "historical"}]),
        "classifications": ([{"path": path, "role": "keep", "reason": "Current fixture reference."}
                             for path in critical]
                            + [{"path": "history/closed/payload", "role": "historical",
                                "reason": "Explicitly closed synthetic batch."},
                               {"path": "history", "role": "historical",
                                "reason": "Synthetic legacy fixture history."},
                               {"path": "Assets", "role": "keep", "reason": "Protected synthetic asset."}]),
        "search": {"exclude": ["history"], "vscode": True, "watcher_exclude": False},
        "archive": {"archive_root": str(archive.resolve()), "records_dir": str(records.resolve()),
                    "candidates": ["history/closed/payload"], "require_no_open_handles": False},
        "budgets": {"max_entries": 1000, "max_seconds": 60, "max_depth": 16,
                    "max_output_bytes": 8192, "max_hash_entries": 20000,
                    "max_hash_bytes": 2147483648, "max_hash_file_bytes": 536870912,
                    "max_artifact_bytes": 33554432, "max_reference_bytes": 67108864,
                    "max_reference_file_bytes": 4194304, "max_reference_files": 20000},
    }
    profile_path = run_root / "directory-profile.json"
    request_path = run_root / "directory-request.json"
    closure_sha = sha256_file(project / "closure.md")
    request = {"schema_version": 1, "batches": [{
        "source": "history/closed/payload", "destination": "synthetic/closed/payload",
        "closure": {"decision": "closed", "reason": "Explicitly closed synthetic batch.",
                    "evidence": [{"path": "closure.md", "sha256": closure_sha}]},
        "known_absent": [{"path": "missing.lock", "reason": "Known absent in synthetic fixture."}],
    }]}
    write_json(profile_path, profile)
    write_json(request_path, request)
    common = ["--project", str(project.resolve()), "--profile", str(profile_path.resolve())]
    search_plan = results / "search-plan.json"
    search_preview = _run_cli(tool, project, results, "search-preview", ["directory", "search-preview", *common,
                                "--plan", str(search_plan.resolve())])
    search_apply = _run_cli(tool, project, results, "search-apply", ["directory", "apply", *common,
                              "--plan", str(search_plan.resolve()), "--records-dir", str(records.resolve())])
    search_journal = Path(search_apply["json"]["journal_path"])
    search_verify = _run_cli(tool, project, results, "search-verify", ["directory", "verify", *common,
                               "--journal", str(search_journal.resolve())])
    search_restore_plan = results / "search-restore-plan.json"
    _run_cli(tool, project, results, "search-restore-preview", ["directory", "restore-preview", *common,
              "--journal", str(search_journal.resolve()), "--plan", str(search_restore_plan.resolve())])
    search_restore = _run_cli(tool, project, results, "search-restore", ["directory", "restore", *common,
                                "--plan", str(search_restore_plan.resolve()), "--records-dir", str(records.resolve())])
    search_restored_verify = _run_cli(tool, project, results, "search-restored-verify", ["directory", "verify", *common,
                                         "--journal", str(search_journal.resolve())])
    if (search_verify["json"].get("state") != "Applied" or search_verify["json"].get("status") != "Passed"
            or search_restore["json"].get("state") != "Restored"
            or search_restored_verify["json"].get("status") != "Passed"):
        raise fixture.FixtureError("old 1.3 search journal did not verify and restore")

    archive_plan = results / "archive-plan.json"
    archive_preview = _run_cli(tool, project, results, "archive-preview", ["directory", "archive-preview", *common,
                               "--request", str(request_path.resolve()), "--archive-root", str(archive.resolve()),
                               "--records-dir", str(records.resolve()), "--plan", str(archive_plan.resolve())])
    archive_apply = _run_cli(tool, project, results, "archive-apply", ["directory", "apply", *common,
                             "--plan", str(archive_plan.resolve()), "--archive-root", str(archive.resolve()),
                             "--records-dir", str(records.resolve())])
    archive_journal = Path(archive_apply["json"]["journal_path"])
    archive_verify = _run_cli(tool, project, results, "archive-verify", ["directory", "verify", *common,
                                "--journal", str(archive_journal.resolve()), "--archive-root", str(archive.resolve())])
    archive_restore_plan = results / "archive-restore-plan.json"
    _run_cli(tool, project, results, "archive-restore-preview", ["directory", "restore-preview", *common,
              "--journal", str(archive_journal.resolve()), "--archive-root", str(archive.resolve()),
              "--plan", str(archive_restore_plan.resolve())])
    archive_restore = _run_cli(tool, project, results, "archive-restore", ["directory", "restore", *common,
                                "--plan", str(archive_restore_plan.resolve()), "--archive-root", str(archive.resolve()),
                                "--records-dir", str(records.resolve())])
    archive_restored_verify = _run_cli(tool, project, results, "archive-restored-verify", ["directory", "verify", *common,
                                         "--journal", str(archive_journal.resolve()), "--archive-root", str(archive.resolve())])
    final = {rel: sha256_file(project / rel) for rel in baseline}
    if (archive_verify["json"].get("state") != "Archived" or archive_verify["json"].get("status") != "Passed"
            or archive_restore["json"].get("state") != "Restored"
            or archive_restored_verify["json"].get("status") != "Passed" or final != baseline
            or (archive / "synthetic/closed/payload").exists()):
        raise fixture.FixtureError("old 1.3 archive journal did not verify and restore the original fixture")
    summary = {"status": "Passed", "project": str(project.resolve()), "archive_root": str(archive.resolve()),
               "records_root": str(records.resolve()), "profile_sha256": sha256_file(profile_path),
               "request_sha256": sha256_file(request_path), "project_original_sha256": baseline,
               "search": {"plan": str(search_plan.resolve()), "plan_sha256": sha256_file(search_plan),
                          "journal": str(search_journal.resolve()), "journal_sha256": sha256_file(search_journal),
                          "restore_plan": str(search_restore_plan.resolve()),
                          "restore_plan_sha256": sha256_file(search_restore_plan),
                          "verified": search_verify["json"]["status"],
                          "restored": search_restore["json"]["state"]},
               "archive": {"plan": str(archive_plan.resolve()), "plan_sha256": sha256_file(archive_plan),
                           "journal": str(archive_journal.resolve()), "journal_sha256": sha256_file(archive_journal),
                           "restore_plan": str(archive_restore_plan.resolve()),
                           "restore_plan_sha256": sha256_file(archive_restore_plan),
                           "verified": archive_verify["json"]["status"],
                           "restored": archive_restore["json"]["state"]},
               "all_original_hashes_match": final == baseline,
               "vscode_ui": "Not run", "business_scripts": "Not run"}
    write_json(run_root / "directory-legacy-summary.json", summary)
    return summary


def _current_appendix_material(tool: Path, run_root: Path, *, allow_mutation: bool = False) -> Dict[str, Any]:
    """Generate one small streaming/dynamic current-1.3 archive record set."""
    project, archive, records = (run_root / name for name in ("project", "archive", "records"))
    results = run_root / "results"
    for root in (project, archive, records, results):
        root.mkdir(parents=True)
    source = project / "evidence/run-1"
    source.mkdir(parents=True)
    (source / "payload.txt").write_bytes(b"synthetic candidate payload\r\n")
    (project / "current.md").write_text("Current entry remains protected.\n", encoding="utf-8")
    closure_bytes = b"Explicit closed appendix fixture decision\n"
    (project / "closure.md").write_bytes(closure_bytes)
    log_block = ("ordinary log 保留 " + "x" * 110 + "\n").encode("utf-8")
    log_size = 512 * 1024
    with (project / "Editor.log").open("wb") as stream:
        written = 0
        while written < log_size:
            block = log_block[:min(len(log_block), log_size - written)]
            stream.write(block)
            written += len(block)
    code = project / "consumer.py"
    code.write_text("".join('print(f\"diagnostic {}\")\n'.format(index) for index in range(3)),
                     encoding="utf-8")
    original = {
        path.relative_to(project).as_posix(): sha256_file(path)
        for path in (project / "current.md", project / "closure.md", project / "Editor.log", code,
                     source / "payload.txt")
    }
    profile = {
        "schema_version": 1, "project_root": str(project.resolve()), "scan_roots": ["."],
        "critical_paths": ["current.md"],
        "reference_sources": [
            {"path": "closure.md", "role": "historical"},
            {"path": "current.md", "role": "current"},
            {"path": "Editor.log", "role": "historical"},
            {"path": "consumer.py", "role": "current"},
        ],
        "classifications": [{"path": "evidence/run-1", "role": "historical",
                             "reason": "Explicit closed appendix fixture"}],
        "streaming_references": ["Editor.log"],
        "archive": {"archive_root": str(archive.resolve()), "records_dir": str(records.resolve()),
                    "candidates": ["evidence/run-1"], "require_no_open_handles": True},
        "budgets": {"max_seconds": 300},
    }
    profile_path, request_path = run_root / "profile.json", run_root / "request.json"
    request = {"schema_version": 1, "batches": [{
        "source": "evidence/run-1", "destination": "fixture/run-1",
        "closure": {"decision": "closed", "reason": "Explicit closed appendix fixture",
        "evidence": [{"path": "closure.md", "sha256": fixture.sha256_bytes(closure_bytes)}]},
        "known_absent": [{"path": "previously-missing.lock", "reason": "Known missing before this operation"}],
    }]}
    write_json(profile_path, profile)
    write_json(request_path, request)
    logs = results / "commands"
    logs.mkdir()
    common = ["--project", str(project.resolve()), "--profile", str(profile_path.resolve())]
    before_output = results / "dynamic-before.json"
    before = _run_cli(tool, project, logs, "dynamic-before", ["directory", "impact", *common,
                        "--request", str(request_path.resolve()), "--output", str(before_output.resolve())])
    value = before["json"]
    dynamic = [item for item in value["batches"][0]["unknowns"]
               if item.get("reason_code") == "DYNAMIC_REFERENCE_UNKNOWN"]
    if len(dynamic) != 3 or value.get("status") != "Unknown":
        raise fixture.FixtureError("current 1.3 baseline did not preserve all three dynamic Unknown entries")
    request["batches"][0]["dynamic_reference_resolutions"] = [
        {**{key: item[key] for key in ("path", "sha256", "line", "column", "line_sha256", "expression_sha256")},
         "source": request["batches"][0]["source"],
         "reason": "Reviewed display-only diagnostic expression, unrelated to this archive candidate",
         "evidence": request["batches"][0]["closure"]["evidence"]}
        for item in dynamic
    ]
    write_json(request_path, request)
    after_output = results / "dynamic-resolved-impact.json"
    after = _run_cli(tool, project, logs, "dynamic-resolved-impact", ["directory", "impact", *common,
                        "--request", str(request_path.resolve()), "--output", str(after_output.resolve())])
    if after["json"].get("status") != "Passed" or after["json"]["batches"][0].get("eligible") is not True:
        raise fixture.FixtureError("resolved current-baseline impact did not qualify the unchanged candidate")
    plan_path = results / "archive-plan.json"
    preview = _run_cli(tool, project, logs, "archive-preview", ["directory", "archive-preview", *common,
                          "--request", str(request_path.resolve()), "--archive-root", str(archive.resolve()),
                          "--records-dir", str(records.resolve()), "--plan", str(plan_path.resolve())])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    # directory archive-preview reports an impact/eligibility summary, not a
    # generic Preview status. A successful command plus a complete, qualified
    # impact result is the meaningful precondition; the output plan itself is
    # still retained for later compatibility work.
    impact = plan.get("impact", {})
    batches = impact.get("batches", [])
    if (preview["exit_code"] != 0 or not plan_path.is_file()
            or plan.get("format") != "fifan-directory-plan"
            or not isinstance(plan.get("fingerprint"), str) or len(plan["fingerprint"]) != 64
            or not isinstance(plan.get("request_sha256"), str) or len(plan["request_sha256"]) != 64
            or impact.get("status") != "Passed" or impact.get("coverage", {}).get("complete") is not True
            or len(batches) != 1 or batches[0].get("eligible") is not True
            or not plan.get("request", {}).get("batches", [{}])[0].get("dynamic_reference_resolutions")):
        raise fixture.FixtureError("current baseline archive preview did not produce a qualified plan")
    # Mutation remains an explicit later gate. This preparation stage records
    # the qualified plan but does not archive or restore the source directory.
    preview_receipt = {"status": "PreviewReady", "root": str(run_root.resolve()),
            "package_version": "1.3.0 plus current streaming/dynamic fixes",
            "streaming_reference": "Editor.log", "streaming_log_bytes": (project / "Editor.log").stat().st_size,
            "body_read_bytes": impact.get("coverage", {}).get("reference_bytes_read"),
            "dynamic_unknown_before": len(dynamic), "dynamic_resolved_after": len(request["batches"][0]["dynamic_reference_resolutions"]),
            "initial_impact_status": value["status"], "resolved_impact_status": after["json"]["status"],
            "archive_impact_status": impact["status"], "archive_plan": str(plan_path.resolve()),
            "archive_plan_sha256": sha256_file(plan_path), "archive_mutation": "Not run; waiting for archive API freeze"}
    if not allow_mutation:
        return preview_receipt
    apply = _run_cli(tool, project, logs, "archive-apply", ["directory", "apply", *common,
                       "--plan", str(plan_path.resolve()), "--archive-root", str(archive.resolve()),
                       "--records-dir", str(records.resolve())])
    journal_path = Path(apply["json"]["journal_path"])
    verified = _run_cli(tool, project, logs, "archive-verify", ["directory", "verify", *common,
                           "--journal", str(journal_path.resolve()), "--archive-root", str(archive.resolve())])
    restore_plan_path = results / "archive-restore-plan.json"
    restore_preview = _run_cli(tool, project, logs, "archive-restore-preview", ["directory", "restore-preview", *common,
                                   "--journal", str(journal_path.resolve()), "--archive-root", str(archive.resolve()),
                                   "--plan", str(restore_plan_path.resolve())])
    restore_plan = json.loads(restore_plan_path.read_text(encoding="utf-8"))
    restored = _run_cli(tool, project, logs, "archive-restore", ["directory", "restore", *common,
                            "--plan", str(restore_plan_path.resolve()), "--archive-root", str(archive.resolve()),
                            "--records-dir", str(records.resolve())])
    final_verify = _run_cli(tool, project, logs, "archive-verify-restored", ["directory", "verify", *common,
                                "--journal", str(journal_path.resolve()), "--archive-root", str(archive.resolve())])
    final_hashes = {path: sha256_file(project / path) for path in original}
    if (verified["json"].get("status") != "Passed" or restored["json"].get("state") != "Restored"
            or final_verify["json"].get("status") != "Passed" or final_hashes != original
            or not plan.get("request", {}).get("batches", [{}])[0].get("dynamic_reference_resolutions")
            or not restore_plan.get("journal_fingerprint")):
        raise fixture.FixtureError("current baseline streaming/dynamic archive records failed restoration checks")
    return {"status": "Passed", "root": str(run_root.resolve()),
            "package_version": "1.3.0 plus current streaming/dynamic fixes",
            "streaming_reference": "Editor.log", "streaming_log_bytes": (project / "Editor.log").stat().st_size,
            "body_read_bytes": after["json"].get("coverage", {}).get("reference_bytes_read"),
            "dynamic_unknown_before": len(dynamic), "dynamic_resolved_after": len(request["batches"][0]["dynamic_reference_resolutions"]),
            "initial_impact_status": value["status"], "resolved_impact_status": after["json"]["status"],
            "archive_status": verified["json"].get("status"), "restored_state": restored["json"].get("state"),
            "restored_verify_status": final_verify["json"].get("status"),
            "plan": str(plan_path.resolve()), "plan_sha256": sha256_file(plan_path),
            "journal": str(journal_path.resolve()), "journal_sha256": sha256_file(journal_path),
            "restore_plan": str(restore_plan_path.resolve()), "restore_plan_sha256": sha256_file(restore_plan_path),
            "restored_source_sha256": final_hashes, "original_source_sha256": original}


def rearchive_current_appendix(results: Path, appendix: Path) -> Dict[str, Any]:
    """Create an additional real 1.3 Archived journal from an existing tiny appendix."""
    results = results.resolve()
    appendix = appendix.resolve()
    if results not in appendix.parents or "current-v13-baseline" not in appendix.parts:
        raise fixture.FixtureError("appendix must stay within the selected current-baseline results tree")
    tool = appendix.parent / "venv/bin/fifan-maintain"
    project, archive, records = (appendix / name for name in ("project", "archive", "records"))
    profile, request = appendix / "profile.json", appendix / "request.json"
    for path in (tool, project, archive, records, profile, request):
        if not path.exists():
            raise fixture.FixtureError("current appendix is incomplete: {}".format(path))
    if _record_command([tool, "--version"], appendix, "rearchive-source-version")["stdout"].strip() != "1.3.0":
        raise fixture.FixtureError("rearchive must run in the preserved real 1.3 environment")
    plan_path = appendix / "results/current-compat-rearchive-plan.json"
    journal_summary_path = appendix / "current-compat-rearchive-summary.json"
    payload = project / "evidence/run-1/payload.txt"
    common = ["--project", str(project), "--profile", str(profile)]
    if journal_summary_path.exists():
        raise fixture.FixtureError("a current 1.3 archive append summary already exists; refusing overwrite")
    restore_plan_path = appendix / "results/current-compat-rearchive-restore-plan.json"
    restore_preview_result = None
    if not plan_path.is_file():
        if not payload.is_file():
            raise fixture.FixtureError("candidate payload is absent before the first archive preview")
        before = {"evidence/run-1/payload.txt": sha256_file(payload),
                  "current.md": sha256_file(project / "current.md"),
                  "Editor.log": sha256_file(project / "Editor.log"),
                  "closure.md": sha256_file(project / "closure.md"),
                  "consumer.py": sha256_file(project / "consumer.py")}
        preview = _run_cli(tool, project, appendix / "rearchive-commands", "current-compat-rearchive-preview",
            ["directory", "archive-preview", *common, "--request", str(request), "--archive-root", str(archive),
             "--records-dir", str(records), "--plan", str(plan_path)])
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        if preview["exit_code"] != 0:
            raise fixture.FixtureError("1.3 archive-preview exited unsuccessfully")
        applied = _run_cli(tool, project, appendix / "rearchive-commands", "current-compat-rearchive-apply",
            ["directory", "apply", *common, "--plan", str(plan_path), "--archive-root", str(archive),
             "--records-dir", str(records)])
        journal = Path(applied["json"]["journal_path"])
    else:
        # Resume the candidate and operation generated by the earlier preview
        # attempt; don't rewrite either sealed artifact or rebuild this source.
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        origin_receipt = json.loads((appendix / "compat-archive-restore-summary.json").read_text(encoding="utf-8"))
        before = origin_receipt["original_source_sha256"]
        journal = records / (plan["operation_id"] + ".directory.json")
        if not journal.is_file():
            raise fixture.FixtureError("sealed 1.3 archive plan has no matching journal")
    impact, batches = plan.get("impact", {}), plan.get("impact", {}).get("batches", [])
    if (plan.get("format") != "fifan-directory-plan"
            or len(str(plan.get("fingerprint", ""))) != 64 or impact.get("status") != "Passed"
            or impact.get("coverage", {}).get("complete") is not True
            or len(batches) != 1 or batches[0].get("eligible") is not True):
        raise fixture.FixtureError("current 1.3 rearchive did not yield a qualified sealed plan")
    verified = _run_cli(tool, project, appendix / "rearchive-commands", "resume-current-compat-rearchive-verify",
        ["directory", "verify", *common, "--journal", str(journal), "--archive-root", str(archive)])
    if not restore_plan_path.exists():
        restore_preview_result = _run_cli(tool, project, appendix / "rearchive-commands", "current-compat-rearchive-restore-preview",
            ["directory", "restore-preview", *common, "--journal", str(journal), "--archive-root", str(archive),
             "--plan", str(restore_plan_path)])
    restore_plan = json.loads(restore_plan_path.read_text(encoding="utf-8"))
    destination = archive / batches[0]["destination"]
    manifest_entries = batches[0].get("manifest", {}).get("entries", [])
    archived_paths = []
    for entry in manifest_entries:
        rel = entry.get("path", ".")
        target = destination if rel == "." else destination / rel
        if entry.get("kind") == "file":
            if not target.is_file() or sha256_file(target) != entry.get("sha256"):
                raise fixture.FixtureError("archived payload did not match its original 1.3 manifest")
        elif entry.get("kind") == "directory" and not target.is_dir():
            raise fixture.FixtureError("archived directory structure is incomplete")
        archived_paths.append(str(target))
    archived_payload = destination / "payload.txt"
    after = {"current.md": sha256_file(project / "current.md"),
             "Editor.log": sha256_file(project / "Editor.log"),
             "closure.md": sha256_file(project / "closure.md"),
             "consumer.py": sha256_file(project / "consumer.py")}
    if (verified["json"].get("status") != "Passed" or verified["json"].get("state") != "Archived"
            or not restore_plan.get("journal_fingerprint")
            or restore_plan.get("journal_fingerprint") != json.loads(journal.read_text(encoding="utf-8"))["fingerprint"]
            or payload.exists() or not archived_payload.is_file()
            or sha256_file(archived_payload) != before["evidence/run-1/payload.txt"]
            or after != {k: v for k, v in before.items() if k != "evidence/run-1/payload.txt"}):
        raise fixture.FixtureError("current 1.3 rearchive did not retain its candidate and protected sources")
    summary = {"status": "Passed", "python": _version_of(appendix.parent / "venv/bin/python", appendix,
                    "rearchive-python-version"), "tool_version": "1.3.0",
                "project": str(project), "archive_root": str(archive), "records_root": str(records),
                "plan": str(plan_path), "plan_sha256": sha256_file(plan_path),
                "journal": str(journal), "journal_sha256": sha256_file(journal),
                "restore_plan": str(restore_plan_path), "restore_plan_sha256": sha256_file(restore_plan_path),
                "archive_state": verified["json"]["state"], "restore_preview_format": restore_plan.get("format"),
                "before_source_sha256": before, "archived_payload_sha256": sha256_file(archived_payload),
                "archived_manifest_paths": archived_paths,
                "unchanged_current_sha256": after, "restoration": "Not run; preserve Archived for 1.4 upgrade"}
    write_json(journal_summary_path, summary)
    return summary


def complete_current_preview(tool: Path, appendix: Path) -> Dict[str, Any]:
    """Apply/verify/restore a preserved current-1.3 preview in its own fixture."""
    appendix = appendix.resolve()
    prior_summary = appendix / "compat-archive-restore-summary.json"
    if prior_summary.is_file():
        receipt = json.loads(prior_summary.read_text(encoding="utf-8"))
        project = appendix / "project"
        actual = {rel: sha256_file(project / rel) for rel in receipt["original_source_sha256"]}
        if receipt.get("status") != "Passed" or actual != receipt.get("original_source_sha256"):
            raise fixture.FixtureError("prior restore receipt no longer matches source fixture hashes")
        return receipt
    project, archive, records = (appendix / name for name in ("project", "archive", "records"))
    profile_path, request_path = appendix / "profile.json", appendix / "request.json"
    plan_path = appendix / "results/archive-plan.json"
    for path in (project, archive, records, profile_path, request_path, plan_path):
        if not path.exists():
            raise fixture.FixtureError("existing preview fixture is incomplete: {}".format(path))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    impact = plan.get("impact", {})
    batches = impact.get("batches", [])
    if (plan.get("format") != "fifan-directory-plan" or len(str(plan.get("fingerprint", ""))) != 64
            or impact.get("status") != "Passed" or impact.get("coverage", {}).get("complete") is not True
            or len(batches) != 1 or batches[0].get("eligible") is not True):
        raise fixture.FixtureError("preserved current preview is not a qualified sealed plan")
    original = {
        rel: sha256_file(project / rel)
        for rel in ("current.md", "closure.md", "Editor.log", "consumer.py", "evidence/run-1/payload.txt")
    }
    logs = appendix / "commands-resume"
    logs.mkdir()
    common = ["--project", str(project), "--profile", str(profile_path)]
    apply = _run_cli(tool, project, logs, "archive-apply", ["directory", "apply", *common,
                       "--plan", str(plan_path), "--archive-root", str(archive), "--records-dir", str(records)])
    journal_path = Path(apply["json"]["journal_path"])
    verified = _run_cli(tool, project, logs, "archive-verify", ["directory", "verify", *common,
                           "--journal", str(journal_path), "--archive-root", str(archive)])
    restore_plan_path = appendix / "results/archive-restore-plan.json"
    _run_cli(tool, project, logs, "archive-restore-preview", ["directory", "restore-preview", *common,
              "--journal", str(journal_path), "--archive-root", str(archive), "--plan", str(restore_plan_path)])
    restore_plan = json.loads(restore_plan_path.read_text(encoding="utf-8"))
    restored = _run_cli(tool, project, logs, "archive-restore", ["directory", "restore", *common,
                            "--plan", str(restore_plan_path), "--archive-root", str(archive),
                            "--records-dir", str(records)])
    final = _run_cli(tool, project, logs, "archive-verify-restored", ["directory", "verify", *common,
                       "--journal", str(journal_path), "--archive-root", str(archive)])
    after = {rel: sha256_file(project / rel) for rel in original}
    receipt = {
        "status": "Passed" if verified["json"].get("status") == "Passed"
            and restored["json"].get("state") == "Restored" and final["json"].get("status") == "Passed"
            and after == original else "Failed",
        "python": _record_command([tool.parent / "python", "-I", "-B", "-c",
                                   "import sys; print('{}.{}'.format(*sys.version_info[:2]))"],
                                  appendix, "resume-interpreter-version")["stdout"].strip(),
        "plan_fingerprint": plan["fingerprint"], "plan_sha256": sha256_file(plan_path),
        "journal": str(journal_path), "journal_sha256": sha256_file(journal_path),
        "restore_plan": str(restore_plan_path), "restore_plan_sha256": sha256_file(restore_plan_path),
        "archive_verify": verified["json"].get("status"), "restore_state": restored["json"].get("state"),
        "restored_verify": final["json"].get("status"), "original_source_sha256": original,
        "restored_source_sha256": after,
    }
    write_json(appendix / "compat-archive-restore-summary.json", receipt)
    if receipt["status"] != "Passed":
        raise fixture.FixtureError("current 1.3 archive restore failed its state/hash assertions")
    return receipt


def generate_legacy(results: Path, python_executables) -> Dict[str, Any]:
    """Generate published 1.3 legacy records and current-baseline appendix material offline."""
    if results.exists() and any(results.iterdir()):
        raise fixture.FixtureError("refusing to overwrite non-empty compat evidence")
    results.mkdir(parents=True, exist_ok=True)
    origins = (("published-v13", OLD_RELEASE_WHEEL), ("current-v13-baseline", CURRENT_13_WHEEL))
    summaries = []
    for origin, wheel in origins:
        if not wheel.is_file():
            raise fixture.FixtureError("required real 1.3 wheel is missing: {}".format(wheel))
        for python in python_executables:
            # Derive the tag from the verified venv directory before resolving
            # its interpreter symlink (which otherwise loses the venv name).
            python = python.absolute()
            env_name = python.parent.parent.name
            if env_name == ".venv39":
                tag = "python39"
            elif env_name == ".venv":
                tag = "python312"
            else:
                version = _record_command([python, "-I", "-B", "-c",
                    "import sys; print('python{}{}'.format(sys.version_info[0], sys.version_info[1]))"],
                    results, "interpreter-version")
                tag = version["stdout"].strip()
            python = python.resolve()
            run_root = results / origin / tag
            if run_root.exists() and any(run_root.iterdir()):
                raise fixture.FixtureError("compat run already exists; preserve it: {}".format(run_root))
            run_root.mkdir(parents=True)
            for directory in OFFLINE_WHEEL_DIRS:
                if not directory.is_dir():
                    raise fixture.FixtureError("offline wheelhouse unavailable: {}".format(directory))
            venv = run_root / "venv"
            _record_command([python, "-I", "-B", "-m", "venv", venv], run_root, "create-venv")
            wheel_python = venv / "bin/python"
            tool = venv / "bin/fifan-maintain"
            pip_args = [wheel_python, "-I", "-B", "-m", "pip", "--isolated", "install",
                        "--no-index", "--no-cache-dir", "--disable-pip-version-check"]
            for directory in OFFLINE_WHEEL_DIRS:
                pip_args.extend(["--find-links", directory])
            pip_args.append(wheel.resolve())
            _record_command(pip_args, run_root, "install-source-wheel")
            version = _record_command([tool, "--version"], run_root, "source-version")
            if version["stdout"].strip() != "1.3.0":
                raise fixture.FixtureError("compat source was not the real 1.3 wheel")

            if origin == "published-v13":
                file_compat = _legacy_file_governance(tool, run_root)
                directory = _legacy_directory_materials(tool, run_root / "directory-fixture")
                compat_material = {"file_governance": file_compat,
                                   "directory_search_archive": directory}
            else:
                appendix = _current_appendix_material(tool, run_root / "current-appendix")
                compat_material = {"current_baseline_appendix": appendix,
                                   "published_full_legacy_chain": "Not repeated by design"}
            summary = {"origin": origin, "wheel": str(wheel.resolve()), "wheel_sha256": sha256_file(wheel),
                       "python": str(python), "venv": str(venv.resolve()), "tool": str(tool.resolve()),
                       "version": "1.3.0", "compat_material": compat_material,
                       "upgrade_to_1_4": "Not run"}
            write_json(run_root / "legacy-materials-summary.json", summary)
            summaries.append(summary)
    result = {"status": "LegacyMaterialsReady", "origins": summaries,
              "current_13_wheel_source_match": str(CURRENT_13_MATCH.resolve()),
              "current_13_wheel_source_match_sha256": sha256_file(CURRENT_13_MATCH),
              "new_1_4_upgrade": "Not run; waiting for the final 1.4 wheel/API freeze"}
    write_json(results / "legacy-materials-summary.json", result)
    return result


def generate_current_appendices(results: Path, python_executables) -> Dict[str, Any]:
    """Resume only the current-baseline appendix after legacy material generation."""
    summaries = []
    for python in python_executables:
        python = python.absolute()
        env_name = python.parent.parent.name
        if env_name == ".venv39":
            tag = "python39"
        elif env_name == ".venv":
            tag = "python312"
        else:
            version = _record_command([python, "-I", "-B", "-c",
                "import sys; print('python{}{}'.format(sys.version_info[0], sys.version_info[1]))"],
                results, "interpreter-version")
            tag = version["stdout"].strip()
        python = python.resolve()
        run_root = results / "current-v13-baseline" / tag
        run_root.mkdir(parents=True, exist_ok=True)
        venv = run_root / "venv"
        if not venv.exists():
            _record_command([python, "-I", "-B", "-m", "venv", venv], run_root,
                            "create-current-baseline-venv")
            wheel_python = venv / "bin/python"
            pip_args = [wheel_python, "-I", "-B", "-m", "pip", "--isolated", "install",
                        "--no-index", "--no-cache-dir", "--disable-pip-version-check"]
            for directory in OFFLINE_WHEEL_DIRS:
                if not directory.is_dir():
                    raise fixture.FixtureError("offline wheelhouse unavailable: {}".format(directory))
                pip_args.extend(["--find-links", directory])
            pip_args.append(CURRENT_13_WHEEL.resolve())
            _record_command(pip_args, run_root, "install-current-baseline-wheel")
        tool = run_root / "venv/bin/fifan-maintain"
        if not tool.is_file():
            raise fixture.FixtureError("current-baseline 1.3 environment is missing: {}".format(tool))
        version = _record_command([tool, "--version"], run_root, "resume-current-wheel-version")
        if version["stdout"].strip() != "1.3.0":
            raise fixture.FixtureError("current-baseline environment no longer runs real 1.3")
        retry = 1
        appendix = run_root / "current-appendix"
        while appendix.exists():
            retry += 1
            appendix = run_root / "current-appendix-r{}".format(retry)
        material = _current_appendix_material(tool, appendix)
        summary = {"origin": "current-v13-baseline", "wheel": str(CURRENT_13_WHEEL.resolve()),
                   "wheel_sha256": sha256_file(CURRENT_13_WHEEL), "python": str(python),
                   "venv": str((run_root / "venv").resolve()), "tool": str(tool.resolve()),
                   "version": "1.3.0", "current_baseline_appendix": material,
                   "published_full_legacy_chain": "Not repeated by design",
                   "upgrade_to_1_4": "Not run"}
        write_json(appendix / "appendix-summary.json", summary)
        summaries.append(summary)
    result = {"status": "CurrentBaselineAppendicesReady", "origins": summaries,
              "current_13_wheel_source_match": str(CURRENT_13_MATCH.resolve()),
              "current_13_wheel_source_match_sha256": sha256_file(CURRENT_13_MATCH),
              "new_1_4_upgrade": "Not run; waiting for final 1.4 wheel/API freeze"}
    write_json(results / "current-baseline-appendix-summary.json", result)
    return result


def _version_of(python: Path, log_dir: Path, label: str) -> str:
    result = _record_command([python, "-I", "-B", "-c",
        "import sys; print('{}.{}'.format(*sys.version_info[:2]))"], log_dir, label)
    return result["stdout"].strip()


def _compat_index(legacy_results: Path, current312_results: Path) -> list[Dict[str, Any]]:
    """Bind already-created 1.3 materials to their real installed environments."""
    legacy_results = legacy_results.resolve()
    current312_results = current312_results.resolve()
    for base in (legacy_results, current312_results):
        if COMPAT_ROOT.resolve() not in base.parents:
            raise fixture.FixtureError("compatibility input must remain inside v1.4 evidence")
    entries = [
        ("published-v13", legacy_results / "published-v13/python3.9"),
        ("published-v13", legacy_results / "published-v13/pythonpytho"),
        ("current-v13-baseline", legacy_results / "current-v13-baseline/python312"),
        ("current-v13-baseline", current312_results / "current-v13-baseline/python312"),
    ]
    index = []
    for origin, run_root in entries:
        tool = run_root / "venv/bin/fifan-maintain"
        python = run_root / "venv/bin/python"
        if not tool.is_file() or not python.exists():
            raise fixture.FixtureError("preserved 1.3 environment is missing: {}".format(run_root))
        # Verify Python and tool versions against installed runtime, not folder names.
        if origin == "published-v13":
            summary_path = run_root / "legacy-materials-summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if summary.get("wheel_sha256") != sha256_file(OLD_RELEASE_WHEEL):
                raise fixture.FixtureError("published legacy materials are not bound to the released 1.3 wheel")
        else:
            appendix = run_root / "current-appendix"
            receipt_path = appendix / "compat-archive-restore-summary.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if receipt.get("status") != "Passed" or receipt.get("original_source_sha256") != receipt.get("restored_source_sha256"):
                raise fixture.FixtureError("current-baseline archive source did not finish exact restoration")
            archived_path = appendix / "current-compat-rearchive-summary.json"
            archived = json.loads(archived_path.read_text(encoding="utf-8"))
            if (archived.get("status") != "Passed" or archived.get("archive_state") != "Archived"
                    or sha256_file(Path(archived["journal"])) != archived.get("journal_sha256")
                    or sha256_file(Path(archived["restore_plan"])) != archived.get("restore_plan_sha256")):
                raise fixture.FixtureError("current-baseline 1.3 Archived journal/restore plan is not preserved")
            summary = None
        index.append({"origin": origin, "python": _version_of(python, run_root, "index-python-version"),
                      "run_root": str(run_root), "venv": str((run_root / "venv").resolve()),
                      "tool": str(tool.resolve()), "legacy_summary": str(summary_path) if origin == "published-v13" else None,
                      "current_appendix": str((run_root / "current-appendix").resolve()) if origin != "published-v13" else None,
                      "current_archive_summary": str(archived_path) if origin != "published-v13" else None})
    seen = {(item["origin"], item["python"]) for item in index}
    if seen != {("published-v13", "3.9"), ("published-v13", "3.12"),
                ("current-v13-baseline", "3.9"), ("current-v13-baseline", "3.12")}:
        raise fixture.FixtureError("compatibility sources do not cover both 1.3 origins on both Python runtimes")
    return index


def _upgrade_commands(run_root: Path, tool: Path, python: Path, final_wheel: Path) -> Dict[str, Any]:
    """Upgrade one existing venv in place, then prove its installed version."""
    source_version = _record_command([tool, "--version"], run_root, "version-before-upgrade")["stdout"].strip()
    def runtime(label: str) -> Dict[str, str]:
        code = ("import json,sys,fifan_maintenance; print(json.dumps({'executable':sys.executable,"
                "'version':'{}.{}'.format(*sys.version_info[:2]),'module_file':fifan_maintenance.__file__}))")
        result = _record_command([python, "-I", "-B", "-c", code], run_root, label)
        value = json.loads(result["stdout"])
        package_file = Path(value["module_file"]).resolve()
        environment = python.parent.parent.resolve()
        if environment not in package_file.parents or "site-packages" not in package_file.parts:
            raise fixture.FixtureError("installed package import escaped the isolated venv: {}".format(package_file))
        return {"executable": str(Path(value["executable"]).resolve()), "version": value["version"],
                "module_file": str(package_file)}
    before_runtime = runtime("runtime-before-upgrade")
    if source_version == "1.3.0":
        pip_args = [python, "-I", "-B", "-m", "pip", "--isolated", "install", "--no-index", "--no-cache-dir",
                    "--disable-pip-version-check", "--upgrade"]
        for directory in OFFLINE_WHEEL_DIRS:
            if not directory.is_dir():
                raise fixture.FixtureError("offline wheelhouse unavailable: {}".format(directory))
            pip_args.extend(["--find-links", directory])
        pip_args.append(final_wheel.resolve())
        _record_command(pip_args, run_root, "upgrade-existing-venv-offline")
    elif source_version == "1.4.0":
        prior = run_root / "upgrade-existing-venv-offline.command.json"
        if not prior.is_file():
            raise fixture.FixtureError("existing 1.4 runtime has no recorded in-place upgrade receipt")
        prior_data = json.loads(prior.read_text(encoding="utf-8"))
        if (prior_data.get("exit_code") != 0
                or str(final_wheel.resolve()) not in prior_data.get("argv", [])):
            raise fixture.FixtureError("existing 1.4 runtime was upgraded from a different wheel")
    else:
        raise fixture.FixtureError("source environment must be real 1.3 or resumable candidate 1.4")
    version = _record_command([tool, "--version"], run_root, "version-after-upgrade")["stdout"].strip()
    if version != "1.4.0":
        raise fixture.FixtureError("existing environment did not load the final 1.4 wheel")
    after_runtime = runtime("runtime-after-upgrade")
    return {"from": "1.3.0", "to": version, "final_wheel_sha256": sha256_file(final_wheel),
            "runtime_before": before_runtime, "runtime_after": after_runtime,
            "package_module_in_venv": True}


def _verify_recover_file_records(tool: Path, run_root: Path, summary: Dict[str, Any]) -> Dict[str, Any]:
    material = summary["compat_material"]["file_governance"]
    project, records = Path(material["project"]), Path(material["records"])
    logs = run_root / "upgrade-compat/file-governance"
    logs.mkdir(parents=True, exist_ok=True)
    common = ["--project", str(project)]
    journals = {label: Path(path) for label, path in material["journal_paths"].items()}
    command_dir = logs / "commands"
    prior_recoveries = sorted(command_dir.glob("session-recover-legacy-plan*.command.json"))
    recovered_receipt = None
    for prior in prior_recoveries:
        entry = json.loads(prior.read_text(encoding="utf-8"))
        if entry.get("exit_code") == 0 and entry.get("passed") is True:
            try:
                candidate = json.loads(entry.get("stdout", ""))
            except json.JSONDecodeError:
                continue
            if candidate.get("completion") == "all_recovered" and candidate.get("status") == "Passed":
                recovered_receipt = candidate
                break
    if recovered_receipt is None:
        before_expected = {"chain-v2": ((0,), "Passed"), "chain-v1": ((1,), "Failed"),
                           "standalone-v2": ((0,), "Passed"), "standalone-v1": ((0,), "Passed")}
    else:
        before_expected = {"chain-v2": ((1,), "Failed"), "chain-v1": ((0,), "Passed"),
                           "standalone-v2": ((0,), "Passed"), "standalone-v1": ((0,), "Passed")}
    before = {}
    for label in ("chain-v2", "chain-v1", "standalone-v2", "standalone-v1"):
        expected_codes, expected_status = before_expected[label]
        outcome = _run_cli(tool, project, logs, "verify-before-recover-" + label,
            ["verify", *common, "--journal", str(journals[label])], expected=expected_codes)
        if outcome["json"].get("status") != expected_status:
            raise fixture.FixtureError("1.4 gave unexpected pre-recovery state for 1.3 {} record".format(label))
        before[label] = outcome["json"]["status"]
    session, old_plan = Path(material["session"]), Path(material["recovery_plan"])
    old_report = Path(next(path for path in material["material_sha256"] if Path(path).name == "legacy-check-report.json"))
    report = _run_cli(tool, project, logs, "report-old-v13-report", ["report", *common, "--input", str(old_report)])
    session_verify = _run_cli(tool, project, logs, "session-verify-before-recovery",
        ["session", "verify", *common, "--session", str(session)])
    old_plan_data = json.loads(old_plan.read_text(encoding="utf-8"))
    new_plan = logs / "new-recovery-plan.json"
    if recovered_receipt is None:
        _run_cli(tool, project, logs, "session-recovery-preview", ["session", "recovery-preview", *common,
            "--session", str(session), "--output", str(new_plan)])
    elif not new_plan.is_file():
        raise fixture.FixtureError("prior successful recovery has no preserved preview for the original session")
    new_plan_data = json.loads(new_plan.read_text(encoding="utf-8"))
    if recovered_receipt is None and old_plan_data != new_plan_data:
        raise fixture.FixtureError("1.4 changed the still-valid 1.3 recovery-plan contract")
    if recovered_receipt is not None:
        stable_fields = ("schema_version", "root", "config_sha256", "dependencies")
        if any(old_plan_data.get(key) != new_plan_data.get(key) for key in stable_fields):
            raise fixture.FixtureError("1.4 changed the recovered session's bound recovery-plan scope")
        old_refs, new_refs = old_plan_data.get("references", {}), new_plan_data.get("references", {})
        for key in ("path", "reports", "profiles"):
            if old_refs.get(key) != new_refs.get(key):
                raise fixture.FixtureError("1.4 changed recovered session {} bindings".format(key))
        if ([entry.get("path") for entry in old_refs.get("journals", [])]
                != [entry.get("path") for entry in new_refs.get("journals", [])]):
            raise fixture.FixtureError("1.4 changed the recovered session journal order")
    if recovered_receipt is None:
        recovered = _run_cli(tool, project, logs, "session-recover-legacy-plan", ["session", "recover", *common,
            "--session", str(session), "--recovery-plan", str(old_plan)])
        recovered_json = recovered["json"]
    else:
        recovered_json = recovered_receipt
    if recovered_json.get("status") != "Passed" or recovered_json.get("completion") != "all_recovered":
        raise fixture.FixtureError("1.4 did not finish reverse-order recovery of the original 1.3 session")
    expected_order = [json.loads(journals[label].read_text(encoding="utf-8"))["plan"]["operation_id"]
                      for label in ("chain-v2", "chain-v1", "standalone-v2", "standalone-v1")]
    if recovered_json.get("restored") != expected_order:
        raise fixture.FixtureError("1.4 did not retain the 1.3 session reverse dependency order")
    final_session = _run_cli(tool, project, logs, "session-verify-recovered",
        ["session", "verify", *common, "--session", str(session)])
    if final_session["json"].get("status") != "Passed":
        raise fixture.FixtureError("recovered 1.3 session failed final verify")
    v1 = _run_cli(tool, project, logs, "verify-v1-after-session-recovery",
        ["verify", *common, "--journal", str(journals["chain-v1"])])
    v2 = _run_cli(tool, project, logs, "verify-v2-superseded-baseline", ["verify", *common,
        "--journal", str(journals["chain-v2"])], expected=(1,))
    standalone = {label: _run_cli(tool, project, logs, "verify-restored-" + label,
        ["verify", *common, "--journal", str(journals[label])])
        for label in ("standalone-v1", "standalone-v2")}
    if (v1["json"].get("status") != "Passed" or v2["json"].get("status") != "Failed"
            or report["exit_code"] != 0 or session_verify["json"].get("status") != "Passed"
            or any(item["json"].get("status") != "Passed" for item in standalone.values())):
        raise fixture.FixtureError("legacy 1.3 file/session compatibility had an unexpected terminal state")
    restored = {rel: sha256_file(project / rel) for rel in material["original_sha256"]}
    if restored != material["original_sha256"]:
        raise fixture.FixtureError("1.4 session recovery did not restore every original source SHA")
    journal_paths = {str(path.resolve()) for path in journals.values()}
    for path, digest in material["material_sha256"].items():
        if path not in journal_paths and sha256_file(Path(path)) != digest:
            raise fixture.FixtureError("immutable 1.3 material changed during compatibility run")
    for path in journal_paths:
        journal = json.loads(Path(path).read_text(encoding="utf-8"))
        if journal.get("status") != "recovered":
            raise fixture.FixtureError("1.3 session recovery did not persist its journal state")
    return {"status": "Passed", "pre_recovery_journal_verify": before,
            "session_verify_before_recovery": session_verify["json"]["status"],
            "session_completion": recovered_json["completion"],
            "restored_operation_order": recovered_json["restored"], "v1_final_verify": v1["json"]["status"],
            "v2_final_verify": v2["json"]["status"], "source_sha256_match": True,
            "standalone_final_verify": {label: item["json"]["status"] for label, item in standalone.items()},
            "file_and_session_artifacts_unchanged": True}


def _verify_directory_records(tool: Path, run_root: Path, summary: Dict[str, Any]) -> Dict[str, Any]:
    material = summary["compat_material"]["directory_search_archive"]
    project = Path(material["project"])
    profile = project.parent / "directory-profile.json"
    logs = run_root / "upgrade-compat/directory"
    logs.mkdir(parents=True, exist_ok=True)
    common = ["--project", str(project), "--profile", str(profile)]
    results = {}
    for label in ("search", "archive"):
        record = material[label]
        argv = ["directory", "verify", *common, "--journal", record["journal"]]
        if label == "archive":
            argv.extend(["--archive-root", material["archive_root"]])
        result = _run_cli(tool, project, logs, "verify-legacy-" + label, argv)
        if result["json"].get("status") != "Passed" or result["json"].get("state") != "Restored":
            raise fixture.FixtureError("1.4 could not verify already-restored 1.3 {} journal".format(label))
        if sha256_file(Path(record["journal"])) != record["journal_sha256"]:
            raise fixture.FixtureError("1.4 changed immutable 1.3 {} journal".format(label))
        restore = Path(record["restore_plan"])
        if sha256_file(restore) != record["restore_plan_sha256"]:
            raise fixture.FixtureError("1.4 changed immutable 1.3 {} restore plan".format(label))
        results[label] = {"state": result["json"]["state"], "status": result["json"]["status"],
                          "journal_sha256": record["journal_sha256"], "restore_plan_sha256": record["restore_plan_sha256"]}
    return {"status": "Passed", "published_search_archive": results}


def run_upgrades(results: Path, final_wheel: Path, legacy_results: Path, current312_results: Path) -> Dict[str, Any]:
    """Upgrade pre-existing 1.3 environments in place; never regenerate old materials."""
    final_wheel = final_wheel.resolve()
    if not final_wheel.is_file() or "1.4.0" not in final_wheel.name:
        raise fixture.FixtureError("--run needs the final 1.4.0 wheel")
    index = _compat_index(legacy_results, current312_results)
    results.mkdir(parents=True, exist_ok=True)
    index_path = results / "compat-material-index.json"
    index_data = {"sources": index,
        "release_13_wheel_sha256": sha256_file(OLD_RELEASE_WHEEL),
        "current_13_wheel_sha256": sha256_file(CURRENT_13_WHEEL),
        "final_14_wheel_sha256": sha256_file(final_wheel)}
    if index_path.is_file():
        if json.loads(index_path.read_text(encoding="utf-8")) != index_data:
            raise fixture.FixtureError("preserved compatibility index differs from this candidate wheel/material")
    else:
        if results.exists() and any(results.iterdir()):
            raise fixture.FixtureError("refusing to overwrite unrelated upgrade result artifacts")
        results.mkdir(parents=True, exist_ok=True)
        write_json(index_path, index_data)
    runs = []
    for item in index:
        run_root = Path(item["run_root"])
        tool, python = Path(item["tool"]), Path(item["venv"]) / "bin/python"
        run_dir = results / (item["origin"] + "-python" + item["python"].replace(".", ""))
        run_dir.mkdir(parents=True, exist_ok=True)
        upgrade = _upgrade_commands(run_dir, tool, python, final_wheel)
        if (upgrade["runtime_before"]["version"] != item["python"]
                or upgrade["runtime_after"]["version"] != item["python"]):
            raise fixture.FixtureError("upgraded runtime version does not match the indexed Python venv")
        if item["origin"] == "published-v13":
            summary = json.loads(Path(item["legacy_summary"]).read_text(encoding="utf-8"))
            file_records = _verify_recover_file_records(tool, run_dir, summary)
            directory_records = _verify_directory_records(tool, run_dir, summary)
        else:
            receipt_path = Path(item["current_appendix"]) / "compat-archive-restore-summary.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            archived = json.loads(Path(item["current_archive_summary"]).read_text(encoding="utf-8"))
            appendix = Path(item["current_appendix"])
            project, archive = appendix / "project", appendix / "archive"
            profile = appendix / "profile.json"
            logs = run_dir / "upgrade-compat/current-baseline"
            logs.mkdir(parents=True, exist_ok=True)
            old_journal = Path(archived["journal"])
            old_restore_plan = Path(archived["restore_plan"])
            if sha256_file(old_journal) != archived["journal_sha256"] or sha256_file(old_restore_plan) != archived["restore_plan_sha256"]:
                raise fixture.FixtureError("current-baseline journal or pre-upgrade restore plan changed")
            verified = _run_cli(tool, project, logs, "verify-archived-current-baseline-journal",
                ["directory", "verify", "--project", str(project), "--profile", str(profile),
                 "--journal", str(old_journal), "--archive-root", str(archive)])
            restored = _run_cli(tool, project, logs, "restore-current-baseline-with-old-plan",
                ["directory", "restore", "--project", str(project), "--profile", str(profile),
                 "--plan", str(old_restore_plan), "--archive-root", str(archive),
                 "--records-dir", str(appendix / "records")])
            final_verify = _run_cli(tool, project, logs, "verify-restored-current-baseline-journal",
                ["directory", "verify", "--project", str(project), "--profile", str(profile),
                 "--journal", str(old_journal), "--archive-root", str(archive)])
            expected = archived["before_source_sha256"]
            current_hashes = {rel: sha256_file(project / rel) for rel in expected}
            if (verified["json"].get("status") != "Passed" or verified["json"].get("state") != "Archived"
                    or restored["json"].get("state") != "Restored" or final_verify["json"].get("status") != "Passed"
                    or current_hashes != expected or sha256_file(old_restore_plan) != archived["restore_plan_sha256"]):
                raise fixture.FixtureError("1.4 failed to restore the pre-existing current 1.3 archive fixture")
            directory_records = {"status": "Passed", "current_streaming_dynamic": {
                "before_state": verified["json"]["state"], "restored_state": restored["json"]["state"],
                "final_verify": final_verify["json"]["status"], "source_sha256_match": True,
                "journal_sha256": archived["journal_sha256"],
                "restore_plan_sha256": archived["restore_plan_sha256"],
                "streaming_reference_sha256": archived["before_source_sha256"].get("Editor.log"),
                "streaming_reference_bytes": (appendix / "project/Editor.log").stat().st_size}}
            file_records = {"status": "Not applicable to current-baseline append-only material"}
        runs.append({"origin": item["origin"], "python": item["python"], "environment": item["venv"],
                     "upgrade": upgrade, "file_governance": file_records,
                     "directory_records": directory_records})
    result = {"status": "Passed", "final_wheel": str(final_wheel),
              "final_wheel_sha256": sha256_file(final_wheel), "origins": runs,
              "old_materials_regenerated": False,
              "business_scripts": "Not run", "Unity Editor": "Not run"}
    write_json(results / "compat-upgrade-summary.json", result)
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true", help="prepare the two 1.3-origin fixtures")
    mode.add_argument("--generate-legacy", action="store_true",
                      help="install real 1.3 wheels offline and generate source-specific compatibility records")
    mode.add_argument("--append-current", action="store_true",
                      help="resume only current-baseline streaming/dynamic materials in existing 1.3 environments")
    mode.add_argument("--rearchive-current", action="store_true",
                      help="produce one additional real 1.3 Archived journal for a preserved current appendix")
    mode.add_argument("--complete-current-preview", action="store_true",
                      help="apply and restore a qualified archived preview inside its synthetic 1.3 fixture")
    mode.add_argument("--run", action="store_true", help="upgrade preserved material to the final 1.4 candidate")
    parser.add_argument("--results", type=Path, help="new directory under evidence/validation/v1.4/compat-*")
    parser.add_argument("--final-wheel", type=Path, help="final 1.4 wheel; required by --run")
    parser.add_argument("--legacy-results", type=Path,
        default=COMPAT_ROOT / "compat-real13-generation-r2",
        help="preserved released-1.3 source materials; never regenerated by --run")
    parser.add_argument("--current312-results", type=Path,
        default=COMPAT_ROOT / "compat-current13-python312-r1",
        help="preserved current-baseline Python 3.12 materials; never regenerated by --run")
    parser.add_argument("--appendix", type=Path, help="existing current-baseline appendix for --complete-current-preview")
    parser.add_argument("--python-executable", type=Path, action="append", dest="pythons")
    args = parser.parse_args(argv)
    results = args.results or Path(tempfile.mkdtemp(prefix="compat-prepared-", dir=str(COMPAT_ROOT)))
    results = results.absolute()
    if results.parent != COMPAT_ROOT.resolve() or not results.name.startswith("compat-"):
        parser.error("results must be a direct new child named compat-* under v1.4 evidence")
    if results.is_symlink():
        parser.error("compat results cannot be a symlink")
    try:
        if args.generate_legacy:
            summary = generate_legacy(results, args.pythons or DEFAULT_PYTHONS)
        elif args.append_current:
            summary = generate_current_appendices(results, args.pythons or DEFAULT_PYTHONS)
        elif args.rearchive_current:
            if args.appendix is None:
                parser.error("--appendix is required by --rearchive-current")
            summary = rearchive_current_appendix(results, args.appendix)
        elif args.complete_current_preview:
            if args.appendix is None:
                parser.error("--appendix is required by --complete-current-preview")
            allowed = (results / "current-v13-baseline").resolve()
            appendix = args.appendix.resolve()
            if allowed not in appendix.parents:
                parser.error("appendix must be inside this results/current-v13-baseline tree")
            tag = appendix.parent.name
            tool = results / "current-v13-baseline" / tag / "venv/bin/fifan-maintain"
            summary = complete_current_preview(tool, appendix)
        elif args.run:
            if args.final_wheel is None:
                parser.error("--final-wheel is required by --run")
            summary = run_upgrades(results, args.final_wheel, args.legacy_results, args.current312_results)
        else:
            summary = prepare(results)
    except (OSError, fixture.FixtureError, json.JSONDecodeError) as exc:
        parser.exit(2, "compat fixture preparation failed: {}\n".format(exc))
    if args.complete_current_preview and args.appendix is not None:
        summary_path = args.appendix.resolve() / "compat-archive-restore-summary.json"
    elif args.rearchive_current and args.appendix is not None:
        summary_path = args.appendix.resolve() / "current-compat-rearchive-summary.json"
    elif args.run:
        summary_path = results / "compat-upgrade-summary.json"
    else:
        summary_path = results / "prepared-summary.json"
    print(json.dumps({"status": summary.get("status", "Unknown"), "summary": str(summary_path),
                      "origins": len(summary.get("origins", []))}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
