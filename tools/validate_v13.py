#!/usr/bin/env python3
"""Synthetic fixture builder for the v1.3 directory-maintenance forward run.

The generated workspace is always contained by evidence/validation/v1.3/forward.
This first stage prepares reproducible source/archive populations only; the CLI
driver is intentionally gated until the public v1.3 command contracts freeze.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOOL = ROOT / "bin/fifan-maintain"
FORWARD = ROOT / "evidence/validation/v1.3/forward"
DEFAULT_HISTORY = 20_005
DEFAULT_CENSUS_ENTRIES = 160_000
DEFAULT_ARCHIVE_BATCHES = (2_938, 4_408)


class FixtureError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def build_fixture(workspace: Path, *, history_files: int = DEFAULT_HISTORY,
                  census_entries: int = DEFAULT_CENSUS_ENTRIES,
                  archive_counts: Iterable[int] = DEFAULT_ARCHIVE_BATCHES,
                  vscode_config: bool = True, max_seconds: int = 60) -> Dict[str, Any]:
    """Create one synthetic project plus same-volume archive and records roots.

    Directories count toward census_entries. Archive batches contain regular
    files only and have deterministic content, mode, and fixed mtime. No source
    project or external path is read.
    """
    if min(history_files, census_entries) < 0:
        raise ValueError("fixture counts must be nonnegative")
    counts = tuple(int(count) for count in archive_counts)
    if len(counts) != 2 or min(counts) < 0:
        raise ValueError("archive_counts must contain two nonnegative counts")
    workspace = workspace.resolve()
    if not workspace.is_relative_to(FORWARD.resolve()):
        raise FixtureError("workspace must be inside evidence/validation/v1.3/forward")
    if workspace.exists() and any(workspace.iterdir()):
        raise FixtureError("workspace must be absent or empty: {}".format(workspace))
    project = workspace / "project"
    archive_root = workspace / "archive-root"
    records_root = workspace / "records"
    for directory in (project, archive_root, records_root):
        directory.mkdir(parents=True, exist_ok=True)

    # Minimal meaningful project population: key documents, refs, protected
    # and critical paths, configuration present, and two explicitly closed
    # synthetic batches. The exact profile schema is supplied after API freeze.
    _write(project / "README.md", b"# Synthetic workspace\n\nSee [plan](PLAN.md) and [decisions](DECISIONS.md).\n")
    _write(project / "PLAN.md", b"# Unique plan\n\n- TODO: touch acceptance remains open.\n")
    _write(project / "DECISIONS.md", b"# Decisions\n\nApproved fixture decision; no product semantics.\n")
    _write(project / ".ignore", b"# User rule retained\n!README.md\n")
    if vscode_config:
        _write(project / ".vscode/settings.json", b'{\n  "search.exclude": {}\n}\n')
    _write(project / "src/current_entry.py", b"# Critical synthetic entry\n")
    _write(project / "Assets/fixture.asset", b"protected synthetic asset\n")
    _write(project / "history/closed-batch-one/close-note.md", b"Synthetic closed batch one.\n")
    _write(project / "history/closed-batch-two/close-note.md", b"Synthetic closed batch two.\n")
    _write(project / "history/old-report.md",
           b"# Retained old report\n\nSee [payload](closed-batch-one/payload/Unicode%20%E7%A9%BA%E6%A0%BC/file-000000.bin).\n")
    _write(project / "history/old-report-two.md",
           b"# Retained old report two\n\nSee [payload](closed-batch-two/payload/Unicode%20%E7%A9%BA%E6%A0%BC/file-000000.bin).\n")

    history_root = project / "history/metadata"
    for index in range(history_files):
        _write(history_root / "record-{:05d}.json".format(index), b'{"fixture":true}\n')

    census_root = project / "census-payload"
    # One file plus zero or more directories per item; empty directory entries
    # are included explicitly so metadata traversal can exercise both types.
    directory_count = census_entries // 4
    for index in range(directory_count):
        (census_root / "empty" / "d{:06d}".format(index)).mkdir(parents=True, exist_ok=True)
    file_count = census_entries - directory_count
    for index in range(file_count):
        _write(census_root / "files" / "f{:06d}.dat".format(index), b"metadata-only fixture\n")

    batch_roots = [project / "history/closed-batch-one/payload",
                   project / "history/closed-batch-two/payload"]
    expected_files: List[Dict[str, Any]] = []
    fixed_mtime_ns = 1_700_000_000_000_000_000
    for batch_index, (batch_root, count) in enumerate(zip(batch_roots, counts), start=1):
        for index in range(count):
            rel = ("Unicode 空格/file-000000.bin" if index == 0 else
                   "item-{:04d}/file-{:06d}.bin".format(index // 100, index))
            path = batch_root / rel
            content = (b"\x00synthetic binary\xff\r\n" if index == 0 else
                       ("synthetic batch {} file {}\n".format(batch_index, index)).encode("ascii"))
            _write(path, content)
            os.chmod(path, 0o640)
            os.utime(path, ns=(fixed_mtime_ns, fixed_mtime_ns))
            info = path.stat()
            expected_files.append({
                "batch": batch_index,
                "path": path.relative_to(project).as_posix(),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "mode": 0o640,
                "mtime_ns": fixed_mtime_ns,
                "device": info.st_dev,
                "inode": info.st_ino,
            })

    archive_directories: List[Dict[str, Any]] = []
    for batch_root in batch_roots:
        (batch_root / "empty-directory").mkdir(parents=True, exist_ok=True)
        directories = sorted((path for path in batch_root.rglob("*") if path.is_dir()),
                             key=lambda path: len(path.parts), reverse=True)
        directories.append(batch_root)
        for directory in directories:
            os.chmod(directory, 0o750)
            os.utime(directory, ns=(fixed_mtime_ns, fixed_mtime_ns))
        for directory in directories:
            info = directory.stat()
            archive_directories.append({
                "path": directory.relative_to(project).as_posix(),
                "mode": info.st_mode & 0o777,
                "mtime_ns": info.st_mtime_ns,
                "device": info.st_dev,
                "inode": info.st_ino,
            })

    roots = {name: str(path.resolve()) for name, path in (
        ("workspace", workspace), ("project", project),
        ("archive_root", archive_root), ("records_root", records_root))}
    if len({os.stat(path).st_dev for path in (project, archive_root, records_root)}) != 1:
        raise FixtureError("project, archive, and records roots must share a filesystem")
    protected_paths = ["Assets", ".git", ".env", "private"]
    critical_paths = ["README.md", "PLAN.md", "DECISIONS.md", "src/current_entry.py"]
    manifest: Dict[str, Any] = {
        "fixture_version": 1,
        "roots": roots,
        "counts": {
            "key_markdown": 3,
            "history_metadata_files": history_files,
            "census_entries_requested": census_entries,
            "census_empty_directories": directory_count,
            "census_regular_files": file_count,
            "archive_batch_files": list(counts),
            "archive_batch_total": sum(counts),
        },
        "critical_paths": critical_paths,
        "protected_paths": protected_paths,
        "vscode_config_present": vscode_config,
        "archive_files": expected_files,
        "archive_directories": archive_directories,
        "baseline_sha256": {
            path: sha256_file(project / path)
            for path in critical_paths + [".ignore"] + ([".vscode/settings.json"] if vscode_config else [])
        },
        "api_contract_status": "awaiting-v1.3-public-cli-freeze",
    }
    profile = {
        "schema_version": 1,
        "project_root": str(project.resolve()),
        "preset": "generic",
        "scan_roots": ["."],
        "critical_paths": critical_paths,
        "reference_sources": [
            {"path": path, "role": "current"}
            for path in critical_paths
        ] + [
            {"path": "history/old-report.md", "role": "historical"},
            {"path": "history/old-report-two.md", "role": "historical"},
            {"path": "history/closed-batch-one/close-note.md", "role": "historical"},
            {"path": "history/closed-batch-two/close-note.md", "role": "historical"},
        ],
        "classifications": [
            {"path": path, "role": "keep", "reason": "Synthetic critical path retained in fixture."}
            for path in critical_paths
        ] + [
            {"path": "history/closed-batch-one/payload", "role": "historical",
             "reason": "Synthetic closed batch; retain original payload and rehearse restoration."},
            {"path": "history/closed-batch-two/payload", "role": "historical",
             "reason": "Synthetic closed batch; retain original payload and rehearse restoration."},
            {"path": "history", "role": "historical",
             "reason": "Synthetic retained history; old references resolve through explicit records."},
            {"path": "Assets", "role": "keep", "reason": "Protected synthetic asset fixture."},
        ],
        "search": {"exclude": ["history", "census-payload"], "vscode": True,
                   "watcher_exclude": False},
        "archive": {
            "archive_root": str(archive_root.resolve()),
            "records_dir": str(records_root.resolve()),
            "candidates": ["history/closed-batch-one/payload", "history/closed-batch-two/payload"],
            "require_no_open_handles": False,
        },
        "budgets": {
            "max_entries": max(1000, census_entries + history_files + sum(counts)
                                + census_entries // 4 + 512),
            "max_seconds": max_seconds, "max_depth": 16, "max_output_bytes": 8192,
            "max_hash_entries": 20000, "max_hash_bytes": 2147483648,
            "max_hash_file_bytes": 536870912, "max_artifact_bytes": 33554432,
            "max_reference_bytes": 67108864, "max_reference_file_bytes": 4194304,
            "max_reference_files": 20000,
        },
    }
    batches = []
    for batch_index in (1, 2):
        name = "closed-batch-{}".format("one" if batch_index == 1 else "two")
        closure_path = project / "history/{}/close-note.md".format(name)
        report_path = "history/old-report{}.md".format("" if batch_index == 1 else "-two")
        batches.append({
            "source": "history/{}/payload".format(name),
            "destination": "synthetic-project/{}".format(name),
            "closure": {
                "decision": "closed",
                "reason": "Explicit synthetic fixture closure; original payload is retained and restored during rehearsal.",
                "evidence": [{"path": closure_path.relative_to(project).as_posix(),
                              "sha256": sha256_file(closure_path)}],
            },
            "historical_references": [{
                "path": report_path,
                "sha256": sha256_file(project / report_path),
                "reason": "Synthetic historical reference; locate or restore before path-based replay.",
            }],
            "known_absent": [],
        })
    request = {
        "schema_version": 1,
        "batches": batches,
    }
    write_json(workspace / "directory-profile.json", profile)
    write_json(workspace / "directory-request.json", request)
    manifest["profile_file_sha256"] = sha256_file(workspace / "directory-profile.json")
    write_json(workspace / "fixture-manifest.json", manifest)
    return manifest


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _project_metadata_snapshot(project: Path) -> List[Dict[str, Any]]:
    """Snapshot synthetic tree names and stat identity without opening bodies."""
    entries: List[Dict[str, Any]] = []
    for current, directories, files in os.walk(str(project), topdown=True, followlinks=False):
        base = Path(current)
        for name in list(directories):
            path = base / name
            info = path.lstat()
            entries.append({"path": path.relative_to(project).as_posix(), "kind": "symlink" if path.is_symlink() else "directory",
                            "mode": info.st_mode & 0o777, "size": info.st_size,
                            "mtime_ns": info.st_mtime_ns, "device": info.st_dev, "inode": info.st_ino})
            if path.is_symlink():
                directories.remove(name)
        for name in files:
            path = base / name
            info = path.lstat()
            entries.append({"path": path.relative_to(project).as_posix(), "kind": "symlink" if path.is_symlink() else "file",
                            "mode": info.st_mode & 0o777, "size": info.st_size,
                            "mtime_ns": info.st_mtime_ns, "device": info.st_dev, "inode": info.st_ino})
    return sorted(entries, key=lambda item: item["path"])


def _run_cli(workspace: Path, profile: Path, action: str, args: List[str], name: str,
             tool: Path) -> Dict[str, Any]:
    results = workspace / "results"
    results.mkdir(parents=True, exist_ok=True)
    output = results / (name + ".json")
    project = workspace / "project"
    argv = [str(tool.resolve()), "directory", action, "--project", str(project.resolve()),
            "--profile", str(profile.resolve()), *args, "--output", str(output.resolve())]
    completed = subprocess.run(argv, cwd=str(ROOT), text=True, encoding="utf-8",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    record = {
        "name": name,
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "output_path": str(output.resolve()),
    }
    if completed.returncode != 0:
        raise FixtureError("{} returned {}; see {}".format(name, completed.returncode, output))
    if not output.is_file():
        raise FixtureError("{} did not write its requested result".format(name))
    record["result"] = _read_json(output)
    return record


def _run_command(workspace: Path, argv: List[str], name: str) -> Dict[str, Any]:
    results = workspace / "results"
    results.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(argv, cwd=str(ROOT), text=True, encoding="utf-8",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    record = {"name": name, "argv": argv, "exit_code": completed.returncode,
              "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()}
    if completed.returncode != 0:
        raise FixtureError("{} returned {}; see captured command record".format(name, completed.returncode))
    return record


def _reuse_result(workspace: Path, name: str, valid) -> Optional[Dict[str, Any]]:
    output = workspace / "results" / (name + ".json")
    if not output.is_file():
        return None
    result = _read_json(output)
    if not valid(result):
        return None
    return {"name": name, "argv": ["existing validated result"], "exit_code": 0,
            "stdout": "", "stderr": "", "output_path": str(output.resolve()),
            "result": result, "reused_existing_result": True}


def run_small_fixture(workspace: Path, *, tool: Path = DEFAULT_TOOL) -> Dict[str, Any]:
    """Run bounded inspect/search/restore CLI flow and assert business states."""
    workspace = workspace.resolve()
    tool = tool if tool.is_absolute() else ROOT / tool
    tool = tool.resolve()
    manifest = _read_json(workspace / "fixture-manifest.json")
    profile = workspace / "directory-profile.json"
    if not profile.is_file():
        raise FixtureError("small fixture profile is missing")
    project = Path(manifest["roots"]["project"])
    baseline = manifest["baseline_sha256"]
    commands: List[Dict[str, Any]] = []

    tree_before_inspect = _project_metadata_snapshot(project)
    inspect = _run_cli(workspace, profile, "workflow", [
        "--records-dir", manifest["roots"]["records_root"],
        "--request", str((workspace / "directory-request.json").resolve()),
    ], "inspect", tool)
    inspect_result = inspect["result"]
    if inspect_result.get("phase") != "inspect" or inspect_result.get("state") != "Inspected" or inspect_result.get("status") != "Passed":
        raise FixtureError("inspect workflow did not reach Passed/Inspected")
    step_status = {item.get("step"): item.get("status") for item in inspect_result.get("steps", [])}
    if step_status != {"census": "Passed", "impact": "Passed", "search-preview": "Preview"}:
        raise FixtureError("inspect workflow step statuses differ from expected contract")
    inspect_receipt = _read_json(Path(inspect_result["workflow_path"]))
    inspect_artifacts = {item["step"]: Path(item["artifact"]) for item in inspect_receipt.get("steps", [])}
    census = _read_json(inspect_artifacts["census"])
    impact = _read_json(inspect_artifacts["impact"])
    if census.get("body_bytes_sent") != 0 or census.get("hash_coverage", {}).get("status") != "Not run":
        raise FixtureError("inspect census read or hashed body content")
    batches = impact.get("batches", [])
    if impact.get("global_no_dependencies") is not None or not batches or batches[0].get("eligible") is not True:
        raise FixtureError("impact must preserve global Unknown and resolve only the explicit fixture batch")
    if batches[0].get("historical_replay_requires_restore") is not True:
        raise FixtureError("historical replay must require restoration")
    after_inspect = {path: sha256_file(project / path) for path in baseline}
    tree_after_inspect = _project_metadata_snapshot(project)
    if after_inspect != baseline or tree_after_inspect != tree_before_inspect:
        raise FixtureError("default inspect changed project files")
    commands.append(inspect)

    search = _run_cli(workspace, profile, "workflow", [
        "--records-dir", manifest["roots"]["records_root"], "--phase", "search",
    ], "search", tool)
    search_result = search["result"]
    if search_result.get("phase") != "search" or search_result.get("state") != "Completed" or search_result.get("status") != "Passed":
        raise FixtureError("search workflow did not reach Passed/Completed")
    steps = search_result.get("steps", [])
    if len(steps) != 1 or steps[0].get("step") != "search-verified" or steps[0].get("state") != "Applied" or steps[0].get("status") != "Passed":
        raise FixtureError("search workflow did not verify the applied state")
    journal_path = Path(steps[0]["artifact"])
    journal = _read_json(journal_path)
    validation = journal.get("validation", {})
    critical = validation.get("critical_paths", {})
    if journal.get("kind") != "search-config" or journal.get("state") != "Applied" or journal.get("status") != "Passed":
        raise FixtureError("search journal did not bind an applied, verified operation")
    if not critical or any(value != "Passed" for value in critical.values()):
        raise FixtureError("search did not preserve every critical path")
    if validation.get("hidden_files", 0) <= 0 or validation.get("vscode_ui") != "Not run":
        raise FixtureError("search visibility/UI evidence does not match the fixture contract")
    commands.append(search)

    restored = _run_cli(workspace, profile, "workflow", [
        "--records-dir", manifest["roots"]["records_root"], "--phase", "restore",
        "--journal", str(journal_path.resolve()),
    ], "restore", tool)
    restore_result = restored["result"]
    if (restore_result.get("state") != "Restored" or restore_result.get("status") != "Passed"
            or restore_result.get("completion") != "all_recovered"):
        raise FixtureError("restore workflow did not complete a verified full restoration")
    commands.append(restored)

    verify = _run_cli(workspace, profile, "verify", ["--journal", str(journal_path.resolve())],
                      "verify-restored", tool)
    verify_result = verify["result"]
    if verify_result.get("state") != "Restored" or verify_result.get("status") != "Passed":
        raise FixtureError("direct verification did not recognize the restored journal")
    commands.append(verify)

    final_hashes = {path: sha256_file(project / path) for path in baseline}
    if final_hashes != baseline:
        raise FixtureError("restore did not reproduce original project hashes")
    vscode_path = project / ".vscode/settings.json"
    expected_vscode = manifest.get("vscode_config_present", True)
    if vscode_path.exists() != expected_vscode or ((project / ".vscode").exists() != expected_vscode):
        raise FixtureError("restore did not reproduce original VS Code config/directory presence")
    for item in manifest["archive_files"]:
        source = project / item["path"]
        stat = source.stat()
        if (sha256_file(source) != item["sha256"] or stat.st_size != item["size"]
                or stat.st_mode & 0o777 != item["mode"] or stat.st_mtime_ns != item["mtime_ns"]
                or (stat.st_dev, stat.st_ino) != (item["device"], item["inode"])):
            raise FixtureError("search/restore changed synthetic archive source {}".format(item["path"]))
    for item in manifest["archive_directories"]:
        source = project / item["path"]
        stat = source.stat()
        if (stat.st_mode & 0o777 != item["mode"] or stat.st_mtime_ns != item["mtime_ns"]
                or (stat.st_dev, stat.st_ino) != (item["device"], item["inode"])):
            raise FixtureError("search/restore changed synthetic archive directory {}".format(item["path"]))

    summary = {
        "status": "Passed",
        "scope": "small synthetic inspect/search/restore only",
        "python_cli": str(tool),
        "profile_file_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "project": str(project.resolve()),
        "inspect": {"status": inspect_result["status"], "steps": step_status,
                    "census_body_bytes_sent": census["body_bytes_sent"],
                    "impact_global_no_dependencies": impact.get("global_no_dependencies"),
                    "project_metadata_entries_unchanged": len(tree_before_inspect)},
        "search": {"status": search_result["status"], "state": steps[0]["state"],
                   "visible_before": validation["before"]["visible_files"],
                   "visible_after": validation["after"]["visible_files"],
                   "hidden_files": validation["hidden_files"],
                   "critical_paths": critical, "vscode_ui": validation["vscode_ui"]},
        "restore": {"status": restore_result["status"], "state": restore_result["state"],
                    "completion": restore_result["completion"],
                    "restored_original_hashes_match": final_hashes == baseline,
                    "vscode_config_presence_restored": vscode_path.exists() == expected_vscode,
                    "archive_source_files_verified": len(manifest["archive_files"])},
        "commands": [{key: value for key, value in item.items() if key != "result"} for item in commands],
    }
    write_json(workspace / "results" / "forward-summary.json", summary)
    write_json(workspace / "results" / "command-results.json", commands)
    return summary


def run_prearchive_full(workspace: Path, *, tool: Path = DEFAULT_TOOL) -> Dict[str, Any]:
    """Run one frozen-size census, three-file check, inspect and search restore.

    Leaves the same workspace, sources, request, archive root and records root
    ready for the separately gated archive phase; it never rebuilds an existing
    fixture.
    """
    workspace = workspace.resolve()
    tool = tool if tool.is_absolute() else ROOT / tool
    tool = tool.resolve()
    manifest = _read_json(workspace / "fixture-manifest.json")
    expected = {"history_metadata_files": DEFAULT_HISTORY,
                "census_entries_requested": DEFAULT_CENSUS_ENTRIES,
                "archive_batch_files": list(DEFAULT_ARCHIVE_BATCHES)}
    if any(manifest["counts"].get(key) != value for key, value in expected.items()):
        raise FixtureError("prearchive full run requires the exact authorized fixture scale")
    profile_data = _read_json(workspace / "directory-profile.json")
    if profile_data.get("budgets", {}).get("max_seconds", 0) < 300:
        raise FixtureError("full fixture must declare the explicitly authorized 300-second observation budget")
    profile_file_sha = sha256_file(workspace / "directory-profile.json")
    if manifest.get("profile_file_sha256") != profile_file_sha:
        raise FixtureError("prepared fixture profile changed since its manifest binding")
    project = Path(manifest["roots"]["project"])
    profile = workspace / "directory-profile.json"
    request = workspace / "directory-request.json"
    records_root = Path(manifest["roots"]["records_root"])
    results = workspace / "results"
    results.mkdir(parents=True, exist_ok=True)
    commands: List[Dict[str, Any]] = []

    census_record = _reuse_result(workspace, "census", lambda result:
        result.get("status") == "Passed"
        and result.get("coverage", {}).get("metadata_complete") is True
        and result.get("body_bytes_sent") == 0 and result.get("hash_coverage", {}).get("status") == "Not run")
    if census_record is None:
        census_record = _run_cli(workspace, profile, "census", [], "census", tool)
    census = census_record["result"]
    if (census.get("status") != "Passed" or census.get("coverage", {}).get("metadata_complete") is not True
            or census.get("body_bytes_sent") != 0 or census.get("hash_coverage", {}).get("status") != "Not run"):
        raise FixtureError("full census did not complete as metadata-only with no body/hash work")
    if census.get("coverage", {}).get("count_is_lower_bound") is not False:
        raise FixtureError("full census is not a complete count")
    commands.append(census_record)

    impact_record = _reuse_result(workspace, "impact", lambda result:
        result.get("profile_sha256") == census.get("profile_sha256") and result.get("status") == "Passed"
        and result.get("coverage", {}).get("complete") is True and result.get("global_no_dependencies") is None
        and len(result.get("batches", [])) == 2 and all(item.get("eligible") is True for item in result.get("batches", [])))
    if impact_record is None:
        impact_record = _run_cli(workspace, profile, "impact", ["--request", str(request.resolve())], "impact", tool)
    impact = impact_record["result"]
    impact_batches = impact.get("batches", [])
    if (impact.get("status") != "Passed" or impact.get("coverage", {}).get("complete") is not True
            or impact.get("global_no_dependencies") is not None or len(impact_batches) != 2
            or any(item.get("eligible") is not True or item.get("historical_replay_requires_restore") is not True
                   for item in impact_batches)):
        raise FixtureError("full impact did not preserve Unknown and explicit two-batch eligibility")
    commands.append(impact_record)

    before_check = {path: sha256_file(project / path) for path in manifest["baseline_sha256"]}
    preflight_output = results / "markdown-preflight.json"
    preflight_argv = [str(tool), "check", "--project", str(project.resolve()), "--files",
                      "README.md", "PLAN.md", "DECISIONS.md", "--preflight", "--format", "json",
                      "--output", str(preflight_output.resolve())]
    preflight = _reuse_result(workspace, "markdown-preflight", lambda result:
        result.get("status") == "Preview" and result.get("requested_source_count") == 3
        and result.get("body_bytes_read") == 0 and result.get("model_calls") == 0)
    if preflight is None:
        preflight = _run_command(workspace, preflight_argv, "markdown-preflight")
    if not preflight_output.is_file():
        raise FixtureError("targeted three-file preflight did not write JSON")
    preflight["output_path"] = str(preflight_output.resolve())
    preflight["result"] = _read_json(preflight_output)
    if (preflight["result"].get("status") != "Preview"
            or preflight["result"].get("requested_source_count") != 3
            or preflight["result"].get("body_bytes_read") != 0
            or preflight["result"].get("model_calls") != 0):
        raise FixtureError("preflight did not remain metadata-only for the exact three Markdown files")
    commands.append(preflight)

    check_output = results / "markdown-check.json"
    check_argv = [str(tool), "check", "--project", str(project.resolve()), "--files",
                  "README.md", "PLAN.md", "DECISIONS.md", "--checks", "documents,links",
                  "--format", "json", "--output", str(check_output.resolve())]
    markdown = _reuse_result(workspace, "markdown-check", lambda result:
        result.get("file_count") == 3 and result.get("finding_total") == 0
        and result.get("has_failures") is False and result.get("model_calls") == 0
        and all(item.get("status") == "Passed" for item in result.get("coverage", [])))
    if markdown is None:
        markdown = _run_command(workspace, check_argv, "targeted-three-markdown-check")
    if not check_output.is_file():
        raise FixtureError("targeted three-file check did not write JSON")
    markdown["output_path"] = str(check_output.resolve())
    markdown["result"] = _read_json(check_output)
    report = markdown["result"]
    if (report.get("file_count") != 3 or report.get("finding_total") != 0
            or report.get("has_failures") is not False or report.get("model_calls") != 0
            or any(item.get("status") != "Passed" for item in report.get("coverage", []))):
        raise FixtureError("targeted three-file check did not report Passed")
    commands.append(markdown)
    if {path: sha256_file(project / path) for path in manifest["baseline_sha256"]} != before_check:
        raise FixtureError("targeted Markdown checks changed the project")

    search_summary_path = results / "forward-summary.json"
    if search_summary_path.is_file():
        stored_search = _read_json(search_summary_path)
        stored_profile_file_sha = stored_search.get("profile_file_sha256", stored_search.get("profile_sha256"))
        search_summary = (stored_search if stored_search.get("status") == "Passed"
                          and stored_profile_file_sha == profile_file_sha else None)
    else:
        search_summary = None
    if search_summary is None:
        search_summary = run_small_fixture(workspace, tool=tool)
    commands.append({"name": "inspect-search-restore", "exit_code": 0,
                     "summary_path": str((results / "forward-summary.json").resolve()),
                     "result": search_summary})
    # Reconfirm sources remain ready for the later archive phase.
    final_project_hashes = {path: sha256_file(project / path) for path in manifest["baseline_sha256"]}
    if final_project_hashes != manifest["baseline_sha256"]:
        raise FixtureError("prearchive search restoration did not reproduce baseline hashes")
    for item in manifest["archive_files"]:
        source = project / item["path"]
        info = source.stat()
        if (sha256_file(source) != item["sha256"] or info.st_mode & 0o777 != item["mode"]
                or info.st_mtime_ns != item["mtime_ns"]
                or (info.st_dev, info.st_ino) != (item["device"], item["inode"])):
            raise FixtureError("archive payload is not at its original source state: {}".format(item["path"]))
    summary = {
        "status": "Passed",
        "scope": "20,005 history metadata + 160,000 census entries + targeted 3MD + inspect/search/restore; archive not run",
        "python_cli": str(tool),
        "profile_file_sha256": profile_file_sha,
        "project": str(project.resolve()),
        "fixture_counts": manifest["counts"],
        "census": {"status": census["status"], "metadata_complete": census["coverage"]["metadata_complete"],
                   "work_entries": census["coverage"]["work_entries"], "body_bytes_sent": census["body_bytes_sent"],
                   "file_count": census["file_count"], "directory_count": census["directory_count"],
                   "hash_status": census["hash_coverage"]["status"]},
        "impact": {"status": impact["status"], "global_no_dependencies": impact.get("global_no_dependencies"),
                   "batch_eligible": [item["eligible"] for item in impact_batches],
                   "historical_replay_requires_restore": [item["historical_replay_requires_restore"] for item in impact_batches]},
        "targeted_markdown": {"preflight_exit": preflight["exit_code"],
                              "check_exit": markdown["exit_code"],
                              "check_status": ("Passed" if markdown["result"].get("finding_total") == 0
                                               and markdown["result"].get("has_failures") is False
                                               else "Failed")},
        "search_restore": search_summary,
        "project_hashes_after": final_project_hashes,
        "archive_payload_still_at_source": True,
        "commands": [{key: value for key, value in item.items() if key != "result"} for item in commands],
    }
    write_json(results / "prearchive-full-summary.json", summary)
    write_json(results / "prearchive-full-command-results.json", commands)
    return summary


def run_archive_fixture(workspace: Path, *, tool: Path = DEFAULT_TOOL) -> Dict[str, Any]:
    """Run a two-batch same-volume archive pilot, rearchive, and full restore."""
    workspace = workspace.resolve()
    tool = tool if tool.is_absolute() else ROOT / tool
    tool = tool.resolve()
    manifest = _read_json(workspace / "fixture-manifest.json")
    profile = workspace / "directory-profile.json"
    request = workspace / "directory-request.json"
    project = Path(manifest["roots"]["project"])
    archive_root = Path(manifest["roots"]["archive_root"])
    records_root = Path(manifest["roots"]["records_root"])
    request_data = _read_json(request)
    if len(request_data.get("batches", [])) != 2:
        raise FixtureError("archive fixture must contain exactly two declared batches")
    commands: List[Dict[str, Any]] = []

    archive = _run_cli(workspace, profile, "workflow", [
        "--phase", "archive", "--request", str(request.resolve()),
        "--archive-root", str(archive_root.resolve()), "--records-dir", str(records_root.resolve()),
    ], "archive-workflow", tool)
    archive_result = archive["result"]
    if (archive_result.get("phase") != "archive" or archive_result.get("state") != "Completed"
            or archive_result.get("status") != "Passed"):
        raise FixtureError("two-batch archive workflow did not reach Passed/Completed")
    archive_receipt_path = Path(archive_result["workflow_path"])
    archive_receipt = _read_json(archive_receipt_path)
    batches = archive_receipt.get("batches", [])
    if len(batches) != 2 or any(item.get("stage") != "Archived" for item in batches):
        raise FixtureError("archive workflow did not leave both authorized batches Archived")
    if batches[0].get("pilot_done") is not True:
        raise FixtureError("first batch pilot restore was not recorded as completed")
    event_names = [item.get("step") for item in archive_receipt.get("steps", [])]
    if "PilotApplying" not in event_names or "restore-verified" not in event_names or event_names.count("FinalApplying") < 2:
        raise FixtureError("workflow did not record pilot, actual restoration, and both final archives")
    plans = list(archive_receipt_path.parent.glob("archive-plan-*.json"))
    plan_file_counts = []
    for plan_path in plans:
        plan = _read_json(plan_path)
        for planned_batch in plan.get("batches", []):
            source = planned_batch.get("source")
            files = sum(entry.get("kind") == "file" for entry in planned_batch.get("manifest", {}).get("entries", []))
            plan_file_counts.append((source, files))
    expected_plan_counts = sorted([
        (request_data["batches"][0]["source"], manifest["counts"]["archive_batch_files"][0]),
        (request_data["batches"][0]["source"], manifest["counts"]["archive_batch_files"][0]),
        (request_data["batches"][1]["source"], manifest["counts"]["archive_batch_files"][1]),
    ])
    if sorted(plan_file_counts) != expected_plan_counts:
        raise FixtureError("archive workflow did not create one pilot plus two exact final plans")
    commands.append(archive)

    journal_paths = [Path(item["journal_path"]) for item in batches]
    before_restore: List[Dict[str, Any]] = []
    for index, (batch, journal_path) in enumerate(zip(request_data["batches"], journal_paths), start=1):
        verified = _run_cli(workspace, profile, "verify", [
            "--journal", str(journal_path.resolve()), "--archive-root", str(archive_root.resolve()),
        ], "archive-verify-{}".format(index), tool)
        result = verified["result"]
        if result.get("state") != "Archived" or result.get("status") != "Passed":
            raise FixtureError("archive batch {} did not verify Archived".format(index))
        first_item = next(item for item in manifest["archive_files"] if item["batch"] == index)
        located = _run_cli(workspace, profile, "locate", [
            "--journal", str(journal_path.resolve()), "--original", first_item["path"],
            "--archive-root", str(archive_root.resolve()),
        ], "archive-locate-{}".format(index), tool)
        location = located["result"]
        if (location.get("status") != "Passed" or location.get("resolution") != "ArchivedResolved"
                or location.get("original_path_status") != "Missing" or location.get("archive_present") is not True):
            raise FixtureError("archive batch {} locator conflated archive resolution with source presence".format(index))
        before_restore.extend([verified, located])
    commands.extend(before_restore)

    restored = _run_cli(workspace, profile, "workflow", [
        "--phase", "restore", "--resume", str(archive_receipt_path.resolve()),
        "--archive-root", str(archive_root.resolve()), "--records-dir", str(records_root.resolve()),
    ], "restore-all-batches", tool)
    restore_result = restored["result"]
    if (restore_result.get("phase") != "archive" or restore_result.get("last_action") != "restore"
            or restore_result.get("state") != "Restored"
            or restore_result.get("status") != "Passed" or restore_result.get("completion") != "all_recovered"):
        raise FixtureError("archive workflow resume did not reach Passed/Restored/all_recovered")
    commands.append(restored)

    after_restore: List[Dict[str, Any]] = []
    for index, (batch, journal_path) in enumerate(zip(request_data["batches"], journal_paths), start=1):
        verified = _run_cli(workspace, profile, "verify", [
            "--journal", str(journal_path.resolve()), "--archive-root", str(archive_root.resolve()),
        ], "restored-verify-{}".format(index), tool)
        result = verified["result"]
        if result.get("state") != "Restored" or result.get("status") != "Passed":
            raise FixtureError("archive batch {} did not verify Restored".format(index))
        first_item = next(item for item in manifest["archive_files"] if item["batch"] == index)
        located = _run_cli(workspace, profile, "locate", [
            "--journal", str(journal_path.resolve()), "--original", first_item["path"],
            "--archive-root", str(archive_root.resolve()),
        ], "restored-locate-{}".format(index), tool)
        location = located["result"]
        if (location.get("status") != "Passed" or location.get("resolution") != "Restored"
                or location.get("original_path_status") != "Present" or location.get("archive_present") is not False):
            raise FixtureError("restored locator did not report original-path presence")
        after_restore.extend([verified, located])
    commands.extend(after_restore)

    baseline = manifest["baseline_sha256"]
    current = {path: sha256_file(project / path) for path in baseline}
    if current != baseline:
        raise FixtureError("archive restore changed critical docs, entry or search config")
    for item in manifest["archive_files"]:
        source = project / item["path"]
        info = source.stat()
        if (sha256_file(source) != item["sha256"] or info.st_size != item["size"]
                or info.st_mode & 0o777 != item["mode"] or info.st_mtime_ns != item["mtime_ns"]
                or (info.st_dev, info.st_ino) != (item["device"], item["inode"])):
            raise FixtureError("archive restore failed to preserve file bytes/metadata {}".format(item["path"]))
    for item in manifest["archive_directories"]:
        source = project / item["path"]
        info = source.stat()
        if (info.st_mode & 0o777 != item["mode"] or info.st_mtime_ns != item["mtime_ns"]
                or (info.st_dev, info.st_ino) != (item["device"], item["inode"])):
            raise FixtureError("archive restore failed to preserve directory metadata {}".format(item["path"]))
    if any((archive_root / batch["destination"]).exists() for batch in request_data["batches"]):
        raise FixtureError("archive payload remained after the full restore")

    summary = {
        "status": "Passed",
        "scope": "two-batch tiny same-volume archive pilot, rearchive, and total restore",
        "python_cli": str(tool),
        "profile_file_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "project": str(project.resolve()),
        "workflow_archive": {"status": archive_result["status"], "state": archive_result["state"],
                             "batch_count": len(batches), "pilot_done": batches[0]["pilot_done"],
                             "workflow_steps": event_names, "archive_plan_file_counts": plan_file_counts},
        "restore": {"status": restore_result["status"], "state": restore_result["state"],
                    "completion": restore_result["completion"],
                    "restored_original_hashes_match": current == baseline,
                    "verified_files": len(manifest["archive_files"]),
                    "verified_directories": len(manifest["archive_directories"])},
        "source_archive_records_are_separate": True,
        "commands": [{key: value for key, value in item.items() if key != "result"} for item in commands],
    }
    write_json(workspace / "results" / "archive-forward-summary.json", summary)
    write_json(workspace / "results" / "archive-command-results.json", commands)
    return summary


def run_unity_protected_fixture(workspace: Path, *, tool: Path = DEFAULT_TOOL) -> Dict[str, Any]:
    """Prove a Unity-preset Assets payload cannot be archived by relabeling it."""
    workspace = workspace.resolve()
    tool = tool if tool.is_absolute() else ROOT / tool
    tool = tool.resolve()
    manifest_path = workspace / "fixture-manifest.json"
    if not manifest_path.is_file():
        manifest = build_fixture(workspace, history_files=8, census_entries=12,
                                 archive_counts=(2, 3), max_seconds=60)
    else:
        manifest = _read_json(manifest_path)
    project = Path(manifest["roots"]["project"])
    archive_root = Path(manifest["roots"]["archive_root"])
    records_root = Path(manifest["roots"]["records_root"])
    profile_path = workspace / "directory-profile.json"
    profile = _read_json(profile_path)
    profile["preset"] = "unity"
    profile["classifications"] = [
        item for item in profile["classifications"] if item.get("path") != "Assets"
    ] + [{"path": "Assets", "role": "historical",
          "reason": "Deliberate adversarial label; Unity protected payload must remain in place."}]
    profile["archive"]["candidates"] = ["Assets"]
    write_json(profile_path, profile)

    asset = project / "Assets/fixture.asset"
    meta = project / "Assets/fixture.asset.meta"
    if not meta.exists():
        _write(meta, b"fileFormatVersion: 2\nguid: synthetic-fixture-only\n")
    closure_path = project / "history/closed-batch-one/close-note.md"
    request = {"schema_version": 1, "batches": [{
        "source": "Assets",
        "destination": "synthetic-project/Assets",
        "closure": {"decision": "closed", "reason": "Adversarial synthetic request; must not override Unity preset protection.",
                    "evidence": [{"path": "history/closed-batch-one/close-note.md",
                                  "sha256": sha256_file(closure_path)}]},
        "historical_references": [],
        "known_absent": [],
    }]}
    request_path = workspace / "unity-protected-request.json"
    write_json(request_path, request)
    before = {str(path.relative_to(project)): sha256_file(path) for path in
              (asset, meta, project / ".ignore", project / ".vscode/settings.json")}
    profile_before = sha256_file(profile_path)
    asset_dir_before = project / "Assets"
    asset_dir_info = asset_dir_before.stat()
    archive_before = sorted(path.relative_to(archive_root).as_posix()
                            for path in archive_root.rglob("*") if path.is_file())
    records_before = sorted(path.relative_to(records_root).as_posix()
                            for path in records_root.rglob("*") if path.is_file())
    results = workspace / "results"
    results.mkdir(parents=True, exist_ok=True)
    plan_path = results / "unity-protected-plan.json"
    output_path = results / "unity-protected-report.json"
    argv = [str(tool), "directory", "archive-preview", "--project", str(project.resolve()),
            "--profile", str(profile_path.resolve()), "--request", str(request_path.resolve()),
            "--archive-root", str(archive_root.resolve()), "--records-dir", str(records_root.resolve()),
            "--plan", str(plan_path.resolve()), "--output", str(output_path.resolve())]
    completed = subprocess.run(argv, cwd=str(ROOT), text=True, encoding="utf-8",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    message = (completed.stderr or completed.stdout).strip()
    try:
        result = json.loads(message) if message else {}
    except json.JSONDecodeError:
        result = {"unparsed_output": message}
    blocked = ((completed.returncode == 2 and result.get("reason_code") == "PROTECTED_PATH")
               or (completed.returncode == 0 and result.get("status") == "Blocked"
                   and result.get("reason_code") == "PROTECTED_PATH"))
    if not blocked:
        raise FixtureError("Unity protected archive-preview did not return the precise PROTECTED_PATH block")
    after = {str(path.relative_to(project)): sha256_file(path) for path in
             (asset, meta, project / ".ignore", project / ".vscode/settings.json")}
    asset_dir_after = asset_dir_before.stat()
    archive_after = sorted(path.relative_to(archive_root).as_posix()
                           for path in archive_root.rglob("*") if path.is_file())
    records_after = sorted(path.relative_to(records_root).as_posix()
                           for path in records_root.rglob("*") if path.is_file())
    if (before != after or profile_before != sha256_file(profile_path)
            or (asset_dir_info.st_dev, asset_dir_info.st_ino, asset_dir_info.st_mode, asset_dir_info.st_mtime_ns)
               != (asset_dir_after.st_dev, asset_dir_after.st_ino, asset_dir_after.st_mode, asset_dir_after.st_mtime_ns)
            or archive_before != archive_after or records_before != records_after
            or plan_path.exists()):
        raise FixtureError("blocked Unity archive preview changed payload/config/meta or created recovery data")
    summary = {
        "status": "Passed",
        "scope": "Unity-preset protected Assets adversarial archive-preview only",
        "python_cli": str(tool),
        "preset": "unity",
        "adversarial_classification": {"path": "Assets", "role": "historical", "closure": "closed"},
        "result": {"exit_code": completed.returncode, "reason_code": result.get("reason_code"),
                   "blocked": blocked, "project_writes": result.get("project_writes")},
        "unchanged_sha256": before,
        "profile_sha256": profile_before,
        "archive_files_unchanged": archive_before == archive_after,
        "records_files_unchanged": records_before == records_after,
        "plan_created": plan_path.exists(),
        "unity_editor": "Not run",
    }
    write_json(results / "unity-protected-summary.json", summary)
    write_json(results / "unity-protected-command.json", {
        "argv": argv, "exit_code": completed.returncode,
        "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip(),
    })
    return summary


def _run_workflow_wrapper(workspace: Path, name: str, args: List[str], *, python: Path) -> Dict[str, Any]:
    workspace = workspace.resolve()
    python = python if python.is_absolute() else ROOT / python
    python = python.resolve()
    results = workspace / "results"
    results.mkdir(parents=True, exist_ok=True)
    output = results / (name + ".json")
    project = workspace / "project"
    profile = workspace / "directory-profile.json"
    records = workspace / "records"
    argv = [str(python), str((ROOT / "tools/run_directory_maintenance.py").resolve()),
            "--project", str(project.resolve()), "--profile", str(profile.resolve()),
            "--records-dir", str(records.resolve()), "--output", str(output.resolve()), *args]
    completed = subprocess.run(argv, cwd=str(ROOT), text=True, encoding="utf-8",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0 or not output.is_file():
        raise FixtureError("{} wrapper returned {}; see {}".format(name, completed.returncode, output))
    return {"name": name, "argv": argv, "exit_code": completed.returncode,
            "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip(),
            "output_path": str(output.resolve()), "result": _read_json(output)}


def run_installed_skill_forward(workspace: Path, *, python: Path) -> Dict[str, Any]:
    """Exercise the installed Skill's prescribed workflow via the formal wrapper."""
    workspace = workspace.resolve()
    manifest = _read_json(workspace / "fixture-manifest.json")
    project = Path(manifest["roots"]["project"])
    archive_root = Path(manifest["roots"]["archive_root"])
    records_root = Path(manifest["roots"]["records_root"])
    profile = workspace / "directory-profile.json"
    request = workspace / "directory-request.json"
    results = workspace / "results"
    results.mkdir(parents=True, exist_ok=True)
    python = python if python.is_absolute() else ROOT / python
    python = python.resolve()
    commands: List[Dict[str, Any]] = []

    history_output = results / "history-before.json"
    history_argv = [str(DEFAULT_TOOL.resolve()), "history", "--project", str(project.resolve()),
                    "--records-dir", str(records_root.resolve()), "--max-records", "20",
                    "--output", str(history_output.resolve())]
    history_before = _run_command(workspace, history_argv, "history-before")
    if not history_output.is_file():
        raise FixtureError("installed Skill history lookup did not write an output")
    history_before["output_path"] = str(history_output.resolve())
    history_before["result"] = _read_json(history_output)
    commands.append(history_before)

    initial_snapshot = _project_metadata_snapshot(project)
    initial_hashes = {path: sha256_file(project / path) for path in manifest["baseline_sha256"]}
    inspect = _run_workflow_wrapper(workspace, "installed-skill-inspect", [
        "--request", str(request.resolve()),
    ], python=python)
    inspect_result = inspect["result"]
    if (inspect_result.get("phase") != "inspect" or inspect_result.get("state") != "Inspected"
            or inspect_result.get("status") != "Passed"):
        raise FixtureError("installed Skill default workflow did not remain inspect-only and complete")
    if (_project_metadata_snapshot(project) != initial_snapshot
            or {path: sha256_file(project / path) for path in manifest["baseline_sha256"]} != initial_hashes):
        raise FixtureError("installed Skill inspect changed the synthetic project")
    inspect_receipt = _read_json(Path(inspect_result["workflow_path"]))
    inspect_steps = {item["step"]: item["status"] for item in inspect_receipt.get("steps", [])}
    if inspect_steps != {"census": "Passed", "impact": "Passed", "search-preview": "Preview"}:
        raise FixtureError("installed Skill inspect receipt does not match expected bounded phases")
    inspect_census = _read_json(Path(next(item["artifact"] for item in inspect_receipt["steps"]
                                          if item["step"] == "census")))
    if inspect_census.get("body_bytes_sent") != 0:
        raise FixtureError("installed Skill inspect sent project body bytes to the CLI")
    commands.append(inspect)

    search = _run_workflow_wrapper(workspace, "installed-skill-search", ["--phase", "search"], python=python)
    search_result = search["result"]
    if search_result.get("status") != "Passed" or search_result.get("state") != "Completed":
        raise FixtureError("installed Skill search workflow did not pass")
    search_receipt = _read_json(Path(search_result["workflow_path"]))
    search_journal_path = Path(search_receipt["search_journal"])
    search_journal = _read_json(search_journal_path)
    search_validation = search_journal.get("validation", {})
    if (search_journal.get("state") != "Applied" or search_journal.get("status") != "Passed"
            or any(value != "Passed" for value in search_validation.get("critical_paths", {}).values())
            or search_validation.get("vscode_ui") != "Not run"):
        raise FixtureError("installed Skill search did not preserve critical paths or disclose UI limits")
    commands.append(search)

    archive = _run_workflow_wrapper(workspace, "installed-skill-archive", [
        "--phase", "archive", "--request", str(request.resolve()),
        "--archive-root", str(archive_root.resolve()),
    ], python=python)
    archive_result = archive["result"]
    if archive_result.get("status") != "Passed" or archive_result.get("state") != "Completed":
        raise FixtureError("installed Skill archive workflow did not pass")
    archive_receipt = _read_json(Path(archive_result["workflow_path"]))
    archived_batches = archive_receipt.get("batches", [])
    archive_steps = [item.get("step") for item in archive_receipt.get("steps", [])]
    if (len(archived_batches) != 2 or not archived_batches[0].get("pilot_done")
            or any(item.get("stage") != "Archived" for item in archived_batches)
            or "PilotApplying" not in archive_steps or "restore-verified" not in archive_steps
            or archive_steps.count("FinalApplying") < 2):
        raise FixtureError("installed Skill archive phase missed the pilot restore/rearchive sequence")
    journals = [Path(item["journal_path"]) for item in archived_batches]
    archived_locations: List[Dict[str, Any]] = []
    for index, (batch_index, journal) in enumerate(zip((1, 2), journals), start=1):
        source_file = next(item for item in manifest["archive_files"] if item["batch"] == batch_index)
        verify = _run_cli(workspace, profile, "verify", ["--journal", str(journal.resolve()),
                            "--archive-root", str(archive_root.resolve())],
                          "installed-skill-archive-verify-{}".format(index), DEFAULT_TOOL)
        if verify["result"].get("state") != "Archived" or verify["result"].get("status") != "Passed":
            raise FixtureError("installed Skill archive verify did not return Archived")
        locate = _run_cli(workspace, profile, "locate", ["--journal", str(journal.resolve()),
                            "--original", source_file["path"], "--archive-root", str(archive_root.resolve())],
                          "installed-skill-archive-locate-{}".format(index), DEFAULT_TOOL)
        location = locate["result"]
        if (location.get("resolution") != "ArchivedResolved" or location.get("original_path_status") != "Missing"
                or location.get("archive_present") is not True):
            raise FixtureError("installed Skill locate conflated archive resolution with source presence")
        archived_locations.extend((verify, locate))
    commands.append(archive)
    commands.extend(archived_locations)

    archive_restore = _run_workflow_wrapper(workspace, "installed-skill-archive-restore", [
        "--phase", "restore", "--resume", str(Path(archive_result["workflow_path"]).resolve()),
        "--archive-root", str(archive_root.resolve()),
    ], python=python)
    restore_result = archive_restore["result"]
    if (restore_result.get("phase") != "archive" or restore_result.get("last_action") != "restore"
            or restore_result.get("state") != "Restored" or restore_result.get("status") != "Passed"
            or restore_result.get("completion") != "all_recovered"):
        raise FixtureError("installed Skill archive workflow total restore did not pass")
    commands.append(archive_restore)
    for index, (batch_index, journal) in enumerate(zip((1, 2), journals), start=1):
        source_file = next(item for item in manifest["archive_files"] if item["batch"] == batch_index)
        verify = _run_cli(workspace, profile, "verify", ["--journal", str(journal.resolve()),
                            "--archive-root", str(archive_root.resolve())],
                          "installed-skill-restored-verify-{}".format(index), DEFAULT_TOOL)
        if verify["result"].get("state") != "Restored" or verify["result"].get("status") != "Passed":
            raise FixtureError("installed Skill archive restore verify did not return Restored")
        locate = _run_cli(workspace, profile, "locate", ["--journal", str(journal.resolve()),
                            "--original", source_file["path"], "--archive-root", str(archive_root.resolve())],
                          "installed-skill-restored-locate-{}".format(index), DEFAULT_TOOL)
        location = locate["result"]
        if (location.get("resolution") != "Restored" or location.get("original_path_status") != "Present"
                or location.get("archive_present") is not False):
            raise FixtureError("installed Skill restore location did not report original-path presence")
        commands.extend((verify, locate))

    # Restore the independently applied search configuration after the archive
    # workflow, leaving the synthetic fixture in its exact original state.
    search_restore = _run_workflow_wrapper(workspace, "installed-skill-search-restore", [
        "--phase", "restore", "--journal", str(search_journal_path.resolve()),
    ], python=python)
    if (search_restore["result"].get("state") != "Restored"
            or search_restore["result"].get("status") != "Passed"
            or search_restore["result"].get("completion") != "all_recovered"):
        raise FixtureError("installed Skill search configuration restore did not pass")
    commands.append(search_restore)

    for item in manifest["archive_files"]:
        source = project / item["path"]
        info = source.stat()
        if (sha256_file(source) != item["sha256"] or info.st_size != item["size"]
                or info.st_mode & 0o777 != item["mode"] or info.st_mtime_ns != item["mtime_ns"]
                or (info.st_dev, info.st_ino) != (item["device"], item["inode"])):
            raise FixtureError("installed Skill final restore changed original archive payload {}".format(item["path"]))
    for item in manifest["archive_directories"]:
        source = project / item["path"]
        info = source.stat()
        if (info.st_mode & 0o777 != item["mode"] or info.st_mtime_ns != item["mtime_ns"]
                or (info.st_dev, info.st_ino) != (item["device"], item["inode"])):
            raise FixtureError("installed Skill final restore changed original archive directory {}".format(item["path"]))
    final_hashes = {path: sha256_file(project / path) for path in manifest["baseline_sha256"]}
    if final_hashes != manifest["baseline_sha256"]:
        raise FixtureError("installed Skill final restore did not reproduce original project/config hashes")
    history_after_output = results / "history-after.json"
    history_after_argv = [str(DEFAULT_TOOL.resolve()), "history", "--project", str(project.resolve()),
                          "--records-dir", str(records_root.resolve()), "--max-records", "40",
                          "--output", str(history_after_output.resolve())]
    history_after = _run_command(workspace, history_after_argv, "history-after")
    history_after["output_path"] = str(history_after_output.resolve())
    history_after["result"] = _read_json(history_after_output)
    commands.extend((history_after,))
    footprint = archive_result.get("metrics", {})
    summary = {
        "status": "Passed",
        "scope": "installed Skill + formal workflow wrapper in a new synthetic fixture; no discovery claim",
        "python": str(python),
        "workspace": str(workspace.resolve()),
        "history_before": history_before["result"],
        "inspect": {"status": inspect_result["status"], "state": inspect_result["state"],
                    "steps": inspect_steps, "body_bytes_sent": inspect_census["body_bytes_sent"],
                    "project_metadata_entries_unchanged": len(initial_snapshot)},
        "search": {"status": search_result["status"], "critical_paths": search_validation.get("critical_paths"),
                   "visible_before": search_validation.get("before", {}).get("visible_files"),
                   "visible_after": search_validation.get("after", {}).get("visible_files"),
                   "hidden_files": search_validation.get("hidden_files"),
                   "vscode_ui": search_validation.get("vscode_ui")},
        "archive": {"status": archive_result["status"], "state": archive_result["state"],
                    "pilot_done": archived_batches[0]["pilot_done"], "steps": archive_steps,
                    "batches": [{"source": item["source"], "state": item["stage"],
                                 "journal_path": item["journal_path"]} for item in archived_batches]},
        "archive_restore": {"status": restore_result["status"], "state": restore_result["state"],
                            "completion": restore_result["completion"],
                            "payload_files_restored": len(manifest["archive_files"]),
                            "payload_directories_restored": len(manifest["archive_directories"]),
                            "original_hashes_match": final_hashes == manifest["baseline_sha256"]},
        "search_restore": {"status": search_restore["result"]["status"],
                           "state": search_restore["result"]["state"],
                           "original_config_hashes_match": final_hashes == manifest["baseline_sha256"]},
        "footprint_metrics": footprint,
        "history_after": history_after["result"],
        "unity_editor": "Not run",
        "commands": [{key: value for key, value in item.items() if key != "result"} for item in commands],
    }
    write_json(results / "installed-skill-forward-summary.json", summary)
    write_json(results / "installed-skill-command-results.json", commands)
    return summary


def _prepare(args: argparse.Namespace) -> int:
    if args.workspace:
        workspace = Path(args.workspace)
        if workspace.exists() and not args.allow_empty_existing:
            raise FixtureError("explicit workspace exists; pass --allow-empty-existing only if empty")
    else:
        FORWARD.mkdir(parents=True, exist_ok=True)
        workspace = Path(tempfile.mkdtemp(prefix="fixture-", dir=str(FORWARD)))
    manifest = build_fixture(workspace, history_files=args.history_files,
                             census_entries=args.census_entries,
                             archive_counts=args.archive_counts)
    print(json.dumps({"status": "Prepared", "manifest": str(workspace / "fixture-manifest.json"),
                      "counts": manifest["counts"], "roots": manifest["roots"]},
                     ensure_ascii=False, sort_keys=True))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true",
                        help="prepare synthetic roots; no product CLI is invoked")
    parser.add_argument("--run-small", action="store_true",
                        help="prepare a small synthetic fixture and run inspect/search/restore")
    parser.add_argument("--run-archive-small", action="store_true",
                        help="prepare a small fixture and run two-batch archive/restore workflow")
    parser.add_argument("--run-prearchive-full", action="store_true",
                        help="prepare exact 1.3 large fixture; census/check/inspect/search/restore only")
    parser.add_argument("--run-archive-existing", action="store_true",
                        help="run archive pilot and total restore on an existing prepared fixture")
    parser.add_argument("--run-unity-protected-small", action="store_true",
                        help="prepare or reuse a small fixture and prove Unity Assets protection")
    parser.add_argument("--run-installed-skill-forward", action="store_true",
                        help="run the installed Skill's formal workflow wrapper on an existing fixture")
    parser.add_argument("--workspace", help="new or empty workspace under the authorized forward directory")
    parser.add_argument("--allow-empty-existing", action="store_true")
    parser.add_argument("--missing-vscode-config", action="store_true",
                        help="prepare the synthetic project without .vscode/settings.json")
    parser.add_argument("--cli", default=str(DEFAULT_TOOL), help="public CLI executable for this interpreter")
    parser.add_argument("--history-files", type=int, default=None)
    parser.add_argument("--census-entries", type=int, default=None)
    parser.add_argument("--archive-counts", type=int, nargs=2, default=None)
    args = parser.parse_args(argv)
    if not args.prepare_only and not args.run_small and not args.run_archive_small and not args.run_prearchive_full and not args.run_archive_existing and not args.run_unity_protected_small and not args.run_installed_skill_forward:
        parser.error("full driver remains gated until archive/workflow interface freeze")
    try:
        if args.run_archive_existing:
            workspace = Path(args.workspace) if args.workspace else None
            if workspace is None or not workspace.is_dir() or not (workspace / "fixture-manifest.json").is_file():
                raise FixtureError("--run-archive-existing requires an existing prepared fixture workspace")
            cli_path = Path(args.cli)
            summary = run_archive_fixture(workspace, tool=cli_path)
            print(json.dumps({"status": summary["status"],
                              "summary": str((workspace / "results/archive-forward-summary.json").resolve()),
                              "counts": _read_json(workspace / "fixture-manifest.json")["counts"]},
                             ensure_ascii=False, sort_keys=True))
            return 0
        if args.run_unity_protected_small:
            if args.workspace:
                workspace = Path(args.workspace)
                if not (workspace / "fixture-manifest.json").is_file():
                    if workspace.exists() and not args.allow_empty_existing:
                        raise FixtureError("explicit workspace exists; pass --allow-empty-existing only if empty")
                    build_fixture(workspace, history_files=8, census_entries=12,
                                  archive_counts=(2, 3), vscode_config=True)
            else:
                FORWARD.mkdir(parents=True, exist_ok=True)
                workspace = Path(tempfile.mkdtemp(prefix="unity-protected-", dir=str(FORWARD)))
                build_fixture(workspace, history_files=8, census_entries=12,
                              archive_counts=(2, 3), vscode_config=True)
            summary = run_unity_protected_fixture(workspace, tool=Path(args.cli))
            print(json.dumps({"status": summary["status"],
                              "summary": str((Path(workspace) / "results/unity-protected-summary.json").resolve())},
                             ensure_ascii=False, sort_keys=True))
            return 0
        if args.run_installed_skill_forward:
            workspace = Path(args.workspace) if args.workspace else None
            if workspace is None or not workspace.is_dir() or not (workspace / "fixture-manifest.json").is_file():
                raise FixtureError("--run-installed-skill-forward requires an existing prepared fixture")
            summary = run_installed_skill_forward(workspace, python=Path(args.cli).parent.parent / "bin/python")
            print(json.dumps({"status": summary["status"],
                              "summary": str((workspace / "results/installed-skill-forward-summary.json").resolve())},
                             ensure_ascii=False, sort_keys=True))
            return 0
        if args.run_small or args.run_archive_small or args.run_prearchive_full:
            if args.workspace:
                workspace = Path(args.workspace)
                existing_manifest = workspace / "fixture-manifest.json"
                if args.run_prearchive_full and existing_manifest.is_file():
                    manifest = _read_json(existing_manifest)
                else:
                    if workspace.exists() and not args.allow_empty_existing:
                        raise FixtureError("explicit workspace exists; pass --allow-empty-existing only if empty")
                    manifest = None
            else:
                FORWARD.mkdir(parents=True, exist_ok=True)
                workspace = Path(tempfile.mkdtemp(prefix="small-run-", dir=str(FORWARD)))
                manifest = None
            small = not args.run_prearchive_full
            if manifest is None:
                manifest = build_fixture(workspace,
                                         history_files=((8 if small else DEFAULT_HISTORY) if args.history_files is None else args.history_files),
                                         census_entries=((12 if small else DEFAULT_CENSUS_ENTRIES) if args.census_entries is None else args.census_entries),
                                         archive_counts=(((2, 3) if small else DEFAULT_ARCHIVE_BATCHES)
                                                         if args.archive_counts is None else args.archive_counts),
                                         max_seconds=(60 if small else 300),
                                         vscode_config=not args.missing_vscode_config)
            cli_path = Path(args.cli)
            if args.run_prearchive_full:
                summary = run_prearchive_full(workspace, tool=cli_path)
                print(json.dumps({"status": summary["status"],
                                  "summary": str((workspace / "results/prearchive-full-summary.json").resolve()),
                                  "counts": manifest["counts"]}, ensure_ascii=False, sort_keys=True))
                return 0
            summary = run_small_fixture(workspace, tool=cli_path)
            if args.run_archive_small:
                archive_summary = run_archive_fixture(workspace, tool=cli_path)
                print(json.dumps({"status": archive_summary["status"],
                                  "summary": str((workspace / "results/archive-forward-summary.json").resolve()),
                                  "counts": manifest["counts"]}, ensure_ascii=False, sort_keys=True))
                return 0
            print(json.dumps({"status": summary["status"],
                              "summary": str((workspace / "results/forward-summary.json").resolve()),
                              "counts": manifest["counts"]}, ensure_ascii=False, sort_keys=True))
            return 0
        if args.history_files is None:
            args.history_files = DEFAULT_HISTORY
        if args.census_entries is None:
            args.census_entries = DEFAULT_CENSUS_ENTRIES
        if args.archive_counts is None:
            args.archive_counts = DEFAULT_ARCHIVE_BATCHES
        return _prepare(args)
    except (FixtureError, OSError, ValueError) as exc:
        parser.exit(2, "fixture preparation failed: {}\n".format(exc))


if __name__ == "__main__":
    raise SystemExit(main())
