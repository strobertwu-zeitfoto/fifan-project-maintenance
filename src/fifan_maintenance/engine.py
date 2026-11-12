from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .inventory import collect
from .models import Context, Finding, FindingLimit, finding_budget
from .project import fingerprint, identity, load_config, project_root
from .worker import MODULES
from .reporting import redacted
from .process import run_bounded


def run(project, *, inventory=False, checks=None, max_seconds=None, files=None, task_profile=None, reference_bodies=None, historical_roots=None, preflight=False, overlay=None):
    root = project_root(project)
    config = load_config(root)
    from .scope import task_config, binding, historical_metadata, preflight as preview_scope
    config = task_config(root, config, files=files, profile=task_profile, reference_bodies=reference_bodies, historical_roots=historical_roots, checks=checks, max_seconds=max_seconds)
    if checks is None and config.get("_task", {}).get("checks"):
        checks = config["_task"]["checks"]
    if checks is not None and set(checks) - set(MODULES):
        raise ValueError("unsupported checks")
    hash_config = dict(config)
    if "_task" in config:
        hash_config["_task"] = {key: value for key, value in config["_task"].items() if key != "checks"}
    config_sha = fingerprint(hash_config)
    if preflight:
        return preview_scope(root, config)
    if overlay is not None:
        import base64
        config["_overlay"] = {p: base64.b64encode(data).decode("ascii") if data is not None else None for p, data in overlay.items()}
    started = time.monotonic()
    ctx = Context(root, {}, config, inventory)
    worker_read_bytes = 0
    reference_read_bytes = 0
    reference_targets = set()
    anchors = {}
    coverage_domains = {}
    stage_seconds = {}
    inventory_limited = False
    with finding_budget(config["max_findings"]) as budget:
        try:
            findings = collect(ctx)
        except FindingLimit:
            findings = list(budget["items"])
            inventory_limited = True
    coverage = [{"check": "inventory", "status": "Unknown" if inventory_limited or any(f.status in {"Unknown", "Blocked", "Not run"} for f in findings) else "Passed", "total": budget["count"], "generation_limited": inventory_limited, "scope": "selected file metadata and bounded hashes"}]
    complete_counts = dict(budget["counts"])
    total_findings = budget["count"]
    has_failures = False
    if inventory_limited:
        findings.append(Finding("inventory", "generation_limit", "盘点问题生成预算耗尽；未检查部分Unknown", status="Unknown"))
        complete_counts["inventory/generation_limit"] = 1
        total_findings += 1
    historical = historical_metadata(ctx, max_seconds=max(0, config["max_seconds"] - (time.monotonic() - started)))
    stage_seconds["inventory"] = round(time.monotonic() - started, 6)
    selected = list(MODULES) if checks is None else checks
    if set(selected) - set(MODULES):
        raise ValueError("unsupported checks")
    payload = json.dumps({"root": str(root), "files": {p: asdict(r) for p, r in ctx.files.items()}, "config": config, "inventory": inventory}).encode()
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "LANG", "LC_ALL"}}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in selected:
        check_started = time.monotonic()
        remaining = config["max_seconds"] - (time.monotonic() - started)
        if remaining <= 0:
            findings.append(Finding(name, "time_budget", "本轮时间预算耗尽，未执行此项", status="Not run"))
            total_findings += 1
            complete_counts[name + "/time_budget"] = 1
            coverage.append({"check": name, "status": "Not run", "total": 0})
            continue
        try:
            if config.get("_task"):
                remaining_bytes = config["max_total_bytes"] - ctx._read_total - worker_read_bytes
                if remaining_bytes <= 0:
                    raise ValueError("task total read budget exhausted")
                worker_config = {**config, "max_total_bytes": remaining_bytes}
                payload = json.dumps({"root": str(root), "files": {p: asdict(r) for p, r in ctx.files.items()}, "config": worker_config, "inventory": inventory}).encode()
            result = run_bounded([sys.executable, "-m", "fifan_maintenance.worker", name], input=payload, timeout=min(remaining, 15), env=env, cwd=str(Path(__file__).resolve().parents[2]))
            if len(result.stdout) > 8 * 1024 * 1024:
                raise ValueError("oversized check output")
            data = json.loads(result.stdout)
            if result.returncode or "error" in data:
                raise ValueError("check worker failed")
            worker_read_bytes += data.get("read_bytes", 0)
            reference_read_bytes += data.get("reference_bytes", 0)
            reference_targets.update(data.get("reference_targets", []))
            anchors.update(data.get("observations", {}).get("anchors", {}))
            coverage_domains.update(data.get("observations", {}).get("coverage_domains", {}))
            stage_seconds[name] = round(time.monotonic() - check_started, 6)
            items = [Finding(**f) for f in data["findings"]]
            findings.extend(items)
            state = data["status"]
            total_findings += data["total"]
            has_failures = has_failures or data["has_failures"]
            for key, value in data["counts"].items():
                complete_counts[key] = complete_counts.get(key, 0) + value
            coverage.append({"check": name, "status": state, "total": data["total"], "generation_limited": data.get("generation_limited", False), "scope": "selected files and declared references only"})
            if data.get("generation_limited"):
                findings.append(Finding(name, "generation_limit", "问题生成预算耗尽；计数仅含已生成部分，未检查部分Unknown", status="Unknown"))
                complete_counts[name + "/generation_limit"] = 1
                total_findings += 1
            if data["total"] > len(items):
                findings.append(Finding(name, "findings_limited", "报告仅展示部分问题；完整数量见coverage", status="Unknown", evidence={"total": data["total"]}))
                complete_counts[name + "/findings_limited"] = 1
                total_findings += 1
        except (subprocess.TimeoutExpired, OSError, ValueError, TypeError, KeyError) as error:
            findings.append(Finding(name, "worker_incomplete", "检查未完成：" + type(error).__name__, status="Unknown"))
            total_findings += 1
            complete_counts[name + "/worker_incomplete"] = 1
            coverage.append({"check": name, "status": "Unknown", "total": 0})
    limit = config["max_findings"]
    findings.sort(key=lambda f: ({"error": 0, "warning": 1, "info": 2}.get(f.severity, 1), {"Failed": 0, "Blocked": 1, "Unknown": 2, "Not run": 3}.get(f.status, 4), f.check, f.path, f.line or 0, f.code))
    files = {p: asdict(r) for p, r in ctx.files.items()}
    for name in selected:
        if name == 'links':
            for domain in ('local_targets', 'local_anchors', 'external'):
                coverage_domains.setdefault(domain, {'status': 'Unknown', 'complete': False, 'checked': 0, 'unknown_reasons': ['WORKER_INCOMPLETE'], 'scope': binding(config)['scope']})
        elif name == 'documents':
            item = next((entry for entry in coverage if entry['check'] == name), {})
            coverage_domains['document_hints'] = {'status': item.get('status', 'Unknown'), 'complete': item.get('status') in ('Passed', 'Failed') and not item.get('generation_limited', False), 'checked': len(files), 'unknown_reasons': [] if item.get('status') in ('Passed', 'Failed') else ['DOCUMENT_HINTS_REQUIRE_REVIEW'], 'scope': binding(config)['scope']}
    coverage_domains['historical_metadata'] = {'status': historical['status'], 'complete': historical.get('complete', historical['status'] == 'Passed'), 'checked': historical['file_count'], 'unknown_reasons': [] if historical['status'] == 'Passed' else ['HISTORICAL_METADATA_INCOMPLETE'], 'scope': {'historical_roots': binding(config)['scope']['historical_roots']}}
    return {"schema_version": 1, "tool_version": __version__, "root": str(root), "identity": identity(root), "checks": selected, "mode": "inventory" if inventory else "check", "config_sha256": config_sha, **binding(config), "historical_metadata": historical, "coverage_domains": coverage_domains, "domain_contract_version": 1, "goal": config.get("_task", {}).get("goal"), "historical_sources": config.get("historical_sources", []), "anchors": anchors, "anchor_encoding": "sha256", "candidate": "Preview" if overlay is not None else "Disk", "metrics": {"inventory_read_bytes": ctx._read_total, "worker_read_bytes": worker_read_bytes, "reference_body_bytes": reference_read_bytes, "reference_target_count": len(reference_targets), "hashed_bytes": sum(r.size for r in ctx.files.values() if r.sha256), "stage_seconds": stage_seconds, "model_usage": "Unknown", "reused_check_results": 0}, "file_count": len(files), "file_bytes": sum(f.size for f in ctx.files.values()), "elapsed_seconds": round(time.monotonic() - started, 3), "coverage": coverage, "finding_counts": complete_counts, "finding_total": total_findings, "has_failures": has_failures, "findings": [f.to_dict() for f in findings[:limit]], "findings_truncated": total_findings > min(len(findings), limit), "files": files, "model_calls": 0, "semantic_acceptance": "Not run"}


def issue_key(finding):
    from .comparison import issue_identity
    return issue_identity(finding)


def compare_state(report, previous):
    """Compatibility wrapper over the same stable, coverage-aware comparison."""
    from .comparison import compare_reports
    if not isinstance(previous, dict):
        return {"baseline": "new", "changed_files": report["file_count"], "new_findings": len(report["findings"]), "resolved_findings": None}
    result = compare_reports(previous, report)
    old, new = previous.get("files", {}), report.get("files", {})
    growth = [{"path": path, "before_bytes": old[path]["size"], "after_bytes": new[path]["size"], "growth_bytes": new[path]["size"] - old[path]["size"]}
              for path in old.keys() & new.keys() if new[path]["size"] > old[path]["size"]]
    growth.sort(key=lambda item: (-item["growth_bytes"], item["path"]))
    return {"baseline": "matched" if result["compatible"] else "new", "changed_files": result["changed_files"],
            "growth": growth[:20], "growth_total_files": len(growth),
            "new_findings": result.get("observed_counts", {}).get("new"),
            "resolved_findings": result["counts"]["resolved"] if result.get("complete") else None,
            "status": result["status"], "no_new_issues": result["no_new_issues"], "reasons": result.get("reasons", []),
            "method": "bounded mechanical recheck; stable multiset identity independent of line numbers"}
