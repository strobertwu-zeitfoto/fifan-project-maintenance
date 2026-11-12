"""Bounded process entry point for parsing untrusted project documents."""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

from .models import Context, FileRecord, FindingLimit, set_finding_budget

MODULES = {name: "fifan_maintenance.checks." + name for name in ["documents", "links", "configs", "dependencies", "repository", "assets", "evidence", "scripts"]}
MODULES["unity"] = "fifan_maintenance.adapters.unity"


def main():
    try:
        name = sys.argv[1]
        if name not in MODULES:
            raise ValueError("unsupported check")
        payload = json.loads(sys.stdin.buffer.read(16 * 1024 * 1024 + 1))
        context = Context(Path(payload["root"]), {p: FileRecord(**r) for p, r in payload["files"].items()}, payload["config"], payload["inventory"])
        module = importlib.import_module(MODULES[name])
        limit = payload["config"]["max_findings"]
        budget = set_finding_budget(limit)
        exhausted = False
        try:
            findings = module.run(context)
        except FindingLimit:
            findings = budget["items"]
            exhausted = True
        status = "Unknown" if exhausted else "Failed" if any(f.status == "Failed" for f in findings) else "Unknown" if any(f.status in {"Unknown", "Blocked"} for f in findings) else "Not run" if findings and all(f.status == "Not run" for f in findings) else "Passed"
        output = {"findings": [f.to_dict() for f in budget["items"]], "total": budget["count"], "counts": budget["counts"], "status": status, "has_failures": budget["has_failures"], "generation_limited": exhausted, "read_bytes": context._read_total, "primary_bytes": context._primary_bytes, "reference_bytes": context._reference_bytes, "reference_targets": sorted(context._reference_targets)[:20000], "observations": context.observations}
        encoded = json.dumps(output, ensure_ascii=True)
        if len(encoded.encode()) > 6 * 1024 * 1024:
            raise ValueError("serialized finding budget exhausted")
        print(encoded)
    except Exception as error:
        print(json.dumps({"error": type(error).__name__}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
