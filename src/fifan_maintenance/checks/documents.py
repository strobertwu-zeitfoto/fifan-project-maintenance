from __future__ import annotations

from collections import defaultdict
import re

from ..models import Finding
from ..adapters.markdown import parse


def run(ctx):
    findings = []
    duplicate = defaultdict(list)
    status_mentions = defaultdict(list)
    versions = []
    tasks = []
    options = ctx.config.get("documents", {})
    for path, record in sorted(ctx.files.items()):
        if not path.lower().endswith((".md", ".markdown")) or record.kind != "file":
            continue
        if record.size > options.get("large_bytes", 100_000):
            findings.append(Finding("documents", "large-document", "文档体量较大，仅为治理提示", path, status="Unknown", evidence={"bytes": record.size}))
        try:
            doc = parse(ctx.read_text(path))
        except (OSError, ValueError, UnicodeError) as exc:
            findings.append(Finding("documents", "read-error", "无法读取或解析文档", path, status="Unknown", evidence={"error": type(exc).__name__}))
            continue
        for line, paragraph in doc.paragraphs:
            if len(paragraph) > options.get("paragraph_chars", 1200):
                findings.append(Finding("documents", "long-paragraph", "段落过长，仅为可读性提示", path, line, status="Unknown", evidence={"characters": len(paragraph)}))
            normalized = " ".join(paragraph.split())
            if len(normalized) >= options.get("duplicate_min_chars", 120):
                duplicate[normalized].append((path, line))
            # Numbers are locations for human comparison, never semantic conflicts.
            for match in re.finditer(r"(完成|剩余|未完成|complete|remaining)\s*[:：]?\s*(\d+)", paragraph, re.I):
                status_mentions[match[1].lower()].append({"path": path, "line": line, "value": int(match[2])})
            for match in re.finditer(r"(\d+)\s*(完成|未完|剩余)", paragraph):
                status_mentions[match[2]].append({"path": path, "line": line, "value": int(match[1])})
            for match in re.finditer(r"\b(?:R\d+|v\d+\.\d+(?:\.\d+)?)\b", paragraph):
                versions.append({"path": path, "line": line, "version": match[0]})
            for match in re.finditer(r"\b([A-Z][A-Z0-9-]*-\d+)\s*[：:|—-]\s*(Passed|Failed|Partial|Blocked|Planned|Not run|Unknown)", paragraph):
                tasks.append({"path": path, "line": line, "task": match[1], "state": match[2]})
        for reason in sorted(set(doc.unsupported)):
            findings.append(Finding("documents", "coverage", reason, path, status="Unknown"))
    for paragraph, places in duplicate.items():
        if len(places) > 1:
            findings.append(Finding("documents", "repeated-fragment", "发现完全重复段落；可能为必要历史或合同，不自动删除", places[0][0], places[0][1], status="Unknown", evidence={"locations": [{"path": p, "line": n} for p, n in places], "characters": len(paragraph)}))
    for label, mentions in status_mentions.items():
        if len({m["value"] for m in mentions}) > 1:
            findings.append(Finding("documents", "status-numbers", "状态数字存在差异；时点和合同尚未经语义核实", status="Unknown", evidence={"label": label, "mentions": mentions}))
    if len({v["version"] for v in versions}) > 1:
        findings.append(Finding("documents", "version-locations", "发现不同版本标记位置；对象与时点需语义核实", status="Unknown", evidence={"total": len(versions), "locations": versions}))
    if tasks:
        findings.append(Finding("documents", "task-locations", "定位任务状态声明；不据此更改唯一计划", status="Unknown", evidence={"total": len(tasks), "locations": tasks}))
    return findings
