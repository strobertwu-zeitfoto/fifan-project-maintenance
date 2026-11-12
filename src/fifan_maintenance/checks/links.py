"""Offline local link checks. Targets are deliberately revalidated on every run."""
from __future__ import annotations

import hashlib
import posixpath
from urllib.parse import unquote, urlsplit

from ..adapters.markdown import parse
from ..models import Finding
from ..inventory import matches


def run(ctx):
    findings = []
    documents = {}
    external = 0
    task = ctx.config.get("_task")
    names = ("local_targets", "local_anchors", "external")
    domains = {name: {"status": "Passed", "complete": False, "checked": 0,
                      "observed": 0, "unknown_reasons": ["RUN_NOT_COMPLETED"],
                      "scope": {"sources": [], "reference_bodies": task.get("reference_bodies", []) if task else None,
                                "selection": "current_source_links; full-original-anchor-identities"}}
               for name in names}
    ctx.observations.setdefault("coverage_domains", {}).update(domains)
    ctx.observations["anchors"] = {}

    def incomplete(affected, reason, status="Unknown"):
        for name in affected:
            domain = domains[name]
            domain["complete"] = False
            if reason not in domain["unknown_reasons"]:
                domain["unknown_reasons"].append(reason)
            # An observed definite failure remains a failure, with a coverage gap.
            if domain["status"] != "Failed":
                domain["status"] = "Unknown" if status == "Unknown" or domain["status"] == "Unknown" else status

    if task:
        for source in task.get("sources", []):
            if source.lower().endswith((".md", ".markdown", ".html", ".htm")) and source not in ctx.files:
                incomplete(names, "SOURCE_NOT_IN_INVENTORY")

    def body_authorized(path):
        return task is None or path in task.get("sources", []) or matches(path, task.get("reference_bodies", []))

    def load(path):
        # A run-local cache is safe against stale results between invocations.
        if not body_authorized(path):
            raise ValueError("reference body is not authorized by task scope")
        if path not in documents:
            # Slugs belong to the full original document, even when historical
            # source links are hidden by an explicitly declared reading view.
            fulltext = ctx.read_bytes(path).decode("utf-8")
            full = parse(fulltext)
            views = task.get("views", []) if task else []
            if any(view.get("path") == path for view in views):
                from ..reading import select_view
                current = parse(select_view(fulltext, path, views))
                current.anchors = full.anchors
                documents[path] = current
            else:
                documents[path] = full
        return documents[path]

    for source, record in sorted(ctx.files.items()):
        if task is not None and source not in task.get("sources", []):
            continue
        if not source.lower().endswith((".md", ".markdown", ".html", ".htm")):
            continue
        for domain in domains.values():
            domain["scope"]["sources"].append(source)
        if record.kind != "file":
            incomplete(names, "SOURCE_NOT_REGULAR")
            continue
        try:
            doc = load(source)
        except (OSError, ValueError, UnicodeError) as exc:
            incomplete(names, "SOURCE_UNAVAILABLE")
            findings.append(Finding("links", "source-read", "文档读取失败，引用覆盖不足", source, status="Unknown", evidence={"error": type(exc).__name__, "coverage_domains": list(names)}))
            continue
        ctx.observations.setdefault("anchors", {})[source] = sorted(hashlib.sha256(anchor.encode("utf-8")).hexdigest() for anchor in doc.anchors)
        for reason in sorted(set(doc.unsupported)):
            incomplete(names, "UNSUPPORTED_SYNTAX")
            findings.append(Finding("links", "coverage", reason, source, status="Unknown", evidence={"coverage_domains": list(names)}))
        for link in doc.links:
            normalized_target, anchor = link.target, ""
            affected = list(names)
            def report(code, message, status="Failed", domain_names=None, **evidence):
                selected_domains = affected if domain_names is None else domain_names
                if matches(source, ctx.config.get("historical_sources", [])) and status == "Failed":
                    status = "Unknown"
                    message += "；历史副本原始相对基准尚未核实"
                if status == "Unknown":
                    incomplete(selected_domains, code.upper().replace("-", "_"))
                elif status == "Failed":
                    for name in selected_domains:
                        domains[name]["status"] = "Failed"
                findings.append(Finding("links", code, message, source, link.line, status=status, evidence={"target": link.target, "normalized_target": normalized_target, "anchor": anchor, "kind": link.kind, "line_precision": "token-block", "coverage_domains": list(selected_domains), **evidence}))
            try:
                url = urlsplit(link.target)
            except ValueError:
                report("invalid-url", "链接语法无法解析", "Unknown")
                continue
            if url.scheme.lower() in {"http", "https", "mailto", "tel", "ftp"} or (not url.scheme and url.netloc):
                external += 1
                domains["external"]["observed"] += 1
                incomplete(["external"], "EXTERNAL_OFFLINE", "Not run")
                continue
            if url.scheme:
                report("unknown-scheme", "协议未支持，未访问目标", "Unknown")
                continue
            decoded = unquote(url.path)
            anchor = unquote(url.fragment)
            affected = ["local_targets"] + (["local_anchors"] if url.fragment else [])
            domains["local_targets"]["observed"] += 1
            if url.fragment:
                domains["local_anchors"]["observed"] += 1
            if "\x00" in decoded or "\\" in decoded or decoded.startswith("/"):
                report("out-of-scope", "绝对路径或非标准路径未读取", "Unknown")
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(source), decoded)) if decoded else source
            normalized_target = target
            try:
                exists = ctx.exists(target)
                domains["local_targets"]["checked"] += 1
                if not exists:
                    report("missing-target", "本地链接目标不存在", domain_names=["local_targets"], resolved_target=target)
                    if url.fragment:
                        incomplete(["local_anchors"], "ANCHOR_TARGET_MISSING")
                    continue
                if url.query:
                    report("query-semantics", "本地查询参数语义未验证", "Unknown")
                if url.fragment:
                    affected = ["local_anchors"]
                    if ctx.is_dir(target) or not target.lower().endswith((".md", ".markdown", ".html", ".htm")):
                        report("anchor-format", "目标格式的章节锚点风格未知", "Unknown")
                        continue
                    style = ctx.config.get("links", {}).get("anchor_style", "github")
                    if style != "github" and not target.lower().endswith((".html", ".htm")):
                        report("anchor-style", "未支持此章节锚点风格", "Unknown")
                        continue
                    if not body_authorized(target):
                        report("anchor-body-not-authorized", "目标存在，但本轮未授权读取正文验证锚点", "Unknown")
                        continue
                    target_doc = load(target)
                    domains["local_anchors"]["checked"] += 1
                    if anchor not in target_doc.anchors:
                        report("missing-anchor", "本地章节锚点不存在（GitHub 风格）", resolved_target=target)
            except FileNotFoundError:
                report("missing-target", "目标在读取前消失", domain_names=["local_targets"], resolved_target=target)
                if url.fragment:
                    incomplete(["local_anchors"], "ANCHOR_TARGET_DISAPPEARED")
            except (OSError, ValueError, UnicodeError) as exc:
                report("target-unavailable", "目标不可安全读取或超出检查范围", "Unknown", error=type(exc).__name__)
    if external:
        findings.append(Finding("links", "external-offline", "外部链接默认不联网检查", status="Not run", severity="info", evidence={"count": external, "coverage_domains": ["external"]}))
    # Until the entire run returns, a worker limit/exception must not expose a
    # partially populated domain as complete.
    for domain in domains.values():
        domain["unknown_reasons"].remove("RUN_NOT_COMPLETED")
        domain["complete"] = not domain["unknown_reasons"]
    return findings
