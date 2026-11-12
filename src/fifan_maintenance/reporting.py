from __future__ import annotations

import json
import re


def sensitive_key(key):
    return bool(re.search(r"(?i)password|secret|credential|access.token|api.key", key))


def redact_text(value):
    value = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    return re.sub(r"(?i)((?:token|api_key|password|secret)=)[^&\s]+", r"\1[REDACTED]", value)


def redacted(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if sensitive_key(k) else redacted(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redacted(v) for v in value]
    if isinstance(value, str):
        value = redact_text(value)
        return value[:1500] + ("…" if len(value) > 1500 else "")
    return value


def render(report, format="markdown", include_files=False):
    data = redacted({k: v for k, v in report.items() if include_files or k != "files"})
    if format == "json":
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    lines = ["# Fifan 项目维护检查", "", "项目：`" + report["root"].replace("`", "") + "`", "", f"模式：{report['mode']}；文件：{report['file_count']}；问题：{report['finding_total']}；模型调用：0。", "", "这是静态检查结果，不代表项目运行、语义治理或用户验收通过。", "", "| 检查 | 状态 | 发现数 |", "| --- | --- | ---: |"]
    for entry in data["coverage"]:
        lines.append(f"| {entry['check']} | {entry['status']} | {entry['total']} |")
    lines.extend(["", "## 按类型归并", ""])
    for code, count in sorted(data["finding_counts"].items()):
        lines.append(f"- {code}: {count}")
    lines.extend(["", "## 定位", ""])
    for item in data["findings"]:
        path = item["path"].replace("\n", "\\n").replace("`", "")
        position = path + (":" + str(item["line"]) if item["line"] else "")
        lines.append(f"- [{item['status']}] `{position}` {item['code']}：{item['message']}")
    if report["findings_truncated"]:
        lines.extend(["", "展示达到上限，其余问题未逐条输出；按类型计数与coverage仍保留。"])
    if "delta" in report:
        lines.extend(["", "增量比较：`" + json.dumps(report["delta"], ensure_ascii=False) + "`"])
    return "\n".join(lines) + "\n"


def summary(report):
    from collections import Counter
    groups = Counter()
    from .inventory import matches
    historical = report.get("scope", {}).get("historical_roots", [])
    for item in report["findings"]:
        age = "historical" if matches(item["path"], report.get("historical_sources", [])) or any(item["path"].startswith(p + "/") for p in historical) else "current"
        groups["/".join([item["check"], age, item["severity"], item["status"]])] += 1
    return {**{key: value for key, value in report.items() if key not in {"files", "findings", "historical_metadata", "anchors"}},
        "groups_displayed_findings": dict(groups), "locations": report["findings"][:10],
        "historical_metadata": {key: value for key, value in report.get("historical_metadata", {}).items() if key != "entries"},
        "omitted_locations": max(0, report["finding_total"] - 10), "summary_only": True,
    }
