from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json
from contextlib import contextmanager
from itertools import islice


class FindingLimit(RuntimeError):
    pass


_budget = None


def set_finding_budget(limit=200):
    global _budget
    _budget = {"bytes": 0, "count": 0, "counts": {}, "items": [], "limit": min(limit, 2000), "has_failures": False}
    return _budget


@contextmanager
def finding_budget(limit=200):
    global _budget
    previous = _budget
    current = set_finding_budget(limit)
    try:
        yield current
    finally:
        _budget = previous


def _bounded(value, remaining, depth=0):
    from .reporting import redact_text, sensitive_key
    if remaining[0] <= 0 or depth > 8:
        return "[limited]"
    if isinstance(value, str):
        value = redact_text(value)
        text = value[:min(1000, remaining[0])]
        remaining[0] -= len(text.encode("utf-8"))
        return text + ("…" if len(text) < len(value) else "")
    if isinstance(value, dict):
        return {str(k)[:100]: "[REDACTED]" if sensitive_key(str(k)) else _bounded(v, remaining, depth + 1) for k, v in islice(value.items(), 30)}
    if isinstance(value, (list, tuple)):
        return [_bounded(v, remaining, depth + 1) for v in value[:30]]
    return value


@dataclass
class Finding:
    check: str
    code: str
    message: str
    path: str = ""
    line: int | None = None
    status: str = "Failed"
    severity: str = "warning"
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.evidence = _bounded(self.evidence, [6000])
        if _budget is not None:
            _budget["count"] += 1
            key = self.check + "/" + self.code
            _budget["counts"][key] = _budget["counts"].get(key, 0) + 1
            _budget["has_failures"] |= self.status == "Failed" and self.severity != "info"
            if len(_budget["items"]) < _budget["limit"]:
                _budget["items"].append(self)
            _budget["bytes"] += len(json.dumps(self.to_dict(), ensure_ascii=True).encode())
            if _budget["count"] >= 4000 or _budget["bytes"] >= 4 * 1024 * 1024:
                raise FindingLimit("finding generation budget exhausted")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileRecord:
    path: str
    size: int
    sha256: str | None
    mtime_ns: int
    kind: str = "file"


@dataclass
class Context:
    root: Path
    files: dict[str, FileRecord]
    config: dict[str, Any]
    inventory: bool = False
    _read_total: int = field(default=0, init=False, repr=False)

    observations: dict = field(default_factory=dict, init=False, repr=False)
    _reference_targets: set = field(default_factory=set, init=False, repr=False)
    _primary_bytes: int = field(default=0, init=False, repr=False)
    _reference_bytes: int = field(default=0, init=False, repr=False)

    def resolve(self, rel: str) -> Path:
        from .project import safe_path, relative_parts
        from .inventory import excluded
        relative_parts(rel)
        if excluded(rel, self.config):
            raise ValueError("excluded or protected content")
        path = safe_path(self.root, rel)
        task = self.config.get("_task")
        if task and rel not in task["sources"]:
            self._reference_targets.add(rel)
        return path

    def metadata(self, rel: str):
        from .project import stat_path
        self.resolve(rel)
        return stat_path(self.root, rel)

    def exists(self, rel: str) -> bool:
        self.resolve(rel)
        overlay = self.config.get("_overlay", {})
        if rel in overlay:
            return overlay[rel] is not None
        if any(path.startswith(rel + "/") and data is not None for path, data in overlay.items()):
            return True
        try:
            self.metadata(rel)
            return True
        except FileNotFoundError:
            return False

    def is_file(self, rel: str) -> bool:
        import stat
        self.resolve(rel)
        overlay = self.config.get("_overlay", {})
        if rel in overlay:
            return overlay[rel] is not None
        try:
            return stat.S_ISREG(self.metadata(rel).st_mode)
        except FileNotFoundError:
            return False

    def is_dir(self, rel: str) -> bool:
        import stat
        self.resolve(rel)
        overlay = self.config.get("_overlay", {})
        if rel in overlay:
            return False
        if any(path.startswith(rel + "/") and data is not None for path, data in overlay.items()):
            return True
        try:
            return stat.S_ISDIR(self.metadata(rel).st_mode)
        except FileNotFoundError:
            return False

    def body_allowed(self, rel: str) -> bool:
        from .inventory import matches
        task = self.config.get("_task")
        return not task or rel in task["sources"] or matches(rel, task.get("reference_bodies", []))

    def read_bytes(self, rel: str) -> bytes:
        from .project import read_bytes
        self.resolve(rel)
        if not self.body_allowed(rel):
            raise ValueError("reference body outside task scope")
        remaining = self.config.get("max_total_bytes", 64 * 1024 * 1024) - self._read_total
        if remaining <= 0:
            raise ValueError("check read budget exhausted")
        overlay = self.config.get("_overlay", {})
        if rel in overlay:
            import base64
            if overlay[rel] is None:
                raise FileNotFoundError(rel)
            data = base64.b64decode(overlay[rel], validate=True)
            if len(data) > min(self.config["max_file_bytes"], remaining):
                raise ValueError("overlay exceeds read budget")
        else:
            data = read_bytes(self.root, rel, min(self.config["max_file_bytes"], remaining))
        self._read_total += len(data)
        if self.config.get("_task") and rel not in self.config["_task"]["sources"]:
            self._reference_bytes += len(data)
        else:
            self._primary_bytes += len(data)
        return data

    def read_text(self, rel: str) -> str:
        text = self.read_bytes(rel).decode("utf-8")
        views = self.config.get("_task", {}).get("views", [])
        if views:
            from .reading import select_view
            text = select_view(text, rel, views)
        return text
