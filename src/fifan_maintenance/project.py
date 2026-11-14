from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

DEFAULT_CONFIG = {
    "schema_version": 1,
    "include": ["*.md", "*.markdown", "*.html", "*.htm", "*.json", "*.toml", "*.yaml", "*.yml", "*.py", "*.sh", "*.command", "requirements*.txt", "docs/**", "tools/**", "scripts/**", ".github/workflows/**", "ProjectSettings/**", "Packages/manifest.json", "Packages/packages-lock.json"],
    "exclude": [],
    "protected": [".git/**", ".venv/**", ".venv39/**", "Library/**", "UserSettings/**"],
    "max_files": 20000,
    "max_file_bytes": 4 * 1024 * 1024,
    "max_total_bytes": 64 * 1024 * 1024,
    "max_seconds": 60,
    "max_findings": 200,
    "document_max_bytes": 64 * 1024,
    "paragraph_max_chars": 1000,
    "large_file_bytes": 10 * 1024 * 1024,
    "paths": [], "equalities": [], "asset_sources": {},
    "evidence_bindings": [], "entrypoints": [], "checks": [], "waivers": [],
    "artifacts": [], "anchor_style": "github",
    "artifact_age_days": 90,
    "documents": {"large_bytes": 65536, "paragraph_chars": 1000, "duplicate_min_chars": 120},
    "links": {"anchor_style": "github"},
    "historical_sources": [],
    "asset_groups": {},
    "json_contracts": [],
}


def project_root(value: str | Path) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError("project must be a directory")
    return path


def relative_parts(rel: str) -> tuple[str, ...]:
    if not isinstance(rel, str) or not rel or "\x00" in rel or "\\" in rel:
        raise ValueError("invalid relative path")
    p = PurePosixPath(rel)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in rel.split("/")) or not p.parts:
        raise ValueError("path must remain inside the project")
    return p.parts


def safe_path(root: Path, rel: str) -> Path:
    """Validate without following symlinks, including missing destination paths."""
    parts = relative_parts(rel)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("project root changed or is a symlink")
    current = root
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink paths are not traversed")
    return current


def read_bytes(root: Path, rel: str, limit: int, *, probe: bool = True) -> bytes:
    """Read a bounded, stable regular file using non-following directory handles."""
    if type(probe) is not bool:
        raise ValueError("invalid read probe policy")
    parts = relative_parts(rel)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None or os.open not in os.supports_dir_fd:
        raise OSError("safe descriptor-relative reading is unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | nofollow
    fd = os.open("/", flags)
    try:
        for part in root.absolute().parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | nofollow, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("only regular files can be read")
            if before.st_size > limit:
                raise ValueError("file exceeds read limit")
            from .preview_policy import authorize_read
            if authorize_read(root, rel, before.st_size):
                limit = min(limit, before.st_size)
            chunks = []
            # Strict callers bound physical IO even on concurrent-growth failure.
            # The after-fstat check still rejects growth without an extra probe.
            remaining = limit + 1 if probe else limit
            while remaining:
                block = os.read(file_fd, min(remaining, 65536))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
            after = os.fstat(file_fd)
            if len(data) > limit:
                raise ValueError("file exceeds read limit")
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_ino):
                raise OSError("file changed during reading")
            named = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
                raise OSError("file name changed during reading")
            return data
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def strict_json(data: str | bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("non-standard JSON constant")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def load_config(root: Path) -> dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        data = strict_json(read_bytes(root, ".fifan-maintenance.json", 262144))
    except FileNotFoundError:
        config["_explicit_include"] = False
        return config
    if not isinstance(data, dict) or set(data) - set(config):
        raise ValueError("config must be an object with supported fields only")
    for key, value in data.items():
        expected = type(config[key])
        if type(value) is not expected:
            raise ValueError("invalid config type: " + key)
        if expected is int and value <= 0:
            raise ValueError("config limits must be positive: " + key)
    config.update(data)
    for group in ["documents", "links"]:
        config[group] = {**DEFAULT_CONFIG[group], **data.get(group, {})}
    for alias, group, key in [("document_max_bytes", "documents", "large_bytes"), ("paragraph_max_chars", "documents", "paragraph_chars"), ("anchor_style", "links", "anchor_style")]:
        if alias in data:
            if key in data.get(group, {}) and data[group][key] != data[alias]:
                raise ValueError("conflicting config aliases")
            config[group][key] = data[alias]
    if config["schema_version"] != 1:
        raise ValueError("unsupported config schema_version")
    for name in ["include", "exclude", "protected", "paths", "entrypoints", "checks", "historical_sources"]:
        if any(not isinstance(x, str) or not x for x in config[name]):
            raise ValueError("expected nonempty strings in " + name)
    for name, allowed in [("documents", {"large_bytes", "paragraph_chars", "duplicate_min_chars"}), ("links", {"anchor_style"})]:
        if set(config[name]) - allowed:
            raise ValueError("unsupported nested config field: " + name)
    if any(type(v) is not int or v <= 0 for v in config["documents"].values()):
        raise ValueError("document thresholds must be positive integers")
    if config["links"].get("anchor_style", "github") not in {"github", "unknown"}:
        raise ValueError("unsupported link anchor style")
    if config["anchor_style"] not in {"github", "unknown"}:
        raise ValueError("unsupported anchor_style")
    validate_json_contracts(config["json_contracts"])
    config["_explicit_include"] = "include" in data
    return config


def fingerprint(config: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def identity(root: Path) -> dict[str, Any]:
    from .process import trusted_executable
    rules = []
    for base in [*reversed(root.parents), root]:
        for name in ["AGENTS.md", "AGENTS.override.md"]:
            path = base / name
            if path.is_file() and not path.is_symlink():
                rules.append(str(path))
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    git = {"status": "Unknown", "root": None, "branch": None, "head": None}
    def query(*args):
        proc = subprocess.run([executable, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, timeout=3)
        return os.fsdecode(proc.stdout).strip() if proc.returncode == 0 else None
    try:
        executable = trusted_executable('git', root)
        git["root"] = query("rev-parse", "--show-toplevel")
        if git["root"]:
            git.update(status="Passed", branch=query("symbolic-ref", "-q", "--short", "HEAD"), head=query("rev-parse", "--verify", "HEAD"))
    except (OSError, subprocess.TimeoutExpired):
        git["status"] = "Unknown"
    return {"real_root": str(root), "applicable_rule_paths": rules, "rules_content_loaded": False, "git": git}


def validate_json_contracts(contracts):
    for item in contracts:
        if not isinstance(item, dict) or set(item) - {"path", "records", "required", "paths"}:
            raise ValueError("invalid JSON contract")
        relative_parts(item.get("path", ""))
        if not item["path"].endswith(".json") or not isinstance(item.get("records", ""), str):
            raise ValueError("invalid JSON contract path or records")
        for key in ("required", "paths"):
            if not isinstance(item.get(key, []), list) or any(not isinstance(x, str) for x in item.get(key, [])):
                raise ValueError("invalid JSON contract pointers")


def stat_path(root: Path, rel: str):
    """Metadata lookup through directory handles, with the same no-link boundary."""
    parts = relative_parts(rel)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for part in root.absolute().parts[1:] + parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('symlink metadata is not followed')
        return info
    finally:
        os.close(fd)
