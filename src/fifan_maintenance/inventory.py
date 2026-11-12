from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
import time
import unicodedata
from pathlib import Path

from .models import Context, FileRecord, Finding

ALWAYS_EXCLUDED = {".git", ".venv", ".venv39", ".venv315", "__pycache__", ".pytest_cache", "node_modules", "Library", "Temp", "Obj", "Logs", ".fifan-maintenance"}


def historical(path: str) -> bool:
    parts = Path(path).parts
    return any(p.lower() in {"history", "archive", "archives", "evidence", "artcandidates"} for p in parts[:-1]) or "_HISTORY_" in Path(path).name.upper() or Path(path).name.upper().startswith("REPORT_")


def matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns if "/" in pattern or "/" not in path)



def protection_key(value):
    """Compare protection aliases conservatively; never use this key for IO.

    This does not normalize selected paths, config fingerprints or ordinary
    include matching. Case-sensitive volumes may conservatively protect more.
    """
    return unicodedata.normalize('NFC', unicodedata.normalize('NFC', value).casefold())


def excluded(path, config):
    """One protection predicate for bodies, metadata and Git-name reporting."""
    path = protection_key(path)
    parts = path.split('/')
    if any(part in {'.git', '.venv', '.venv39', '.venv315', '.env'} or part.startswith('.env.') for part in parts):
        return True
    patterns = [protection_key(pattern) for pattern in config.get('exclude', []) + config.get('protected', [])]
    prefixes = ['/'.join(parts[:index]) for index in range(1, len(parts) + 1)]
    return any(matches(prefix, patterns) or matches(prefix + '/', patterns) for prefix in prefixes) or any(path == pattern.removesuffix('/**') for pattern in patterns)

def collect(ctx: Context) -> list[Finding]:
    if ctx.config.get("_task"):
        return collect_selected(ctx)
    findings = []
    started = time.monotonic()
    total = 0
    seen = 0
    includes = ctx.config["include"]
    def walk_error(error):
        findings.append(Finding("inventory", "directory_unreadable", "目录不可读取，扫描范围不完整", status="Unknown"))
    for base, dirs, names, directory_fd in os.fwalk(ctx.root, follow_symlinks=False, onerror=walk_error):
        if time.monotonic() - started > ctx.config["max_seconds"]:
            findings.append(Finding("inventory", "scan_limit", "目录遍历时间预算耗尽；未检查部分保持Unknown", status="Unknown"))
            return findings
        parent = Path(base).relative_to(ctx.root).as_posix()
        parent = "" if parent == "." else parent + "/"
        kept = []
        for name in sorted(dirs):
            if time.monotonic() - started > ctx.config["max_seconds"]:
                findings.append(Finding("inventory", "scan_limit", "目录遍历时间预算耗尽；未检查部分保持Unknown", status="Unknown"))
                return findings
            rel = parent + name
            if name in ALWAYS_EXCLUDED or name.endswith(".egg-info") or excluded(rel, ctx.config):
                continue
            if not ctx.inventory and not ctx.config.get("_explicit_include", False) and historical(rel + "/placeholder"):
                continue
            if (Path(base) / name).is_symlink():
                findings.append(Finding("inventory", "symlink_not_followed", "不遍历目录符号链接", rel, status="Blocked", severity="info"))
                continue
            if ctx.inventory or any(p.startswith(rel + "/") or rel.startswith(p.split("/**")[0] + "/") for p in includes if "/" in p):
                kept.append(name)
        dirs[:] = kept
        for name in sorted(names):
            if time.monotonic() - started > ctx.config["max_seconds"]:
                findings.append(Finding("inventory", "scan_limit", "文件项遍历时间预算耗尽；未检查部分保持Unknown", status="Unknown"))
                return findings
            rel = parent + name
            if not ctx.inventory and not ctx.config.get("_explicit_include", False) and historical(rel):
                continue
            if name in {".env", ".DS_Store"} or name.startswith(".env.") or excluded(rel, ctx.config):
                continue
            if not ctx.inventory and not matches(rel, includes):
                continue
            seen += 1
            if seen > ctx.config["max_files"] or time.monotonic() - started > ctx.config["max_seconds"]:
                findings.append(Finding("inventory", "scan_limit", "扫描达到文件数或时间上限；未检查部分保持Unknown", status="Unknown"))
                return findings
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    kind = "symlink" if stat.S_ISLNK(info.st_mode) else "special"
                    ctx.files[rel] = FileRecord(rel, info.st_size, None, info.st_mtime_ns, kind)
                    findings.append(Finding("inventory", "nonregular_skipped", "未读取链接或特殊文件", rel, status="Blocked", severity="info"))
                    continue
                digest = None
                if info.st_size <= ctx.config["max_file_bytes"] and total + info.st_size <= ctx.config["max_total_bytes"]:
                    data = ctx.read_bytes(rel)
                    total += len(data)
                    digest = hashlib.sha256(data).hexdigest()
                ctx.files[rel] = FileRecord(rel, info.st_size, digest, info.st_mtime_ns)
                if digest is None:
                    findings.append(Finding("inventory", "hash_limit", "达到单文件或总读取预算，未计算内容哈希", rel, status="Unknown", severity="info"))
            except (OSError, ValueError) as error:
                findings.append(Finding("inventory", "read_error", "读取失败或路径变化：" + type(error).__name__, rel, status="Unknown"))
    return findings


def collect_selected(ctx):
    """Exact sources: never enumerate sibling directories for a file selection."""
    findings = []
    started = time.monotonic()
    for index, rel in enumerate(ctx.config["_task"]["sources"]):
        if index >= ctx.config["max_files"] or time.monotonic() - started > ctx.config["max_seconds"]:
            findings.append(Finding("inventory", "scan_limit", "定点盘点预算耗尽", status="Unknown"))
            break
        try:
            path = ctx.resolve(rel)
            override = ctx.config.get("_overlay", {})
            if rel in override:
                if override[rel] is None:
                    raise FileNotFoundError(rel)
                data = ctx.read_bytes(rel)
                size, mtime = len(data), 0
            else:
                info = ctx.metadata(rel)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("source must be regular file")
                size, mtime = info.st_size, info.st_mtime_ns
                data = ctx.read_bytes(rel)
            ctx.files[rel] = FileRecord(rel, size, hashlib.sha256(data).hexdigest(), mtime)
        except (OSError, ValueError) as error:
            findings.append(Finding("inventory", "read_error", "定点来源不可读取：" + type(error).__name__, rel, status="Unknown"))
    return findings
