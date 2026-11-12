"""Bounded Unity text inspection: never launches or contacts an Editor."""
from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
import re

from ..models import Finding

_GUID = re.compile(r"\bguid:\s*([0-9a-fA-F]{32})\b")
_ZERO = "0" * 32
_TEXT = (".unity", ".prefab", ".mat", ".asset", ".controller", ".anim", ".overridecontroller", ".meta")


def run(ctx):
    if not any(p.startswith(("Assets/", "ProjectSettings/")) for p in ctx.files):
        try:
            if not ctx.is_dir("Assets") and not ctx.is_dir("ProjectSettings"):
                return []
        except (OSError, ValueError):
            return [Finding("unity", "scope-unavailable", "无法确认 Unity 工程目录", status="Unknown")]
    findings = []
    guids = defaultdict(list)
    texts = {}
    assets = {p for p in ctx.files if p.startswith("Assets/")}

    def emit(code, message, path="", status="Failed", **evidence):
        findings.append(Finding("unity", code, message, path, status=status, evidence=evidence))

    def read(path):
        try:
            return ctx.read_text(path)
        except (OSError, ValueError, UnicodeError) as exc:
            emit("read-error", "离线文本无法读取", path, "Unknown", error=type(exc).__name__)
            return None

    if not ctx.inventory or not assets:
        emit("assets-partial", "未声明全量盘点，Assets/.meta 与 GUID 覆盖不完整", status="Unknown")
    for path in sorted(assets):
        record = ctx.files[path]
        if record.kind != "file":
            continue
        if path.endswith(".meta"):
            target = path[:-5]
            try:
                if not ctx.exists(target):
                    emit("orphan-meta", ".meta 对应素材或目录不存在", path)
            except (OSError, ValueError):
                emit("meta-target-unavailable", ".meta 对应路径不可核实", path, "Unknown")
            text = read(path)
            if text is not None:
                texts[path] = text
                own = re.search(r"^guid:\s*([0-9a-fA-F]{32})\s*$", text, re.M)
                if own is None or own[1] == _ZERO:
                    emit("missing-guid", ".meta 缺少有效自身 GUID", path)
                else:
                    guids[own[1].lower()].append(path)
        else:
            try:
                if not ctx.is_file(path + ".meta"):
                    emit("missing-meta", "素材缺少配套 .meta", path)
            except (OSError, ValueError):
                emit("meta-unavailable", ".meta 路径不可核实", path, "Unknown")
            if path.lower().endswith(_TEXT):
                text = read(path)
                if text is not None:
                    texts[path] = text
    folders = {str(parent) for path in assets for parent in PurePosixPath(path).parents if str(parent).startswith("Assets/")}
    for folder in sorted(folders):
        try:
            if not ctx.is_file(folder + ".meta"):
                emit("missing-folder-meta", "素材目录缺少配套 .meta", folder)
        except (OSError, ValueError):
            emit("meta-unavailable", "目录 .meta 路径不可核实", folder, "Unknown")
    for guid, paths in guids.items():
        if len(paths) > 1:
            emit("duplicate-guid", "多个 .meta 声明相同 GUID", paths[0], paths=paths, guid=guid)
    for path, text in texts.items():
        for guid in sorted({m.lower() for m in _GUID.findall(text)}):
            # All-zero and Unity's built-in resource GUIDs are not project references.
            if guid == _ZERO or re.fullmatch(r"0{16}[ef]0{15}", guid):
                continue
            if guid not in guids:
                emit("unresolved-guid", "GUID 未在本次扫描的 .meta 中找到；包与动态解析域尚未完整核实", path, "Unknown", guid=guid)
    version_path = "ProjectSettings/ProjectVersion.txt"
    if version_path in ctx.files:
        version = read(version_path)
        if version is not None:
            match = re.search(r"^m_EditorVersion:\s*(\S+)\s*$", version, re.M)
            emit("editor-version", "仅记录工程版本声明，未验证 Editor 安装或兼容性", version_path, "Unknown", declared_version=match[1] if match else None)
    else:
        emit("missing-version", "本次范围缺少 ProjectVersion.txt", version_path, "Unknown")
    build = "ProjectSettings/EditorBuildSettings.asset"
    if build in ctx.files:
        text = read(build)
        if text is not None:
            for scene in re.findall(r"^\s*path:\s*(.*?)\s*$", text, re.M):
                scene = scene.strip("\"'")
                if not scene:
                    continue
                try:
                    if not ctx.is_file(scene):
                        emit("missing-build-scene", "构建场景路径不存在", build, scene=scene)
                except (OSError, ValueError):
                    emit("build-scene-unavailable", "构建场景路径无法安全核实", build, "Unknown", scene=scene)
    emit("dynamic-references", "动态加载、二进制素材与运行时引用未验证；不据此删除素材", status="Unknown")
    return findings
