"""Inventory advice never authorizes deleting duplicate or old files."""
from __future__ import annotations

import time
import fnmatch
import math
from pathlib import PurePosixPath
from ..models import Context, Finding


ASSETS = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.psd', '.fbx', '.obj', '.wav', '.mp3', '.ogg', '.mp4', '.ttf', '.otf'}
ARTIFACTS = {'logs', 'cache', '.cache', 'build', 'builds', 'backup', 'backups'}


def run(ctx: Context) -> list[Finding]:
    out = []
    groups = {}
    from ..inventory import matches
    distribution = {}
    roles = ctx.config.get('asset_groups', {})
    if not isinstance(roles, dict) or any(not isinstance(k, str) or not isinstance(v, list) or any(not isinstance(p, str) for p in v) for k, v in roles.items()):
        out.append(Finding('assets', 'invalid_groups', 'asset_groups 必须是标签到 glob 字符串列表的映射'))
        roles = {}
    sources = ctx.config.get('asset_sources', {})
    if not isinstance(sources, dict):
        out.append(Finding('assets', 'invalid_sources', 'asset_sources 必须为素材路径到来源记录路径的映射'))
        sources = {}
    days = ctx.config.get('artifact_age_days', 90)
    if not isinstance(days, (int, float)) or isinstance(days, bool) or not math.isfinite(days) or days < 0:
        out.append(Finding('assets', 'invalid_threshold', 'artifact_age_days 必须为非负数'))
        days = 90
    rules = ctx.config.get('artifacts', [])
    valid_rules = []
    if not isinstance(rules, list):
        out.append(Finding('assets', 'invalid_artifacts', 'artifacts 必须为规则列表'))
        rules = []
    for rule in rules:
        if not isinstance(rule, dict):
            out.append(Finding('assets', 'invalid_artifacts', '产物规则必须含 pattern 与 age_days'))
            continue
        pattern, age = rule.get('pattern'), rule.get('age_days', days)
        if (not isinstance(pattern, str) or not pattern or pattern.startswith(('/', '\\'))
                or '..' in PurePosixPath(pattern).parts or ':' in pattern or '\\' in pattern
                or not isinstance(age, (int, float)) or isinstance(age, bool)
                or not math.isfinite(age) or age < 0):
            out.append(Finding('assets', 'invalid_artifacts', '产物模式须为相对 glob；年龄须为非负有限数'))
            continue
        valid_rules.append((pattern, age))
    now = time.time_ns()
    for path, record in sorted(ctx.files.items()):
        if record.kind != 'file':
            continue
        if record.sha256:
            groups.setdefault(record.sha256, []).append(path)
        if PurePosixPath(path).suffix.lower() in ASSETS and path not in sources:
            out.append(Finding('assets', 'source_unknown', '素材缺少显式来源记录映射；动态引用情况未知', path, status='Unknown', severity='info'))
        if PurePosixPath(path).suffix.lower() in ASSETS:
            labels = [label for label, patterns in roles.items() if matches(path, patterns)] or ['unclassified']
            for label in labels:
                entry = distribution.setdefault(label, {'files': 0, 'bytes': 0})
                entry['files'] += 1
                entry['bytes'] += record.size
        thresholds = [(pattern, threshold) for pattern, threshold in valid_rules if fnmatch.fnmatchcase(path, pattern)]
        if ARTIFACTS.intersection(part.lower() for part in PurePosixPath(path).parts[:-1]):
            thresholds.append(('known-artifact-directory', days))
        if thresholds:
            age = (now - record.mtime_ns) / 86400000000000
            exceeded = [(pattern, threshold) for pattern, threshold in thresholds if age > threshold]
            if exceeded:
                out.append(Finding('assets', 'old_artifact', '产物年龄超过提示阈值；仅建议人工确认', path, severity='info', evidence={'age_days': round(age, 1), 'rules': [{'pattern': p, 'age_days': d} for p, d in exceeded], 'size': record.size}))
    for digest, paths in sorted(groups.items()):
        if len(paths) > 1:
            out.append(Finding('assets', 'duplicate_hash', '发现内容哈希相同文件；不自动删除', paths[0], severity='info', evidence={'sha256': digest, 'paths': paths}))
    if distribution:
        out.append(Finding('assets', 'directory_distribution', '按显式目录标签盘点素材；标签不代表正式采用或用户接受', status='Unknown', severity='info', evidence={'groups': distribution}))
    for asset, source in sources.items():
        if not isinstance(asset, str) or not isinstance(source, str):
            out.append(Finding('assets', 'invalid_sources', '每项素材来源必须是路径字符串'))
            continue
        for path in (asset, source):
            try:
                if not ctx.is_file(path):
                    out.append(Finding('assets', 'missing_source_record' if path == source else 'missing_asset', '素材或声明来源记录不存在', path))
            except (OSError, ValueError):
                out.append(Finding('assets', 'source_unavailable', '素材来源路径越界或不可访问', path, status='Unknown'))
    return out
