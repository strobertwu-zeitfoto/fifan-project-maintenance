"""Read-only Git hygiene, scoped even inside an ancestor repository."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import PurePosixPath
from ..models import Context, Finding
from ..inventory import ALWAYS_EXCLUDED, excluded
from ..process import run_bounded, trusted_executable


GENERATED = (ALWAYS_EXCLUDED - {'.git'}) | {'obj'}
MARKERS = re.compile(r'^(?:<{7}(?:[ \t].*)?|={7}|>{7}(?:[ \t].*)?)\r?$', re.MULTILINE)


def run(ctx: Context) -> list[Finding]:
    out = []
    limit = ctx.config.get('large_file_bytes', 10 * 1024 * 1024)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        out.append(Finding('repository', 'invalid_threshold', 'large_file_bytes 必须为非负整数'))
        limit = 10 * 1024 * 1024
    for path, record in sorted(ctx.files.items()):
        if record.size > limit:
            out.append(Finding('repository', 'large_file', '文件超过体量提示阈值；不构成删除依据', path, evidence={'size': record.size, 'threshold': limit}))
        try:
            content = ctx.read_text(path)
        except UnicodeError:
            continue  # Binary assets are not text conflict candidates.
        except (OSError, ValueError) as exc:
            out.append(Finding('repository', 'conflict_scan_unknown', '无法检查文件冲突标记', path, status='Unknown', evidence={'error': type(exc).__name__}))
            continue
        in_conflict = False
        for match in MARKERS.finditer(content):
            marker = match.group()
            if marker.startswith('<<<<<<<'):
                in_conflict = True
            elif not in_conflict:
                continue  # Setext titles and orphan closing markers are not blocks.
            if marker.startswith('>>>>>>>'):
                in_conflict = False
            out.append(Finding('repository', 'conflict_marker', '发现可能未解决的合并冲突标记', path, line=content.count('\n', 0, match.start()) + 1))
    # No shell, project commands, hooks, fsmonitor, optional locks or index refresh.
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('GIT_'):
            del env[key]
    env.update({'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull})
    try:
        task = ctx.config.get('_task')
        pathspecs = [':(literal)' + path for path in task['sources']] if task else ['.']
        executable = trusted_executable('git', ctx.root)
        proc = run_bounded([executable, '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + os.devnull,
                            'ls-files', '-z', '--', *pathspecs], input=b"", cwd=ctx.root, env=env, timeout=10)
        if proc.returncode:
            out.append(Finding('repository', 'git_unavailable', 'Git 文件清单不可用（可能不是仓库）', status='Unknown', evidence={'returncode': proc.returncode}))
        else:
            for raw in proc.stdout.split(b'\0'):
                if not raw:
                    continue
                path = os.fsdecode(raw)
                # Inventory intentionally omits generated directories. Git's -- .
                # supplies only scoped names; do not open those omitted files.
                if task and path not in task["sources"]:
                    continue
                parts = PurePosixPath(path).parts
                if excluded(path, ctx.config):
                    continue
                if GENERATED.intersection(PurePosixPath(path).parts):
                    out.append(Finding('repository', 'tracked_generated', 'Git 跟踪了常见生成目录中的文件；请确认用途', path))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        out.append(Finding('repository', 'git_unavailable', 'Git 文件清单未完成', status='Unknown', evidence={'error': type(exc).__name__}))
    return out
