"""Inspect entries and plain paths; never execute project code."""
from __future__ import annotations

import datetime
import os
import re
from pathlib import PurePosixPath
from ..models import Context, Finding


SCRIPT_SUFFIXES = {'.sh', '.bash', '.zsh', '.command', '.py', '.pl', '.rb'}
# Deliberately only literal relative paths, excluding shell substitutions.
RELATIVE_PATH = re.compile(r'''(?<![\w/])((?:\./|\.\./)[\w./ -]+?)(?=["'\s;]|$)''')

# Migration clues only: neither resolve nor stat these external paths.
ABSOLUTE_PATH = re.compile(r"""(?<![\w:/\\])(?:/(?:Users|Volumes)/[^\s"'`;$<>]+|[A-Za-z]:[\\/][^\s"'`;$<>]+)""")


def run(ctx: Context) -> list[Finding]:
    out = []

    def check_path(path, code):
        try:
            if not ctx.exists(path):
                out.append(Finding('scripts', code, '明确声明的入口路径不存在', path))
        except (OSError, ValueError):
            out.append(Finding('scripts', 'path_unknown', '入口路径越界或不可访问', path, status='Unknown'))

    for key in ('entrypoints', 'checks'):
        paths = ctx.config.get(key, [])
        if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
            out.append(Finding('scripts', 'invalid_declaration', key + ' 必须为路径字符串列表'))
            continue
        for path in paths:
            check_path(path, 'missing_' + key)
    waivers = ctx.config.get('waivers', [])
    if not isinstance(waivers, list):
        out.append(Finding('scripts', 'invalid_waiver', 'waivers 必须为列表'))
        waivers = []
    for waiver in waivers:
        try:
            if not isinstance(waiver, dict) or not isinstance(waiver.get('id'), str) or not waiver['id']:
                raise ValueError('invalid waiver')
            expires = waiver['expires']
            if not isinstance(expires, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', expires):
                raise ValueError('invalid date')
            date = datetime.date.fromisoformat(expires)
            if date < datetime.date.today():
                out.append(Finding('scripts', 'expired_waiver', '明确豁免已到期', evidence={'id': waiver['id'], 'expires': expires}))
        except (KeyError, TypeError, ValueError):
            out.append(Finding('scripts', 'invalid_waiver', '豁免须含 id 与有效的 YYYY-MM-DD 到期日'))
    for path in sorted(ctx.files):
        if PurePosixPath(path).suffix.lower() not in SCRIPT_SUFFIXES:
            continue
        try:
            text = ctx.read_text(path)
            mode = ctx.metadata(path).st_mode
        except (OSError, UnicodeError, ValueError) as exc:
            out.append(Finding('scripts', 'script_unknown', '脚本无法读取', path, status='Unknown', evidence={'error': type(exc).__name__}))
            continue
        executable = bool(mode & (os.X_OK | 0o110))
        shebang = text.startswith('#!')
        if executable != shebang:
            out.append(Finding('scripts', 'shebang_mode', 'shebang 与可执行权限不一致；请确认调用方式', path))
        # Relative shell paths depend on runtime cwd and may occur in examples;
        # report unresolved literals as Unknown, never assume the script's folder.
        for line, content in enumerate(text.splitlines(), 1):
            if content.lstrip().startswith('#'):
                continue
            for match in ABSOLUTE_PATH.finditer(content):
                out.append(Finding('scripts', 'absolute_path_unknown', '发现固定机器或盘符路径；可用性及迁移需要确认，未访问外部目标', path, line=line, status='Unknown', evidence={'target': match.group()}))
            for match in RELATIVE_PATH.finditer(content):
                literal = match[1]
                try:
                    if not ctx.exists(literal):
                        out.append(Finding('scripts', 'literal_path_unknown', '相对路径在项目根不存在；运行工作目录未知', path, line=line, status='Unknown', evidence={'target': literal}))
                except (OSError, ValueError):
                    out.append(Finding('scripts', 'literal_path_unknown', '脚本路径超出当前范围；未访问外部目标', path, line=line, status='Unknown', evidence={'target': literal}))
    return out
