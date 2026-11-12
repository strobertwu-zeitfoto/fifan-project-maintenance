"""Only compare declarations whose version meaning can be established locally."""
from __future__ import annotations

import re
from .configs import parse
from ..models import Context, Finding


def _exact(value):
    return isinstance(value, str) and bool(re.fullmatch(r'\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.]+)?', value))


def _node_exact(value):
    if not isinstance(value, str):
        return False
    segment = r'[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*'
    match = re.fullmatch(r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?P<pre>' + segment + r'))?(?:\+' + segment + r')?', value)
    if not match:
        return False
    return not any(part.isdigit() and len(part) > 1 and part.startswith('0') for part in (match['pre'] or '').split('.'))


def _node_resolved(package, lock, out):
    """Npm lockfile v2/v3 stores actual direct packages by install path."""
    path = 'package-lock.json'
    if type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] not in (2, 3):
        out.append(Finding('dependencies', 'lock_format_unknown', '实际安装条目仅支持 lockfileVersion 2/3', path, status='Unknown'))
        return
    packages = lock['packages']
    direct = {}
    for group in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
        direct.update(package.get(group, {}))
    optional = package.get('optionalDependencies', {})
    required = set(package.get('dependencies', {})) | set(package.get('devDependencies', {}))
    # An optional declaration overrides the dependency of the same name.
    required.difference_update(optional)
    for name, declared in sorted(direct.items()):
        item = packages.get('node_modules/' + name)
        details = {'dependency': name, 'entry': 'node_modules/' + name}
        if item is None:
            if name in required and _node_exact(declared):
                out.append(Finding('dependencies', 'resolved_dependency_missing', '锁文件缺少必需的精确版本直接依赖条目', path, evidence=details))
            else:
                out.append(Finding('dependencies', 'resolved_dependency_unknown', '可选、peer 或非精确声明缺少实际条目；不能确定安装合同', path, status='Unknown', evidence=details))
            continue
        if not isinstance(item, dict):
            out.append(Finding('dependencies', 'resolved_dependency_unknown', '实际依赖条目格式无法解释', path, status='Unknown', evidence=details))
            continue
        actual = item.get('version')
        resolved = item.get('resolved')
        supported_source = resolved is None or (isinstance(resolved, str) and re.fullmatch(r'https?://[^?#]+\.tgz(?:[?#].*)?', resolved))
        if (item.get('link') or not supported_source or not _node_exact(declared)
                or not _node_exact(actual)):
            out.append(Finding('dependencies', 'resolved_dependency_unknown', '范围、链接、来源或实际版本超出支持的精确版本比较', path, status='Unknown', evidence=details))
        elif declared != actual:
            out.append(Finding('dependencies', 'resolved_version_mismatch', '直接依赖实际安装条目与清单精确版本不一致', path, evidence=details))


def run(ctx: Context) -> list[Finding]:
    out = []

    def load(path, suffix='.json'):
        return parse(ctx.read_text(path), suffix)

    def compare(path, name, declared, locked, exact=_exact):
        if declared is None:
            out.append(Finding('dependencies', 'missing_manifest_dependency', '锁文件根声明包含清单中没有的依赖', path, evidence={'dependency': name}))
        elif locked is None:
            out.append(Finding('dependencies', 'missing_locked_dependency', '锁文件缺少直接依赖声明', path, evidence={'dependency': name}))
        elif declared == locked:
            return
        elif exact(declared) and exact(locked):
            out.append(Finding('dependencies', 'version_mismatch', '直接依赖精确版本不一致', path, evidence={'dependency': name}))
        else:
            out.append(Finding('dependencies', 'version_unknown', '范围、来源或版本语义无法离线确定', path, status='Unknown', evidence={'dependency': name}))

    def guard(path, work):
        try:
            work()
        except Exception as exc:
            out.append(Finding('dependencies', 'manifest_unknown', '依赖清单或锁文件无法解释', path, status='Unknown', evidence={'error': type(exc).__name__}))

    if 'package.json' in ctx.files:
        def node():
            package = load('package.json')
            if 'package-lock.json' not in ctx.files:
                out.append(Finding('dependencies', 'lock_missing', '未发现支持的 Node 锁文件', 'package.json', status='Unknown'))
                return
            lock = load('package-lock.json')
            root = lock.get('packages', {}).get('')
            if not isinstance(root, dict):
                out.append(Finding('dependencies', 'lock_format_unknown', '仅支持含 packages 根声明的 package-lock', 'package-lock.json', status='Unknown'))
                return
            for group in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                declarations = package.get(group, {})
                locked = root.get(group, {})
                for name in sorted(set(declarations) | set(locked)):
                    compare('package-lock.json', name, declarations.get(name), locked.get(name), exact=_node_exact)
            _node_resolved(package, lock, out)
        guard('package.json', node)
    if 'Packages/manifest.json' in ctx.files:
        def unity():
            manifest = load('Packages/manifest.json')['dependencies']
            lock = load('Packages/packages-lock.json')['dependencies']
            for name, version in manifest.items():
                item = lock.get(name)
                if item is not None and item.get('depth') != 0:
                    out.append(Finding('dependencies', 'not_direct', '清单依赖在锁文件中不是直接依赖', 'Packages/packages-lock.json', evidence={'dependency': name}))
                else:
                    compare('Packages/packages-lock.json', name, version, item.get('version') if item else None)
        guard('Packages/manifest.json', unity)
    if 'pyproject.toml' in ctx.files:
        def python():
            project = load('pyproject.toml', '.toml').get('project', {})
            if 'dependencies' in project.get('dynamic', []):
                out.append(Finding('dependencies', 'dynamic_dependencies', '动态 Python 依赖无法静态确定', 'pyproject.toml', status='Unknown'))
            declarations = project.get('dependencies', [])
            if not declarations:
                return
            if 'requirements.txt' not in ctx.files:
                out.append(Finding('dependencies', 'lock_missing', '未发现 requirements.txt 精确版本对照', 'pyproject.toml', status='Unknown'))
                return
            exact = re.compile(r'^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([A-Za-z0-9.!+_-]+)$')
            normalize = lambda name: re.sub(r'[-_.]+', '-', name).lower()
            pins = {}
            for line in ctx.read_text('requirements.txt').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = exact.fullmatch(line)
                if match:
                    name = normalize(match[1])
                    if name in pins and pins[name] != match[2]:
                        out.append(Finding('dependencies', 'duplicate_pin', 'requirements 存在冲突精确版本', 'requirements.txt', evidence={'dependency': name}))
                    pins[name] = match[2]
                else:
                    out.append(Finding('dependencies', 'version_unknown', 'requirements 行不是支持的无条件精确版本', 'requirements.txt', status='Unknown'))
            for declaration in declarations:
                match = exact.fullmatch(declaration)
                if match:
                    compare('requirements.txt', normalize(match[1]), match[2], pins.get(normalize(match[1])))
                else:
                    out.append(Finding('dependencies', 'version_unknown', 'Python 依赖不是支持的无条件精确版本', 'pyproject.toml', status='Unknown'))
        guard('pyproject.toml', python)
    return out
