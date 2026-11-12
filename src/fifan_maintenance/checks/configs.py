"""Parse declarative configurations without executing project code."""
from __future__ import annotations

import json
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9–3.10
    import tomli as tomllib
from pathlib import PurePosixPath

from ..models import Context, Finding


class DuplicateKey(ValueError):
    pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise DuplicateKey(f"duplicate key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("non-standard JSON constant")


def parse(text: str, suffix: str):
    if suffix == '.json':
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    if suffix == '.toml':
        return tomllib.loads(text)
    if suffix in ('.yaml', '.yml'):
        import yaml
        # Bound token and alias work before constructing any YAML values.
        aliases = 0
        for count, token in enumerate(yaml.scan(text), 1):
            if isinstance(token, yaml.tokens.AliasToken):
                aliases += 1
            if count > 100000 or aliases > 100:
                raise NotImplementedError('YAML resource limit')
        # Compose first so a custom tag cannot mask a later syntax error.
        list(yaml.compose_all(text, Loader=yaml.SafeLoader))
        return list(yaml.safe_load_all(text))
    raise NotImplementedError('unsupported configuration format')


def _pointer(value, pointer):
    if pointer == '':
        return value
    if not pointer.startswith('/'):
        raise ValueError('invalid JSON pointer')
    for part in pointer[1:].split('/'):
        # JSON Pointer only defines these two escapes.
        import re
        if re.search(r'~(?![01])', part):
            raise ValueError('invalid JSON pointer escape')
        part = part.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            if not part.isdigit() or (len(part) > 1 and part[0] == '0'):
                raise ValueError('invalid array index')
            value = value[int(part)]
        elif isinstance(value, dict):
            value = value[part]
        else:
            raise ValueError('pointer traverses scalar')
    return value


def _canonical(value):
    remaining = 10000

    def bounded(item, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 100:
            raise ValueError('comparison resource limit')
        if isinstance(item, dict):
            for child in item.values():
                bounded(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                bounded(child, depth + 1)
    bounded(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def _reference(ctx, reference):
    path, sep, pointer = reference.partition('#')
    if not sep:
        raise ValueError('reference requires # and JSON pointer')
    return _pointer(parse(ctx.read_text(path), PurePosixPath(path).suffix.lower()), pointer)


def _json_contracts(ctx, parsed):
    """Only declared JSON pointers are meaningful; no project code or schema plugins."""
    findings = []
    contracts = ctx.config.get('json_contracts', [])
    if not isinstance(contracts, list):
        return [Finding('configs', 'invalid_json_contract', 'json_contracts 必须为列表')]
    for contract in contracts:
        try:
            if (not isinstance(contract, dict) or set(contract) - {'path', 'records', 'required', 'paths'}
                    or not isinstance(contract.get('path'), str) or not contract['path'].endswith('.json')
                    or not isinstance(contract.get('records', ''), str)):
                raise ValueError('invalid JSON contract')
            for key in ('required', 'paths'):
                if not isinstance(contract.get(key, []), list) or any(not isinstance(p, str) for p in contract.get(key, [])):
                    raise ValueError('invalid pointer list')
            # Validate syntax even if no selected records exist.
            import re
            for pointer in [contract.get('records', ''), *contract.get('required', []), *contract.get('paths', [])]:
                if (pointer and not pointer.startswith('/')) or re.search(r'~(?![01])', pointer):
                    raise ValueError('invalid JSON pointer')
        except ValueError:
            findings.append(Finding('configs', 'invalid_json_contract', 'JSON 合同只接受 path、records、required、paths 及有效 JSON Pointer'))
            continue
        path = contract['path']
        try:
            if path not in parsed:
                parsed[path] = parse(ctx.read_text(path), '.json')
            value = parsed[path]
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            findings.append(Finding('configs', 'json_contract_unavailable', 'JSON 合同原件无法安全读取或解析', path, status='Unknown', evidence={'error': type(exc).__name__}))
            continue
        try:
            selected = _pointer(value, contract.get('records', ''))
        except (KeyError, IndexError, TypeError, ValueError):
            findings.append(Finding('configs', 'json_records_missing', '声明的 JSON 记录位置不存在', path, evidence={'records': contract.get('records', '')}))
            continue
        records = selected if isinstance(selected, list) else [selected]
        for index, record in enumerate(records):
            evidence = {'records': contract.get('records', ''), 'record_index': index if isinstance(selected, list) else None}
            if not isinstance(record, dict):
                findings.append(Finding('configs', 'json_record_type', '声明记录必须为对象或对象数组', path, evidence=evidence))
                continue
            for pointer in contract.get('required', []):
                try:
                    _pointer(record, pointer)
                except (KeyError, IndexError, TypeError, ValueError):
                    findings.append(Finding('configs', 'json_required_missing', '明确声明的必需字段不存在', path, evidence={**evidence, 'pointer': pointer}))
            for pointer in contract.get('paths', []):
                try:
                    target = _pointer(record, pointer)
                    if not isinstance(target, str) or not target:
                        raise TypeError('path must be a nonempty string')
                except (KeyError, IndexError, TypeError, ValueError):
                    findings.append(Finding('configs', 'json_path_field', '明确声明的路径字段缺失或不是非空字符串', path, evidence={**evidence, 'pointer': pointer}))
                    continue
                try:
                    if not ctx.exists(target):
                        findings.append(Finding('configs', 'json_path_missing', 'JSON 声明的工程根相对路径不存在', path, evidence={**evidence, 'pointer': pointer, 'target': target}))
                except (OSError, ValueError) as exc:
                    findings.append(Finding('configs', 'json_path_unavailable', 'JSON 路径越界、受保护或无法核实，未读取目标正文', path, status='Unknown', evidence={**evidence, 'pointer': pointer, 'target': target, 'error': type(exc).__name__}))
    return findings


def run(ctx: Context) -> list[Finding]:
    parsed = {}
    results = _json_contracts(ctx, parsed)
    for path in sorted(ctx.files):
        task = ctx.config.get("_task")
        if task is not None and path not in task.get("sources", []):
            continue
        suffix = PurePosixPath(path).suffix.lower()
        if path in parsed or suffix not in ('.json', '.toml', '.yaml', '.yml'):
            continue
        try:
            source = ctx.read_text(path)
        except (OSError, UnicodeError, ValueError) as exc:
            results.append(Finding('configs', 'unreadable', '配置文件无法读取或解码', path, status='Unknown', evidence={'error': type(exc).__name__}))
            continue
        try:
            parse(source, suffix)
        except ImportError:
            results.append(Finding('configs', 'parser_unavailable', 'YAML 解析依赖不可用', path, status='Not run'))
        except (NotImplementedError, RecursionError):
            results.append(Finding('configs', 'resource_limit', '配置超出安全解析能力', path, status='Unknown'))
        except Exception as exc:
            custom = type(exc).__name__ == 'ConstructorError'
            results.append(Finding('configs', 'custom_tag' if custom else 'invalid_format', '自定义 YAML 标签无法安全解释' if custom else '配置格式错误', path, line=getattr(getattr(exc, 'problem_mark', None), 'line', -1) + 1 or None, status='Unknown' if custom else 'Failed', evidence={'error': type(exc).__name__}))
    paths = ctx.config.get('paths', [])
    if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
        results.append(Finding('configs', 'invalid_declaration', 'paths 必须为字符串列表'))
    else:
        for path in paths:
            try:
                if not ctx.exists(path):
                    results.append(Finding('configs', 'missing_path', '声明路径不存在', path))
            except (ValueError, OSError):
                results.append(Finding('configs', 'unsafe_path', '声明路径越界或不可访问', path))
    equalities = ctx.config.get('equalities', [])
    if not isinstance(equalities, list):
        return results + [Finding('configs', 'invalid_declaration', 'equalities 必须为列表')]
    for item in equalities:
        try:
            if not isinstance(item, dict) or not all(isinstance(item.get(k), str) for k in ('left', 'right')):
                raise ValueError('invalid equality')
            left = _reference(ctx, item['left'])
            right = _reference(ctx, item['right'])
            # Python considers True == 1; declarative JSON equality must not.
            if _canonical(left) != _canonical(right):
                results.append(Finding('configs', 'unequal', '明确声明的一致性不匹配', evidence={'left': item['left'], 'right': item['right']}))
        except Exception as exc:
            results.append(Finding('configs', 'equality_unknown', '一致性声明无法核实', status='Unknown', evidence={'error': type(exc).__name__}))
    return results
