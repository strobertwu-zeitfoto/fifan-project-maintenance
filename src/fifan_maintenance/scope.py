"""Data-only per-task selection. Project protection always remains authoritative."""
from __future__ import annotations

import copy
import os
import stat
import time
from pathlib import Path

from .inventory import matches
from .models import Context, FileRecord, Finding
from .project import fingerprint, relative_parts, strict_json, read_bytes

HARD_LIMITS = {"max_files": 100000, "max_file_bytes": 16 * 1024 * 1024,
               "max_total_bytes": 256 * 1024 * 1024, "max_seconds": 300,
               "max_findings": 2000}
FIELDS = {"schema_version", "sources", "reference_bodies", "historical_roots", "views", "checks", "budgets"}

FIELDS_V2 = FIELDS | {"goal", "measurement", "history_budget", "parent_binding"}


def load_task_profile(root, profile):
    path = Path(profile).expanduser().absolute()
    if path.resolve().is_relative_to(root):
        raise ValueError("task profile must be outside project")
    task = strict_json(read_bytes(path.parent.resolve(strict=True), path.name, 262144))
    if not isinstance(task, dict) or type(task.get("schema_version")) is not int or task["schema_version"] not in (1, 2):
        raise ValueError("unsupported task profile")
    allowed = FIELDS if task["schema_version"] == 1 else FIELDS_V2
    if set(task) - allowed:
        raise ValueError("unsupported task profile fields")
    return task


def task_config(root, config, *, files=None, profile=None, reference_bodies=None, historical_roots=None, checks=None, max_seconds=None):
    result = copy.deepcopy(config)
    task = {}
    if profile is not None:
        task = load_task_profile(root, profile)
    declared = bool(task) or files is not None or reference_bodies is not None or historical_roots is not None
    for name, value in [("sources", files), ("reference_bodies", reference_bodies), ("historical_roots", historical_roots), ("checks", checks)]:
        if value is not None:
            if name in task and task[name] != value:
                raise ValueError("conflicting task selection")
            task[name] = value
    for name in ("sources", "reference_bodies", "historical_roots", "checks"):
        value = task.get(name, [])
        if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value) or len(value) != len(set(value)):
            raise ValueError("invalid task list")
        if name != "checks":
            for rel in value:
                relative_parts(rel)
        if declared:
            task[name] = value
    if declared and not task.get("sources"):
        raise ValueError("task scope needs explicit source files")
    if len(task.get("sources", [])) > HARD_LIMITS["max_files"]:
        raise ValueError("source list too large")
    budgets = task.get("budgets", {})
    if not isinstance(budgets, dict) or set(budgets) - set(HARD_LIMITS):
        raise ValueError("unsupported task budget")
    if max_seconds is not None:
        if "max_seconds" in budgets and budgets["max_seconds"] != max_seconds:
            raise ValueError("conflicting task budget")
        budgets = {**budgets, "max_seconds": max_seconds}
    for key, value in budgets.items():
        if type(value) is not int or not 0 < value <= HARD_LIMITS[key]:
            raise ValueError("task budget outside hard limits")
        result[key] = value
    if declared:
        if task.get("schema_version") == 2:
            validate_task_v2(root, task)
        views = task.get("views", [])
        if not isinstance(views, list):
            raise ValueError("invalid views")
        seen = set()
        for view in views:
            if not isinstance(view, dict) or set(view) - {"name", "path", "start_line", "end_line", "kind"}:
                raise ValueError("invalid view")
            relative_parts(view.get("path", ""))
            if view["path"] not in task["sources"] or not isinstance(view.get("name"), str) or not view["name"] or view.get("kind") not in {"current", "historical"}:
                raise ValueError("view needs explicit source and classification")
            start, end = view.get("start_line"), view.get("end_line")
            if type(start) is not int or type(end) is not int or start < 1 or end < start:
                raise ValueError("invalid view range")
            key = (view["path"], view["name"])
            if key in seen:
                raise ValueError("duplicate view")
            seen.add(key)
        task["views"] = views
        task["budgets"] = budgets
        result["_task"] = task
        ctx = Context(root, {}, result)
        for rel in task["sources"] + task["historical_roots"]:
            ctx.resolve(rel)
    return result


def binding(config):
    task = config.get("_task")
    return {
        "scope": {key: task.get(key, []) for key in ("sources", "reference_bodies", "historical_roots")} if task else {"sources": None, "reference_bodies": None, "historical_roots": []},
        "views": task.get("views", []) if task else [],
        "budgets": {**{key: config[key] for key in HARD_LIMITS}, **({"history": task["history_budget"]} if task and "history_budget" in task else {})},
    }


def preflight(root, config):
    """Metadata only: no primary bodies or referenced bodies are read here."""
    ctx = Context(root, {}, config)
    task = config.get("_task")
    items = []
    if task:
        for rel in task["sources"]:
            try:
                info = ctx.metadata(rel)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("source must be regular file")
                items.append({"path": rel, "bytes": info.st_size, "status": "Selected"})
            except (OSError, ValueError) as error:
                items.append({"path": rel, "status": "Blocked", "reason": type(error).__name__})
    return {"status": "Blocked" if any(x["status"] == "Blocked" for x in items) else "Preview", "root": str(root), **binding(config), "sources": items, "requested_source_count": len(task["sources"]) if task else None, "file_count": sum(x["status"] == "Selected" for x in items) if task else None,
            "estimated_primary_bytes": sum(x.get("bytes", 0) for x in items), "default_scan_estimate": "Unknown" if not task else None,
            "reference_targets": "Unknown until source parsing; metadata allowed, bodies require explicit scope" if task else "legacy project scope",
            "excluded_patterns": config["exclude"] + config["protected"], "body_bytes_read": 0, "model_calls": 0}


def _legacy_historical_metadata(ctx, max_seconds=None):
    """Explicit historical roots are metadata-only, with an independent bounded walk."""
    entries, excluded, complete = [], 0, True
    started = time.monotonic()
    seconds = ctx.config["max_seconds"] if max_seconds is None else max_seconds
    for rel in ctx.config.get("_task", {}).get("historical_roots", []):
        try:
            directory = ctx.resolve(rel)
            if not directory.is_dir():
                raise ValueError("historical root must be directory")
            def onerror(error):
                nonlocal complete
                complete = False
            for base, dirs, names in os.walk(directory, followlinks=False, onerror=onerror):
                if time.monotonic() - started >= seconds:
                    complete = False
                    break
                kept = []
                for name in dirs:
                    child = (Path(base) / name).relative_to(ctx.root).as_posix()
                    try:
                        ctx.resolve(child)
                        kept.append(name)
                    except (OSError, ValueError):
                        excluded += 1
                dirs[:] = kept
                for name in names:
                    if len(entries) >= ctx.config["max_files"] or time.monotonic() - started >= seconds:
                        complete = False
                        break
                    child = (Path(base) / name).relative_to(ctx.root).as_posix()
                    try:
                        info = ctx.metadata(child)
                        if not stat.S_ISREG(info.st_mode):
                            raise ValueError("not regular")
                        entries.append({"path": child, "bytes": info.st_size, "mtime_ns": info.st_mtime_ns})
                    except (OSError, ValueError):
                        excluded += 1
                if not complete:
                    break
        except (OSError, ValueError):
            complete = False
        if not complete:
            break
    return {"status": "Passed" if complete and not excluded else "Unknown", "file_count": len(entries), "file_bytes": sum(x["bytes"] for x in entries), "excluded": excluded, "body_bytes_read": 0, "entries": entries}


def validate_task_v2(root, task):
    goal = task.get('goal')
    if goal is not None:
        if isinstance(goal, str):
            if goal not in {'navigation', 'body-slim', 'storage'}:
                raise ValueError('unsupported goal')
        elif isinstance(goal, dict):
            if set(goal) - {'kind', 'each_file', 'max_after_bytes', 'minimum_reduction_bytes', 'exceptions'} or goal.get('kind') not in {'navigation', 'body-slim', 'storage'}:
                raise ValueError('invalid goal')
            if 'each_file' in goal and type(goal['each_file']) is not bool:
                raise ValueError('invalid goal each_file')
            for key in ('max_after_bytes', 'minimum_reduction_bytes'):
                if key in goal and (type(goal[key]) is not int or goal[key] < 0):
                    raise ValueError('invalid goal threshold')
            exceptions = goal.get('exceptions', [])
            if not isinstance(exceptions, list):
                raise ValueError('invalid goal exceptions')
            for item in exceptions:
                if not isinstance(item, dict) or set(item) != {'path', 'reason'} or not isinstance(item['reason'], str) or not item['reason'].strip():
                    raise ValueError('invalid goal exception')
                relative_parts(item['path'])
                if item['path'] not in task.get('sources', []):
                    raise ValueError('goal exception outside sources')
        else:
            raise ValueError('invalid goal')
    if 'measurement' in task and not isinstance(task['measurement'], dict):
        raise ValueError('invalid measurement request')
    historical = task.get('history_budget', {})
    if not isinstance(historical, dict) or set(historical) - {'max_files', 'max_seconds', 'max_depth', 'per_root_max_files', 'max_output_entries'}:
        raise ValueError('invalid history budget')
    for name, cap in [('max_files', HARD_LIMITS['max_files']), ('max_seconds', HARD_LIMITS['max_seconds']), ('max_depth', 100), ('max_output_entries', 2000)]:
        if name in historical and (type(historical[name]) is not int or not (0 if name in {'max_depth', 'max_output_entries'} else 1) <= historical[name] <= cap):
            raise ValueError('history budget outside hard limits')
    per_root = historical.get('per_root_max_files', {})
    if not isinstance(per_root, dict):
        raise ValueError('invalid per-root budget')
    for path, value in per_root.items():
        relative_parts(path)
        if path not in task.get('historical_roots', []) or type(value) is not int or not 1 <= value <= HARD_LIMITS['max_files']:
            raise ValueError('invalid per-root budget')
    if 'parent_binding' in task:
        value = task['parent_binding']
        import re
        if not isinstance(value, dict) or set(value) != {'root', 'parent_profile_sha256', 'parent_scope_sha256'} or value['root'] != str(root) or any(not isinstance(value[key], str) or not re.fullmatch('[0-9a-f]{64}', value[key]) for key in ('parent_profile_sha256', 'parent_scope_sha256')):
            raise ValueError('invalid parent profile binding')


def _literal_pattern(path):
    return ''.join({'*': '[*]', '?': '[?]', '[': '[[]'}.get(char, char) for char in path)


def derive_profile(root, config, parent, *, sources, checks=None, reference_bodies=None):
    """A child can only retain or narrow the parent's existing body grants."""
    original = load_task_profile(root, parent)
    parent_config = task_config(root, config, profile=parent)
    if not isinstance(sources, list) or not sources or len(sources) != len(set(sources)) or set(sources) - set(original['sources']):
        raise ValueError('derived sources must be a nonempty parent subset')
    inherited = list(original.get('reference_bodies', []))
    transferred = [path for path in original['sources'] if path not in sources]
    inherited.extend(_literal_pattern(path) for path in transferred)
    inherited = list(dict.fromkeys(inherited))
    if reference_bodies is not None:
        if not isinstance(reference_bodies, list) or set(reference_bodies) - set(inherited):
            raise ValueError('derived body permissions may only retain known grants')
        inherited = reference_bodies
    child = copy.deepcopy(original)
    child.update(schema_version=2, sources=sources, reference_bodies=inherited)
    if checks is not None:
        from .worker import MODULES
        if not isinstance(checks, list) or len(checks) != len(set(checks)) or set(checks) - set(MODULES):
            raise ValueError('unsupported derived checks')
        child['checks'] = checks
    child['views'] = [view for view in original.get('views', []) if view['path'] in sources]
    if isinstance(child.get('goal'), dict):
        child['goal']['exceptions'] = [item for item in child['goal'].get('exceptions', []) if item['path'] in sources]
    if 'measurement' in child:
        # Keep archive/record role declarations; narrow primary and selected views.
        child['measurement']['active'] = [path for path in child['measurement'].get('active', original['sources']) if path in sources]
        if 'views' in child['measurement']:
            child['measurement']['views'] = [view for view in child['measurement']['views'] if view.get('path') in sources]
    path = Path(parent).expanduser().absolute()
    child['parent_binding'] = {'root': str(root), 'parent_profile_sha256': fingerprint(original), 'parent_scope_sha256': fingerprint(binding(parent_config))}
    # Validate the completed child without temporary files or any project writes.
    validate_task_v2(root, child)
    ctx = Context(root, {}, parent_config)
    for rel in sources:
        ctx.resolve(rel)
    return {'schema_version': 1, 'status': 'Preview', 'profile': child, 'changes': {'sources': sources, 'body_permissions': inherited, 'transferred_parent_source_permissions': transferred, 'permission_expansion': False}, 'model_calls': 0}


def historical_metadata(ctx, max_seconds=None):
    task = ctx.config.get('_task', {})
    if task.get('schema_version') != 2:
        return _legacy_historical_metadata(ctx, max_seconds=max_seconds)
    budget = task.get('history_budget', {})
    total_limit = budget.get('max_files', ctx.config['max_files'])
    seconds = min(budget.get('max_seconds', ctx.config['max_seconds']), max_seconds if max_seconds is not None else ctx.config['max_seconds'])
    output_limit = budget.get('max_output_entries', 100)
    depth_limit = budget.get('max_depth', 100)
    entries, roots, unvisited = [], [], []
    total_count = total_bytes = excluded = total_entries = total_directories = 0
    started = time.monotonic()

    def open_directory(rel):
        # scandir(path) would follow a raced ancestor. Walk non-following directory
        # handles instead, retaining the same project/protection boundary as stat.
        ctx.resolve(rel)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open('/', flags)
        try:
            for part in ctx.root.absolute().parts[1:] + tuple(relative_parts(rel)):
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    for rel in task.get('historical_roots', []):
        summary = {'root': rel, 'file_count': 0, 'file_bytes': 0, 'entry_count': 0, 'directory_count': 0,
                   'excluded': 0, 'complete': True, 'reasons': [], 'unvisited_directories': []}
        roots.append(summary)
        per_limit = budget.get('per_root_max_files', {}).get(rel, total_limit)

        def unavailable(reason, directory):
            summary['complete'] = False
            if reason not in summary['reasons']:
                summary['reasons'].append(reason)
            if len(summary['unvisited_directories']) < 50 and directory not in summary['unvisited_directories']:
                summary['unvisited_directories'].append(directory)

        def stop_reason():
            if time.monotonic() - started >= seconds:
                return 'TIME_BUDGET'
            if total_entries >= total_limit or summary['entry_count'] >= per_limit:
                return 'FILE_BUDGET'
            return None

        def visit(parent, depth):
            nonlocal total_count, total_bytes, total_entries, total_directories
            reason = stop_reason()
            if reason:
                unavailable(reason, parent)
                return
            try:
                fd = open_directory(parent)
            except (OSError, ValueError):
                unavailable('DIRECTORY_UNREADABLE', parent)
                return
            try:
                with os.scandir(fd) as children:
                    while True:
                        # Check before fetching the next entry: neither directory
                        # enumeration nor sorting can grow beyond the budget.
                        reason = stop_reason()
                        if reason:
                            unavailable(reason, parent)
                            return
                        try:
                            entry = next(children)
                        except StopIteration:
                            return
                        except OSError:
                            unavailable('DIRECTORY_UNREADABLE', parent)
                            return
                        total_entries += 1
                        summary['entry_count'] += 1
                        child = parent + '/' + entry.name
                        try:
                            info = ctx.metadata(child)
                            if stat.S_ISDIR(info.st_mode):
                                total_directories += 1
                                summary['directory_count'] += 1
                                if depth >= depth_limit:
                                    unavailable('DEPTH_LIMIT', child)
                                else:
                                    visit(child, depth + 1)
                                    reason = stop_reason()
                                    if reason:
                                        unavailable(reason, parent)
                                        return
                            elif stat.S_ISREG(info.st_mode):
                                summary['file_count'] += 1
                                summary['file_bytes'] += info.st_size
                                total_count += 1
                                total_bytes += info.st_size
                                if len(entries) < output_limit:
                                    entries.append({'path': child, 'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns})
                            else:
                                raise ValueError('not an ordinary file or directory')
                        except (OSError, ValueError):
                            # Rejected and non-regular entries still consumed one
                            # unit of enumeration work; they cannot bypass caps.
                            summary['excluded'] += 1
                            unavailable('EXCLUDED_OR_UNAVAILABLE', child)
            except OSError:
                unavailable('DIRECTORY_UNREADABLE', parent)
            finally:
                os.close(fd)

        reason = stop_reason()
        if reason:
            unavailable(reason, rel)
        else:
            try:
                if not ctx.is_dir(rel):
                    raise ValueError('historical root must be directory')
                visit(rel, 0)
            except (OSError, ValueError):
                unavailable('ROOT_UNAVAILABLE', rel)
        excluded += summary['excluded']
        summary['status'] = 'Passed' if summary['complete'] else 'Unknown'
        unvisited.extend(summary['unvisited_directories'][:max(0, 100-len(unvisited))])
    complete = all(item['complete'] for item in roots)
    return {'status': 'Passed' if complete else 'Unknown', 'file_count': total_count, 'file_bytes': total_bytes,
            'entry_count': total_entries, 'directory_count': total_directories,
            'excluded': excluded, 'body_bytes_read': 0, 'entries': entries, 'roots': roots, 'complete': complete,
            'count_is_lower_bound': not complete, 'unvisited_directories': unvisited,
            'entries_truncated': total_count > len(entries),
            'budgets': {'max_files': total_limit, 'max_seconds': seconds, 'max_depth': depth_limit,
                        'max_output_entries': output_limit, 'entry_limit_includes': ['files', 'directories', 'excluded_entries']}}
