from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from . import __version__, changes
from .engine import compare_state, run
from .project import load_config, project_root, read_bytes, strict_json
from .reporting import redacted, render


def input_json(path):
    path = Path(path).expanduser().absolute()
    value = strict_json(read_bytes(path.parent.resolve(strict=True), path.name, 16 * 1024 * 1024))
    changes._reject_cleanup_material(value)
    return value


def output_file(value, text, root):
    """Explicit output is outside the inspected project; never follow output links."""
    path = Path(value).expanduser().absolute()
    if path.resolve().is_relative_to(root):
        raise ValueError("output must be outside the inspected project")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    temp = ".fifan-" + secrets.token_hex(12)
    try:
        for name in path.parts[1:-1]:
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        try:
            st = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            import stat
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("output must be a regular file")
        except FileNotFoundError:
            pass
        out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as stream:
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path.name, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        try:
            os.unlink(temp, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def parser():
    result = argparse.ArgumentParser(description="Fifan offline maintenance")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    from .directory_cli import add_parser as add_directory_parser
    add_directory_parser(commands)
    from .cleanup_cli import add_parser as add_cleanup_parser
    add_cleanup_parser(commands)
    def common(cmd, output=False):
        cmd.add_argument("--project", "--root", required=True)
        cmd.add_argument("--max-output-bytes", type=int, default=30720)
        if output:
            cmd.add_argument("--output")
    for name in ("archive-coverage", "history"):
        cmd = commands.add_parser(name)
        common(cmd, output=True)
        if name == "archive-coverage":
            cmd.add_argument("--request", required=True)
        else:
            cmd.add_argument("--records-dir", nargs="+", action="extend", required=True)
            cmd.add_argument("--max-records", type=int, default=1000)
            cmd.add_argument("--max-record-bytes", type=int, default=64 * 1024 * 1024)
    group = commands.add_parser("profile").add_subparsers(dest="action", required=True)
    cmd = group.add_parser("derive")
    common(cmd, output=True)
    cmd.add_argument("--from", dest="parent_profile", required=True)
    cmd.add_argument("--sources", nargs="+", required=True)
    cmd.add_argument("--checks")
    cmd.add_argument("--reference-bodies", nargs="*")
    group = commands.add_parser("session").add_subparsers(dest="action", required=True)
    for name in ("report", "verify", "recovery-preview", "recover"):
        cmd = group.add_parser(name)
        common(cmd, output=True)
        cmd.add_argument("--session", required=True)
        if name == "recover":
            cmd.add_argument("--recovery-plan", required=True)
    for name in ["check", "inventory", "read", "compare", "report", "preview", "apply", "verify", "recover"]:
        cmd = commands.add_parser(name)
        cmd.add_argument("--project", "--root", required=True)
        if name in {"check", "inventory", "read", "compare"}:
            cmd.add_argument("--files", nargs="+")
            cmd.add_argument("--reference-bodies", nargs="+")
            cmd.add_argument("--historical-roots", nargs="+")
            cmd.add_argument("--task-profile")
        if name in {"read", "compare", "report", "preview"}:
            cmd.add_argument("--max-output-bytes", type=int, default=30720)
        if name == "report":
            source = cmd.add_mutually_exclusive_group(required=True)
            source.add_argument("--input")
            source.add_argument("--measure-request")
            source.add_argument("--before")
            cmd.add_argument("--after")
            goal = cmd.add_mutually_exclusive_group()
            goal.add_argument("--goal", choices=["navigation", "body-slim", "storage"])
            goal.add_argument("--goal-profile")
            cmd.add_argument("--output")
        elif name == "read":
            cmd.add_argument("--file", required=True)
            cmd.add_argument("--outline", action="store_true")
            cmd.add_argument("--heading")
            cmd.add_argument("--view")
            cmd.add_argument("--cursor")
            cmd.add_argument("--max-depth", type=int)
            cmd.add_argument("--heading-filter")
            cmd.add_argument("--lines")
            cmd.add_argument("--section-id")
        elif name == "compare":
            cmd.add_argument("--before", required=True)
            pair = cmd.add_mutually_exclusive_group(required=True)
            pair.add_argument("--after")
            pair.add_argument("--plan")
            cmd.add_argument("--output")
        elif name in {"check", "inventory"}:
            cmd.add_argument("--format", choices=["markdown", "json", "summary"], default="markdown")
            cmd.add_argument("--output")
            cmd.add_argument("--state")
            cmd.add_argument("--checks")
            cmd.add_argument("--max-seconds", type=int)
            cmd.add_argument("--preflight", action="store_true")
            cmd.add_argument("--max-output-bytes", type=int, default=30720)
        elif name == "preview":
            cmd.add_argument("--request", required=True)
            cmd.add_argument("--diff-output")
            cmd.add_argument("--plan", required=True)
            cmd.add_argument("--task-profile")
            cmd.add_argument("--receipt")
        elif name == "apply":
            cmd.add_argument("--plan", required=True)
            cmd.add_argument("--operations-dir", required=True)
        else:
            cmd.add_argument("--journal", required=True)
    return result


def emit_result(value, args, root):
    from .reading import bounded_json
    if getattr(args, 'output', None):
        from .reading import _redact
        output_file(args.output, json.dumps(_redact(value), ensure_ascii=False, indent=2), root)
    print(bounded_json(value, args.max_output_bytes), end='')



def compilation_summary(value):
    if not value:
        return None
    operations = value.get('operations', [])
    return {'status': value.get('status'), 'input_version': value.get('input_version'), 'output_version': value.get('output_version'), 'operations': len(operations), 'patches': sum(len(item.get('patches', [])) for item in operations), 'archive_proofs': len(value.get('archive_proofs', []))}


def save_preview_receipt(value, args, root, required=False):
    path = args.receipt
    if path is None and required:
        plan = Path(args.plan).expanduser().absolute()
        path = str(plan.with_name(plan.name + '.receipt-' + secrets.token_hex(12) + '.json'))
        if Path(path).exists() or Path(path).is_symlink():
            raise ValueError('receipt destination exists')
    if path is not None:
        from .reading import _redact
        content = json.dumps(_redact(value), ensure_ascii=False, indent=2)
        if len(content.encode('utf-8')) > 16 * 1024 * 1024:
            raise ValueError('preview receipt budget exhausted')
        output_file(path, content, root)
    return path

def main(argv=None):
    args = parser().parse_args(argv)
    from contextlib import ExitStack
    read_scopes = ExitStack()
    try:
        root = project_root(args.project)
        config = load_config(root)
        if args.command in {'cleanup', 'maintenance'}:
            from .cleanup_cli import run as run_cleanup
            return run_cleanup(root, config, args)
        if args.command == 'directory':
            from .directory_cli import run as run_directory
            return run_directory(root, config, args)
        if args.command == 'archive-coverage':
            from .archive_coverage import archive_coverage
            value = archive_coverage(root, config, input_json(args.request))
            emit_result(value, args, root)
            return 1 if value.get('status') == 'Failed' else 0
        if args.command == 'history':
            from .sessions import history
            value = history(root, config, args.records_dir, max_files=args.max_records, max_bytes=args.max_record_bytes)
            emit_result(value, args, root)
            return 0
        if args.command == 'profile':
            from .scope import derive_profile
            value = derive_profile(root, config, args.parent_profile, sources=args.sources, checks=args.checks.split(',') if args.checks else None, reference_bodies=args.reference_bodies)
            if args.output:
                output_file(args.output, json.dumps(value['profile'], ensure_ascii=False, indent=2), root)
            from .reading import bounded_json
            print(bounded_json(value, args.max_output_bytes), end='')
            return 0
        if args.command == 'session':
            from . import sessions
            if args.action == 'recover':
                value = sessions.recover(root, config, args.session, input_json(args.recovery_plan))
            else:
                function = {'report': sessions.report, 'verify': sessions.verify, 'recovery-preview': sessions.recovery_preview}[args.action]
                value = function(root, config, args.session)
            emit_result(value, args, root)
            return 1 if value.get('status') in ('Failed', 'Blocked') or args.action in ('verify', 'recover') and value.get('status') != 'Passed' else 0
        if args.command == "report":
            from .reporting import summary
            if args.input:
                if args.after or args.goal or args.goal_profile:
                    raise ValueError("summary input cannot be combined with goal evaluation")
                value = input_json(args.input)
                if value.get("root") != str(root):
                    raise ValueError("report project mismatch")
                value = summary(value)
            elif args.measure_request:
                if args.after or args.goal or args.goal_profile:
                    raise ValueError("measurement request cannot be combined with goal evaluation")
                from .goals import measure
                value = measure(root, config, input_json(args.measure_request))
            else:
                from .goals import evaluate
                from .scope import load_task_profile
                if not args.after or not (args.goal or args.goal_profile):
                    raise ValueError('goal evaluation requires before, after and goal')
                goal = load_task_profile(root, args.goal_profile).get('goal') if args.goal_profile else args.goal
                before, after = input_json(args.before), input_json(args.after)
                if before.get('root') != str(root) or after.get('root') != str(root):
                    raise ValueError('report project mismatch')
                value = evaluate(before, after, goal)
            emit_result(value, args, root)
            return 1 if value.get('goal_result') == 'Failed' else 0
        if args.command == "read":
            from .scope import task_config
            from .reading import read_document, bounded_json
            config = task_config(root, config, files=args.files if args.files is not None or args.task_profile else [args.file], profile=args.task_profile, reference_bodies=args.reference_bodies, historical_roots=args.historical_roots)
            value = read_document(root, config, args.file, outline=args.outline, heading=args.heading, cursor=args.cursor, max_output_bytes=args.max_output_bytes, view=args.view, max_depth=args.max_depth, heading_filter=args.heading_filter, lines=args.lines, section_id=args.section_id)
            print(bounded_json(value, args.max_output_bytes), end="")
            return 0
        if args.command == "compare":
            from .comparison import compare_reports
            from .reading import bounded_json
            before = input_json(args.before)
            if args.plan:
                proposed = changes.overlay(root, input_json(args.plan), config)
                after = run(root, files=args.files, task_profile=args.task_profile, reference_bodies=args.reference_bodies, historical_roots=args.historical_roots, checks=before.get("checks"), overlay=proposed)
            else:
                after = input_json(args.after)
                if before.get("root") != str(root) or after.get("root") != str(root):
                    raise ValueError("comparison project mismatch")
            value = compare_reports(before, after)
            value["candidate"] = after.get("candidate", "Disk")
            if args.output:
                output_file(args.output, json.dumps(redacted(value), ensure_ascii=False, indent=2), root)
            print(bounded_json(value, args.max_output_bytes), end="")
            return 1 if value.get("status") == "Failed" else 0
        if args.command in {"check", "inventory"}:
            checks = args.checks.split(",") if args.checks else None
            report = run(root, inventory=args.command == "inventory", checks=checks, max_seconds=args.max_seconds, files=args.files, task_profile=args.task_profile, reference_bodies=args.reference_bodies, historical_roots=args.historical_roots, preflight=args.preflight)
            if args.preflight:
                from .reading import bounded_json
                text = bounded_json(report, args.max_output_bytes)
                if args.output:
                    output_file(args.output, text, root)
                print(text, end="")
                return 2 if report["status"] == "Blocked" else 0
            if args.state:
                try:
                    previous = input_json(args.state)
                except FileNotFoundError:
                    previous = None
                report["delta"] = compare_state(report, previous)
            if args.format == "summary":
                from .reading import bounded_json
                from .reporting import summary
                text = bounded_json(summary(report), args.max_output_bytes)
            else:
                text = render(report, args.format)
            if args.output:
                output_file(args.output, text, root)
                print(json.dumps({"output": str(Path(args.output).absolute()), "files": report["file_count"], "findings": report["finding_total"]}, ensure_ascii=False))
            else:
                print(text, end="")
            if args.state:
                state = redacted({k: v for k, v in report.items() if k != "files"})
                # File-map keys are identities, not secret-bearing config keys.
                # Values contain size/time/hash metadata only, never file bodies.
                state["files"] = report["files"]
                output_file(args.state, json.dumps(state, ensure_ascii=True), root)
            return 1 if report["has_failures"] else 0
        if args.command == "preview":
            request = input_json(args.request)
            compilation = None
            prepared_plan = None
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            task_config = None
            if args.task_profile:
                from .scope import task_config as configure
                from .preview_policy import validate_preview_scope, preview_read_scope
                task_config = configure(root, config, profile=args.task_profile)
                # Check every participant before compilation, locator reads or
                # the v3 NoChange early return. Plans retain the base config.
                validate_preview_scope(root, task_config, request)
                read_scopes.enter_context(preview_read_scope(root, task_config))
            if isinstance(request, dict) and isinstance(request.get("operations"), list):
                from .reading import locate_original
                for operation in request["operations"]:
                    if isinstance(operation, dict) and "old_locator" in operation:
                        if operation.get("type") != "replace" or "old" in operation:
                            raise ValueError("invalid original locator operation")
                        locator = operation.pop("old_locator")
                        if not isinstance(locator, dict) or set(locator) != {"sha256", "start_byte", "end_byte"}:
                            raise ValueError("invalid original locator")
                        original = locate_original(root, config, operation.get("path"), **locator)
                        operation["old"] = original["old"]
            if request.get("version") == 3:
                prepared = changes.prepare_request(root, request, config)
                request, compilation = prepared["request"], prepared["compilation"]
                prepared_plan = prepared.get("plan")
                if not request["operations"]:
                    from .reading import bounded_json
                    receipt_path = save_preview_receipt({'schema_version': 1, 'root': str(root), 'status': 'NoChange', 'compilation': compilation}, args, root, required=True)
                    print(bounded_json({"status": "NoChange", "plan": None, "requested_plan_written": False, "compilation": compilation_summary(compilation), "receipt": receipt_path}, args.max_output_bytes), end="")
                    return 0
            plan = prepared_plan if prepared_plan is not None else changes.preview(root, request, config)
            before_measure = None
            if task_config and task_config['_task'].get('goal') is not None:
                from .goals import measure, evaluate
                import base64
                task = task_config['_task']
                measurement = task.get('measurement', {'version': 1, 'active': task['sources']})
                measurement_config = dict(task_config)
                # Explicitly declared future external records must be measured
                # before preview itself creates its plan, diff or receipt.
                before_measure = measure(root, measurement_config, measurement)
            output_file(args.plan, json.dumps(plan, ensure_ascii=True, indent=2), root)
            from .reading import bounded_json
            proposed = changes.overlay(root, plan, config)
            from .models import Context
            ctx = Context(root, {}, config)
            diffs = []
            for path, after_bytes in sorted(proposed.items()):
                try:
                    before_bytes = ctx.read_bytes(path)
                except FileNotFoundError:
                    before_bytes = b""
                before_text = before_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
                after_text = (after_bytes or b"").decode("utf-8", errors="replace").splitlines(keepends=True)
                diffs.extend(difflib.unified_diff(before_text, after_text, fromfile=path, tofile=path))
            from .reading import _display
            full_diff = _display("".join(diffs))
            if args.diff_output:
                output_file(args.diff_output, full_diff, root)
            receipt = {'schema_version': 1, 'root': str(root), 'plan_operation_id': plan['operation_id'], 'request_sha256': hashlib.sha256(json.dumps(input_json(args.request), sort_keys=True).encode()).hexdigest(), 'compilation': compilation}
            if before_measure is not None:
                after_config = {**measurement_config, '_overlay': {path: base64.b64encode(data).decode('ascii') if data is not None else None for path, data in proposed.items()}}
                after_measure = measure(root, after_config, measurement)
                receipt['goal_preview'] = evaluate(before_measure, after_measure, task['goal'])
                receipt['measurements'] = {'before': before_measure, 'candidate': after_measure}
            receipt_path = save_preview_receipt(receipt, args, root, required=compilation is not None or receipt.get("goal_preview") is not None)
            value = {"status": "Preview", "plan": str(Path(args.plan).absolute()), "operations": len(plan["operations"]), "diff_bytes": len(full_diff.encode("utf-8")), "diff": full_diff, "diff_output": args.diff_output, "diff_truncated": False, "compilation": compilation_summary(compilation), "goal_preview": {key: val for key, val in receipt.get("goal_preview", {}).items() if key in {"goal_result", "before_bytes", "after_bytes", "reduction_bytes", "candidate", "reasons"}} if receipt.get("goal_preview") else None, "receipt": receipt_path}
            from .reading import _redact
            while len((json.dumps(_redact(value), ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")) > args.max_output_bytes and value["diff"]:
                value["diff"] = value["diff"][:len(value["diff"]) // 2]
                value["diff_truncated"] = True
            print(bounded_json(value, args.max_output_bytes), end="")
        elif args.command == "apply":
            record = changes.apply(root, input_json(args.plan), config, Path(args.operations_dir))
            print(json.dumps({"status": record.get("status"), "journal": record.get("journal_path")}, ensure_ascii=False))
        elif args.command == "verify":
            record = changes.verify(root, input_json(args.journal), config)
            print(json.dumps(record, ensure_ascii=False))
            return 0 if record.get("status") == "Passed" else 1
        else:
            record = changes.recover(root, Path(args.journal), config)
            print(json.dumps({"status": record.get("status"), "journal": record.get("journal_path")}, ensure_ascii=False))
        return 0
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        from .diagnostics import diagnose
        diagnostic = diagnose(error)
        diagnostic["project_writes"] = 0 if args.command in {"check", "inventory", "read", "compare", "report", "preview", "profile", "history", "archive-coverage"} or args.command == "session" and args.action != "recover" else "Unknown"
        if args.command == 'directory' and (args.directory_action in {'census', 'impact', 'search-preview', 'archive-preview', 'locate', 'restore-preview', 'verify'} or args.directory_action == 'workflow' and args.phase == 'inspect'):
            diagnostic['project_writes'] = 0
        if args.command == 'cleanup' and args.cleanup_action in {'inspect', 'preview', 'verify', 'restore-preview', 'purge-preview', 'history'}:
            diagnostic['project_writes'] = 0
        if args.command == 'maintenance' and args.mode == 'inspect':
            diagnostic['project_writes'] = 0
        # Do not echo parser input, arbitrary project content or credentials.
        print(json.dumps({"status": "Blocked", "error": type(error).__name__, **diagnostic, "message": "操作未完成；检查路径、格式、指纹与授权范围。中途写入失败时保留operations目录供恢复。"}, ensure_ascii=False), file=sys.stderr)
        return 2
    finally:
        read_scopes.close()


if __name__ == "__main__":
    raise SystemExit(main())
