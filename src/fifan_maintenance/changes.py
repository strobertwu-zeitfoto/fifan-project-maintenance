"""Explicit, hash-bound changes. Journals are integrity checks, not authorization tokens.

Directory descriptors and O_NOFOLLOW constrain writes. Other processes are not
locked: detected concurrent writes stop the batch, whose journal must be
retained. Non-cooperating writers must be paused: checks cannot close the final
stat-to-replace/unlink system-call windows. A batch is not an atomic transaction.
"""
from __future__ import annotations

import base64
import hashlib
import fnmatch
import fcntl
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path

from .inventory import protection_key

VERSION = 1
MAX_BYTES = 16 * 1024 * 1024


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _digest(value):
    return _hash(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())


def _journal_budget():
    # Reserve receipt/indentation/directory identity space without constructing it.
    return MAX_BYTES - min(2 * 1024 * 1024, MAX_BYTES // 4)


class _ChangeBudget:
    def __init__(self):
        self.used = 0

    def charge(self, size):
        if size > _journal_budget() - self.used:
            raise ValueError("Blocked: change journal budget exceeded")
        self.used += size

    def json(self, value):
        # Stream JSON accounting rather than allocating another whole plan string.
        encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True)
        for chunk in encoder.iterencode(value):
            self.charge(len(chunk.encode("utf-8")))

    def backup(self, data):
        self.charge(4 * ((len(data) + 2) // 3) + 2)


def _root(root):
    root = Path(root).absolute()
    for part in (root, *root.parents):
        if part.is_symlink():
            raise ValueError("symlink root/ancestor")
    if not root.is_dir():
        raise ValueError("project root is not a directory")
    return root.resolve()


def _relative(rel, config):
    if not isinstance(rel, str) or not rel or "\x00" in rel or "\\" in rel:
        raise ValueError("invalid relative path")
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts) or Path(rel).is_absolute():
        raise ValueError("path escape or noncanonical path")
    protected = [".git", ".venv", ".fifan-maintenance.json", *config.get("protected", [])]
    comparison = protection_key(rel)
    if any(part in (".git", ".venv", ".venv39", ".venv315", ".env") or part.startswith(".env.") for part in comparison.split('/')):
        raise ValueError("protected path")
    for pattern in protected:
        pattern = protection_key(pattern)
        prefix = pattern.rstrip("/")
        if prefix.endswith("/**"):
            prefix = prefix[:-3]
        if fnmatch.fnmatchcase(comparison, pattern) or comparison == prefix or comparison.startswith(prefix + "/"):
            raise ValueError("protected path")
    return rel


def _open_directory(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(path).absolute().parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _project_lock(root, exclusive=True):
    """Serialize this tool across journals; advisory locks do not lock other editors.

    Directory flock is supported on the target Darwin host. Unsupported locking
    fails closed: callers must not continue an apply/recovery without this lock.
    """
    fd = _open_directory(root)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("project busy: another maintenance operation holds the lock") from exc
        except OSError as exc:
            raise OSError("Blocked: project directory locking is unavailable") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _unique_match(text, old):
    # Searching again at start+1 includes overlapping matches (aaa / aa).
    first = text.find(old)
    return first >= 0 and text.find(old, first + 1) < 0


@contextmanager
def _parent(root, rel):
    fd = _open_directory(root)
    try:
        for part in rel.split("/")[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd, rel.split("/")[-1]
    finally:
        os.close(fd)


def _read(root, rel, config):
    _relative(rel, config)
    with _parent(root, rel) as (fd, name):
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            st = os.fstat(f)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("ordinary file required")
            limit = min(config.get("max_file_bytes", MAX_BYTES), MAX_BYTES)
            if st.st_size > limit:
                raise ValueError("file exceeds change limit")
            from .preview_policy import authorize_read
            if authorize_read(root, rel, st.st_size):
                limit = min(limit, st.st_size)
            with os.fdopen(os.dup(f), "rb") as stream:
                data = stream.read(limit + 1)
            end = os.fstat(f)
            if len(data) > limit or (st.st_ino, st.st_size, st.st_mtime_ns) != (end.st_ino, end.st_size, end.st_mtime_ns):
                raise ValueError("file changed during read")
            # Verify the name still identifies the opened file.
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (st.st_dev, st.st_ino):
                raise ValueError("file changed during read")
            return data, stat.S_IMODE(st.st_mode)
        finally:
            os.close(f)


def _missing(root, rel):
    # Missing parent is permitted; every existing component must be a directory.
    fd = _open_directory(root)
    try:
        parts = rel.split("/")
        for part in parts[:-1]:
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                return True
            os.close(fd)
            fd = nxt
        try:
            os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            return False
        except FileNotFoundError:
            return True
    finally:
        os.close(fd)


def _seal(value, field):
    value[field] = _digest({k: v for k, v in value.items() if k != field})
    return value


def _check_operation_aliases(root, operations):
    """Reject different spellings/entities before publication, not during undo.

    Keep exact-path snapshot reads followed by a replace legal. Name comparison
    uses the existing conservative protection equivalence; IO retains raw names.
    """
    names, entities = {}, {}
    for op in operations:
        for rel in [op["path"]] + ([op["destination"]] if "destination" in op else []):
            key = protection_key(rel)
            if key in names and names[key] != rel:
                raise ValueError("operation paths alias the same name")
            names[key] = rel
            try:
                with _parent(root, rel) as (fd, name):
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            entity = st.st_dev, st.st_ino
            if entity in entities and entities[entity] != rel:
                raise ValueError("operation paths alias the same entity")
            entities[entity] = rel


def _preview_v1(root: Path, request: dict, config: dict) -> dict:
    root = _root(root)
    if not isinstance(request, dict) or set(request) != {"operations"}:
        raise ValueError("request must contain only operations")
    raw = request["operations"]
    if not isinstance(raw, list) or not raw or len(raw) > 100:
        raise ValueError("expected 1..100 operations")
    operations, used = [], set()
    budget = _ChangeBudget()
    budget.json({"version": VERSION, "root": str(root), "config_sha256": _digest(config)})
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("invalid operation")
        kind = entry.get("type")
        keys = {"type", "path", "old", "new"} if kind == "replace" else {"type", "path", "destination"}
        if kind not in ("replace", "move") or set(entry) != keys:
            raise ValueError("unknown operation/fields")
        rel = _relative(entry["path"], config)
        paths = [rel]
        data, mode = _read(root, rel, config)
        budget.backup(data)
        if kind == "replace":
            old, new = entry["old"], entry["new"]
            if not isinstance(old, str) or not old or not isinstance(new, str):
                raise ValueError("replace requires nonempty old and textual new")
            text = data.decode("utf-8")
            if not _unique_match(text, old):
                raise ValueError("old text must match exactly once")
            after = text.replace(old, new, 1).encode("utf-8")
            if len(after) > min(config.get("max_file_bytes", MAX_BYTES), MAX_BYTES):
                raise ValueError("proposed file exceeds change limit")
        else:
            dest = _relative(entry["destination"], config)
            paths.append(dest)
            if not _missing(root, dest):
                raise ValueError("destination exists")
            after = data
        if used.intersection(paths) or len(set(paths)) != len(paths):
            raise ValueError("operations must use disjoint paths")
        used.update(paths)
        operations.append({**entry, "before_sha256": _hash(data), "after_sha256": _hash(after), "mode": mode,
                           "destination_sha256": None} if kind == "move" else
                          {**entry, "before_sha256": _hash(data), "after_sha256": _hash(after), "mode": mode})
        budget.json(operations[-1])
    return _seal({"version": VERSION, "root": str(root), "config_sha256": _digest(config),
                  "operations": operations}, "operation_id")


def _reject_cleanup_material(value):
    if isinstance(value, dict) and str(value.get('format', '')).startswith(('fifan-cleanup-', 'fifan-maintenance-')):
        from .diagnostics import DiagnosticError
        raise DiagnosticError('CLEANUP_FORMAT_UNSUPPORTED', 'Use the explicit cleanup commands')


def _validate_plan(root, plan, config, current=True):
    _reject_cleanup_material(plan)
    if isinstance(plan, dict) and plan.get("version") == 2:
        return _validate_plan_v2(root, plan, config, current)
    if not isinstance(plan, dict) or set(plan) != {"version", "root", "config_sha256", "operations", "operation_id"}:
        raise ValueError("invalid plan schema")
    if plan["version"] != VERSION or plan["root"] != str(root) or _matching_config(plan["config_sha256"], config) is None:
        raise ValueError("plan scope/config/version mismatch")
    if plan["operation_id"] != _digest({k: v for k, v in plan.items() if k != "operation_id"}):
        raise ValueError("plan integrity mismatch")
    request = {"operations": []}
    for op in plan["operations"]:
        kind = op.get("type")
        fields = ("type", "path", "old", "new") if kind == "replace" else ("type", "path", "destination")
        request["operations"].append({k: op[k] for k in fields})
    if current and _preview_v1(root, request, _matching_config(plan["config_sha256"], config)) != plan:
        raise ValueError("plan no longer matches project")
    return request


def _output(output_dir, root):
    output = Path(output_dir).absolute()
    # Recovery material must be outside the inspected project.
    if output == root or root in output.parents:
        raise ValueError("operation directory must be outside project")
    for item in (output, *output.parents):
        if item.is_symlink():
            raise ValueError("symlink output directory")
    if any(p in (".git", ".venv") for p in output.parts) or ".." in output.parts:
        raise ValueError("protected/noncanonical operation directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in output.parts[1:]:
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=fd)
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
    finally:
        os.close(fd)
    return output.resolve()


def _atomic(root, rel, data, mode, expected, config):
    with _parent(root, rel) as (fd, name):
        # mkstemp cannot be dirfd-relative; use an unpredictable O_EXCL name.
        import secrets
        temp = ".fifan-" + secrets.token_hex(16)
        f = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
        try:
            with os.fdopen(f, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            current, current_mode = _read(root, rel, config)
            after = os.stat(name, dir_fd=fd, follow_symlinks=False)
            identity = lambda st: (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode)
            if _hash(current) != expected or current_mode != mode or identity(before) != identity(after):
                raise ValueError("concurrent modification")
            # No portable compare-and-swap rename exists here. Non-cooperating
            # editors must be stopped; they can still race this final replace.
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(temp, dir_fd=fd)
            except FileNotFoundError:
                pass


def _save(path, record):
    import secrets
    _seal(record, "record_sha256")
    encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2)
    if len(encoded.encode("utf-8")) > MAX_BYTES:
        raise ValueError("journal exceeds recovery size limit")
    temp = ".journal-" + secrets.token_hex(16)
    with _parent(path.parent, path.name) as (dfd, name):
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("journal is not an ordinary file")
        except FileNotFoundError:
            pass
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(encoded)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
        finally:
            try:
                os.unlink(temp, dir_fd=dfd)
            except FileNotFoundError:
                pass


def _mkdirs(root, rel, record, journal):
    current = []
    for part in rel.split("/")[:-1]:
        current.append(part)
        directory = "/".join(current)
        with _parent(root, directory) as (fd, name):
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode):
                    raise ValueError("destination ancestor is not a directory")
            except FileNotFoundError:
                os.mkdir(name, dir_fd=fd)
                made = os.stat(name, dir_fd=fd, follow_symlinks=False)
                record["created_dirs"].append({"path": directory, "device": made.st_dev, "inode": made.st_ino})
                _save(journal, record)


def _move(root, source, dest, expected, config):
    with _parent(root, source) as (sfd, sn), _parent(root, dest) as (dfd, dn):
        if _hash(_read(root, source, config)[0]) != expected:
            raise ValueError("concurrent source modification")
        os.link(sn, dn, src_dir_fd=sfd, dst_dir_fd=dfd, follow_symlinks=False)
        # A replacement between check and link must not be silently accepted.
        if _hash(_read(root, dest, config)[0]) != expected or _hash(_read(root, source, config)[0]) != expected:
            raise ValueError("concurrent move modification")
        source_now = os.stat(sn, dir_fd=sfd, follow_symlinks=False)
        dest_now = os.stat(dn, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(source_now.st_mode) or (source_now.st_dev, source_now.st_ino) != (dest_now.st_dev, dest_now.st_ino):
            raise ValueError("source name changed before unlink")
        # Advisory locking excludes our own overlapping operations. An external
        # writer can still race between this identity check and unlink.
        os.unlink(sn, dir_fd=sfd)
        os.fsync(sfd)
        os.fsync(dfd)


def _apply(root: Path, plan: dict, config: dict, output_dir: Path) -> dict:
    root = _root(root)
    _validate_plan(root, plan, config)
    _check_operation_aliases(root, plan["operations"])
    backups = []
    budget = _ChangeBudget()
    budget.json(plan)
    for op in plan["operations"]:
        data, mode = _read(root, op["path"], config)
        if _hash(data) != op["before_sha256"] or mode != op["mode"]:
            raise ValueError("concurrent change during preflight")
        budget.backup(data)
        backups.append(base64.b64encode(data).decode("ascii"))
    # Recovery is bounded too: reserve space for receipts and created directories.
    if len(json.dumps({"plan": plan, "backups": backups}).encode("utf-8")) > _journal_budget():
        raise ValueError("batch exceeds journal size limit")
    output = _output(output_dir, root)
    journal = output / (plan["operation_id"] + ".json")
    # Exclusive reservation prevents two identical applies from sharing a journal.
    with _parent(output, journal.name) as (dfd, name):
        try:
            reserved = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        except FileExistsError as exc:
            raise ValueError("operation already recorded") from exc
        os.close(reserved)
    record = {"version": plan["version"], "plan": plan, "backups": backups, "completed": [], "intent": None,
              "created_dirs": [], "restored": [], "status": "applying", "journal_path": str(journal), "error": None}
    if plan["version"] == 2:
        record["created_files"] = []
    _save(journal, record)
    try:
        for index, op in enumerate(plan["operations"]):
            record["intent"] = index
            _save(journal, record)
            data, mode = _read(root, op["path"], config)
            if _hash(data) != op["before_sha256"] or mode != op["mode"]:
                raise ValueError("concurrent modification before operation")
            if _kind(op) == "snapshot":
                _mkdirs(root, op["destination"], record, journal)
                _snapshot(root, op, data, mode, config, record, journal, index)
            elif _kind(op) == "replace":
                after = data.decode("utf-8").replace(op["old"], op["new"], 1).encode("utf-8")
                _atomic(root, op["path"], after, mode, op["before_sha256"], config)
            else:
                _mkdirs(root, op["destination"], record, journal)
                _move(root, op["path"], op["destination"], op["before_sha256"], config)
            target = op.get("destination", op["path"])
            written, written_mode = _read(root, target, config)
            if (_hash(written), written_mode) != (op["after_sha256"], op["mode"]):
                raise ValueError("post-write verification failed")
            record["completed"].append(index)
            record["intent"] = None
            _save(journal, record)
        if plan["version"] == 2:
            _check_guard_files(root, plan, config, after=True)
        record["status"] = "applied"
    except BaseException as exc:
        record["status"] = "failed"
        record["error"] = type(exc).__name__
        _save(journal, record)
        raise
    _save(journal, record)
    return record


def _validate_record(root, record, config):
    _reject_cleanup_material(record)
    fields = {"version", "plan", "backups", "completed", "intent", "created_dirs", "status", "journal_path", "error", "record_sha256", "restored"}
    if isinstance(record, dict) and record.get("version") == 2:
        fields.add("created_files")
    if not isinstance(record, dict) or set(record) != fields or record["version"] not in (1, 2):
        raise ValueError("unknown journal format")
    if record["record_sha256"] != _digest({k: v for k, v in record.items() if k != "record_sha256"}):
        raise ValueError("journal integrity mismatch")
    plan = record["plan"]
    _validate_plan(root, plan, config, current=False)
    ops = plan["operations"]
    if not isinstance(ops, list) or not 1 <= len(ops) <= 100 or len(record["backups"]) != len(ops):
        raise ValueError("invalid journal operations")
    if record["version"] != plan["version"]:
        raise ValueError("journal/plan version mismatch")
    if record["version"] == 2:
        backups = _validate_record_v2(root, record, config)
        expected_dirs = set()
        for op in ops:
            if _kind(op) != "replace":
                parts = op["destination"].split("/")[:-1]
                expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    else:
        used, expected_dirs, backups = set(), set(), []
        for op, encoded in zip(ops, record["backups"]):
            kind = op.get("type")
            keys = {"type", "path", "old", "new", "before_sha256", "after_sha256", "mode"} if kind == "replace" else {"type", "path", "destination", "before_sha256", "after_sha256", "mode", "destination_sha256"}
            if kind not in ("replace", "move") or set(op) != keys:
                raise ValueError("unknown recorded operation")
            rel = _relative(op["path"], config)
            paths = [rel]
            data = base64.b64decode(encoded, validate=True)
            if len(data) > min(config.get("max_file_bytes", MAX_BYTES), MAX_BYTES):
                raise ValueError("backup exceeds limit")
            if type(op["mode"]) is not int or not 0 <= op["mode"] <= 0o7777:
                raise ValueError("invalid recorded permissions")
            if kind == "replace":
                old, new = op["old"], op["new"]
                if not isinstance(old, str) or not old or not isinstance(new, str) or not _unique_match(data.decode("utf-8"), old):
                    raise ValueError("invalid recorded replacement")
                after = data.decode("utf-8").replace(old, new, 1).encode("utf-8")
            else:
                dest = _relative(op["destination"], config)
                paths.append(dest)
                if op["destination_sha256"] is not None:
                    raise ValueError("invalid destination expectation")
                parts = dest.split("/")[:-1]
                expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
                after = data
            if len(set(paths)) != len(paths) or used.intersection(paths):
                raise ValueError("overlapping recorded paths")
            used.update(paths)
            if _hash(data) != op["before_sha256"] or _hash(after) != op["after_sha256"]:
                raise ValueError("recorded content hash mismatch")
            backups.append(data)
    completed, intent, restored = record["completed"], record["intent"], record["restored"]
    if not isinstance(completed, list) or completed != list(range(len(completed))) or any(type(i) is not int for i in completed) or len(completed) > len(ops):
        raise ValueError("invalid completed list")
    if intent is not None and (type(intent) is not int or intent != len(completed) or intent >= len(ops)):
        raise ValueError("invalid intent")
    eligible = completed + ([] if intent is None else [intent])
    if not isinstance(restored, list) or any(type(i) is not int or i not in eligible for i in restored) or len(restored) != len(set(restored)):
        raise ValueError("invalid restored list")
    dirs = record["created_dirs"]
    if not isinstance(dirs, list):
        raise ValueError("invalid created directory list")
    seen_dirs = set()
    for directory in dirs:
        if not isinstance(directory, dict) or set(directory) != {"path", "device", "inode"}:
            raise ValueError("invalid created directory record")
        if directory["path"] not in expected_dirs or directory["path"] in seen_dirs or any(type(directory[k]) is not int for k in ("device", "inode")):
            raise ValueError("invalid created directory identity")
        seen_dirs.add(directory["path"])
    if record["status"] not in {"applying", "applied", "failed", "recovering", "recovered"}:
        raise ValueError("unknown journal status")
    if record["status"] == "applied" and (len(completed) != len(ops) or intent is not None):
        raise ValueError("incomplete applied journal")
    if record["status"] == "recovered" and set(restored) != set(eligible):
        raise ValueError("incomplete recovered journal")
    path = Path(record["journal_path"])
    if not path.is_absolute() or path.name != plan["operation_id"] + ".json":
        raise ValueError("invalid journal path")
    if path.parent == root or root in path.parent.parents or any(p in (".git", ".venv", "..") for p in path.parts):
        raise ValueError("journal is inside project/protected directory")
    return backups


def _state(root, op, config, owner=None):
    def fingerprint(rel):
        if _missing(root, rel):
            return None
        data, mode = _read(root, rel, config)
        return _hash(data), mode
    if _kind(op) == "snapshot":
        dest = fingerprint(op["destination"])
        if dest is None:
            return "before"
        if dest == (op["after_sha256"], op["mode"]) and owner is not None:
            with _parent(root, op["destination"]) as (fd, name):
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (st.st_dev, st.st_ino) == (owner["device"], owner["inode"]):
                    return "after"
        raise ValueError("snapshot has subsequent or unknown modifications")
    source = fingerprint(op["path"])
    before = op["before_sha256"], op["mode"]
    if op["type"] == "replace":
        if source == before == (op["after_sha256"], op["mode"]):
            return "both"
        if source == before:
            return "before"
        if source == (op["after_sha256"], op["mode"]):
            return "after"
    else:
        dest = fingerprint(op["destination"])
        if source == before and dest is None:
            return "before"
        if source is None and dest == before:
            return "after"
        if source == before and dest == before:
            # The only legitimate interrupted duplicate is our hard link.
            with _parent(root, op["path"]) as (sfd, sn), _parent(root, op["destination"]) as (dfd, dn):
                a = os.stat(sn, dir_fd=sfd, follow_symlinks=False)
                b = os.stat(dn, dir_fd=dfd, follow_symlinks=False)
                if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
                    return "linked"
    raise ValueError("file has subsequent or unknown modifications")


def _verify(root: Path, record: dict, config: dict) -> dict:
    root = _root(root)
    _validate_record(root, record, config)
    issues = []
    for index, op in enumerate(record["plan"]["operations"]):
        try:
            state = _state(root, op, config, _owner(record, index))
            expected = "before" if record["status"] == "recovered" or index in record["restored"] else "after" if index in record["completed"] else "before"
            if state not in (expected, "both"):
                issues.append({"operation": index, "state": state, "expected": expected})
        except (OSError, ValueError) as exc:
            issues.append({"operation": index, "error": type(exc).__name__})
    if record["plan"]["version"] == 2:
        try:
            _check_snapshot_sources(root, record["plan"], config)
            _check_record_guard_files(root, record, config)
        except (OSError, ValueError) as exc:
            issues.append({"error": type(exc).__name__, "check": "guards/snapshot sources"})
    complete = (record["status"] == "applied" and len(record["completed"]) == len(record["plan"]["operations"]) and record["intent"] is None) or (record["status"] == "recovered" and set(record["restored"]) == set(record["completed"] + ([] if record["intent"] is None else [record["intent"]])))
    return {"status": "Failed" if issues else "Passed" if complete else "Unknown",
            "journal_consistency": "Failed" if issues else "Passed", "operation_status": record["status"],
            "operation_id": record["plan"]["operation_id"], "issues": issues}


def _recover(root: Path, record_path: Path, config: dict) -> dict:
    root = _root(root)
    path = Path(record_path).absolute()
    for p in (path, *path.parents):
        if p.is_symlink():
            raise ValueError("symlink journal")
    raw, _ = _read(_root(path.parent), path.name, {"max_file_bytes": MAX_BYTES})
    record = json.loads(raw)
    backups = _validate_record(root, record, config)
    if str(path) != record["journal_path"]:
        raise ValueError("journal location changed")
    eligible = record["completed"] + ([] if record["intent"] is None else [record["intent"]])
    # Inspect every path before restoring any, including operations never started.
    for index, op in enumerate(record["plan"]["operations"]):
        state = _state(root, op, config, _owner(record, index))
        if (index not in eligible or index in record["restored"]) and state not in ("before", "both"):
            raise ValueError("unstarted/restored file changed")
    if record["plan"]["version"] == 2:
        _check_snapshot_sources(root, record["plan"], config)
        for owner in record["created_files"]:
            _check_owned_temp(root, owner, record["plan"]["operations"][owner["index"]], config)
        _check_record_guard_files(root, record, config)
    record["status"] = "recovering"
    _save(path, record)
    for index in reversed(eligible):
        if index in record["restored"]:
            continue
        op = record["plan"]["operations"][index]
        state = _state(root, op, config, _owner(record, index))
        if state == "after":
            if _kind(op) == "snapshot":
                _unlink_owned(root, op["destination"], _owner(record, index))
            elif _kind(op) == "replace":
                _atomic(root, op["path"], backups[index], op["mode"], op["after_sha256"], config)
            else:
                _move(root, op["destination"], op["path"], op["after_sha256"], config)
        elif state == "linked":
            with _parent(root, op["destination"]) as (fd, name):
                os.unlink(name, dir_fd=fd)
                os.fsync(fd)
        if _state(root, op, config, _owner(record, index)) not in ("before", "both"):
            raise ValueError("restore verification failed")
        record["restored"].append(index)
        _save(path, record)
    for owner in record.get("created_files", []):
        _unlink_owned(root, owner["temp"], owner, missing_ok=True)
    for directory in reversed(record["created_dirs"]):
        if _missing(root, directory["path"]):
            continue
        with _parent(root, directory["path"]) as (fd, name):
            try:
                existing = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (existing.st_dev, existing.st_ino) != (directory["device"], directory["inode"]) or not stat.S_ISDIR(existing.st_mode):
                    continue
                os.rmdir(name, dir_fd=fd)
            except FileNotFoundError:
                pass
            except OSError:
                # Never remove other work placed in a created directory.
                pass
    record["status"] = "recovered"
    _save(path, record)
    return record


def apply(root: Path, plan: dict, config: dict, output_dir: Path) -> dict:
    root = _root(root)
    with _project_lock(root):
        return _apply(root, plan, config, output_dir)


def verify(root: Path, record: dict, config: dict) -> dict:
    root = _root(root)
    with _project_lock(root, exclusive=False):
        return _verify(root, record, config)


def recover(root: Path, record_path: Path, config: dict) -> dict:
    root = _root(root)
    with _project_lock(root):
        return _recover(root, record_path, config)


# Frozen 1.0 configuration keys. Only newly introduced DEFAULT values can be
# removed when reproducing a v1 fingerprint; changed existing rules still fail.
_V1_CONFIG_KEYS = frozenset("schema_version include exclude protected max_files max_file_bytes max_total_bytes max_seconds max_findings document_max_bytes paragraph_max_chars large_file_bytes paths equalities asset_sources evidence_bindings entrypoints checks waivers artifacts anchor_style artifact_age_days documents links historical_sources asset_groups".split())


def _matching_config(expected, config, snapshot=None):
    if _digest(config) == expected:
        return config
    from .project import DEFAULT_CONFIG
    original_keys = set(snapshot) if snapshot is not None else _V1_CONFIG_KEYS
    projected = {k: v for k, v in config.items()
                 if k in original_keys or k not in DEFAULT_CONFIG or v != DEFAULT_CONFIG[k]}
    return projected if _digest(projected) == expected else None


def _kind(op):
    return op.get("kind", op.get("type"))


def _request_v2(plan):
    ops = []
    for op in plan["operations"]:
        keys = ("kind", "path", "destination", "expected_sha256", "origin") if _kind(op) == "snapshot" else ("type", "path", "old", "new") if _kind(op) == "replace" else ("type", "path", "destination")
        ops.append({k: op[k] for k in keys})
    return {"version": 2, "operations": ops, "guards": plan["guards"]}


def _proposed(operations, sources):
    result = {}
    for op in operations:
        data = sources[op["path"]][0]
        if _kind(op) == "replace":
            result[op["path"]] = data.decode("utf-8").replace(op["old"], op["new"], 1).encode("utf-8")
        else:
            result[op["destination"]] = data
            if _kind(op) == "move":
                result[op["path"]] = None
    return result


def _guard_block(data, guard):
    from markdown_it import MarkdownIt
    from .adapters.markdown import github_slug
    from html.parser import HTMLParser
    kind, value = guard["kind"], guard["value"]
    text = data.decode("utf-8")
    if kind == "snippet":
        if not _unique_match(text, value):
            raise ValueError("guard snippet missing or ambiguous")
        return value
    tokens = MarkdownIt("commonmark", {"html": True}).enable("table").parse(text)
    from .selection import source_lines
    lines = source_lines(text)
    if kind in ("heading", "table"):
        blocks = []
        for i, token in enumerate(tokens):
            wanted = "heading_open" if kind == "heading" else "table_open"
            if token.type != wanted or token.map is None:
                continue
            start, end = token.map
            if kind == "heading":
                title = "".join(lines[start:end]).rstrip("\r\n")
                if title != value:
                    continue
                end = len(lines)
                for following in tokens[i + 1:]:
                    if following.type == "heading_open" and int(following.tag[1:]) <= int(token.tag[1:]):
                        end = following.map[0]
                        break
                blocks.append("".join(lines[start:end]))
            elif "".join(lines[start:end]) == value:
                blocks.append(value)
        if len(blocks) != 1:
            raise ValueError("guard block missing or ambiguous")
        return blocks[0]
    # Count actual heading/HTML anchors, including duplicate explicit HTML IDs.
    anchors, counts, used = [], {}, set()
    class Anchors(HTMLParser):
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if attrs.get("id"):
                anchors.append(attrs["id"])
            if tag == "a" and attrs.get("name"):
                anchors.append(attrs["name"])
        handle_startendtag = handle_starttag
    for i, token in enumerate(tokens):
        if token.type == "heading_open":
            inline = tokens[i + 1]
            title = "".join(t.content for t in inline.children or [] if t.type in {"text", "code_inline", "image"})
            base = github_slug(title)
            number = counts.get(base, 0)
            slug = base if not number else base + "-" + str(number)
            while slug in used:
                number += 1
                slug = base + "-" + str(number)
            counts[base] = number + 1
            used.add(slug)
            anchors.append(slug)
        elif token.type == "html_block":
            Anchors().feed(token.content)
        elif token.type == "inline":
            for child in token.children or []:
                if child.type == "html_inline":
                    Anchors().feed(child.content)
    if anchors.count(value) != 1:
        raise ValueError("guard anchor missing or ambiguous")
    return value


def _guards(guards, sources, proposed, config, budget):
    if not isinstance(guards, list) or len(guards) > 100:
        raise ValueError("invalid guards list")
    evidence, normalized = [], []
    for guard in guards:
        if not isinstance(guard, dict) or set(guard) - {"kind", "path", "value", "exceptions"} or not {"kind", "path", "value"} <= set(guard):
            raise ValueError("invalid guard schema")
        kind = guard["kind"]
        rel = _relative(guard["path"], config)
        if kind not in {"snippet", "heading", "table", "anchor"} or not isinstance(guard["value"], str) or not guard["value"]:
            raise ValueError("invalid guard kind/value")
        exceptions = guard.get("exceptions", [])
        if not isinstance(exceptions, list) or len(exceptions) > 100 or kind == "anchor" and exceptions:
            raise ValueError("invalid guard exceptions")
        before = sources[rel][0]
        after = proposed.get(rel, before)
        if after is None:
            raise ValueError("guard source is removed")
        block = _guard_block(before, guard)
        expected = block
        after_guard = dict(guard)
        for exception in exceptions:
            if not isinstance(exception, dict) or set(exception) != {"old", "new"}:
                raise ValueError("invalid precise exception")
            old, new = exception["old"], exception["new"]
            if not isinstance(old, str) or not old or not isinstance(new, str) or old == expected or not _unique_match(expected, old):
                raise ValueError("exception missing, ambiguous, or exempts entire block")
            expected = expected.replace(old, new, 1)
            # Table/snippet selectors are their exact content; heading selectors
            # remain fixed, so a guard cannot silently rename its heading.
            if kind in ("snippet", "table"):
                after_guard["value"] = expected
        actual = _guard_block(after, after_guard)
        if actual != expected:
            raise ValueError("preservation guard failed")
        declaration = {**guard, "exceptions": exceptions}
        item = {"path": rel, "source_mode": sources[rel][1], "before_file_sha256": _hash(before), "after_file_sha256": _hash(after),
                "before_sha256": _hash(block.encode("utf-8")), "after_sha256": _hash(actual.encode("utf-8"))}
        # Each guard currently embeds its own source. Account for that duplicate
        # before base64 encoding so repeated small selectors cannot amplify memory.
        budget.json(declaration)
        budget.json(item)
        budget.charge(len('"source_base64": '))
        budget.backup(before)
        item["source_base64"] = base64.b64encode(before).decode("ascii")
        normalized.append(declaration)
        evidence.append(item)
    return normalized, evidence


def _build_v2(root, request, config, read, missing):
    if not isinstance(request, dict) or set(request) - {"version", "operations", "guards"} or request.get("version") != 2:
        raise ValueError("invalid v2 request schema")
    raw = request.get("operations")
    if not isinstance(raw, list) or not 1 <= len(raw) <= 100 or any(not isinstance(op, dict) for op in raw):
        raise ValueError("expected 1..100 operations")
    # A deterministic execution order is part of the sealed, reviewable plan.
    raw = [o for o in raw if _kind(o) == "snapshot"] + [o for o in raw if _kind(o) != "snapshot"]
    operations, sources, writes, readers = [], {}, {}, {}
    budget = _ChangeBudget()
    budget.json({"version": 2, "root": str(root), "config_snapshot": config, "config_sha256": _digest(config), "config_contract": 1})
    for entry in raw:
        kind = _kind(entry)
        keys = {"kind", "path", "destination", "expected_sha256", "origin"} if kind == "snapshot" else {"type", "path", "old", "new"} if kind == "replace" else {"type", "path", "destination"}
        if kind not in {"snapshot", "replace", "move"} or set(entry) != keys:
            raise ValueError("unknown v2 operation/fields")
        rel = _relative(entry["path"], config)
        data, mode = read(rel)
        budget.backup(data)
        if rel in sources and sources[rel] != (data, mode):
            raise ValueError("source changed during preview")
        sources[rel] = data, mode
        readers.setdefault(rel, []).append(kind)
        after = data
        targets = [rel] if kind in {"replace", "move"} else []
        if kind == "replace":
            old, new = entry["old"], entry["new"]
            if not isinstance(old, str) or not old or not isinstance(new, str) or not _unique_match(data.decode("utf-8"), old):
                raise ValueError("old text must match exactly once")
            after = data.decode("utf-8").replace(old, new, 1).encode("utf-8")
            if len(after) > min(config.get("max_file_bytes", MAX_BYTES), MAX_BYTES):
                raise ValueError("proposed file exceeds change limit")
        else:
            dest = _relative(entry["destination"], config)
            targets.append(dest)
            if not missing(dest):
                raise ValueError("destination exists")
        if kind == "snapshot":
            if entry["expected_sha256"] != _hash(data):
                raise ValueError("snapshot source fingerprint mismatch")
            origin = entry["origin"]
            if not isinstance(origin, dict) or set(origin) != {"reference_base", "classification_basis"} or not isinstance(origin["classification_basis"], str) or not origin["classification_basis"].strip():
                raise ValueError("snapshot requires explicit origin")
            if origin["reference_base"] != ".":
                _relative(origin["reference_base"], config)
        for target in targets:
            if target in writes:
                raise ValueError("multiple writes to same path")
            writes[target] = kind
        op = {**entry, "before_sha256": _hash(data), "after_sha256": _hash(after), "mode": mode}
        if kind != "replace":
            op["destination_sha256"] = None
        budget.json(op)
        operations.append(op)
    for rel, kinds in readers.items():
        if rel in writes and not (writes[rel] == "replace" and all(k in {"snapshot", "replace"} for k in kinds)) and not (writes[rel] == "move" and kinds == ["move"]):
            raise ValueError("read/write path conflict")
    guard_list = request.get("guards", [])
    if not isinstance(guard_list, list):
        raise ValueError("invalid guards")
    for guard in guard_list:
        if not isinstance(guard, dict) or "path" not in guard:
            raise ValueError("invalid guard")
        rel = _relative(guard["path"], config)
        current = read(rel)
        if rel in sources and current != sources[rel]:
            raise ValueError("guard source changed during preview")
        sources[rel] = current
    proposed = _proposed(operations, sources)
    guards, evidence = _guards(guard_list, sources, proposed, config, budget)
    plan = _seal({"version": 2, "root": str(root), "config_sha256": _digest(config), "config_snapshot": config,
                  "config_contract": 1, "operations": operations, "guards": guards, "guard_evidence": evidence}, "operation_id")
    if len(json.dumps(plan).encode("utf-8")) > _journal_budget():
        raise ValueError("plan exceeds size limit")
    return plan


def preview(root: Path, request: dict, config: dict) -> dict:
    root = _root(root)
    if isinstance(request, dict) and request.get("version") == 3:
        prepared = prepare_request(root, request, config)
        if not prepared["request"]["operations"]:
            raise ChangeRequestError("NO_CHANGES", "No effective changes to preview")
        _check_operation_aliases(root, prepared["plan"]["operations"])
        return prepared["plan"]
    if isinstance(request, dict) and request.get("version") == 2:
        plan = _build_v2(root, request, config, lambda rel: _read(root, rel, config), lambda rel: _missing(root, rel))
    else:
        plan = _preview_v1(root, request, config)
    _check_operation_aliases(root, plan["operations"])
    return plan


def _validate_plan_v2(root, plan, config, current):
    fields = {"version", "root", "config_sha256", "config_snapshot", "config_contract", "operations", "guards", "guard_evidence", "operation_id"}
    if set(plan) != fields or plan["config_contract"] != 1 or plan["root"] != str(root) or not isinstance(plan["config_snapshot"], dict):
        raise ValueError("invalid v2 plan scope/schema")
    if _digest(plan["config_snapshot"]) != plan["config_sha256"] or _matching_config(plan["config_sha256"], config, plan["config_snapshot"]) is None:
        raise ValueError("plan config mismatch")
    if plan["operation_id"] != _digest({k: v for k, v in plan.items() if k != "operation_id"}):
        raise ValueError("plan integrity mismatch")
    request = _request_v2(plan)
    if current:
        rebuilt = _build_v2(root, request, plan["config_snapshot"], lambda rel: _read(root, rel, config), lambda rel: _missing(root, rel))
        if rebuilt != plan:
            raise ValueError("plan no longer matches project")
    return request


def overlay(root: Path, plan: dict, config: dict) -> dict:
    """Return fingerprint-checked proposed bytes, never a disk-backed candidate."""
    root = _root(root)
    with _project_lock(root, exclusive=False):
        _validate_plan(root, plan, config)
        sources = {op["path"]: _read(root, op["path"], config) for op in plan["operations"]}
        for op in plan["operations"]:
            data, mode = sources[op["path"]]
            if (_hash(data), mode) != (op["before_sha256"], op["mode"]):
                raise ValueError("source changed during overlay")
        return _proposed(plan["operations"], sources)


def _validate_record_v2(root, record, config):
    plan = record["plan"]
    sources, backups = {}, []
    for op, encoded in zip(plan["operations"], record["backups"]):
        data = base64.b64decode(encoded, validate=True)
        if len(data) > min(config.get("max_file_bytes", MAX_BYTES), MAX_BYTES):
            raise ValueError("backup exceeds limit")
        rel = _relative(op["path"], config)
        if type(op["mode"]) is not int or not 0 <= op["mode"] <= 0o7777:
            raise ValueError("invalid permissions")
        item = data, op["mode"]
        if rel in sources and sources[rel] != item:
            raise ValueError("inconsistent backup sources")
        sources[rel] = item
        backups.append(data)
    for evidence in plan["guard_evidence"]:
        rel = _relative(evidence["path"], config)
        data = base64.b64decode(evidence["source_base64"], validate=True)
        if len(data) > min(config.get("max_file_bytes", MAX_BYTES), MAX_BYTES):
            raise ValueError("guard source exceeds limit")
        if type(evidence["source_mode"]) is not int or not 0 <= evidence["source_mode"] <= 0o7777:
            raise ValueError("invalid guard permissions")
        item = data, evidence["source_mode"]
        if rel in sources and sources[rel] != item:
            raise ValueError("guard/backup source conflict")
        sources[rel] = item
    rebuilt = _build_v2(root, _request_v2(plan), plan["config_snapshot"], lambda rel: sources[rel], lambda rel: True)
    if rebuilt != plan:
        raise ValueError("recorded v2 content/guards mismatch")
    owners = record["created_files"]
    if not isinstance(owners, list):
        raise ValueError("invalid created files")
    seen = set()
    eligible = record["completed"] + ([] if record["intent"] is None else [record["intent"]])
    for owner in owners:
        if not isinstance(owner, dict) or set(owner) != {"index", "path", "temp", "device", "inode"} or type(owner["index"]) is not int:
            raise ValueError("invalid created file ownership")
        index = owner["index"]
        if index in seen or index not in eligible or not 0 <= index < len(plan["operations"]):
            raise ValueError("invalid snapshot ownership index")
        seen.add(index)
        op = plan["operations"][index]
        if _kind(op) != "snapshot" or owner["path"] != op["destination"]:
            raise ValueError("invalid snapshot ownership path")
        temp = _relative(owner["temp"], config)
        if Path(temp).parent != Path(owner["path"]).parent or not Path(temp).name.startswith(".fifan-snapshot-") or len(Path(temp).name) != len(".fifan-snapshot-") + 32 or any(c not in "0123456789abcdef" for c in Path(temp).name[-32:]):
            raise ValueError("invalid snapshot temporary path")
        if any(type(owner[k]) is not int or owner[k] < 0 for k in ("device", "inode")):
            raise ValueError("invalid snapshot inode")
    return backups


def _owner(record, index):
    return next((o for o in record.get("created_files", []) if o["index"] == index), None)


def _snapshot(root, op, data, mode, config, record, journal, index):
    import secrets
    dest = op["destination"]
    with _parent(root, dest) as (fd, name):
        temp = ".fifan-snapshot-" + secrets.token_hex(16)
        f = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
        try:
            with os.fdopen(f, "wb") as out:
                out.write(data)
                out.flush()
                os.fchmod(out.fileno(), mode)
                os.fsync(out.fileno())
                st = os.fstat(out.fileno())
            owner = {"index": index, "path": dest, "temp": str(Path(dest).parent / temp), "device": st.st_dev, "inode": st.st_ino}
            record["created_files"].append(owner)
            _save(journal, record)
            current, current_mode = _read(root, op["path"], config)
            if (_hash(current), current_mode) != (op["expected_sha256"], mode):
                raise ValueError("snapshot source changed before publication")
            os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.fsync(fd)
        finally:
            try:
                os.unlink(temp, dir_fd=fd)
                os.fsync(fd)
            except FileNotFoundError:
                pass


def _unlink_owned(root, rel, owner, missing_ok=False):
    if missing_ok and _missing(root, rel):
        return
    with _parent(root, rel) as (fd, name):
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            if missing_ok:
                return
            raise
        if owner is None or not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (owner["device"], owner["inode"]):
            raise ValueError("created file ownership changed")
        os.unlink(name, dir_fd=fd)
        os.fsync(fd)


def _check_snapshot_sources(root, plan, config):
    changed = {op["path"] for op in plan["operations"] if _kind(op) in {"replace", "move"}}
    for op in plan["operations"]:
        if _kind(op) == "snapshot" and op["path"] not in changed:
            data, mode = _read(root, op["path"], config)
            if (_hash(data), mode) != (op["before_sha256"], op["mode"]):
                raise ValueError("snapshot original subsequently changed")


def _check_guard_files(root, plan, config, after):
    for evidence in plan["guard_evidence"]:
        data, mode = _read(root, evidence["path"], config)
        expected = evidence["after_file_sha256"] if after else evidence["before_file_sha256"]
        if _hash(data) != expected or mode != evidence["source_mode"]:
            raise ValueError("guard source subsequently changed")


def _check_owned_temp(root, owner, op, config):
    if _missing(root, owner["temp"]):
        return
    data, mode = _read(root, owner["temp"], config)
    with _parent(root, owner["temp"]) as (fd, name):
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (_hash(data), mode, st.st_dev, st.st_ino) != (op["after_sha256"], op["mode"], owner["device"], owner["inode"]):
            raise ValueError("snapshot temporary file subsequently changed")


def _check_record_guard_files(root, record, config):
    """Check guards in every phase, using the observed corresponding file state.

    An intent can represent either side of an interrupted write. Matching that
    side checks the guard without claiming the interrupted batch was completed.
    The caller separately checks receipts and decides Failed/Unknown/Passed.
    """
    replacements = {op["path"]: (index, op) for index, op in enumerate(record["plan"]["operations"])
                    if _kind(op) == "replace"}
    for evidence in record["plan"]["guard_evidence"]:
        replacement = replacements.get(evidence["path"])
        after = False
        if replacement is not None:
            index, op = replacement
            after = _state(root, op, config, _owner(record, index)) == "after"
        data, mode = _read(root, evidence["path"], config)
        expected = evidence["after_file_sha256"] if after else evidence["before_file_sha256"]
        if (_hash(data), mode) != (expected, evidence["source_mode"]):
            raise ValueError("guard source subsequently changed")


class ChangeRequestError(ValueError):
    """Safe request diagnostics; neither message nor details contains patch text."""
    def __init__(self, reason_code, message, **details):
        super().__init__(message)
        self.reason_code = reason_code
        self.details = details


def _patch_error(code, message, path, operation_index, patch_index=None):
    details = {"path": path, "operation_index": operation_index}
    if patch_index is not None:
        details["patch_index"] = patch_index
    raise ChangeRequestError(code, message, **details)


def _compile_many(root, operation, config, operation_index):
    path = _relative(operation.get("path"), config)
    if set(operation) != {"type", "path", "expected_sha256", "patches"}:
        _patch_error("INVALID_REQUEST", "replace_many requires path, expected_sha256 and patches", path, operation_index)
    data, mode = _read(root, path, config)
    source_sha = _hash(data)
    if operation["expected_sha256"] != source_sha:
        _patch_error("SOURCE_CHANGED", "Patch source fingerprint changed", path, operation_index)
    try:
        source_text = data.decode("utf-8")
    except UnicodeDecodeError:
        _patch_error("UNSUPPORTED_ENCODING", "Patch source must be UTF-8", path, operation_index)
    patches = operation["patches"]
    if not isinstance(patches, list) or not 1 <= len(patches) <= 1000:
        _patch_error("INVALID_REQUEST", "Expected 1..1000 patches", path, operation_index)
    located = []
    for index, patch in enumerate(patches):
        if not isinstance(patch, dict) or set(patch) not in ({"old", "new"}, {"old_locator", "new"}) or not isinstance(patch["new"], str):
            _patch_error("INVALID_REQUEST", "Patch requires old or old_locator and textual new", path, operation_index, index)
        if "old" in patch:
            if not isinstance(patch["old"], str) or not patch["old"]:
                _patch_error("INVALID_REQUEST", "Patch old must be nonempty text", path, operation_index, index)
            try:
                old = patch["old"].encode("utf-8")
            except UnicodeEncodeError:
                _patch_error("UNSUPPORTED_ENCODING", "Patch old must be UTF-8", path, operation_index, index)
            start = data.find(old)
            end = start + len(old)
        else:
            locator = patch["old_locator"]
            if not isinstance(locator, dict) or set(locator) != {"sha256", "start_byte", "end_byte"}:
                _patch_error("INVALID_REQUEST", "Invalid patch locator schema", path, operation_index, index)
            if locator["sha256"] != source_sha:
                _patch_error("SOURCE_CHANGED", "Patch locator fingerprint changed", path, operation_index, index)
            start, end = locator["start_byte"], locator["end_byte"]
            if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(data):
                _patch_error("PATCH_RANGE_INVALID", "Patch locator range is outside the original", path, operation_index, index)
            old = data[start:end]
            try:
                data[:start].decode("utf-8")
                old.decode("utf-8")
            except UnicodeDecodeError:
                _patch_error("PATCH_RANGE_INVALID", "Patch locator splits a UTF-8 character", path, operation_index, index)
        first = data.find(old)
        if first < 0:
            _patch_error("PATCH_NOT_FOUND", "Patch original text is missing", path, operation_index, index)
        if data.find(old, first + 1) >= 0:
            _patch_error("SELECTOR_AMBIGUOUS", "Patch original text is ambiguous", path, operation_index, index)
        if first != start:
            _patch_error("PATCH_RANGE_INVALID", "Patch locator does not identify its original", path, operation_index, index)
        try:
            new = patch["new"].encode("utf-8")
        except UnicodeEncodeError:
            _patch_error("UNSUPPORTED_ENCODING", "Patch new must be UTF-8", path, operation_index, index)
        located.append({"index": index, "start_byte": start, "end_byte": end, "new": new,
                        "status": "NoChange" if old == new else "Changed"})
    ordered = sorted(located, key=lambda item: item["start_byte"])
    for left, right in zip(ordered, ordered[1:]):
        if left["end_byte"] > right["start_byte"]:
            _patch_error("PATCH_OVERLAP", "Patch ranges overlap on the original", path, operation_index, right["index"])
    after_size = len(data) + sum(len(p["new"]) - (p["end_byte"] - p["start_byte"]) for p in located)
    if after_size > min(config.get("max_file_bytes", MAX_BYTES), MAX_BYTES):
        _patch_error("BUDGET_EXHAUSTED", "Compiled file exceeds the change limit", path, operation_index)
    # Walk the original ranges backwards; each byte is copied only once.
    chunks, cursor = [], len(data)
    for patch in reversed(ordered):
        chunks.extend((data[patch["end_byte"]:cursor], patch["new"]))
        cursor = patch["start_byte"]
    chunks.append(data[:cursor])
    after = b"".join(reversed(chunks))
    receipt = {"operation_index": operation_index, "path": path, "source_sha256": source_sha,
               "after_sha256": _hash(after), "before_bytes": len(data), "after_bytes": len(after),
               "status": "NoChange" if after == data else "Compiled",
               "patches": [{"patch_index": p["index"], "start_byte": p["start_byte"], "end_byte": p["end_byte"],
                            "before_bytes": p["end_byte"] - p["start_byte"], "after_bytes": len(p["new"]),
                            "status": p["status"]} for p in located]}
    compiled = None if after == data else {"type": "replace", "path": path, "old": source_text, "new": after.decode("utf-8")}
    return compiled, receipt, data, mode


def prepare_request(root: Path, request: dict, config: dict) -> dict:
    """Compile v3 data to an unchanged v2 request plus a text-free external receipt.

    The returned request is protected, review-only compiler material containing
    exact original text. In particular, re-previewing that bare v2 request loses
    archive proof preconditions: only the returned sealed ``plan`` may be used
    for apply/overlay. ``preview(original_v3)`` also returns that bound plan.
    Only ``compilation`` is suitable for bounded, redacted user-facing output.
    This function performs no writes and creates no journal.
    """
    root = _root(root)
    if not isinstance(request, dict) or request.get("version") != 3 or set(request) - {"version", "operations", "guards", "archive_proofs"}:
        raise ChangeRequestError("INVALID_REQUEST", "Expected a version 3 change request")
    raw = request.get("operations")
    if not isinstance(raw, list) or not 1 <= len(raw) <= 100 or any(not isinstance(op, dict) for op in raw):
        raise ChangeRequestError("INVALID_REQUEST", "Expected 1..100 operations")
    writers, total_patches = set(), 0
    for index, operation in enumerate(raw):
        if _kind(operation) in {"replace", "replace_many", "move"}:
            path = _relative(operation.get("path"), config)
            if path in writers:
                _patch_error("MULTIPLE_WRITES", "Multiple source writers are not allowed", path, index)
            writers.add(path)
        if _kind(operation) == "replace_many" and isinstance(operation.get("patches"), list):
            total_patches += len(operation["patches"])
    if total_patches > 1000:
        raise ChangeRequestError("BUDGET_EXHAUSTED", "Batch exceeds the patch count limit")
    compiled, receipts, baselines = [], [], {}
    budget = _ChangeBudget()
    for index, operation in enumerate(raw):
        if _kind(operation) == "replace_many":
            result, receipt, data, mode = _compile_many(root, operation, config, index)
            baselines[receipt["path"]] = (data, mode)
            receipts.append(receipt)
            if result is not None:
                budget.backup(data)
                budget.json(result)
                compiled.append(result)
        else:
            # Standard operation validation remains exactly the v2 contract.
            budget.json(operation)
            compiled.append(dict(operation))
            receipts.append({"operation_index": index, "path": operation.get("path"), "status": "Standard"})
    guards = request.get("guards", [])
    if not isinstance(guards, list):
        raise ChangeRequestError("INVALID_REQUEST", "Guards must be a list")
    guards = list(guards)
    proof_receipts, proof_bindings = _prepare_archive_proofs(root, config, request.get("archive_proofs", []), compiled, guards, budget, set(baselines))
    result = {"version": 2, "operations": compiled, "guards": guards}
    def bound_read(rel):
        data, mode = _read(root, rel, config)
        if rel in proof_bindings and _hash(data) != proof_bindings[rel]:
            raise ChangeRequestError("SOURCE_CHANGED", "Archive proof participant changed", path=rel)
        return data, mode
    plan = None
    if compiled:
        # This sealed plan, rather than re-previewing the bare compiled request,
        # is the authoritative result when archive proof bindings participate.
        plan = _build_v2(root, result, config, bound_read, lambda rel: _missing(root, rel))
        _check_operation_aliases(root, plan["operations"])
    else:
        sources = {_relative(g["path"], config): _read(root, g["path"], config) for g in guards}
        _guards(guards, sources, {}, config, budget)
    for path in proof_bindings:
        bound_read(path)
    for path, baseline in baselines.items():
        if _read(root, path, config) != baseline:
            raise ChangeRequestError("SOURCE_CHANGED", "Source changed while compiling", path=path)
    return {"request": result, "plan": plan, "compilation": {"version": 1, "input_version": 3, "output_version": 2,
            "status": "Compiled" if compiled else "NoChange", "operations": receipts, "archive_proofs": proof_receipts}}


def _prepare_archive_proofs(root, config, proofs, operations, guards, budget, precharged_sources):
    if not isinstance(proofs, list) or len(proofs) > 100:
        raise ChangeRequestError("INVALID_REQUEST", "Archive proofs must be a bounded list")
    if not proofs:
        return [], {}
    from .archive_coverage import compile_v2_guards
    receipts, all_bindings = [], {}
    for proof in proofs:
        checked = compile_v2_guards(root, config, proof)
        for binding in checked["source_bindings"]:
            path = _relative(binding["path"], config)
            writer = next((op for op in operations if _kind(op) == "replace" and op["path"] == path), None)
            if writer is None:
                raise ChangeRequestError("SOURCE_BINDING_MISSING", "Archive source must have a replacement writer", path=path)
            data, _ = _read(root, path, config)
            if _hash(data) != binding["expected_sha256"]:
                raise ChangeRequestError("SOURCE_CHANGED", "Archive proof source changed", path=path)
            text = data.decode("utf-8")
            if not isinstance(writer.get("old"), str) or not writer["old"] or not isinstance(writer.get("new"), str) or not _unique_match(text, writer["old"]):
                raise ChangeRequestError("SELECTOR_AMBIGUOUS", "Archive-bound replacement is not unique", path=path)
            after = text.replace(writer["old"], writer["new"], 1)
            if path not in precharged_sources:
                before_size = sum(len(chunk.encode("utf-8")) for chunk in json.JSONEncoder(ensure_ascii=False, sort_keys=True).iterencode(writer))
                replacement = {**writer, "old": text, "new": after}
                after_size = sum(len(chunk.encode("utf-8")) for chunk in json.JSONEncoder(ensure_ascii=False, sort_keys=True).iterencode(replacement))
                budget.charge(max(0, after_size - before_size))
                budget.backup(data)
                precharged_sources.add(path)
            writer.update(old=text, new=after)
        for binding in checked["source_bindings"] + checked["archive_bindings"]:
            path = _relative(binding["path"], config)
            if path in all_bindings and all_bindings[path] != binding["expected_sha256"]:
                raise ChangeRequestError("SOURCE_CHANGED", "Archive proofs disagree on a participant", path=path)
            all_bindings[path] = binding["expected_sha256"]
        for guard in checked["guards"]:
            if guard not in guards:
                budget.json(guard)
                budget.backup(guard["value"].encode("utf-8"))
                budget.charge(512)  # v2 guard evidence metadata, before base64.
                guards.append(guard)
        receipt = {"proof_sha256": checked["proof_sha256"], "source_bindings": checked["source_bindings"],
                   "archive_bindings": checked["archive_bindings"]}
        budget.json(receipt)
        receipts.append(receipt)
    return receipts, all_bindings
