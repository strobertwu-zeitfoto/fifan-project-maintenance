"""Read-only bounded directory census and explicitly scoped archive impact.

No age/name/no-hit heuristic approves a directory. Impact examines only declared
reference bodies, never claims that all project/external consumers were checked.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import heapq
import json
import os
import posixpath
import re
import stat
import time
from urllib.parse import unquote, urlsplit

from . import directory_common as dc


def _within(path, parent):
    try:
        path, parent = dc.path_key(path), dc.path_key(parent)
    except dc.DirectoryError:
        return False  # Untrusted reference text is never an executable path.
    return _raw_within(path, parent)


def _raw_within(path, parent):
    return parent == '.' or path == parent or path.startswith(parent + '/')


def _minimal_roots(roots):
    # Sort declarations only; never materialize/sort filesystem directories.
    result = []
    for path in sorted(set(roots), key=lambda value: (value.count('/'), value)):
        dc.relative(path, allow_dot=True)
        parents = [parent for parent in result if _within(path, parent)]
        if any(not _raw_within(path, parent) for parent in parents):
            raise dc.DirectoryError('PATH_ALIAS', 'overlapping declarations use alternate spelling')
        if not parents:
            result.append(path)
    return result


def _role(profile, path):
    matches = [item for item in profile.data['classifications'] if _within(path, item['path'])]
    if any(item['role'] == 'keep' for item in matches):
        return 'keep'
    if any(item['role'] == 'active' for item in matches):
        return 'active'
    selected = max(matches, key=lambda item: len(dc.path_key(item['path']))) if matches else None
    # A folded key can strengthen a restriction, but cannot grant historical
    # eligibility to a separately named tree on a case-sensitive filesystem.
    if selected and not _raw_within(path, selected['path']):
        return 'unknown'
    return selected['role'] if selected else 'unknown'


def _identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


class _Walk:
    def __init__(self, profile, *, started=None):
        self.profile = profile
        self.started = time.monotonic() if started is None else started
        self.work_entries = self.observed_entries = self.excluded = self.gap_count = 0
        self.gaps = []
        self.complete = True
        self.directories = {}
        self.files = self.logical_bytes = self.unique_file_bytes = 0
        self.inodes, self.file_inodes = set(), set()
        self.roles = Counter()
        self.types = Counter()
        self.top_files = []
        self.root_summaries, self.unvisited_roots = [], []
        self.last_path = "."
        self.root_identities = set()

    def gap(self, path, reason):
        self.complete = False
        self.gap_count += 1
        if len(self.gaps) < 50:
            self.gaps.append({'path': path, 'reason_code': reason})

    def charge(self):
        if self.work_entries >= self.profile.budgets['max_entries'] or time.monotonic() - self.started >= self.profile.budgets['max_seconds']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED')
        self.work_entries += 1

    def walk(self, roots):
        roots = _minimal_roots(roots)
        for index, root in enumerate(roots):
            before = (self.files, len(self.directories), self.logical_bytes, self.gap_count)
            exhausted = False
            try:
                yield from self._visit(root, 0)
            except dc.DirectoryError as error:
                self.gap(self.last_path, error.reason_code)
                self.unvisited_roots = roots[index + 1:]
                exhausted = True
            self.root_summaries.append({'path': root, 'observed_files': self.files - before[0],
                'observed_directories': len(self.directories) - before[1], 'observed_bytes': self.logical_bytes - before[2],
                'complete': self.gap_count == before[3]})
            if exhausted:
                break

    def _visit(self, path, depth, known=None, charged=False):
        if not charged:
            self.charge()  # Directory/root visits and each processing iteration cost work.
        self.last_path = path
        self.observed_entries += 1
        if dc.protected(self.profile, path):
            self.excluded += 1
            self.gap(path, 'PROTECTED_PATH')
            return
        try:
            if depth == 0:
                dc.validate_path_spelling(self.profile.root, path)
            info = known if known is not None else dc.stat_entry(self.profile.root, path)
        except (OSError, dc.DirectoryError):
            self.gap(path, 'METADATA_UNAVAILABLE')
            return
        identity = (info.st_dev, info.st_ino)
        if depth == 0:
            if identity in self.root_identities:
                self.gap(path, 'DUPLICATE_SOURCE_IDENTITY')
                return
            self.root_identities.add(identity)
        self.inodes.add(identity)
        self.roles[_role(self.profile, path)] += 1
        if stat.S_ISREG(info.st_mode):
            self.files += 1
            self.logical_bytes += info.st_size
            key = (info.st_dev, info.st_ino)
            if key not in self.file_inodes:
                self.file_inodes.add(key)
                self.unique_file_bytes += info.st_size
            suffix = posixpath.splitext(path)[1].lower() or '(no extension)'
            if suffix not in self.types and len(self.types) >= 100:
                suffix = '(other types)'
            self.types[suffix] += 1
            item = (info.st_size, path)
            if len(self.top_files) < 20:
                heapq.heappush(self.top_files, item)
            elif item > self.top_files[0]:
                heapq.heapreplace(self.top_files, item)
            parent = posixpath.dirname(path) or '.'
            while True:
                if parent in self.directories:
                    self.directories[parent]['observed_bytes'] += info.st_size
                if parent == '.':
                    break
                parent = posixpath.dirname(parent) or '.'
            yield path, info
        elif stat.S_ISDIR(info.st_mode):
            self.directories[path] = {'path': path, 'observed_bytes': 0, 'depth': depth}
            if depth > self.profile.budgets['max_depth']:
                self.gap(path, 'DEPTH_LIMIT')
                return
            try:
                with dc.open_dir(self.profile.root, path) as fd:
                    before_directory = os.fstat(fd)
                    with os.scandir(fd) as iterator:
                        while True:
                            self.charge()  # Includes EOF attempts and empty directories.
                            try:
                                entry = next(iterator)
                            except StopIteration:
                                break
                            child = entry.name if path == '.' else path + '/' + entry.name
                            # stat_entry uses the same nofollow directory FD contract.
                            yield from self._visit(child, depth + 1, charged=True)
                    after_directory = os.fstat(fd)
                    if (before_directory.st_mtime_ns, before_directory.st_ctime_ns) != (after_directory.st_mtime_ns, after_directory.st_ctime_ns):
                        self.gap(path, 'SOURCE_CHANGED')
            except dc.DirectoryError as error:
                if error.reason_code == 'BUDGET_EXHAUSTED':
                    raise
                self.gap(path, error.reason_code)
            except OSError:
                self.gap(path, 'DIRECTORY_UNAVAILABLE')
        else:
            self.gap(path, 'SYMLINK_OR_SPECIAL')

    def coverage(self):
        return {'complete': self.complete, 'count_is_lower_bound': not self.complete, 'work_entries': self.work_entries,
                'observed_entries': self.observed_entries, 'excluded_entries': self.excluded, 'gap_count': self.gap_count,
                'gaps': self.gaps, 'gaps_truncated': self.gap_count > len(self.gaps), 'roots': self.root_summaries, 'unvisited_roots': self.unvisited_roots}


def census(profile, *, hash_candidates=None):
    dc.validate_profile_root(profile)
    selected = [] if hash_candidates is None else hash_candidates
    if not isinstance(selected, list) or len(selected) > dc.HARD_BUDGETS['max_hash_entries']:
        raise dc.DirectoryError('INVALID_INPUT')
    for path in selected:
        dc.relative(path)
    if sum(len(path.encode('utf-8', errors='surrogatepass')) for path in selected) > profile.budgets['max_artifact_bytes'] // 2:
        raise dc.DirectoryError('BUDGET_EXHAUSTED')
    selected = set(selected)
    walk = _Walk(profile)
    hash_budget = dc.HashBudget(profile)
    metadata = {}
    roots = _minimal_roots(profile.data['scan_roots'])
    for path, info in walk.walk(roots):
        if path in selected:
            metadata[path] = info
    if time.monotonic() - walk.started >= profile.budgets['max_seconds']:
        walk.gap('.', 'BUDGET_EXHAUSTED')
    groups = defaultdict(list)
    hash_gaps = []
    for path in sorted(selected):
        if not any(_within(path, root) for root in roots) or path not in metadata:
            hash_gaps.append({'path': path, 'reason_code': 'CANDIDATE_NOT_OBSERVED'})
        else:
            groups[metadata[path].st_size].append(path)
    hashes = defaultdict(list)
    for paths in groups.values():
        if len(paths) < 2:
            continue  # Different lengths cannot be exact byte duplicates.
        for path in paths:
            try:
                result = dc.stream_hash(profile, path, hash_budget)
                before = metadata[path]
                if any(result[key] != value for key, value in [('bytes', before.st_size), ('device', before.st_dev), ('inode', before.st_ino), ('mtime_ns', before.st_mtime_ns), ('ctime_ns', before.st_ctime_ns)]):
                    raise dc.DirectoryError('SOURCE_CHANGED')
                hashes[result['sha256']].append(path)
            except (OSError, dc.DirectoryError) as error:
                hash_gaps.append({'path': path, 'reason_code': getattr(error, 'reason_code', 'HASH_UNAVAILABLE')})
    complete = walk.complete and not hash_gaps
    top_dirs = heapq.nlargest(20, walk.directories.values(), key=lambda item: (item['observed_bytes'], item['path']))
    result = {'schema_version': 1, 'kind': 'directory-census', 'project_root': str(profile.root), 'profile_sha256': profile.sha256,
              'status': 'Passed' if complete else 'Unknown', 'coverage': walk.coverage(), 'hash_coverage': {'requested': hash_candidates is not None,
              'status': 'Not run' if hash_candidates is None else 'Unknown' if hash_gaps else 'Passed',
              'complete': hash_candidates is not None and not hash_gaps, 'scope': 'explicit regular-file candidates only', 'gaps': hash_gaps, **hash_budget.snapshot()},
              'file_count': walk.files, 'directory_count': len(walk.directories), 'logical_bytes': walk.logical_bytes,
              'observed_unique_inodes': len(walk.inodes), 'observed_unique_file_inodes': len(walk.file_inodes), 'unique_inode_logical_bytes': walk.unique_file_bytes,
              'physical_space_released_bytes': None, 'physical_space_status': 'Unknown', 'body_bytes_sent': 0,
              'top_files': [{'path': path, 'bytes': size} for size, path in sorted(walk.top_files, reverse=True)],
              'top_directories': [{**item, 'bytes_are_lower_bound': not walk.complete} for item in top_dirs],
              'types': dict(walk.types), 'roles': dict(walk.roles), 'scan_roots': roots,
              'overlapping_roots_removed': len(profile.data['scan_roots']) - len(roots),
              'duplicates': [{'sha256': sha, 'paths': paths, 'deletion_authorized': False} for sha, paths in sorted(hashes.items()) if len(paths) > 1],
              'elapsed_seconds': round(time.monotonic() - walk.started, 6), 'semantic_acceptance': 'Not run'}
    result['coverage']['complete'] = complete
    result['coverage']['metadata_complete'] = walk.complete
    result['coverage']['count_is_lower_bound'] = not walk.complete
    if len(dc.canonical(result)) > profile.budgets['max_artifact_bytes']:
        raise dc.DirectoryError('BUDGET_EXHAUSTED')
    dc.validate_profile_root(profile)
    return dc.seal(result)


def _ref_role(profile, path):
    matches = [item['role'] for item in profile.data['reference_sources'] if _within(path, item['path'])]
    return 'current' if 'current' in matches else 'historical' if matches else None


class _References:
    def __init__(self, profile, sources=()):
        self.profile = profile
        self.sources = sources
        self.analysis = {}
        self.analysis_bytes = 0
        self.walk = _Walk(profile)
        self.cache, self.failures = {}, {}
        self.bytes = self.files = self.returned_bytes = 0
        self.failed_read = False
        self.read_bytes_unknown = False
        self.links = {}
        self.cache_keys = {}

    def read(self, path):
        if time.monotonic() - self.walk.started >= self.profile.budgets['max_seconds']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED')
        dc.validate_profile_root(self.profile)
        dc.relative(path)
        if (_ref_role(self.profile, path) is None
                or not any(_raw_within(path, item['path']) for item in self.profile.data['reference_sources'])):
            raise dc.DirectoryError('BODY_NOT_AUTHORIZED')
        if dc.protected(self.profile, path):
            raise dc.DirectoryError('PROTECTED_PATH')
        dc.validate_path_spelling(self.profile.root, path)
        key = dc.path_key(path)
        if key in self.cache_keys and self.cache_keys[key] != path:
            raise dc.DirectoryError('PATH_ALIAS')
        if path in self.cache:
            return self.cache[path]
        if self.failed_read:
            raise dc.DirectoryError('BUDGET_EXHAUSTED')
        if dc.protected(self.profile, path):
            raise dc.DirectoryError('PROTECTED_PATH')
        limits = self.profile.budgets
        if self.files >= limits['max_reference_files'] or time.monotonic() - self.walk.started >= limits['max_seconds']:
            raise dc.DirectoryError('BUDGET_EXHAUSTED')
        self.walk.charge()
        info = dc.stat_entry(self.profile.root, path)
        if not stat.S_ISREG(info.st_mode):
            raise dc.DirectoryError('REFERENCE_NOT_REGULAR')
        remaining = limits['max_reference_bytes'] - self.bytes
        streaming = path in self.profile.data.get('streaming_references', [])
        limit = remaining if streaming else min(limits['max_reference_file_bytes'], remaining)
        if info.st_size > limit:
            raise dc.DirectoryError('BUDGET_EXHAUSTED')
        self.files += 1
        self.bytes += info.st_size  # Charge attempted bytes even if stable reading fails.
        raw = None
        if streaming:
            return self._read_stream(path, info, limit)
        try:
            raw = dc.read_file(self.profile.root, path, min(limit, info.st_size))
            self.returned_bytes += len(raw)
            dc.validate_profile_root(self.profile)
            self.walk.charge()
            after = dc.stat_entry(self.profile.root, path)
            if (_identity(info), info.st_size, info.st_nlink) != (_identity(after), after.st_size, after.st_nlink):
                raise dc.DirectoryError('SOURCE_CHANGED')
        except (OSError, ValueError):
            self.failed_read = True  # Bound a growth probe to one byte for the whole run.
            self.read_bytes_unknown |= raw is None
            raise
        # Keep original bytes only inside the bounded run; report never includes them.
        value = {'sha256': hashlib.sha256(raw).hexdigest(), 'raw': raw, 'bytes': len(raw), 'role': _ref_role(self.profile, path)}
        self.cache[path] = value
        self.cache_keys[key] = path
        self._analyze(path, raw.decode('utf-8') if self._valid_text(raw) else None,
                      invalid_reason='REFERENCE_BINARY_UNKNOWN' if b'\x00' in raw else 'REFERENCE_ENCODING_UNKNOWN')
        value.pop('raw')
        return value

    @staticmethod
    def _valid_text(raw):
        try:
            raw.decode('utf-8')
            return b'\x00' not in raw
        except UnicodeError:
            return False

    def _analyze(self, path, text, offset=0, invalid_reason='REFERENCE_ENCODING_UNKNOWN'):
        for source in self.sources:
            found, unknown = ([], [{'path': path, 'reason_code': invalid_reason}]) if text is None else _scan_text(self, path, source, text)
            key = (path, source)
            old_found, old_unknown = self.analysis.setdefault(key, ([], []))
            for item in found + unknown:
                if 'line' in item:
                    item['line'] += offset
            old_found.extend(found[:max(0, 200 - len(old_found))])
            old_unknown.extend(unknown)
            self.analysis_bytes += len(dc.canonical(found)) + len(dc.canonical(unknown))
            if self.analysis_bytes > self.profile.budgets['max_artifact_bytes']:
                raise dc.DirectoryError('BUDGET_EXHAUSTED')

    def _read_stream(self, path, info, limit):
        # Only explicitly authorized plain-text files use this path. Memory is
        # bounded independently of the complete-file reference byte allowance.
        value = {'sha256': None, 'bytes': 0, 'role': _ref_role(self.profile, path)}
        self.cache[path] = value
        for source in self.sources:
            self.analysis[(path, source)] = ([], [])
        size, pending, line_number = 0, b'', 0
        hasher = hashlib.sha256()
        try:
            with dc.parent_fd(self.profile.root, path) as (parent, name):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    before = os.fstat(fd)
                    if dc._stable(before) != dc._stable(info):
                        raise dc.DirectoryError('SOURCE_CHANGED')
                    while size < before.st_size:
                        if time.monotonic() - self.walk.started >= self.profile.budgets['max_seconds']:
                            raise dc.DirectoryError('BUDGET_EXHAUSTED')
                        block = os.read(fd, min(65536, before.st_size - size, limit - size))
                        if not block:
                            raise dc.DirectoryError('SOURCE_CHANGED')
                        size += len(block)
                        self.returned_bytes += len(block)
                        hasher.update(block)
                        pending += block
                        cut = pending.rfind(b'\n')
                        if cut >= 0:
                            complete, pending = pending[:cut + 1], pending[cut + 1:]
                            if any(len(line) > 1024 * 1024 for line in complete.split(b'\n')):
                                raise dc.DirectoryError('REFERENCE_LINE_TOO_LONG')
                            text = complete.decode('utf-8')
                            if '\x00' in text:
                                raise dc.DirectoryError('REFERENCE_BINARY_UNKNOWN')
                            self._analyze(path, text, line_number)
                            from .selection import source_lines
                            line_number += len(source_lines(text))
                        if len(pending) > 1024 * 1024:
                            raise dc.DirectoryError('REFERENCE_LINE_TOO_LONG')
                    if pending:
                        text = pending.decode('utf-8')
                        if '\x00' in text:
                            raise dc.DirectoryError('REFERENCE_BINARY_UNKNOWN')
                        self._analyze(path, text, line_number)
                    after = os.fstat(fd)
                    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if dc._stable(before) != dc._stable(after) or dc._stable(before) != dc._stable(named):
                        raise dc.DirectoryError('SOURCE_CHANGED')
                finally:
                    os.close(fd)
            dc.validate_profile_root(self.profile)
            value.update(sha256=hasher.hexdigest(), bytes=size)
            for source in self.sources:
                for item in sum(self.analysis.get((path, source), ([], [])), []):
                    if 'sha256' in item:
                        item['sha256'] = value['sha256']
            self.cache_keys[dc.path_key(path)] = path
            return value
        except (OSError, ValueError) as error:
            self.cache.pop(path, None)
            for source in self.sources:
                self.analysis.pop((path, source), None)
            if isinstance(error, UnicodeError):
                raise dc.DirectoryError('REFERENCE_ENCODING_UNKNOWN') from error
            raise

    def load_all(self):
        declarations = self.profile.data['reference_sources']
        for path, _ in self.walk.walk([item['path'] for item in declarations]):
            try:
                self.read(path)
            except (OSError, ValueError) as error:
                self.failures[path] = getattr(error, 'reason_code', 'REFERENCE_UNAVAILABLE')
        if not declarations:
            self.walk.gap('.', 'REFERENCE_SCOPE_EMPTY')

    def coverage(self):
        return {**self.walk.coverage(), 'complete': self.walk.complete and not self.failures,
                'reference_files_attempted': self.files, 'reference_bytes_charged': self.bytes,
                'reference_bytes_read': None if self.read_bytes_unknown else self.returned_bytes,
                'reference_bytes_read_lower_bound': self.returned_bytes,
                'read_bytes_status': 'Unknown' if self.read_bytes_unknown else 'Passed',
                'failed_files': [{'path': path, 'reason_code': reason} for path, reason in sorted(self.failures.items())],
                'scope': 'declared reference_sources only', 'global_no_dependencies': None, 'snapshot_atomic': False,
                'dynamic_external_limitations': 'Static references only; external consumers were not inspected.'}


# Match one expression origin, never greedily consume a later expression on the
# same physical line. Every legal f/fr/rf prefix (all letter cases and quote
# forms) remains unknown even without interpolation or across physical lines.
_DYNAMIC = re.compile(
    r'\$\{|\$\(|\$[A-Za-z_]\w*[/\\]|'
    r'\b(?:os\.path\.join|path\.join|Path\.Combine|string\.Format)\s*\(|'
    r"(?<!\w)(?:[fF][rR]?|[rR][fF])(?:\"\"\"|'''|[\"'])|"
    r"['\"][^'\"\r\n]*[/\\][^'\"\r\n]*['\"]\s*\+|"
    r'\bPath\((?=[^\r\n]*?\)\s*/)|\bPath\(\s*[A-Za-z_]|\b[A-Za-z_]\w*\s*/\s*[\'\"]'
)



def _reference_keys(profile, referring, token):
    """Comparison keys only; none of these values are passed to filesystem IO."""
    result = []
    for spelling in (token, token.rstrip(':.;')):
        try:
            url = urlsplit(spelling.replace('\\', '/'))
            if url.scheme not in ('', 'file') or url.netloc not in ('', 'localhost'):
                continue
            path = unquote(url.path)
            if path.startswith('/'):
                absolute = dc.path_key(posixpath.normpath(path).lstrip('/'))
                root = dc.path_key(str(profile.root).lstrip('/'))
                if _raw_within(absolute, root) and absolute != root:
                    result.append(absolute[len(root) + 1:])
            else:
                for candidate in (path, posixpath.join(posixpath.dirname(referring), path)):
                    try:
                        result.append(dc.path_key(posixpath.normpath(candidate)))
                    except dc.DirectoryError:
                        # A root-relative ../ spelling is invalid while the
                        # same token relative to its referring folder is valid.
                        continue
        except (ValueError, dc.DirectoryError):
            continue
    return result


def _references_to(reader, path, source):
    return reader.analysis.get((path, source), ([], [{'path': path, 'reason_code': 'REFERENCE_SCAN_INCOMPLETE'}]))


def _scan_text(reader, path, source, text, *, json_strings=True, dynamics=True):
    value = reader.cache[path]
    if path not in reader.links:
        # Shared parser does not execute plugins or render project content.
        from .adapters.markdown import parse
        reader.links[path] = parse(text) if path.lower().endswith(('.md', '.markdown', '.html', '.htm')) else None
    parsed = reader.links[path]
    if time.monotonic() - reader.walk.started >= reader.profile.budgets['max_seconds']:
        return [], [{'path': path, 'reason_code': 'BUDGET_EXHAUSTED'}]
    found, unknown = [], []
    seen = set()
    def record(line, kind):
        key = (line, kind)
        if key not in seen and len(found) < 200:
            seen.add(key)
            found.append({'path': path, 'line': line, 'kind': kind, 'sha256': value['sha256']})
    if parsed is not None:
        for link in parsed.links:
            try:
                url = urlsplit(link.target)
            except ValueError:
                if len(unknown) < 20:
                    unknown.append({'path': path, 'reason_code': 'REFERENCE_URL_UNKNOWN'})
                continue
            if url.scheme not in ('', 'file') or url.netloc not in ('', 'localhost'):
                continue
            decoded = unquote(url.path)
            if decoded.startswith(str(reader.profile.root) + '/'):
                target = decoded[len(str(reader.profile.root)) + 1:]
            elif decoded.startswith('/'):
                continue
            else:
                target = posixpath.normpath(posixpath.join(posixpath.dirname(path), decoded))
            if _within(target, source):
                record(link.line, 'local-link')
        if parsed.unsupported:
            unknown.append({'path': path, 'reason_code': 'REFERENCE_SYNTAX_UNKNOWN'})
    # Literal paths in scripts/config/code/plain text are consumers too. Exact
    # path component boundaries avoid treating run-10 as a reference to run-1.
    variants = [source, str(reader.profile.root / source), source.replace('/', '\\')]
    literal = re.compile(r'(?<![\w./\\-])(?:' + '|'.join(re.escape(part) for part in variants) + r')(?=$|[/\\\s\"\'`#?<>),;:\]])')
    from .selection import source_lines
    referring_inside = _within(posixpath.dirname(path) or '.', source)
    basename_key = dc._key(posixpath.basename(source))
    if json_strings and path.lower().endswith(('.json', '.jsonc')):
        # Decode strings before the cheap basename filter: ordinary json.dumps
        # escapes non-ASCII names, and JSON permits escaping ASCII letters too.
        try:
            from .jsonc_edit import Parser
            Parser(text).parse() if path.lower().endswith('.jsonc') else json.loads(text)
        except (ValueError, RecursionError):
            unknown.append({'path': path, 'reason_code': 'REFERENCE_SYNTAX_UNKNOWN'})
        for number, line in enumerate(source_lines(text), 1):
            for match in re.finditer(r'"(?:[^"\\\r\n]|\\.)*"', line):
                try:
                    token = json.loads(match.group())
                except ValueError:
                    continue  # The syntax gap above already keeps this unknown.
                decoded_expressions = Counter(m.group() for m in _DYNAMIC.finditer(token))
                raw_expressions = Counter(m.group() for m in _DYNAMIC.finditer(match.group()))
                if decoded_expressions - raw_expressions:
                    # Escaped expression offsets are not raw-source offsets;
                    # do not let existing resolution proofs close this gap.
                    unknown.append({'path': path, 'line': number,
                                    'reason_code': 'REFERENCE_SYNTAX_UNKNOWN'})
                # A JSON value may be a whole command, not just one pathname.
                # Reuse all static lexical rules on the decoded contents. The
                # synthetic offsets must never create closable dynamic proofs.
                if any(_within(key, source) for key in _reference_keys(reader.profile, path, token)):
                    # Keep the JSON string boundary for relative names with
                    # spaces; lexical tokenization alone would split the name.
                    record(number, 'json-string-path')
                nested_found, nested_unknown = _scan_text(
                    reader, path, source, token, json_strings=False, dynamics=False)
                for item in nested_found:
                    record(number, 'json-string-path')
                unknown.extend({**item, 'line': number} for item in nested_unknown)
            if time.monotonic() - reader.walk.started >= reader.profile.budgets['max_seconds']:
                unknown.append({'path': path, 'reason_code': 'BUDGET_EXHAUSTED'})
                return found, unknown
    for number, line in enumerate(source_lines(text), 1):
        decoded_line = unquote(line)
        # Every normalized path into a candidate must spell its final component,
        # unless resolution starts from within that candidate. This is only a
        # necessary-condition filter: matching lines still use the full parser.
        # Decode URI escapes before NFC/casefold; backslashes do not remove a
        # component's spelling. Dynamic expressions are scanned independently.
        if referring_inside or basename_key in dc._key(decoded_line):
            exact_literal = literal.search(decoded_line)
            if exact_literal:
                record(number, 'literal-path')
            else:
                quoted_tokens = [match[2] for match in re.finditer(r'''(["'])(.*?)\1''', line)]
                tokens = quoted_tokens + re.findall(r'''[^\s"'`<>()[\],;=]+''', line)
                for token in tokens:
                    if any(_within(key, source) for key in _reference_keys(reader.profile, path, token)):
                        record(number, 'relative-literal' if token.replace('\\', '/').startswith(('./', '../')) else 'literal-path')
            # CommonMark intentionally filters file: links. Their explicit local
            # paths remain fixed current consumers, without following the URI.
            for uri_path in re.findall(r'''file://(?:localhost)?(/[^\s"'`<>)]*)''', line):
                decoded = unquote(uri_path)
                prefix = str(reader.profile.root) + '/'
                if decoded.startswith(prefix) and _within(decoded[len(prefix):], source):
                    record(number, 'file-uri')
            # Resolve explicit ./ and ../ paths using the referring file's folder,
            # including quoted paths containing spaces. Never execute concatenation.
            quoted = [match[2] for match in re.finditer(r'''(["'])(.*?)\1''', line)]
            relative_tokens = re.findall(r'''(?<![\w/])\.{1,2}/[^\s"'`<>),;]+''', line)
            for token in quoted + relative_tokens:
                if token.startswith(('./', '../')):
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(path), unquote(token)))
                    if _within(target, source):
                        record(number, 'relative-literal')
        for match in (_DYNAMIC.finditer(line) if dynamics else ()):
            unknown.append({'path': path, 'line': number, 'sha256': value['sha256'],
                            'column': match.start() + 1,
                            'line_sha256': hashlib.sha256(line.rstrip('\r\n').encode('utf-8')).hexdigest(),
                            'expression_sha256': hashlib.sha256(match.group(0).encode('utf-8')).hexdigest(),
                            'reason_code': 'DYNAMIC_REFERENCE_UNKNOWN'})
        if time.monotonic() - reader.walk.started >= reader.profile.budgets['max_seconds']:
            unknown.append({'path': path, 'reason_code': 'BUDGET_EXHAUSTED'})
            break
    return found, unknown


def _request_batches(profile, request):
    if (not isinstance(request, dict) or set(request) != {'schema_version', 'batches'} or type(request['schema_version']) is not int
            or request['schema_version'] != 1 or not isinstance(request['batches'], list) or not 1 <= len(request['batches']) <= 100):
        raise dc.DirectoryError('INVALID_INPUT')
    if len(dc.canonical(request)) > profile.budgets['max_artifact_bytes']:
        raise dc.DirectoryError('BUDGET_EXHAUSTED', 'request exceeds artifact budget')
    for batch in request['batches']:
        if not isinstance(batch, dict) or set(batch) - {'source', 'destination', 'closure', 'historical_references', 'known_absent', 'dynamic_reference_resolutions'} or not {'source', 'destination', 'closure'} <= set(batch):
            raise dc.DirectoryError('INVALID_INPUT')
        dc.relative(batch['source'])
        dc.relative(batch['destination'])
        closure = batch['closure']
        if (not isinstance(closure, dict) or set(closure) != {'decision', 'reason', 'evidence'} or not isinstance(closure['decision'], str) or not isinstance(closure['reason'], str)
                or not isinstance(closure['evidence'], list) or len(closure['evidence']) > 100):
            raise dc.DirectoryError('INVALID_INPUT')
        for field in ('evidence',):
            for evidence in closure[field]:
                if not isinstance(evidence, dict) or set(evidence) != {'path', 'sha256'} or not _sha_string(evidence['sha256']):
                    raise dc.DirectoryError('INVALID_INPUT')
                dc.relative(evidence['path'])
        resolutions = batch.get('dynamic_reference_resolutions', [])
        if not isinstance(resolutions, list) or len(resolutions) > 100000:
            raise dc.DirectoryError('INVALID_INPUT')
        identities = set()
        for entry in resolutions:
            keys = {'source', 'path', 'sha256', 'line', 'column', 'line_sha256', 'expression_sha256', 'reason', 'evidence'}
            if (not isinstance(entry, dict) or set(entry) != keys or type(entry['line']) is not int or entry['line'] < 1
                    or type(entry['column']) is not int or entry['column'] < 1
                    or not isinstance(entry['reason'], str) or not entry['reason'].strip()
                    or any(not _sha_string(entry[key]) for key in ('sha256', 'line_sha256', 'expression_sha256'))
                    or not isinstance(entry['evidence'], list) or not 1 <= len(entry['evidence']) <= 100):
                raise dc.DirectoryError('INVALID_INPUT')
            if entry['source'] != batch['source']:
                raise dc.DirectoryError('DYNAMIC_RESOLUTION_MISMATCH', 'resolution candidate mismatch')
            dc.relative(entry['path'])
            identity = tuple(entry[k] for k in ('path', 'line', 'column', 'expression_sha256'))
            if identity in identities:
                raise dc.DirectoryError('INVALID_INPUT', 'duplicate dynamic resolution')
            identities.add(identity)
            for evidence in entry['evidence']:
                if not isinstance(evidence, dict) or set(evidence) != {'path', 'sha256'} or not _sha_string(evidence['sha256']):
                    raise dc.DirectoryError('INVALID_INPUT')
                dc.relative(evidence['path'])
        for field, keys in [('historical_references', {'path', 'sha256', 'reason'}), ('known_absent', {'path', 'reason'})]:
            entries = batch.get(field, [])
            if not isinstance(entries, list) or len(entries) > 1000:
                raise dc.DirectoryError('INVALID_INPUT')
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != keys or not isinstance(entry['reason'], str) or not entry['reason'].strip():
                    raise dc.DirectoryError('INVALID_INPUT')
                dc.relative(entry['path'])
                if field == 'historical_references' and not _sha_string(entry['sha256']):
                    raise dc.DirectoryError('INVALID_INPUT')
    # Source and archive destination are different namespaces; compare overlap
    # within each namespace, never equate their same relative spellings.
    for field in ('source', 'destination'):
        previous = []
        for batch in request['batches']:
            if any(_within(batch[field], path) or _within(path, batch[field]) for path in previous):
                raise dc.DirectoryError('PROFILE_CONFLICT', 'directory batch paths overlap')
            previous.append(batch[field])
    return request['batches']


def _sha_string(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[0-9a-f]{64}', value))


def impact(profile, request):
    dc.validate_profile_root(profile)
    batches = _request_batches(profile, request)
    reader = _References(profile, tuple(batch['source'] for batch in batches))
    reader.load_all()
    results = []
    artifact_bytes = 8192
    source_identities = {}
    for batch_index, batch in enumerate(batches):
        source = batch['source']
        blocked, unknowns, historical, current = [], [], [], []
        matches = [path for path in profile.data['archive']['candidates'] if dc.path_key(path) == dc.path_key(source)]
        if not matches:
            blocked.append({'reason_code': 'CANDIDATE_NOT_DECLARED'})
        elif source not in matches:
            blocked.append({'reason_code': 'PATH_ALIAS'})
        conflicts = [item for item in profile.data['classifications'] if item['role'] in ('keep', 'active') and (_within(source, item['path']) or _within(item['path'], source))]
        if conflicts or any(_within(path, source) or _within(source, path) for path in profile.data['critical_paths']):
            blocked.append({'reason_code': 'CURRENT_OR_CRITICAL_PATH'})
        current_sources = [item['path'] for item in profile.data['reference_sources'] if item['role'] == 'current'
                           and (_within(item['path'], source) or _within(source, item['path']))]
        if current_sources:
            # A current original must stay put even when it has no path tokens.
            # Per-file historical_references change how its references are
            # interpreted, not permission to move that current original itself.
            blocked.append({'reason_code': 'CURRENT_REFERENCE_SOURCE', 'paths': current_sources[:20], 'total': len(current_sources)})
        if any(_within(item['path'], source) and item['role'] in ('unknown', 'rebuildable') for item in profile.data['classifications']):
            unknowns.append({'reason_code': 'MIXED_CLASSIFICATION'})
        if _role(profile, source) != 'historical':
            unknowns.append({'reason_code': 'HISTORICAL_CLASSIFICATION_MISSING'})
        source_identity = None
        try:
            reader.walk.charge()
            if dc.protected(profile, source, archive=True):
                raise dc.DirectoryError('PROTECTED_PATH')
            dc.validate_path_spelling(profile.root, source)
            info = dc.stat_entry(profile.root, source)
            if not stat.S_ISDIR(info.st_mode):
                raise dc.DirectoryError('SOURCE_NOT_DIRECTORY')
            source_identity = _identity(info)
            inode = (info.st_dev, info.st_ino)
            if inode in source_identities:
                blocked.append({'reason_code': 'DUPLICATE_SOURCE_IDENTITY'})
                previous = results[source_identities[inode]]
                previous.update(eligible=False, status='Blocked')
                previous['blockers'].append({'reason_code': 'DUPLICATE_SOURCE_IDENTITY'})
            else:
                source_identities[inode] = len(results)
        except (OSError, dc.DirectoryError) as error:
            reason = getattr(error, 'reason_code', 'SOURCE_UNAVAILABLE')
            (unknowns if reason == 'BUDGET_EXHAUSTED' else blocked).append({'reason_code': reason})
        closure = batch['closure']
        if closure['decision'] != 'closed' or not closure['reason'].strip() or not closure['evidence']:
            blocked.append({'reason_code': 'CLOSURE_NOT_SUPPORTED'})
        evidence_fingerprints = []
        for evidence in closure['evidence']:
            try:
                observed = reader.read(evidence['path'])
                if observed['sha256'] != evidence['sha256']:
                    raise dc.DirectoryError('SOURCE_CHANGED')
                evidence_fingerprints.append({'path': evidence['path'], 'sha256': observed['sha256']})
            except (OSError, ValueError) as error:
                reason = getattr(error, 'reason_code', 'CLOSURE_EVIDENCE_UNAVAILABLE')
                (unknowns if reason == 'BUDGET_EXHAUSTED' else blocked).append({'path': evidence['path'], 'reason_code': reason})
        overrides = {}
        for entry in batch.get('historical_references', []):
            try:
                observed = reader.read(entry['path'])
                if observed['sha256'] != entry['sha256']:
                    raise dc.DirectoryError('SOURCE_CHANGED')
                overrides[dc.path_key(entry['path'])] = {'path': entry['path'], 'sha256': entry['sha256'], 'reason_sha256': hashlib.sha256(entry['reason'].encode()).hexdigest()}
            except (OSError, ValueError) as error:
                reason = getattr(error, 'reason_code', 'HISTORICAL_REFERENCE_UNAVAILABLE')
                (unknowns if reason == 'BUDGET_EXHAUSTED' else blocked).append({'path': entry['path'], 'reason_code': reason})
        resolutions = {}
        resolution_fields = ('path', 'sha256', 'line', 'column', 'line_sha256', 'expression_sha256')
        dynamic_index = {tuple(item[key] for key in resolution_fields)
                         for path in reader.cache for item in _references_to(reader, path, source)[1]
                         if item.get('reason_code') == 'DYNAMIC_REFERENCE_UNKNOWN'}
        for entry in batch.get('dynamic_reference_resolutions', []):
            try:
                # load_all already validated/charged these immutable snapshots.
                # Do not reopen the same evidence for every expression review.
                observed = reader.cache.get(entry['path']) or reader.read(entry['path'])
                if observed['sha256'] != entry['sha256']:
                    raise dc.DirectoryError('SOURCE_CHANGED')
                for evidence in entry['evidence']:
                    proof = reader.cache.get(evidence['path']) or reader.read(evidence['path'])
                    if proof['sha256'] != evidence['sha256']:
                        raise dc.DirectoryError('SOURCE_CHANGED')
                if tuple(entry[key] for key in resolution_fields) not in dynamic_index:
                    raise dc.DirectoryError('DYNAMIC_RESOLUTION_MISMATCH')
                resolutions[(entry['path'], entry['line'], entry['column'], entry['expression_sha256'])] = entry
            except (OSError, ValueError) as error:
                blocked.append({'path': entry['path'], 'reason_code': getattr(error, 'reason_code', 'DYNAMIC_RESOLUTION_UNAVAILABLE')})
        fingerprints = []
        for path, observed in sorted(reader.cache.items()):
            role = 'historical' if dc.path_key(path) in overrides else observed['role']
            fingerprints.append({'path': path, 'sha256': observed['sha256'], 'role': role})
            found, unresolved = _references_to(reader, path, source)
            unresolved = [item for item in unresolved if item.get('reason_code') != 'DYNAMIC_REFERENCE_UNKNOWN'
                          or (item['path'], item['line'], item['column'], item['expression_sha256']) not in resolutions]
            if role == 'current':
                current.extend(found)
                unknowns.extend(unresolved)
            else:
                historical.extend(found)
                # Explicit historical classification does not turn scripts into
                # current consumers; replay still requires restoring old paths.
                historical.extend({**item, 'kind': 'historical-unresolved'} for item in unresolved)
        if current:
            blocked.append({'reason_code': 'CURRENT_DEPENDENCIES'})
        known_absent = []
        for entry in batch.get('known_absent', []):
            path = source + '/' + entry['path']
            try:
                reader.walk.charge()
                if dc.protected(profile, path, archive=True):
                    raise dc.DirectoryError('PROTECTED_PATH')
                dc.stat_entry(profile.root, path)
                blocked.append({'path': path, 'reason_code': 'EXPECTED_ABSENT_PRESENT'})
                state = 'Present'
            except FileNotFoundError:
                state = 'Missing'
            except (OSError, dc.DirectoryError) as error:
                state = 'Unknown'
                unknowns.append({'path': path, 'reason_code': getattr(error, 'reason_code', 'ABSENCE_UNKNOWN')})
            known_absent.append({'path': path, 'declared_path': entry['path'], 'status': state, 'reason_sha256': hashlib.sha256(entry['reason'].encode()).hexdigest()})
        coverage = reader.coverage()
        missing_critical = [path for path in profile.data['critical_paths'] if not any(item['role'] == 'current' and _within(path, item['path']) and _raw_within(path, item['path']) for item in profile.data['reference_sources'])]
        if missing_critical:
            unknowns.append({'reason_code': 'CRITICAL_REFERENCE_SCOPE_MISSING', 'paths': missing_critical})
        if not coverage['complete']:
            unknowns.append({'reason_code': 'REFERENCE_COVERAGE_INCOMPLETE'})
        coverage['complete'] = coverage['complete'] and not unknowns
        status = 'Blocked' if blocked else 'Unknown' if unknowns else 'Passed'
        result = {'source': source, 'destination': batch['destination'], 'eligible': status == 'Passed', 'status': status,
                        'source_identity': source_identity, 'closure': {'decision': closure['decision'], 'reason_sha256': hashlib.sha256(closure['reason'].encode()).hexdigest(), 'evidence': evidence_fingerprints},
                        'current_dependencies': current, 'historical_dependencies': historical, 'unknowns': unknowns, 'blockers': blocked,
                        'reference_fingerprints': fingerprints, 'historical_overrides': list(overrides.values()), 'known_absent': known_absent,
                        'coverage': coverage, 'historical_replay_requires_restore': bool(historical)}
        # Account for the full result plus its stable proof material before
        # appending. Exhaustion never produces an eligible truncated batch.
        artifact_bytes += 2 * len(dc.canonical(result))
        if artifact_bytes > profile.budgets['max_artifact_bytes']:
            break
        results.append(result)
    unchecked = len(batches) - len(results)
    status = 'Blocked' if any(item['status'] == 'Blocked' for item in results) else 'Unknown' if any(item['status'] == 'Unknown' for item in results) else 'Passed'
    if unchecked and status != 'Blocked':
        status = 'Unknown'
    # This material is stable across scans; timing/counters are not proof identity.
    material = {'profile_sha256': profile.sha256, 'request_sha256': dc.digest(request),
                'batches': [{key: item[key] for key in ('source', 'destination', 'eligible', 'status', 'source_identity', 'closure', 'reference_fingerprints', 'historical_overrides', 'known_absent', 'current_dependencies', 'historical_dependencies', 'unknowns', 'blockers')} for item in results]}
    value = {'schema_version': 1, 'kind': 'directory-impact', 'project_root': str(profile.root), 'profile_sha256': profile.sha256,
                    'request_sha256': dc.digest(request), 'status': status, 'batches': results, 'unchecked_batches': unchecked,
                    'coverage': {**reader.coverage(), 'complete': not unchecked and reader.coverage()['complete'] and all(item['coverage']['complete'] for item in results)},
                    'material': material, 'material_sha256': dc.digest(material), 'eligibility_scope': 'closure/classification/declared references only; archive manifest and runtime safety checks remain required',
                    'reference_hits_are_samples': True, 'hit_sample_limit_per_file': 200, 'body_bytes_sent': 0, 'semantic_acceptance': 'Not run'}
    if len(dc.canonical(value)) + 100 > profile.budgets['max_artifact_bytes']:
        raise dc.DirectoryError('BUDGET_EXHAUSTED')
    dc.validate_profile_root(profile)
    return dc.seal(value)
