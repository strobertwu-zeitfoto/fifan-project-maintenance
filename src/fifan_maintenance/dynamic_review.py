"""Conservative classification and deduplication of reference review hints.

Classification is not an absence-of-dependency proof. Only a Python f-string
with no interpolation is treated as a literal; ordinary literal scanning still
decides whether its contents refer to a candidate.
"""
from __future__ import annotations

import ast
import hashlib
import re


IO_CALLS = re.compile(r'\b(?:open|read_text|read_bytes|write_text|write_bytes|readFile|writeFile|ReadAllText|WriteAllText|load|save)\s*\(')
PATH_CALLS = re.compile(r'\b(?:Path|os\.path\.join|path\.join|Path\.Combine)\s*\(')
COMPACT_PATH = re.compile(r'(?:[\w.-]+/)+\{[^{}\r\n]*[,，][^{}\r\n]*\}')


def literal_positions(path, text):
    """Parse a file once; no global body cache or cross-operation proof reuse."""
    if not path.lower().endswith('.py') or len(text.encode('utf-8')) > 256 * 1024:
        return set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    result = set()
    for node in ast.walk(tree):
        if (not isinstance(node, ast.JoinedStr) or node.end_lineno != node.lineno
                or not all(isinstance(item, ast.Constant) and isinstance(item.value, str)
                           for item in node.values)):
            continue
        segment = ast.get_source_segment(text, node)
        # The lexical dependency scanner sees raw source, not Python's decoded
        # or concatenated value. Only one unescaped token is equivalent to it.
        token = re.fullmatch(r'''(?i:fr|rf|f)(["'])([^"'\\\r\n]*)\1''', segment or '')
        if token and token.group(2) == ''.join(item.value for item in node.values):
            result.add((node.lineno, node.col_offset))
    return result


def classify(path, text, line, column, *, literals=None, line_text=None):
    """Return a hint, never a semantic authorization to move/delete files."""
    if line_text is None:
        lines = text.splitlines()
        value = lines[line - 1] if 1 <= line <= len(lines) else ''
    else:
        value = line_text
    kind = 'file_access' if IO_CALLS.search(value) else 'path_construction' if PATH_CALLS.search(value) else 'dynamic_syntax'
    result = {'reference_layer': kind, 'dependency_status': 'Unknown',
              'candidate_relation': 'Not established', 'literal_only': False}
    # AST columns count UTF-8 bytes; scanner columns count characters.
    byte_column = len(value[:column - 1].encode('utf-8'))
    literals = literal_positions(path, text) if literals is None else literals
    if (line, byte_column) in literals:
        result.update(reference_layer='static_literal', dependency_status='Literal scan required', literal_only=True)
    return result


def unresolved_compact_paths(path, text, sha256):
    """Unsupported prose expansion is explicit, not an unnoticed missing edge."""
    for number, line in enumerate(text.splitlines(), 1):
        for match in COMPACT_PATH.finditer(line):
            yield {'path': path, 'sha256': sha256, 'line': number,
                   'column': match.start() + 1, 'reason_code': 'DYNAMIC_REFERENCE_UNKNOWN',
                   'line_sha256': hashlib.sha256(line.encode('utf-8')).hexdigest(),
                   'expression_sha256': hashlib.sha256(match.group(0).encode('utf-8')).hexdigest()}


def review_pack(report, texts=None):
    """Group exact observed origins across candidates without closing Unknowns."""
    if not isinstance(report, dict) or not isinstance(report.get('items', report.get('batches')), list):
        raise ValueError('review requires an observed items/batches report')
    groups, syntax, lines_by_path, observed_shas = {}, {}, {}, {}
    items = report.get('items', report.get('batches', []))
    for item in items:
        candidate = item.get('source')
        for hint in item.get('unknowns', []):
            if hint.get('reason_code') not in {'DYNAMIC_REFERENCE_UNKNOWN', 'COMPACT_REFERENCE_UNRESOLVED'}:
                continue
            fields = ('path', 'sha256', 'line', 'column', 'expression_sha256', 'reason_code')
            if any(hint.get(field) is None for field in fields):
                raise ValueError('review origin lacks its source binding')
            key = tuple(hint[field] for field in fields)
            group = groups.setdefault(key, {'origin': dict(hint), 'candidates': []})
            if texts is not None and hint['path'] in texts:
                text = texts[hint['path']]
                if hint['path'] not in observed_shas:
                    observed_shas[hint['path']] = hashlib.sha256(text.encode('utf-8')).hexdigest()
                if observed_shas[hint['path']] != hint['sha256']:
                    raise ValueError('review source changed')
                if hint['path'] not in syntax:
                    syntax[hint['path']] = literal_positions(hint['path'], text)
                    lines_by_path[hint['path']] = text.splitlines()
                lines = lines_by_path[hint['path']]
                line_text = lines[hint['line'] - 1] if 1 <= hint['line'] <= len(lines) else ''
                group['classification'] = classify(hint['path'], text, hint['line'], hint['column'],
                                                   literals=syntax[hint['path']], line_text=line_text)
            if candidate is not None and candidate not in group['candidates']:
                group['candidates'].append(candidate)
    return {'schema_version': 1, 'kind': 'reference-review-pack',
            'status': 'Unknown' if groups else 'NoHints',
            'origin_count': len(groups), 'groups': list(groups.values()),
            'scope': 'Observed hints only; source files not revalidated',
            'semantic_acceptance': 'Not run', 'authorizes_mutation': False}
