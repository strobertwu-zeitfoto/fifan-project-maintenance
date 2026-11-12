"""Position-preserving JSONC object edits, without comment stripping/reformatting."""
from __future__ import annotations

import json
import re


class Node:
    def __init__(self, kind, start, end, value=None, properties=None):
        self.kind, self.start, self.end = kind, start, end
        self.value, self.properties = value, properties or []


class Parser:
    def __init__(self, text):
        self.text, self.pos = text, 1 if text.startswith('\ufeff') else 0

    def space(self):
        t = self.text
        while self.pos < len(t):
            if t[self.pos] in ' \t\r\n':
                self.pos += 1
            elif t.startswith('//', self.pos):
                end = t.find('\n', self.pos + 2)
                self.pos = len(t) if end < 0 else end + 1
            elif t.startswith('/*', self.pos):
                end = t.find('*/', self.pos + 2)
                if end < 0:
                    raise ValueError('CONFIG_CONFLICT: unterminated JSONC comment')
                self.pos = end + 2
            else:
                break

    def string(self):
        start = self.pos
        self.pos += 1
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == '\\':
                self.pos += 1
            elif char == '"':
                raw = self.text[start:self.pos]
                try:
                    return json.loads(raw), start
                except ValueError as exc:
                    raise ValueError('CONFIG_CONFLICT: invalid JSONC string') from exc
        raise ValueError('CONFIG_CONFLICT: unterminated JSONC string')

    def value(self, depth=0):
        if depth > 100:
            raise ValueError('CONFIG_CONFLICT: JSONC nesting limit')
        self.space()
        start = self.pos
        if start >= len(self.text):
            raise ValueError('CONFIG_CONFLICT: incomplete JSONC')
        char = self.text[start]
        if char == '"':
            value, _ = self.string()
            return Node('string', start, self.pos, value)
        if char in '{[':
            self.pos += 1
            end = '}' if char == '{' else ']'
            properties, values, seen = [], [], set()
            self.space()
            while self.pos < len(self.text) and self.text[self.pos] != end:
                key, key_start = None, self.pos
                if char == '{':
                    if self.text[self.pos] != '"':
                        raise ValueError('CONFIG_CONFLICT: JSONC object key required')
                    key, key_start = self.string()
                    if key in seen:
                        raise ValueError('CONFIG_CONFLICT: duplicate JSONC key')
                    seen.add(key)
                    self.space()
                    if self.pos >= len(self.text) or self.text[self.pos] != ':':
                        raise ValueError('CONFIG_CONFLICT: JSONC colon required')
                    self.pos += 1
                node = self.value(depth + 1)
                self.space()
                comma = None
                if self.pos < len(self.text) and self.text[self.pos] == ',':
                    comma = self.pos
                    self.pos += 1
                    self.space()
                elif self.pos >= len(self.text) or self.text[self.pos] != end:
                    raise ValueError('CONFIG_CONFLICT: JSONC comma required')
                if char == '{':
                    properties.append((key, key_start, node, comma))
                else:
                    values.append(node.value)
                if comma is None:
                    break
            if self.pos >= len(self.text) or self.text[self.pos] != end:
                raise ValueError('CONFIG_CONFLICT: JSONC closing delimiter required')
            self.pos += 1
            return Node('object' if char == '{' else 'array', start, self.pos,
                        {p[0]: p[2].value for p in properties} if char == '{' else values, properties)
        match = re.match(r'(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)', self.text[start:])
        if not match:
            raise ValueError('CONFIG_CONFLICT: invalid JSONC value')
        self.pos += len(match.group())
        value = json.loads(match.group())
        return Node('scalar', start, self.pos, value)

    def parse(self):
        node = self.value()
        self.space()
        if self.pos != len(self.text) or node.kind != 'object':
            raise ValueError('CONFIG_CONFLICT: JSONC root object required')
        return node


def merge_settings(data, targets):
    """Add true entries only; preserve every unrelated byte, including comments."""
    try:
        text = data.decode('utf-8')
    except UnicodeError as exc:
        raise ValueError('CONFIG_CONFLICT: UTF-8 settings required') from exc
    root = Parser(text).parse()
    newline = '\r\n' if '\r\n' in text else '\n'
    edits, root_additions = [], {}

    def additions(node, values):
        if not values:
            return
        if node.properties and node.properties[-1][3] is None:
            last = node.properties[-1][2]
            edits.append((last.end, last.end, ','))
        close = node.end - 1
        line_start = text.rfind('\n', 0, node.start) + 1
        parent_indent = text[line_start:node.start]
        if parent_indent.strip():
            parent_indent = '  '
        indent = parent_indent + '  '
        content = (',' + newline + indent).join(json.dumps(k, ensure_ascii=False) + ': ' + json.dumps(v, ensure_ascii=False) for k, v in values.items())
        edits.append((close, close, newline + indent + content + newline + parent_indent))

    root_properties = {p[0]: p[2] for p in root.properties}
    for name, desired in targets.items():
        if name not in root_properties:
            root_additions[name] = desired
            continue
        node = root_properties[name]
        if node.kind != 'object':
            raise ValueError('CONFIG_CONFLICT: search setting must be an object')
        existing, missing = node.value, {}
        for key, value in desired.items():
            if key in existing:
                if existing[key] is not True:
                    raise ValueError('CONFIG_CONFLICT: existing search entry disagrees')
            else:
                missing[key] = value
        additions(node, missing)
    additions(root, root_additions)
    # Insertions at one offset are composed in their original order: the
    # comma precedes new properties even when a compact object's value ends
    # immediately at its closing brace. Apply later insertions first.
    for start, end, replacement in sorted(reversed(edits), key=lambda e: (e[0], e[1]), reverse=True):
        text = text[:start] + replacement + text[end:]
    # The editor itself must not emit malformed JSONC.
    Parser(text).parse()
    return text.encode('utf-8')
