"""Bounded, source-bound document reading; display is never patch source."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import time
from pathlib import Path

from markdown_it import MarkdownIt

from .adapters.markdown import github_slug
from .models import Context
from .project import fingerprint, project_root
from .reporting import redact_text, sensitive_key
from .selection import SelectionError, line_range, source_lines

MAX_OUTPUT_BYTES = 30720


def _json(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'


def _display(text):
    # Match escaped quotes as part of a value, before the generic URL/form
    # redactor. Redacting only a prefix would expose the remainder on a page.
    quoted = r'''"(?:\\[^\r\n]|[^"\\\r\n])*(?:"|(?=\r?$))|'(?:\\[^\r\n]|[^'\\\r\n])*(?:'|(?=\r?$))'''
    pattern = r'''(?im)((?:["']?(?:password|secret|api[_.-]?key|access[_.-]?token|credential|token)["']?)\s*[:=]\s*)(?P<value>''' + quoted + r'''|[^\s,\r\n}]+)'''

    def replace(match):
        value = match['value']
        # A page may end inside our own already-safe placeholder. Preserve it
        # across output passes so pagination offsets and byte counts stay exact.
        return match[1] + (value if '[REDACTED]'.startswith(value) else '[REDACTED]')

    text = re.sub(pattern, replace, text)
    return re.sub(r'(?i)(https?://)[^/@\s]+:[^/@\s]+@', r'\1[REDACTED]@', text)


def _redact(data):
    if isinstance(data, str):
        return _display(data)
    if isinstance(data, list):
        return [_redact(item) for item in data]
    if isinstance(data, dict):
        return {key: '[REDACTED]' if sensitive_key(str(key)) else _redact(value) for key, value in data.items()}
    return data


def _output_page(data):
    data = _redact(data)
    data['output_bytes'] = 0
    while True:
        size = len(_json(data).encode('utf-8'))
        if size == data['output_bytes']:
            return data
        data['output_bytes'] = size


def bounded_json(data, maxbytes=MAX_OUTPUT_BYTES):
    """Return newline-terminated valid JSON within a UTF-8 byte budget.

    Generic oversized data becomes an explicit Unknown envelope, never a sliced
    JSON string. Stateful reading builds its own resumable pages before calling.
    """
    if type(maxbytes) is not int or maxbytes < 128 or maxbytes > 1024 * 1024:
        raise ValueError('output budget must be 128..1048576 bytes')
    clean = _redact(data)
    encoded = _json(clean)
    if len(encoded.encode('utf-8')) <= maxbytes:
        return encoded
    summary = {'status': 'Unknown', 'output_truncated': True, 'original_output_bytes': len(encoded.encode('utf-8'))}
    if isinstance(clean, dict):
        for name in ('next_cursor', 'sha256', 'complete'):
            if name in clean:
                summary[name] = clean[name]
    result = _json(summary)
    if len(result.encode('utf-8')) > maxbytes:
        result = _json({'status': 'Unknown', 'output_truncated': True})
    return result


def _line_offsets(text):
    lines = source_lines(text)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line.encode('utf-8')))
    return lines, offsets


def _views(text, file, declarations):
    if not isinstance(declarations, list):
        raise ValueError('views must be a list')
    lines, offsets = _line_offsets(text)
    found = []
    names = set()
    for item in declarations:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str):
            raise ValueError('invalid view declaration')
        if item['path'] != file:
            continue
        name, kind = item.get('name'), item.get('kind')
        start, end = item.get('start_line'), item.get('end_line')
        if (not isinstance(name, str) or not name or name in names or kind not in ('current', 'historical')
                or type(start) is not int or type(end) is not int or start < 1 or end < start or end > len(lines)):
            raise ValueError('view requires unique name, kind and valid inclusive line range')
        names.add(name)
        found.append({**item, 'start_byte': offsets[start - 1], 'end_byte': offsets[end]})
    ordered = sorted(found, key=lambda item: item['start_byte'])
    if any(left['end_byte'] > right['start_byte'] for left, right in zip(ordered, ordered[1:])):
        raise ValueError('overlapping views are ambiguous')
    return found


def select_view(text, file, views):
    """Hide only explicitly historical lines, keeping line endings/positions.

    Unclassified text and current details blocks are always retained. Byte
    positions are original-only metadata; filtering preserves line numbers.
    """
    selected = _views(text, file, views)
    lines = source_lines(text)
    for item in selected:
        if item['kind'] == 'historical':
            for index in range(item['start_line'] - 1, item['end_line']):
                match = re.search(r'(\r\n|\r|\n)$', lines[index])
                lines[index] = match.group() if match else ''
    return ''.join(lines)


def _headings(text, check=None):
    if check is None:
        check = lambda: None
    check()
    _, offsets = _line_offsets(text)
    check()
    parser = MarkdownIt('commonmark')
    # Cooperative checks run inside tokenization too, rather than waiting for
    # an entire heading-heavy document to finish parsing.
    def block_budget(state, start, end, silent):
        check()
        return False
    def inline_budget(state, silent):
        check()
        return False
    parser.block.ruler.before('code', 'read_budget', block_budget)
    parser.inline.ruler.before('text', 'read_budget', inline_budget)
    tokens = parser.parse(text)
    check()
    headings = []
    counts, used = {}, set()
    for index, token in enumerate(tokens):
        check()
        if token.type != 'heading_open' or token.map is None:
            continue
        inline = tokens[index + 1]
        title = ''.join(child.content for child in (inline.children or []) if child.type in ('text', 'code_inline', 'image'))
        base = github_slug(title)
        number = counts.get(base, 0)
        anchor = base if number == 0 else base + '-' + str(number)
        while anchor in used:
            number += 1
            anchor = base + '-' + str(number)
        counts[base] = number + 1
        used.add(anchor)
        headings.append({'title': title, 'raw_title': inline.content, 'anchor': anchor, 'level': int(token.tag[1:]), 'line': token.map[0] + 1,
                         'start_byte': offsets[token.map[0]], 'end_byte': offsets[min(token.map[1], len(offsets) - 1)]})
    size = len(text.encode('utf-8'))
    pending = []
    for item in headings:
        check()
        while pending and pending[-1]['level'] >= item['level']:
            previous = pending.pop()
            previous['section_end_byte'] = item['start_byte']
            previous['section_bytes'] = item['start_byte'] - previous['start_byte']
        pending.append(item)
    for item in pending:
        item['section_end_byte'] = size
        item['section_bytes'] = size - item['start_byte']
    return headings


def _heading_display(item):
    raw_title = item['raw_title']
    safe_title = _display(raw_title)
    displayed = _redact({key: value for key, value in item.items() if key != 'raw_title'})
    if safe_title != raw_title:
        # Redact before Markdown consumes backslash escapes. Otherwise a JSON
        # value containing escaped quotes can become ambiguous plain title text.
        inline = MarkdownIt('commonmark').parseInline(safe_title)
        displayed['title'] = ''.join(child.content for token in inline for child in (token.children or []) if child.type in ('text', 'code_inline', 'image'))
    if safe_title != raw_title or _display(item['title']) != item['title']:
        # A slug derived from the original can retain a credential even after
        # the heading itself was redacted. Keep the real slug internal only.
        displayed['anchor'] = '[REDACTED]'
        displayed['anchor_sensitive'] = True
    return displayed


def _source(root, config, file):
    root = project_root(root)
    task = config.get('_task')
    if task is not None and file not in task.get('sources', []):
        raise SelectionError('BODY_NOT_AUTHORIZED')
    raw = Context(root, {}, config).read_bytes(file)
    return root, raw, raw.decode('utf-8')


def _cursor(binding, mode, position):
    return base64.urlsafe_b64encode(_json({'v': 1, 'b': binding, 'm': mode, 'n': position}).encode()).decode().rstrip('=')


def _resume(cursor, binding, mode):
    if cursor is None:
        return 0
    if not isinstance(cursor, str) or len(cursor) > 2048:
        raise ValueError('invalid read cursor')
    try:
        data = json.loads(base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('invalid read cursor') from exc
    if (not isinstance(data, dict) or set(data) != {'v', 'b', 'm', 'n'} or data['v'] != 1
            or data['b'] != binding or data['m'] != mode or type(data['n']) is not int or data['n'] < 0):
        raise SelectionError('CURSOR_BINDING_MISMATCH')
    return data['n']


def _section_binding(root, config, file, sha):
    return hashlib.sha256(_json({'root': str(root), 'path': file, 'sha256': sha, 'config': fingerprint(config)}).encode()).hexdigest()


def _section_id(binding, sha, start, end):
    # Fixed-size binary metadata avoids carrying titles and keeps each outline
    # entry small. A separate source hash distinguishes drift from permission.
    payload = struct.pack('!B32s32sQQ', 1, bytes.fromhex(binding), bytes.fromhex(sha), start, end)
    return base64.urlsafe_b64encode(payload).decode().rstrip('=')


def _read_section_id(value, binding, sha):
    if not isinstance(value, str) or len(value) > 1024:
        raise SelectionError('SECTION_BINDING_MISMATCH')
    try:
        data = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        version, actual_binding, original_sha, start, end = struct.unpack('!B32s32sQQ', data)
    except (ValueError, UnicodeError, struct.error) as exc:
        raise SelectionError('SECTION_BINDING_MISMATCH') from exc
    if original_sha.hex() != sha:
        raise SelectionError('SOURCE_CHANGED')
    if version != 1 or actual_binding.hex() != binding or not 0 <= start < end:
        raise SelectionError('SECTION_BINDING_MISMATCH')
    return start, end


def read_document(root, config, file, *, outline=False, heading=None, cursor=None, max_output_bytes=MAX_OUTPUT_BYTES, view=None, max_depth=None, heading_filter=None, lines=None, section_id=None):
    if type(max_output_bytes) is not int or not 1024 <= max_output_bytes <= MAX_OUTPUT_BYTES:
        raise ValueError('read output budget must be 1024..30720 bytes')
    if sum(value is not None for value in (heading, lines, section_id)) > 1 or outline and any(value is not None for value in (heading, lines, section_id)):
        raise SelectionError('SELECTOR_CONFLICT')
    if (max_depth is not None or heading_filter is not None) and not outline:
        raise SelectionError('SELECTOR_CONFLICT')
    if max_depth is not None and (type(max_depth) is not int or not 1 <= max_depth <= 6):
        raise SelectionError('SELECTOR_INVALID')
    if heading_filter is not None and not isinstance(heading_filter, str):
        raise SelectionError('SELECTOR_INVALID')
    deadline = time.monotonic() + config.get('max_seconds', 60)
    def check():
        if time.monotonic() >= deadline:
            raise SelectionError('BUDGET_EXHAUSTED')
    check()
    root, raw, text = _source(root, config, file)
    check()
    sha = hashlib.sha256(raw).hexdigest()
    declarations = config.get('_task', {}).get('views', [])
    views = _views(text, file, declarations)
    check()
    headings = _headings(text, check) if outline or heading is not None or section_id is not None else []
    start, end = 0, len(raw)
    if view is not None:
        matches = [item for item in views if item['name'] == view]
        if len(matches) != 1:
            raise ValueError('unknown or ambiguous view')
        start, end = matches[0]['start_byte'], matches[0]['end_byte']
    if heading is not None:
        if not isinstance(heading, str) or not heading:
            raise SelectionError('SELECTOR_INVALID')
        matches = [item for item in headings if (item['anchor'] == heading[1:] if heading.startswith('#') else item['title'] == heading)]
        if not matches:
            raise SelectionError('HEADING_NOT_FOUND')
        if len(matches) > 1:
            raise SelectionError('SELECTOR_AMBIGUOUS', 'heading is ambiguous')
        first, last = matches[0]['start_byte'], matches[0]['section_end_byte']
        if first < start or last > end:
            raise SelectionError('SELECTOR_OUTSIDE_VIEW')
        start, end = first, last
    if lines is not None:
        first, last = line_range(text, lines)
        if first < start or last > end:
            raise SelectionError('SELECTOR_OUTSIDE_VIEW')
        start, end = first, last
    section_binding = _section_binding(root, config, file, sha)
    if section_id is not None:
        first, last = _read_section_id(section_id, section_binding, sha)
        if first < start or last > end:
            raise SelectionError('SELECTOR_OUTSIDE_VIEW')
        if not any(item['start_byte'] == first and item['section_end_byte'] == last for item in headings):
            raise SelectionError('SECTION_BINDING_MISMATCH')
        start, end = first, last
    mode = 'outline' if outline else 'text'
    binding = hashlib.sha256(_json({'root': str(root), 'path': file, 'sha256': sha, 'config': fingerprint(config),
                                   'mode': mode, 'heading': heading, 'view': view, 'range': [start, end]}).encode()).hexdigest()
    if any(value is not None for value in (max_depth, heading_filter, lines, section_id)):
        binding = hashlib.sha256(_json({'legacy_binding': binding, 'max_depth': max_depth, 'heading_filter': heading_filter, 'lines': lines, 'section_id': section_id}).encode()).hexdigest()
    position = _resume(cursor, binding, mode)
    base = {'schema_version': 1, 'path': file, 'sha256': sha, 'source_bytes': len(raw), 'source_start_byte': start,
            'source_end_byte': end, 'mode': mode, 'display_only': True, 'read_bytes': len(raw),
            'views': [{k: v for k, v in item.items() if k in ('name', 'kind', 'start_line', 'end_line')} for item in views]}
    if outline:
        selected_headings = [item for item in headings if start <= item['start_byte'] < end]
        items = [{**_heading_display(item), 'section_id': _section_id(section_binding, sha, item['start_byte'], item['section_end_byte'])} for item in selected_headings if (max_depth is None or item['level'] <= max_depth) and (heading_filter is None or heading_filter in item['title'])]
        if position > len(items):
            raise ValueError('outline cursor is out of range')
        def page(stop):
            complete = stop == len(items)
            return _output_page({**base, 'headings': items[position:stop], 'heading_total': len(items), 'heading_source_total': len(selected_headings), 'excluded_heading_count': len(selected_headings) - len(items), 'sent_headings': stop - position,
                    'remaining_headings': len(items) - stop, 'next_cursor': None if complete else _cursor(binding, mode, stop),
                    'status': 'Passed' if complete else 'Unknown', 'complete': complete})
        low, high = position, len(items)
    else:
        selected_text = select_view(text, file, declarations) if view is None and heading is None and lines is None and section_id is None else raw[start:end].decode('utf-8')
        display = _display(selected_text).encode('utf-8')
        if position > len(display):
            raise ValueError('text cursor is out of range')
        try:
            display[:position].decode('utf-8')
        except UnicodeError as exc:
            raise ValueError('cursor is not at a UTF-8 boundary') from exc
        def page(stop):
            # Shrink to a whole Unicode codepoint; never split an encoded character.
            content = display[position:stop].decode('utf-8', errors='ignore')
            actual = position + len(content.encode('utf-8'))
            complete = actual == len(display)
            return _output_page({**base, 'content': content, 'display_offset': position, 'display_total_bytes': len(display),
                    'sent_display_bytes': actual - position, 'remaining_display_bytes': len(display) - actual,
                    'next_cursor': None if complete else _cursor(binding, mode, actual),
                    'status': 'Passed' if complete else 'Unknown', 'complete': complete})
        low, high = position, min(len(display), position + max_output_bytes)
    # Fit the entire JSON envelope, including cursor and escaping overhead.
    best = page(position)
    while low <= high:
        check()
        middle = (low + high) // 2
        candidate = page(middle)
        if len(_json(candidate).encode('utf-8')) <= max_output_bytes:
            best, low = candidate, middle + 1
        else:
            high = middle - 1
    if len(_json(best).encode('utf-8')) > max_output_bytes or (not best['complete'] and (not best.get('headings') if outline else best['sent_display_bytes'] == 0)):
        raise SelectionError('BUDGET_EXHAUSTED')
    check()
    return _redact(best)


def locate_original(root, config, file, *, sha256, start_byte, end_byte):
    """Internal patch locator. The returned old is raw, NEVER display this dict."""
    _, raw, text = _source(root, config, file)
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise SelectionError('SOURCE_CHANGED')
    if type(start_byte) is not int or type(end_byte) is not int or not 0 <= start_byte < end_byte <= len(raw):
        raise ValueError('invalid original byte range')
    old = raw[start_byte:end_byte].decode('utf-8')
    raw[:start_byte].decode('utf-8')  # Both boundaries must be whole characters.
    first = text.find(old)
    if first < 0 or text.find(old, first + 1) >= 0:
        raise ValueError('original fragment is ambiguous')
    return {'path': file, 'sha256': sha256, 'old': old, 'start_byte': start_byte, 'end_byte': end_byte}
