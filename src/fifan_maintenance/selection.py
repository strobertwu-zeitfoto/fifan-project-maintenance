"""Exact UTF-8 source selections shared by reading and archive coverage."""
from __future__ import annotations

import re
from markdown_it import MarkdownIt


class SelectionError(ValueError):
    def __init__(self, reason_code, message=None):
        super().__init__(message or reason_code)
        self.reason_code = reason_code


def source_lines(text):
    # CommonMark recognizes CR, LF and CRLF, not Unicode paragraph separators.
    return re.findall(r'[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$', text)


def line_range(text, value):
    if isinstance(value, str):
        match = re.fullmatch(r'([1-9]\d*):([1-9]\d*)', value)
        if not match:
            raise SelectionError('SELECTOR_INVALID')
        start, end = int(match[1]), int(match[2])
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        start, end = value
    else:
        raise SelectionError('SELECTOR_INVALID')
    lines = source_lines(text)
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
        raise SelectionError('SELECTOR_OUT_OF_RANGE')
    first = sum(len(line.encode('utf-8')) for line in lines[:start - 1])
    return first, first + sum(len(line.encode('utf-8')) for line in lines[start - 1:end])


def _unique(raw, value):
    first = raw.find(value)
    if first < 0:
        raise SelectionError('SELECTOR_MISSING')
    if raw.find(value, first + 1) >= 0:
        raise SelectionError('SELECTOR_AMBIGUOUS')
    return first, first + len(value)


def heading_range(text, value):
    from .reading import _headings
    if not isinstance(value, str) or not value:
        raise SelectionError('SELECTOR_INVALID')
    headings = _headings(text)
    found = [item for item in headings if (item['anchor'] == value[1:] if value.startswith('#') else item['title'] == value)]
    if not found:
        raise SelectionError('HEADING_NOT_FOUND')
    if len(found) > 1:
        raise SelectionError('SELECTOR_AMBIGUOUS', 'heading is ambiguous')
    return found[0]['start_byte'], found[0]['section_end_byte']


def select_bytes(raw, selector):
    """Return an exact [start,end) range. Never return or normalize source text."""
    if not isinstance(selector, dict) or not isinstance(selector.get('kind'), str):
        raise SelectionError('SELECTOR_INVALID')
    text = raw.decode('utf-8')
    kind = selector['kind']
    if kind == 'bytes':
        if set(selector) != {'kind', 'start_byte', 'end_byte'}:
            raise SelectionError('SELECTOR_INVALID')
        start, end = selector['start_byte'], selector['end_byte']
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(raw):
            raise SelectionError('SELECTOR_OUT_OF_RANGE')
    elif kind in ('heading', 'snippet'):
        if set(selector) != {'kind', 'value'} or not isinstance(selector['value'], str) or not selector['value']:
            raise SelectionError('SELECTOR_INVALID')
        if kind == 'heading':
            start, end = heading_range(text, selector['value'])
        else:
            start, end = _unique(raw, selector['value'].encode('utf-8'))
    elif kind == 'table':
        if set(selector) - {'kind', 'index', 'heading', 'value'} or ('value' in selector and 'index' in selector):
            raise SelectionError('SELECTOR_INVALID')
        if 'value' in selector and (not isinstance(selector['value'], str) or not selector['value']):
            raise SelectionError('SELECTOR_INVALID')
        lower, upper = heading_range(text, selector['heading']) if 'heading' in selector else (0, len(raw))
        lines = source_lines(text)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line.encode('utf-8')))
        tables = []
        for token in MarkdownIt('commonmark').enable('table').parse(text):
            if token.type == 'table_open' and token.map:
                first, last = offsets[token.map[0]], offsets[token.map[1]]
                if lower <= first and last <= upper:
                    if 'value' not in selector or raw[first:last] == selector['value'].encode('utf-8'):
                        tables.append((first, last))
        if 'index' in selector:
            index = selector['index']
            if type(index) is not int or index < 1:
                raise SelectionError('SELECTOR_INVALID')
            if index > len(tables):
                raise SelectionError('SELECTOR_MISSING')
            start, end = tables[index - 1]
        elif len(tables) != 1:
            raise SelectionError('SELECTOR_MISSING' if not tables else 'SELECTOR_AMBIGUOUS')
        else:
            start, end = tables[0]
    else:
        raise SelectionError('SELECTOR_INVALID')
    try:
        raw[:start].decode('utf-8')
        raw[start:end].decode('utf-8')
    except UnicodeError as exc:
        raise SelectionError('SELECTOR_UTF8_BOUNDARY') from exc
    return start, end
