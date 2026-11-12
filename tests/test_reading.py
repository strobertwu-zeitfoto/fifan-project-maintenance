from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from fifan_maintenance.project import DEFAULT_CONFIG
from fifan_maintenance.reading import bounded_json, read_document, select_view, locate_original


@pytest.fixture
def config():
    return deepcopy(DEFAULT_CONFIG)


def test_large_unicode_crlf_reading_has_no_gap_duplicate_or_host_truncation(tmp_path, config):
    text = '# 文档\r\n' + '汉🐈' * 45000 + '\r\n结束\r\n'
    (tmp_path / 'large.md').write_bytes(text.encode())
    cursor, pages = None, []
    sent = 0
    while True:
        page = read_document(tmp_path, config, 'large.md', cursor=cursor)
        serialized = bounded_json(page)
        assert len(serialized.encode()) <= 30720
        assert not json.loads(serialized).get('output_truncated')
        assert page['display_offset'] == sent
        assert len(page['content'].encode()) == page['sent_display_bytes']
        sent += page['sent_display_bytes']
        pages.append(page['content'])
        cursor = page['next_cursor']
        if cursor is None:
            assert page['remaining_display_bytes'] == 0
            assert page['complete'] is True
            break
        assert page['complete'] is False and page['status'] == 'Unknown'
    assert len(pages) > 10
    assert ''.join(pages) == text
    assert page['source_bytes'] == len(text.encode())


def test_cursor_rejects_source_config_path_drift_and_malformed_tokens(tmp_path, config):
    raw = ('# A\n' + '内容' * 3000).encode()
    (tmp_path / 'a.md').write_bytes(raw)
    (tmp_path / 'b.md').write_bytes(raw)
    cursor = read_document(tmp_path, config, 'a.md', max_output_bytes=1024)['next_cursor']
    assert cursor
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'b.md', cursor=cursor)
    altered = {**config, 'max_findings': 10}
    with pytest.raises(ValueError):
        read_document(tmp_path, altered, 'a.md', cursor=cursor)
    (tmp_path / 'a.md').write_bytes(raw + b'!')
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'a.md', cursor=cursor)
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'b.md', cursor='%%%')


def test_heading_outline_paginates_and_duplicate_titles_need_anchor(tmp_path, config):
    text = '\n'.join('## Same\n段落' for _ in range(40)) + '\n```\n# Fake\n```\n'
    (tmp_path / 'a.md').write_text(text)
    headings, cursor = [], None
    while True:
        page = read_document(tmp_path, config, 'a.md', outline=True, cursor=cursor, max_output_bytes=1200)
        assert len(bounded_json(page, 1200).encode()) <= 1200
        headings.extend(page['headings'])
        cursor = page['next_cursor']
        if not cursor:
            break
    assert len(headings) == 40
    assert [h['anchor'] for h in headings[:2]] == ['same', 'same-1']
    with pytest.raises(ValueError, match='ambiguous'):
        read_document(tmp_path, config, 'a.md', heading='Same')
    page = read_document(tmp_path, config, 'a.md', heading='#same-1')
    assert page['content'] == '## Same\n段落\n'
    assert page['source_start_byte'] == headings[1]['start_byte']


def test_explicit_views_preserve_current_details_and_hide_only_declared_history(tmp_path, config):
    text = '# Current\r\n<details>\r\ncurrent detail\r\n</details>\r\n# History\r\nhistorical secret\r\nUnclassified\r\n'
    views = [{'name': 'past', 'path': 'a.md', 'kind': 'historical', 'start_line': 5, 'end_line': 6},
             {'name': 'now', 'path': 'a.md', 'kind': 'current', 'start_line': 1, 'end_line': 4}]
    selected = select_view(text, 'a.md', views)
    assert selected == '# Current\r\n<details>\r\ncurrent detail\r\n</details>\r\n\r\n\r\nUnclassified\r\n'
    (tmp_path / 'a.md').write_bytes(text.encode())
    config['_task'] = {'sources': ['a.md'], 'views': views}
    assert 'historical secret' not in read_document(tmp_path, config, 'a.md')['content']
    assert read_document(tmp_path, config, 'a.md', view='past')['content'] == '# History\r\nhistorical secret\r\n'
    assert '<details>' in read_document(tmp_path, config, 'a.md', view='now')['content']
    with pytest.raises(ValueError):
        select_view(text, 'a.md', views + [{'name': 'overlap', 'path': 'a.md', 'kind': 'current', 'start_line': 2, 'end_line': 5}])
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'a.md', view='missing')


def test_scope_protection_symlinks_invalid_encoding_and_read_budget(tmp_path, config):
    (tmp_path / 'a.md').write_bytes(b'a')
    (tmp_path / 'bad.md').write_bytes(b'\xff')
    (tmp_path / 'link.md').symlink_to(tmp_path / 'a.md')
    config['_task'] = {'sources': ['a.md']}
    for path in ('../outside', 'bad.md', 'link.md', '/absolute'):
        with pytest.raises(ValueError):
            read_document(tmp_path, config, path)
    del config['_task']
    with pytest.raises(UnicodeError):
        read_document(tmp_path, config, 'bad.md')
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'link.md')
    config['protected'] = ['a.md']
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'a.md')
    config['protected'] = []
    config['max_total_bytes'] = 1
    (tmp_path / 'a.md').write_bytes(b'ab')
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'a.md')


def test_redaction_happens_before_chunking_and_raw_locator_is_source_bound(tmp_path, config):
    raw = ('# Header\npassword: ' + 'PRIVATE' * 1000 + '\npublic text\n').encode()
    (tmp_path / 'a.md').write_bytes(raw)
    page = read_document(tmp_path, config, 'a.md', max_output_bytes=1024)
    assert 'PRIVATE' not in page['content']
    assert '[REDACTED]' in page['content']
    assert page['complete']
    start = raw.index(b'password:')
    located = locate_original(tmp_path, config, 'a.md', sha256=page['sha256'], start_byte=start, end_byte=raw.index(b'\npublic'))
    assert 'PRIVATE' in located['old']
    assert located['old'] != page['content']
    with pytest.raises(ValueError):
        locate_original(tmp_path, config, 'a.md', sha256='0' * 64, start_byte=start, end_byte=len(raw))
    (tmp_path / 'a.md').write_bytes(b'same same')
    with pytest.raises(ValueError, match='ambiguous'):
        locate_original(tmp_path, config, 'a.md', sha256=hashlib.sha256(b'same same').hexdigest(), start_byte=0, end_byte=4)


def test_bounded_json_is_whole_utf8_json_and_marks_generic_truncation():
    result = bounded_json({'content': '汉🐈' * 10000}, 200)
    assert len(result.encode()) <= 200
    assert json.loads(result)['status'] == 'Unknown'
    assert json.loads(result)['output_truncated'] is True
    assert 'abc' not in bounded_json({'password': 'abc'}, 200)
    with pytest.raises(ValueError):
        bounded_json({}, 10)


def test_original_locator_rejects_overlapping_matches_and_split_unicode(tmp_path, config):
    (tmp_path / 'a.md').write_bytes(b'aaa')
    with pytest.raises(ValueError, match='ambiguous'):
        locate_original(tmp_path, config, 'a.md', sha256=hashlib.sha256(b'aaa').hexdigest(), start_byte=0, end_byte=2)
    raw = '汉字'.encode()
    (tmp_path / 'a.md').write_bytes(raw)
    with pytest.raises(UnicodeError):
        locate_original(tmp_path, config, 'a.md', sha256=hashlib.sha256(raw).hexdigest(), start_byte=1, end_byte=3)


def test_reported_output_bytes_include_complete_json_envelope_and_newline(tmp_path, config):
    (tmp_path / 'a.md').write_bytes(('# 标题\r\n' + '汉🐈' * 1000).encode())
    for outline in (False, True):
        page = read_document(tmp_path, config, 'a.md', outline=outline, max_output_bytes=1200)
        assert page['output_bytes'] == len(bounded_json(page, 1200).encode())
        assert page['output_bytes'] <= 1200


def test_quoted_credentials_do_not_leak_after_redaction(tmp_path, config):
    (tmp_path / 'a.md').write_text('password="top private value"\napi_key: "some spaced value"\n')
    page = read_document(tmp_path, config, 'a.md')
    assert page['content'] == 'password=[REDACTED]\napi_key: [REDACTED]\n'
    assert 'private' not in bounded_json(page)


def test_sensitive_heading_slug_never_exposes_secret_in_outline(tmp_path, config):
    (tmp_path / 'a.md').write_text('# password=PRIVATEHEADING\ntext\n')
    page = read_document(tmp_path, config, 'a.md', outline=True)
    serialized = bounded_json(page)
    assert 'PRIVATEHEADING' not in serialized
    assert 'privateheading' not in serialized
    assert page['headings'][0]['anchor_sensitive'] is True


def test_escaped_quotes_and_unicode_pagination_do_not_leak_secret_suffix(tmp_path, config):
    import json
    prefix, suffix = '前汉🐈' * 200, '后汉🐈' * 200
    secret = 'PRIVATE "quoted" \\backslash 后半SECRET'
    text = prefix + '\n' + json.dumps({'password': secret}, ensure_ascii=False) + '\n' + suffix
    (tmp_path / 'a.md').write_text(text)
    pages, cursor = [], None
    while True:
        page = read_document(tmp_path, config, 'a.md', cursor=cursor, max_output_bytes=1200)
        assert page['output_bytes'] == len(bounded_json(page, 1200).encode())
        pages.append(page['content'])
        cursor = page['next_cursor']
        if cursor is None:
            break
    assert len(pages) > 2
    display = ''.join(pages)
    assert prefix in display and suffix in display
    assert 'PRIVATE' not in display and 'SECRET' not in display and 'quoted' not in display


def test_placeholder_crossing_any_page_boundary_stays_exact(tmp_path, config):
    text = 'x' * 330 + '\npassword="PRIVATE"\n' + '后汉🐈' * 100
    (tmp_path / 'a.md').write_text(text)
    expected = text.replace('"PRIVATE"', '[REDACTED]')
    for limit in range(1024, 1070, 3):
        pages, cursor = [], None
        while True:
            page = read_document(tmp_path, config, 'a.md', cursor=cursor, max_output_bytes=limit)
            assert page['output_bytes'] == len(bounded_json(page, limit).encode())
            assert page['sent_display_bytes'] == len(page['content'].encode())
            pages.append(page['content'])
            cursor = page['next_cursor']
            if cursor is None:
                break
        assert ''.join(pages) == expected


def test_heading_escapes_are_redacted_before_markdown_unescapes_them(tmp_path, config):
    (tmp_path / 'a.md').write_text('# password="PRIVATE \\"quoted\\" 后半SECRET"\n')
    page = read_document(tmp_path, config, 'a.md', outline=True)
    output = bounded_json(page)
    assert 'PRIVATE' not in output and 'SECRET' not in output and 'quoted' not in output
    assert page['headings'][0]['anchor_sensitive']


def test_outline_literal_depth_section_id_and_line_ranges(tmp_path, config):
    text = '# Current\r\nbody\r\n## Needle [literal].*\r\n汉🐈\r\n### Deep\r\nmore\r\n# Other\r\nend\r\n'
    (tmp_path / 'a.md').write_bytes(text.encode())
    page = read_document(tmp_path, config, 'a.md', outline=True, max_depth=2, heading_filter='[literal].*')
    assert len(page['headings']) == 1
    assert page['heading_source_total'] == 4 and page['excluded_heading_count'] == 3
    section = page['headings'][0]
    assert read_document(tmp_path, config, 'a.md', section_id=section['section_id'])['content'] == '## Needle [literal].*\r\n汉🐈\r\n### Deep\r\nmore\r\n'
    assert read_document(tmp_path, config, 'a.md', lines='3:4')['content'] == '## Needle [literal].*\r\n汉🐈\r\n'
    assert read_document(tmp_path, config, 'a.md', lines=(3, 4))['content'] == read_document(tmp_path, config, 'a.md', lines='3:4')['content']
    assert page['output_bytes'] == len(bounded_json(page).encode())


def test_section_id_does_not_encode_secret_and_rejects_source_authorization_drift(tmp_path, config):
    import base64
    text = '# password=PRIVATESECTION\nbody\n'
    (tmp_path / 'a.md').write_text(text)
    page = read_document(tmp_path, config, 'a.md', outline=True)
    token = page['headings'][0]['section_id']
    decoded = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)).decode('utf-8', errors='replace')
    assert 'PRIVATESECTION' not in decoded and 'privatesection' not in decoded
    assert 'PRIVATESECTION' not in read_document(tmp_path, config, 'a.md', section_id=token)['content']
    narrowed = deepcopy(config)
    narrowed['_task'] = {'sources': ['a.md'], 'views': []}
    with pytest.raises(ValueError) as error:
        read_document(tmp_path, narrowed, 'a.md', section_id=token)
    assert error.value.reason_code == 'SECTION_BINDING_MISMATCH'
    (tmp_path / 'a.md').write_text(text + 'changed')
    with pytest.raises(ValueError):
        read_document(tmp_path, config, 'a.md', section_id=token)


def test_new_selectors_conflicts_bounds_view_and_cursor_filter_binding(tmp_path, config):
    text = '\n'.join('# Current ' + str(index) for index in range(20)) + '\n'
    (tmp_path / 'a.md').write_text(text)
    first = read_document(tmp_path, config, 'a.md', outline=True, max_depth=2, heading_filter='Current', max_output_bytes=1400)
    assert first['next_cursor']
    with pytest.raises(ValueError) as error:
        read_document(tmp_path, config, 'a.md', outline=True, max_depth=1, heading_filter='Current', cursor=first['next_cursor'])
    assert error.value.reason_code == 'CURSOR_BINDING_MISMATCH'
    for flags in ({'lines': '0:3'}, {'lines': '1:200'}, {'lines': '2:1'}, {'heading': 'Current 0', 'lines': '1:2'},
                  {'outline': True, 'lines': '1:2'}, {'max_depth': 1}, {'outline': True, 'max_depth': True}, {'section_id': 'bad'}):
        with pytest.raises(ValueError):
            read_document(tmp_path, config, 'a.md', **flags)
    config['_task'] = {'sources': ['a.md'], 'views': [{'path': 'a.md', 'name': 'short', 'kind': 'current', 'start_line': 1, 'end_line': 2}]}
    with pytest.raises(ValueError) as error:
        read_document(tmp_path, config, 'a.md', view='short', lines='1:3')
    assert error.value.reason_code == 'SELECTOR_OUTSIDE_VIEW'


def test_unicode_paragraph_separator_is_not_a_markdown_linebreak(tmp_path, config):
    text = 'text\u2028still same line\n# Heading\nbody\n'
    (tmp_path / 'a.md').write_text(text)
    page = read_document(tmp_path, config, 'a.md', outline=True)
    assert page['headings'][0]['line'] == 2
    assert page['headings'][0]['start_byte'] == len('text\u2028still same line\n'.encode())
    assert read_document(tmp_path, config, 'a.md', lines='2:3')['content'] == '# Heading\nbody\n'


def test_heading_stack_preserves_mixed_level_boundaries():
    from fifan_maintenance.reading import _headings
    text = '# A\r\n## B\r\n### C\r\n## D\r\n# E\r\n'
    headings = _headings(text)
    raw = text.encode()
    assert [raw[h['start_byte']:h['section_end_byte']].decode() for h in headings] == [
        '# A\r\n## B\r\n### C\r\n## D\r\n', '## B\r\n### C\r\n', '### C\r\n', '## D\r\n', '# E\r\n']
    large = _headings('# A\n' * 16000)
    assert len(large) == 16000
    assert all(h['section_bytes'] == 4 for h in large)


def test_local_read_avoids_markdown_parse_and_honors_deadline(tmp_path, config, monkeypatch):
    from fifan_maintenance import reading
    (tmp_path / 'a.md').write_text('# Heading\nbody\n' * 100)
    def no_parse(*args, **kwargs):
        raise AssertionError('local line read must not parse headings')
    monkeypatch.setattr(reading, '_headings', no_parse)
    assert read_document(tmp_path, config, 'a.md', lines='1:2')['content'] == '# Heading\nbody\n'
    ticks = iter([0, 0, 2])
    monkeypatch.setattr(reading.time, 'monotonic', lambda: next(ticks))
    config['max_seconds'] = 1
    with pytest.raises(ValueError, match='BUDGET_EXHAUSTED'):
        read_document(tmp_path, config, 'a.md', lines='1:2')


def test_outline_checks_deadline_during_parser_work(tmp_path, config, monkeypatch):
    from fifan_maintenance import reading
    (tmp_path / 'a.md').write_text('# H\n' * 1000)
    calls = [0]
    def clock():
        calls[0] += 1
        return 0 if calls[0] < 20 else 2
    monkeypatch.setattr(reading.time, 'monotonic', clock)
    config['max_seconds'] = 1
    with pytest.raises(ValueError, match='BUDGET_EXHAUSTED'):
        read_document(tmp_path, config, 'a.md', outline=True)
    assert calls[0] == 20
