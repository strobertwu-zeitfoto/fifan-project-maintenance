"""Protection intent also applies to aliases on a case-insensitive Mac volume."""
import json

import pytest

from fifan_maintenance.cli import main
from fifan_maintenance import changes
from fifan_maintenance.project import load_config


def test_old_read_does_not_expose_environment_through_case_alias(tmp_path, capsys):
    (tmp_path / '.env').write_text('fixture_private_value=do-not-display')
    if not (tmp_path / '.ENV').exists():
        pytest.skip('This case requires a case-insensitive filesystem')
    result = main(['read', '--project', str(tmp_path), '--file', '.ENV'])
    captured = capsys.readouterr()
    assert result == 2
    assert 'do-not-display' not in captured.out + captured.err
    assert json.loads(captured.err)['status'] == 'Blocked'


@pytest.mark.parametrize('relative', ['.ENV', '.GIT/config'])
def test_old_changes_reject_protected_case_alias(tmp_path, relative):
    (tmp_path / '.env').write_text('before')
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git/config').write_text('before')
    if not (tmp_path / relative).exists():
        pytest.skip('This case requires a case-insensitive filesystem')
    request = {'operations': [{'type': 'replace', 'path': relative, 'old': 'before', 'new': 'after'}]}
    with pytest.raises(ValueError):
        changes.preview(tmp_path, request, load_config(tmp_path))
    assert (tmp_path / relative).read_text() == 'before'


def test_custom_unicode_protection_is_shared_without_changing_config(tmp_path):
    from copy import deepcopy
    import unicodedata
    from fifan_maintenance.inventory import excluded
    from fifan_maintenance.models import Context
    folder = tmp_path / 'Résumé'
    folder.mkdir()
    (folder / 'private.md').write_text('before')
    config = load_config(tmp_path)
    config['protected'].append('Résumé/**')
    original_config = deepcopy(config)
    alias = unicodedata.normalize('NFD', 'RÉSUMÉ/private.md')
    assert (tmp_path / alias).exists()
    assert excluded(alias, config)
    with pytest.raises(ValueError, match='protected'):
        Context(tmp_path, {}, config).read_bytes(alias)
    with pytest.raises(ValueError, match='protected'):
        changes.preview(tmp_path, {'operations': [{'type': 'replace', 'path': alias,
                                                  'old': 'before', 'new': 'after'}]}, config)
    assert (folder / 'private.md').read_text() == 'before'
    assert config == original_config


def test_exclude_aliases_still_only_restrict_reads_not_old_write_semantics(tmp_path):
    from fifan_maintenance.inventory import excluded
    (tmp_path / 'Ordinary.md').write_text('before')
    config = load_config(tmp_path)
    config['exclude'] = ['ordinary.md']
    assert excluded('Ordinary.md', config)
    plan = changes.preview(tmp_path, {'operations': [{'type': 'replace', 'path': 'Ordinary.md',
                                                     'old': 'before', 'new': 'after'}]}, config)
    assert plan['operations'][0]['path'] == 'Ordinary.md'
    assert (tmp_path / 'Ordinary.md').read_text() == 'before'
    assert config['exclude'] == ['ordinary.md']


@pytest.mark.parametrize('alias', ['.VENV/inside', '.VENV39/inside', '.VENV315/inside', '.FIFAN-MAINTENANCE.JSON', 'LIBRARY/private'])
def test_old_write_protection_compares_aliases_but_preserves_raw_path_validation(tmp_path, alias):
    with pytest.raises(ValueError, match='protected'):
        changes._relative(alias, load_config(tmp_path))
    for ordinary in ('Résumé/当前.md', 'Normal/File.md'):
        assert changes._relative(ordinary, load_config(tmp_path)) == ordinary


def test_ordinary_include_patterns_keep_existing_case_sensitive_matching():
    from fifan_maintenance.inventory import matches
    assert matches('README.md', ['README.md'])
    assert not matches('readme.md', ['README.md'])
