from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from fifan_maintenance.models import FileRecord
from fifan_maintenance.adapters.markdown import parse
from fifan_maintenance.adapters import unity
from fifan_maintenance.checks import documents, links


class FixtureContext:
    def __init__(self, root):
        self.root = root
        self.config = {"documents": {"duplicate_min_chars": 20}}
        self.inventory = True
        self.files = {}
        self.reads = []
        self.observations = {}

    def resolve(self, rel):
        path = (self.root / rel).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError("outside scope")
        return path

    def exists(self, rel):
        return self.resolve(rel).exists()

    def is_file(self, rel):
        return self.resolve(rel).is_file()

    def is_dir(self, rel):
        return self.resolve(rel).is_dir()

    def read_bytes(self, rel):
        path = self.resolve(rel)
        self.reads.append(rel)
        return path.read_bytes()

    def read_text(self, rel):
        return self.read_bytes(rel).decode("utf-8")

    def put(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.files[name] = FileRecord(name, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)


class DocumentsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ctx = FixtureContext(Path(self.temp.name).resolve())

    def test_all_supported_links_and_code_exclusion(self):
        self.ctx.put("中文 空格%.md", "# 中文 标题\r\n# 中文 标题\r\n")
        self.ctx.put("图.png", "image")
        self.ctx.put("index.md", '[正文](中文%20空格%25.md#中文-标题-1)\n\n[引用][r]\n\n[r]: <中文 空格%.md>\n\n![图](图.png)\n\n<a href="中文%20空格%25.md#中文-标题">跳转</a>\n\n```md\n[伪链接](missing.md)\n```\n\n`[内联伪链接](missing.md)`\n')
        self.assertEqual([], links.run(self.ctx))
        parsed = parse(self.ctx.read_text("index.md"))
        self.assertEqual(5, len(parsed.links))
        self.assertEqual(1, sum(link.kind == "definition" for link in parsed.links))
        self.assertEqual(sorted(hashlib.sha256(a.encode()).hexdigest() for a in ["中文-标题", "中文-标题-1"]), self.ctx.observations["anchors"]["中文 空格%.md"])

    def test_missing_target_and_anchor_are_distinct(self):
        self.ctx.put("a.md", "[a](b.md#missing)\n\n![x](absent.png)")
        self.ctx.put("b.md", "# Found")
        codes = {f.code for f in links.run(self.ctx)}
        self.assertEqual({"missing-target", "missing-anchor"}, codes)

    def test_source_unchanged_target_changes(self):
        self.ctx.put("a.md", "[b](b.md#old)")
        self.ctx.put("b.md", "# old")
        self.assertEqual([], links.run(self.ctx))
        self.ctx.put("b.md", "# new")
        self.assertIn("missing-anchor", [f.code for f in links.run(self.ctx)])
        (self.ctx.root / "b.md").unlink()
        self.assertIn("missing-target", [f.code for f in links.run(self.ctx)])

    def test_out_of_scope_targets_never_read(self):
        self.ctx.put("a.md", "[bad](../outside.md#secret)\n\n[x](/etc/passwd)\n\n[odd](unknown:thing)\n\n[web](https://example.com)")
        found = links.run(self.ctx)
        self.assertEqual(["a.md"], self.ctx.reads)
        self.assertTrue(all(f.status in {"Unknown", "Not run"} for f in found))
        with tempfile.TemporaryDirectory() as other:
            secret = Path(other) / "secret.md"
            secret.write_text("# hidden")
            (self.ctx.root / "escape.md").symlink_to(secret)
            self.ctx.put("a.md", "[bad](escape.md#hidden)")
            self.ctx.reads.clear()
            self.assertEqual("Unknown", links.run(self.ctx)[0].status)
            self.assertNotIn("escape.md", self.ctx.reads)

    def test_history_and_repetition_are_only_unknown(self):
        paragraph = "历史中独有的要求与重复合同必须保留，不自动删除。"
        self.ctx.put("history.md", f"完成: 2\n\n{paragraph}\n\n```\n完成: 999\n```\n")
        self.ctx.put("current.md", f"完成: 3\n\n{paragraph}\n")
        found = documents.run(self.ctx)
        self.assertTrue({"status-numbers", "repeated-fragment"} <= {f.code for f in found})
        self.assertTrue(all(f.status == "Unknown" for f in found))
        mentions = next(f.evidence["mentions"] for f in found if f.code == "status-numbers")
        self.assertEqual({2, 3}, {m["value"] for m in mentions})

    def test_nested_parentheses_and_duplicate_heading_collision(self):
        self.ctx.put("a(b).md", "# title\n# title\n# title-1\n# title\n")
        self.ctx.put("index.md", "[nested](a(b).md#title-1-1)\n\n[third](a(b).md#title-2)")
        self.assertEqual([], links.run(self.ctx))

    def test_permission_failure_is_unknown_not_missing(self):
        self.ctx.put("a.md", "[b](b.md#title)")
        self.ctx.put("b.md", "# title")
        original = self.ctx.read_bytes

        def restricted(path):
            if path == "b.md":
                raise PermissionError("denied")
            return original(path)

        self.ctx.read_bytes = restricted
        found = links.run(self.ctx)
        self.assertTrue(any(f.code == "target-unavailable" and f.status == "Unknown" for f in found))
        self.assertFalse(any(f.code == "missing-target" for f in found))

    def test_unknown_coverage(self):
        self.ctx.put("a.md", "[[wiki]]\n\n[unresolved][ref]\n\n<img srcset='a.png 1x'>")
        self.assertTrue(any(f.code == "coverage" and f.status == "Unknown" for f in links.run(self.ctx)))

    def test_unity_guid_and_build_paths(self):
        guid = "a" * 32
        self.ctx.put("Assets/a.prefab", "guid: " + "b" * 32)
        self.ctx.put("Assets/a.prefab.meta", "guid: " + guid)
        self.ctx.put("Assets/b.png", "pixels")
        self.ctx.put("Assets/b.png.meta", "guid: " + guid)
        self.ctx.put("Assets/c.png", "pixels")
        self.ctx.put("Assets/c.png.meta", "fileFormatVersion: 2")
        self.ctx.put("ProjectSettings/ProjectVersion.txt", "m_EditorVersion: 6000.0.0f1")
        self.ctx.put("ProjectSettings/EditorBuildSettings.asset", "  path: Assets/missing.unity")
        found = unity.run(self.ctx)
        self.assertTrue({"duplicate-guid", "missing-guid", "unresolved-guid", "missing-build-scene"} <= {f.code for f in found})
        self.ctx.inventory = False
        self.assertTrue(any(f.code == "assets-partial" and f.status == "Unknown" for f in unity.run(self.ctx)))
        self.assertTrue(all(f.status == "Unknown" for f in unity.run(self.ctx) if f.code == "unresolved-guid"))


    def test_task_scope_checks_reference_metadata_without_body_reads(self):
        self.ctx.put("source.md", "[target](target.md#标题)\n\n[missing](gone.md#x)")
        self.ctx.put("target.md", "# 标题")
        self.ctx.config['_task'] = {'sources': ['source.md'], 'reference_bodies': [], 'historical_roots': [], 'views': []}
        found = links.run(self.ctx)
        self.assertEqual(['source.md'], self.ctx.reads)
        denied = next(f for f in found if f.code == 'anchor-body-not-authorized')
        self.assertEqual('Unknown', denied.status)
        self.assertEqual('target.md', denied.evidence['normalized_target'])
        self.assertEqual('标题', denied.evidence['anchor'])
        self.assertTrue(any(f.code == 'missing-target' and f.status == 'Failed' for f in found))
        self.ctx.config['_task']['reference_bodies'] = ['target.md']
        self.ctx.reads.clear()
        found = links.run(self.ctx)
        self.assertEqual(['source.md', 'target.md'], self.ctx.reads)
        self.assertEqual(['missing-target'], [f.code for f in found])

    def test_link_identity_ignores_line_shift_and_percent_spelling(self):
        self.ctx.put('dir/source.md', '[x](../target%20space.md#中文)')
        self.ctx.put('target space.md', '# other')
        before = links.run(self.ctx)[0]
        self.ctx.put('dir/source.md', '\n\nnew introduction\n\n[x](<../target space.md#中文>)')
        after = links.run(self.ctx)[0]
        self.assertNotEqual(before.line, after.line)
        for key in ('normalized_target', 'anchor'):
            self.assertEqual(before.evidence[key], after.evidence[key])
        self.assertEqual('target space.md', after.evidence['normalized_target'])


    def test_validated_overlay_anchor_target_is_candidate_not_missing(self):
        import base64
        from fifan_maintenance.models import Context
        self.ctx.put('source.md', '[copy](archive/copy.md#保留)')
        records = dict(self.ctx.files)
        config = {'max_file_bytes': 10000, '_task': {'sources': ['source.md'], 'reference_bodies': ['archive/*.md']},
                  '_overlay': {'archive/copy.md': base64.b64encode('# 保留'.encode()).decode()}}
        ctx = Context(self.ctx.root, records, config)
        self.assertEqual([], links.run(ctx))
        self.assertFalse((self.ctx.root / 'archive/copy.md').exists())


    def test_historical_view_keeps_real_duplicate_heading_slugs(self):
        self.ctx.put('source.md', '# Intro\n[old](gone.md)\n# Intro\n[current](#intro-1)\n')
        self.ctx.config['_task'] = {'sources': ['source.md'], 'reference_bodies': [],
                                   'views': [{'name': 'history', 'path': 'source.md', 'kind': 'historical', 'start_line': 1, 'end_line': 2},
                                             {'name': 'current', 'path': 'source.md', 'kind': 'current', 'start_line': 3, 'end_line': 4}]}
        self.assertEqual([], links.run(self.ctx))
        self.assertEqual(sorted(hashlib.sha256(a.encode()).hexdigest() for a in ['intro', 'intro-1']), self.ctx.observations['anchors']['source.md'])
        self.ctx.put('source.md', '# Intro\n[old](gone.md)\n# Intro\n[current](#intro-2)\n')
        found = links.run(self.ctx)
        self.assertEqual(['missing-anchor'], [f.code for f in found])
        self.assertEqual('intro-2', found[0].evidence['anchor'])


    def test_anchor_observations_do_not_expose_secret_derived_slugs(self):
        self.ctx.put('source.md', '# password=HIDDENVALUE\n')
        self.assertEqual([], links.run(self.ctx))
        observed = self.ctx.observations['anchors']['source.md']
        self.assertEqual([hashlib.sha256(b'passwordhiddenvalue').hexdigest()], observed)
        self.assertNotIn('hiddenvalue', repr(self.ctx.observations).lower())


    def test_domain_coverage_keeps_local_evidence_separate_from_external(self):
        self.ctx.put('source.md', '[local](target.txt)\n\n[external](https://example.invalid)')
        self.ctx.put('target.txt', 'content')
        found = links.run(self.ctx)
        domains = self.ctx.observations['coverage_domains']
        self.assertEqual(('Passed', True, 1), tuple(domains['local_targets'][k] for k in ('status', 'complete', 'checked')))
        self.assertEqual(('Passed', True, 0), tuple(domains['local_anchors'][k] for k in ('status', 'complete', 'checked')))
        self.assertEqual(('Not run', False, 0, 1), tuple(domains['external'][k] for k in ('status', 'complete', 'checked', 'observed')))
        self.assertEqual(['external'], found[0].evidence['coverage_domains'])
        self.assertEqual('Not run', found[0].status)

    def test_domain_coverage_body_denial_only_invalidates_anchors(self):
        self.ctx.put('source.md', '[target](target.md#title)')
        self.ctx.put('target.md', '# title')
        self.ctx.config['_task'] = {'sources': ['source.md'], 'reference_bodies': []}
        found = links.run(self.ctx)
        domains = self.ctx.observations['coverage_domains']
        self.assertTrue(domains['local_targets']['complete'])
        self.assertEqual(1, domains['local_targets']['checked'])
        self.assertFalse(domains['local_anchors']['complete'])
        self.assertEqual('Unknown', domains['local_anchors']['status'])
        self.assertEqual(['local_anchors'], found[0].evidence['coverage_domains'])
        self.assertTrue(domains['external']['complete'])
        self.assertEqual(['source.md'], self.ctx.reads)

    def test_domain_coverage_unknown_syntax_cannot_be_ignored(self):
        self.ctx.put('source.md', '[[unparsed]]\n\n[ok](target.txt)')
        self.ctx.put('target.txt', 'content')
        links.run(self.ctx)
        domains = self.ctx.observations['coverage_domains']
        self.assertEqual(1, domains['local_targets']['checked'])
        self.assertTrue(all(not domain['complete'] and 'UNSUPPORTED_SYNTAX' in domain['unknown_reasons'] for domain in domains.values()))

    def test_domain_coverage_definite_failures_are_still_complete(self):
        self.ctx.put('source.md', '[missing](missing.txt)\n\n[bad anchor](target.md#missing)')
        self.ctx.put('target.md', '# present')
        links.run(self.ctx)
        domains = self.ctx.observations['coverage_domains']
        self.assertEqual(('Failed', True, 2), tuple(domains['local_targets'][k] for k in ('status', 'complete', 'checked')))
        self.assertEqual(('Failed', True, 1), tuple(domains['local_anchors'][k] for k in ('status', 'complete', 'checked')))
        self.assertTrue(domains['external']['complete'])

    def test_domain_coverage_missing_or_unreadable_source_is_unknown(self):
        self.ctx.put('source.md', '# title')
        self.ctx.config['_task'] = {'sources': ['source.md', 'missing.md'], 'reference_bodies': []}
        links.run(self.ctx)
        self.assertTrue(all(not item['complete'] and 'SOURCE_NOT_IN_INVENTORY' in item['unknown_reasons'] for item in self.ctx.observations['coverage_domains'].values()))
        self.ctx.config['_task']['sources'] = ['source.md']
        def denied(path):
            raise PermissionError('unavailable')
        self.ctx.read_bytes = denied
        links.run(self.ctx)
        self.assertTrue(all(not item['complete'] and 'SOURCE_UNAVAILABLE' in item['unknown_reasons'] for item in self.ctx.observations['coverage_domains'].values()))
        self.assertEqual({}, self.ctx.observations['anchors'])


    def test_domain_coverage_unknown_protocol_authority_is_not_external_pass(self):
        self.ctx.put('source.md', '[unknown](custom://target#anchor)')
        found = links.run(self.ctx)
        self.assertEqual(['unknown-scheme'], [item.code for item in found])
        self.assertTrue(all(not item['complete'] and item['status'] == 'Unknown' for item in self.ctx.observations['coverage_domains'].values()))


    def test_domain_coverage_generation_limit_never_claims_complete(self):
        from fifan_maintenance.models import FindingLimit, finding_budget
        self.ctx.put('source.md', '\n\n'.join('[missing](missing.txt)' for _ in range(4001)))
        with finding_budget(200):
            with self.assertRaises(FindingLimit):
                links.run(self.ctx)
        self.assertTrue(all(not item['complete'] and 'RUN_NOT_COMPLETED' in item['unknown_reasons'] for item in self.ctx.observations['coverage_domains'].values()))


if __name__ == "__main__":
    unittest.main()
