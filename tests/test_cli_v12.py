"""Fixture contract checks; CLI end-to-end cases are appended once 1.2 APIs freeze."""
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_v12 import build_fixture, write_prepared_inputs  # noqa: E402


class V12FixtureContractTests(unittest.TestCase):
    def setUp(self):
        self.work = ROOT / "evidence/validation/v1.2/forward/test-work"
        self.work.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="fixture-", dir=str(self.work))
        self.project = Path(self.temporary.name) / "project"
        self.results = Path(self.temporary.name) / "results"
        self.results.mkdir()
        self.manifest = build_fixture(self.project, history_files=7)
        self.manifest = write_prepared_inputs(self.project, self.results, self.manifest)

    def tearDown(self):
        self.temporary.cleanup()

    def test_profile_groups_are_13_and_split_11_plus_2(self):
        groups = self.manifest["profile_groups"]
        self.assertEqual(len(groups["parent"]), 13)
        self.assertEqual(len(groups["child_11"]), 11)
        self.assertEqual(len(groups["child_2"]), 2)
        self.assertEqual(set(groups["child_11"]) | set(groups["child_2"]), set(groups["parent"]))
        self.assertFalse(set(groups["child_11"]) & set(groups["child_2"]))

    def test_archive_fixture_contains_23_exact_and_4_different_sections(self):
        current = (self.project / "docs/current/policy.md").read_text(encoding="utf-8")
        archived = (self.project / "docs/archive/policy.md").read_text(encoding="utf-8")
        for index in range(1, 24):
            phrase = "Requirement {:02d}: preserve this exact sentence.".format(index)
            self.assertIn(phrase, current)
            self.assertIn(phrase, archived)
        for index in range(24, 28):
            self.assertIn("Requirement {:02d}: preserve this exact sentence.".format(index), current)
            self.assertIn("Historical requirement {:02d}: wording differs.".format(index), archived)
        self.assertEqual(current.count("## Repeated heading"), 2)

    def test_patch_and_protection_fixtures_keep_crlf_and_scope(self):
        patch_source = (self.project / "docs/current/table.md").read_bytes()
        self.assertIn(b"\r\n", patch_source)
        self.assertNotIn(b"\n", patch_source.replace(b"\r\n", b""))
        self.assertIn("api_token=fixture-secret-not-real".encode(), patch_source)
        config = (self.project / ".fifan-maintenance.json").read_text(encoding="utf-8")
        self.assertIn('"private/**"', config)
        self.assertTrue((self.project / "private/restricted.md").is_file())

    def test_history_fixture_includes_flat_and_nested_entries(self):
        flat = list((self.project / "history").glob("REPORT_*.md"))
        nested = list((self.project / "history/deep/level2").glob("REPORT_DEEP_*.md"))
        self.assertEqual(len(flat), 7)
        self.assertEqual(len(nested), 5)
        self.assertEqual(self.manifest["history_files_flat"], 7)

    def test_prepared_requests_bind_exact_fixture_sources(self):
        coverage = __import__("json").loads((self.results / "archive-coverage-request.json").read_text())
        self.assertEqual(coverage["version"], 1)
        self.assertEqual(len(coverage["items"]), 33)
        self.assertEqual(coverage["allowed_external_roots"], [])
        v1 = __import__("json").loads((self.results / "legacy-v1-request.json").read_text())
        self.assertEqual(v1["operations"][0]["path"], "legacy-v1.md")
        v3 = __import__("json").loads((self.results / "replace-many-v3-request.json").read_text())
        patches = v3["operations"][2]["patches"]
        self.assertEqual(len(patches), 3)
        self.assertIn("old_locator", patches[2])
        raw = (self.project / "docs/current/table.md").read_bytes()
        locator = patches[2]["old_locator"]
        self.assertEqual(raw[locator["start_byte"]:locator["end_byte"]], b"api_token=fixture-secret-not-real")


if __name__ == "__main__":
    unittest.main()
