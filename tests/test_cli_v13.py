"""Small fixture-contract tests; these do not invoke the unfinished v1.3 CLI."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_v13 import (FORWARD, build_fixture, run_archive_fixture,
                          run_small_fixture, run_unity_protected_fixture)  # noqa: E402


class V13FixtureContractTests(unittest.TestCase):
    def setUp(self):
        FORWARD.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="fixture-contract-", dir=str(FORWARD))
        self.workspace = Path(self.temp.name) / "run"
        self.manifest = build_fixture(self.workspace, history_files=9, census_entries=24,
                                      archive_counts=(5, 7))
        self.project = Path(self.manifest["roots"]["project"])

    def tearDown(self):
        outcome = getattr(self, "_outcome", None)
        result = getattr(outcome, "result", None)
        failed = (bool(getattr(result, "failures", ())) or bool(getattr(result, "errors", ()))
                  or getattr(outcome, "success", True) is False)
        if failed:
            self.temp._finalizer.detach()
            print("preserved failed fixture:", self.temp.name)
        else:
            self.temp.cleanup()

    def test_fixture_is_isolated_and_all_roots_share_a_volume(self):
        workspace = Path(self.manifest["roots"]["workspace"]).resolve()
        self.assertTrue(workspace.is_relative_to(FORWARD.resolve()))
        devices = {path.stat().st_dev for path in (
            Path(self.manifest["roots"]["project"]),
            Path(self.manifest["roots"]["archive_root"]),
            Path(self.manifest["roots"]["records_root"]))}
        self.assertEqual(len(devices), 1)
        self.assertEqual(self.manifest["counts"]["key_markdown"], 3)

    def test_history_and_census_population_are_deterministic(self):
        history = list((self.project / "history/metadata").glob("*.json"))
        census = self.project / "census-payload"
        files = list((census / "files").iterdir())
        empty_dirs = list((census / "empty").iterdir())
        self.assertEqual(len(history), 9)
        self.assertEqual(len(files) + len(empty_dirs), 24)
        self.assertEqual(self.manifest["counts"]["census_entries_requested"], 24)

    def test_archive_manifests_bind_hash_mode_mtime_and_batch_counts(self):
        rows = self.manifest["archive_files"]
        self.assertEqual(len(rows), 12)
        self.assertEqual([sum(row["batch"] == n for row in rows) for n in (1, 2)], [5, 7])
        self.assertIn("Unicode 空格", rows[0]["path"])
        self.assertTrue(any("empty-directory" in row["path"] for row in self.manifest["archive_directories"]))
        for row in rows:
            path = self.project / row["path"]
            info = path.stat()
            self.assertEqual(info.st_mode & 0o777, row["mode"])
            self.assertEqual(info.st_mtime_ns, row["mtime_ns"])
            self.assertEqual((info.st_dev, info.st_ino), (row["device"], row["inode"]))
            from validate_v13 import sha256_file
            self.assertEqual(sha256_file(path), row["sha256"])
        for row in self.manifest["archive_directories"]:
            info = (self.project / row["path"]).stat()
            self.assertEqual(info.st_mode & 0o777, row["mode"])
            self.assertEqual(info.st_mtime_ns, row["mtime_ns"])
            self.assertEqual((info.st_dev, info.st_ino), (row["device"], row["inode"]))

    def test_protected_critical_and_key_config_fingerprints_are_present(self):
        self.assertIn("Assets", self.manifest["protected_paths"])
        self.assertIn("src/current_entry.py", self.manifest["critical_paths"])
        self.assertEqual(set(self.manifest["baseline_sha256"]), {
            "README.md", "PLAN.md", "DECISIONS.md", "src/current_entry.py",
            ".ignore", ".vscode/settings.json"})
        stored = json.loads((self.workspace / "fixture-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["api_contract_status"], "awaiting-v1.3-public-cli-freeze")

    def test_profile_grants_only_declared_current_and_historical_sources(self):
        profile = json.loads((self.workspace / "directory-profile.json").read_text(encoding="utf-8"))
        request = json.loads((self.workspace / "directory-request.json").read_text(encoding="utf-8"))
        roles = {item["path"]: item["role"] for item in profile["reference_sources"]}
        self.assertEqual(roles["README.md"], "current")
        self.assertEqual(roles["src/current_entry.py"], "current")
        self.assertEqual(roles["history/old-report.md"], "historical")
        self.assertEqual(roles["history/old-report-two.md"], "historical")
        self.assertEqual(roles["history/closed-batch-one/close-note.md"], "historical")
        self.assertEqual(len(request["batches"]), 2)
        self.assertEqual(request["batches"][0]["historical_references"][0]["path"],
                         "history/old-report.md")
        self.assertEqual(request["batches"][1]["historical_references"][0]["path"],
                         "history/old-report-two.md")
        self.assertGreaterEqual(profile["budgets"]["max_entries"],
                                self.manifest["counts"]["census_entries_requested"] +
                                self.manifest["counts"]["history_metadata_files"] +
                                self.manifest["counts"]["archive_batch_total"])

    def test_existing_nonempty_workspace_is_never_overwritten(self):
        marker = self.workspace / "user-marker.txt"
        marker.write_text("preserve", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            build_fixture(self.workspace, history_files=0, census_entries=0, archive_counts=(0, 0))
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_inspect_search_restore_cli_flow_and_original_hashes(self):
        summary = run_small_fixture(self.workspace)
        self.assertEqual(summary["status"], "Passed")
        self.assertEqual(summary["inspect"]["census_body_bytes_sent"], 0)
        self.assertIsNone(summary["inspect"]["impact_global_no_dependencies"])
        self.assertGreater(summary["inspect"]["project_metadata_entries_unchanged"], 0)
        self.assertEqual(summary["search"]["state"], "Applied")
        self.assertEqual(summary["restore"]["state"], "Restored")
        self.assertTrue(summary["restore"]["restored_original_hashes_match"])
        self.assertTrue(summary["restore"]["vscode_config_presence_restored"])

    def test_search_restore_removes_only_owned_missing_vscode_config(self):
        workspace = Path(self.temp.name) / "missing-vscode-config"
        build_fixture(workspace, history_files=8, census_entries=12,
                      archive_counts=(2, 3), vscode_config=False)
        project = workspace / "project"
        self.assertFalse((project / ".vscode/settings.json").exists())
        summary = run_small_fixture(workspace)
        self.assertEqual(summary["status"], "Passed")
        self.assertFalse((project / ".vscode/settings.json").exists())
        self.assertFalse((project / ".vscode").exists())

    def test_two_batch_archive_pilot_rearchive_and_total_restore(self):
        summary = run_archive_fixture(self.workspace)
        self.assertEqual(summary["status"], "Passed")
        self.assertEqual(summary["workflow_archive"]["batch_count"], 2)
        self.assertTrue(summary["workflow_archive"]["pilot_done"])
        self.assertIn("PilotApplying", summary["workflow_archive"]["workflow_steps"])
        self.assertEqual(summary["restore"]["state"], "Restored")
        self.assertTrue(summary["restore"]["restored_original_hashes_match"])

    def test_unity_preset_blocks_adversarial_assets_archive(self):
        summary = run_unity_protected_fixture(self.workspace)
        self.assertEqual(summary["status"], "Passed")
        self.assertEqual(summary["adversarial_classification"]["role"], "historical")
        self.assertEqual(summary["result"]["reason_code"], "PROTECTED_PATH")
        self.assertTrue(summary["archive_files_unchanged"])
        self.assertTrue(summary["records_files_unchanged"])
        self.assertFalse(summary["plan_created"])


if __name__ == "__main__":
    unittest.main()
