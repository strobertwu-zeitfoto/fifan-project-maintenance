"""Synthetic v1.4 fixture and repeatable large/metadata driver contracts."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import os
from unittest.mock import patch
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(sys.prefix) / "bin/fifan-maintain"
sys.path.insert(0, str(ROOT / "tools"))
from validate_v14 import (CLEANUP_CANDIDATES, DISPOSABLE_FILES, FORWARD, PROTECTED_FILES,  # noqa: E402
                          FixtureError, prepare_fixture, sha256_file, _call_cli, run_metadata_contract, run_large_contract, main)


class V14FixtureContractTests(unittest.TestCase):
    def setUp(self):
        FORWARD.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="driver-checks-", dir=str(FORWARD))
        self.workspace = Path(self.temp.name) / "fixture"
        self.manifest = prepare_fixture(self.workspace, log_bytes=1024)
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

    def test_three_runtime_roots_are_distinct_external_siblings_on_one_device(self):
        roots = [Path(self.manifest["roots"][key]).resolve()
                 for key in ("project", "quarantine_root", "records_dir")]
        self.assertEqual(len({root.stat().st_dev for root in roots}), 1)
        self.assertEqual(len(set(roots)), 3)
        for root in roots[1:]:
            self.assertNotIn(roots[0], root.parents)
            self.assertNotIn(root, roots[0].parents)
        self.assertEqual(self.manifest["counts"]["current_markdown"], 3)

    def test_current_build_is_backed_by_actual_matching_evidence_sha(self):
        profile = json.loads(Path(self.manifest["profile"]).read_text(encoding="utf-8"))
        keep = profile["keep"][0]
        build = self.project / keep["path"]
        evidence = keep["evidence"][0]
        self.assertEqual(keep["sha256"], sha256_file(build))
        self.assertEqual(keep["sha256"], self.manifest["current_build_sha256"])
        self.assertEqual(evidence["sha256"], sha256_file(self.project / evidence["path"]))
        self.assertEqual(keep["build"]["platform"], "mac")

    def test_disposables_and_closure_evidence_are_exact_and_separate(self):
        self.assertEqual(set(self.manifest["disposable_sha256"]), set(DISPOSABLE_FILES))
        evidence = Path(self.manifest["roots"]["closure_evidence"])
        self.assertTrue(evidence.is_file())
        self.assertIn(self.project, evidence.parents)
        self.assertNotIn(self.project / "build/old", evidence.parents)
        self.assertEqual(self.manifest["roots"]["closure_evidence_project_path"], "closed-batch.md")
        self.assertEqual(sha256_file(evidence), self.manifest["closure_evidence_sha256"])
        self.assertEqual(set(self.manifest["protected_sha256"]), set(PROTECTED_FILES))

    def test_profile_and_request_bind_current_keep_closure_and_loss_authorization(self):
        profile = json.loads(Path(self.manifest["profile"]).read_text(encoding="utf-8"))
        request = json.loads(Path(self.manifest["request"]).read_text(encoding="utf-8"))
        self.assertEqual(sha256_file(Path(self.manifest["profile"])), self.manifest["profile_sha256"])
        self.assertEqual(sha256_file(Path(self.manifest["request"])), self.manifest["request_sha256"])
        current = {item["path"]: item["role"] for item in profile["reference_sources"]}
        self.assertEqual(current, {"current": "current", "closed-batch.md": "historical"})
        keep = next(item for item in profile["keep"] if item["path"] == "builds/keep.zip")
        old_build = next(item for item in request["items"] if item["kind"] == "old_build")
        self.assertEqual(keep["build"], old_build["build"])
        self.assertEqual(old_build["retained"], ["builds/keep.zip"])
        self.assertEqual(request["approval"]["actions"], ["quarantine", "purge"])
        self.assertEqual({item["source"] for item in request["items"]}, set(CLEANUP_CANDIDATES))
        for item in request["items"]:
            self.assertEqual(item["disposition"], "purge")
            self.assertTrue(item["loss"]["accepted"])
            evidence = item["closure"]["evidence"][0]
            self.assertEqual(evidence["path"], "closed-batch.md")
            self.assertEqual(evidence["sha256"], self.manifest["closure_evidence_sha256"])

    def test_quarantine_only_request_does_not_grant_purge_or_loss_acceptance(self):
        request = json.loads(Path(self.manifest["quarantine_only_request"]).read_text(encoding="utf-8"))
        self.assertEqual(request["approval"]["actions"], ["quarantine"])
        self.assertEqual({item["disposition"] for item in request["items"]}, {"quarantine"})
        self.assertTrue(all(item["loss"]["accepted"] is False for item in request["items"]))

    def test_protected_files_have_baseline_hashes_including_asset_meta_and_environment(self):
        for rel, digest in self.manifest["protected_sha256"].items():
            self.assertEqual(sha256_file(self.project / rel), digest, rel)
        self.assertIn("Assets/fixture.asset.meta", self.manifest["protected_sha256"])
        self.assertIn(".git/HEAD", self.manifest["protected_sha256"])
        self.assertIn(".env", self.manifest["protected_sha256"])

    def test_fixture_refuses_to_overwrite_nonempty_workspace(self):
        marker = self.workspace / "user-marker"
        marker.write_text("keep", encoding="utf-8")
        with self.assertRaises(FixtureError):
            prepare_fixture(self.workspace, log_bytes=0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_tiny_log_fixture_is_ready_without_emitting_log_text(self):
        self.assertIn("stable cleanup 1.4", self.manifest["api_contract_status"])
        self.assertEqual(self.manifest["counts"]["log_bytes"], 1024)
        self.assertEqual((self.project / "logs/completed-run.log").stat().st_size,
                         len(b"synthetic completed log\n") + 1024)
        # Fixture setup computes integrity hashes only; no body is loaded into a report.
        self.assertNotIn("log_body", self.manifest)


    def test_cli_workspace_symlink_cannot_escape_authorized_forward_tree(self):
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(ROOT, target_is_directory=True)
        target = alias / ("must-not-write-" + Path(self.temp.name).name)
        with self.assertRaises(SystemExit) as error:
            main(["--prepare-only", "--workspace", str(target)])
        self.assertEqual(error.exception.code, 2)
        self.assertFalse((ROOT / target.name).exists())

    def test_subprocess_environment_drops_python_injection_and_keeps_full_receipt(self):
        cli = CLI
        with patch.dict(os.environ, {"PYTHONPATH": "/untrusted", "PYTHONHOME": "/untrusted"}):
            with patch("validate_v14.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout='{"status":"Passed"}', stderr="")) as run:
                result = _call_cli(self.workspace, cli, "env-contract", ["cleanup", "inspect"], expected_status="Passed")
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("PYTHONHOME", environment)
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(result["record"]["argv"][0], str(cli))
        self.assertIn("--output", result["record"]["argv"])
        self.assertTrue((self.workspace / "commands/env-contract.json").is_file())

    def test_metadata_new_mode_tiny_real_cli_budget_and_exclusion(self):
        result = run_metadata_contract(Path(self.temp.name) / "metadata-tiny", CLI, files=23)
        self.assertEqual(result["synthetic_files"], 23)
        self.assertEqual(result["body_bytes_read"], 0)
        self.assertEqual(result["default_hash_bytes"], 0)
        self.assertEqual(result["excluded_entries"], 2)
        self.assertTrue(result["limited_count_is_lower_bound"])
        self.assertEqual(result["limited_status"], "Unknown")

    def test_large_new_mode_tiny_real_cli_restoration_purge_and_retained_control(self):
        result = run_large_contract(Path(self.temp.name) / "large-tiny", CLI, log_bytes=65536)
        self.assertEqual(result["status"], "Passed")
        self.assertEqual(result["cleanup_chain"]["status"], "PurgedAndVerified")
        self.assertEqual(result["retained_cli_status"], "Blocked")
        self.assertEqual(result["retained_sha256_before"], result["retained_sha256_after"])
        self.assertGreater(result["verify_hash_usage"]["verify-restored"]["hash_bytes"], 65536)
        self.assertFalse(result["hash_accounting_is_os_physical_io"])


if __name__ == "__main__":
    unittest.main()
