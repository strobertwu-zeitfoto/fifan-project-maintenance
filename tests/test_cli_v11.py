"""Small direct CLI compatibility checks; the full workflow is in tools/validate_v11.py."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = Path(os.environ.get("FIFAN_MAINTAIN_TOOL", str(ROOT / "bin/fifan-maintain")))
WORK = ROOT / "evidence/validation/v1.1/forward/test-work"


class CliV11Tests(unittest.TestCase):
    def test_v1_default_check_still_accepts_project_and_output(self):
        WORK.mkdir(parents=True, exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix="legacy-check-", dir=str(WORK)))
        try:
            project = run_dir / "project"
            results = run_dir / "results"
            project.mkdir()
            results.mkdir()
            (project / "README.md").write_text("# Legacy\n\n入口。\n", encoding="utf-8")
            report_path = results / "check.json"
            completed = subprocess.run(
                [str(TOOL), "check", "--project", str(project), "--files", "README.md",
                 "--format", "json", "--output", str(report_path)],
                cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["file_count"], 1)
            self.assertEqual(report["mode"], "check")
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_new_cli_options_are_exposed_without_changing_old_command(self):
        completed = subprocess.run([str(TOOL), "read", "--help"],
                                   cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for option in ("--outline", "--heading", "--view", "--cursor"):
            self.assertIn(option, completed.stdout)
        check_help = subprocess.run([str(TOOL), "check", "--help"],
                                    cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(check_help.returncode, 0, check_help.stderr)
        for option in ("--preflight", "--task-profile", "--historical-roots", "--format"):
            self.assertIn(option, check_help.stdout)

    def test_cursor_rejects_changed_heading_but_accepts_same_selection(self):
        WORK.mkdir(parents=True, exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix="cursor-binding-", dir=str(WORK)))
        try:
            project = run_dir / "project"
            project.mkdir()
            (project / "large.md").write_text(
                "# Long\n\n## Section A\n\n" + "UTF-8中文连续读取。\n" * 900 +
                "\n## Section B\n\nend\n", encoding="utf-8")
            profile = run_dir / "task-profile.json"
            profile.write_text(json.dumps({"schema_version": 1, "sources": ["large.md"],
                                           "checks": ["links"]}), encoding="utf-8")
            common = ["--project", str(project), "--task-profile", str(profile),
                      "--file", "large.md", "--max-output-bytes", "1024"]
            first = subprocess.run([str(TOOL), "read", *common, "--heading", "Long"],
                                   cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            cursor = json.loads(first.stdout)["next_cursor"]
            changed = subprocess.run([str(TOOL), "read", *common, "--heading", "Section A",
                                      "--cursor", cursor], cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(changed.returncode, 2)
            self.assertIn('"status": "Blocked"', changed.stderr)
            resumed = subprocess.run([str(TOOL), "read", *common, "--heading", "Long",
                                      "--cursor", cursor], cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(json.loads(resumed.stdout)["display_offset"],
                             json.loads(first.stdout)["sent_display_bytes"])
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
