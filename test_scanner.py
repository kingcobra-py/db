from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from database_manager import DatabaseManager
from extractor import validate_member, ExtractionError
from parse_credentials import scan_tree, write_results


class SecurityTests(unittest.TestCase):
    def test_traversal_rejected(self):
        for value in ("../secret.txt", "/etc/passwd", "C:\\Windows\\file.txt"):
            with self.assertRaises(ExtractionError):
                validate_member(value)

    def test_scanner_redacts_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_id = "AKIAABCDEFGHIJKLMNOP"
            fake_secret = "A" * 40
            (root / "sample.log").write_text(
                f"aws_access_key_id={fake_id}\naws_secret_access_key={fake_secret}\n"
            )
            findings, summary = scan_tree(root, 100_000, b"test-key")
            text, js = write_results(root / "out", 123, findings, summary)
            combined = text.read_text() + js.read_text()
            self.assertNotIn(fake_secret, combined)
            self.assertNotIn(fake_id, combined)
            self.assertEqual(summary["findings"], 2)

    def test_session_token_detected_and_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_id = "ASIAABCDEFGHIJKLMNOP"
            fake_secret = "B" * 40
            fake_token = "C" * 120
            (root / "creds.log").write_text(
                f"aws_access_key_id={fake_id}\n"
                f'aws_secret_access_key="{fake_secret}"\n'
                f"aws_session_token = {fake_token}\n"
            )
            findings, summary = scan_tree(root, 100_000, b"test-key")
            text, js = write_results(root / "out", 456, findings, summary)
            combined = text.read_text() + js.read_text()
            self.assertNotIn(fake_id, combined)
            self.assertNotIn(fake_secret, combined)
            self.assertNotIn(fake_token, combined)
            self.assertEqual(summary["findings"], 3)
            self.assertEqual(summary["by_type"]["aws_access_key_id"], 1)
            self.assertEqual(summary["by_type"]["aws_secret_access_key"], 1)
            self.assertEqual(summary["by_type"]["aws_session_token"], 1)

    def test_short_token_not_matched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "short.log").write_text("aws_session_token=" + "D" * 40 + "\n")
            findings, summary = scan_tree(root, 100_000, b"test-key")
            self.assertEqual(summary["by_type"]["aws_session_token"], 0)

    def test_unscanned_suffix_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.md").write_text("aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n")
            findings, summary = scan_tree(root, 100_000, b"test-key")
            self.assertEqual(summary["files_scanned"], 0)
            self.assertEqual(summary["findings"], 0)

    def test_database_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            job_id = db.create_job(1, 2, 3, ["x.zip"])
            db.mark_running(job_id)
            restored = db.restore_interrupted_jobs()
            self.assertEqual([j.id for j in restored], [job_id])
            self.assertEqual(restored[0].status, "pending")


if __name__ == "__main__":
    unittest.main()