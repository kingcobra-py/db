from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from database_manager import DatabaseManager
from extractor import validate_member, ExtractionError, is_rar
from parse_credentials import scan_tree, write_results


class SecurityTests(unittest.TestCase):
    def test_traversal_rejected(self):
        for value in ("../secret.txt", "/etc/passwd", "C:\\Windows\\file.txt"):
            with self.assertRaises(ExtractionError):
                validate_member(value)

    def test_is_rar_detects_rar_names(self):
        self.assertTrue(is_rar(Path("logs.rar")))
        self.assertTrue(is_rar(Path("@Channel Logs.part1.rar")))
        self.assertFalse(is_rar(Path("logs.zip")))

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

    def test_same_message_id_different_chats(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            a = db.create_job(10, 100, 1, ["a.zip"])
            b = db.create_job(10, 200, 1, ["b.zip"])
            self.assertNotEqual(a, b)
            self.assertEqual(db.get_job(a).chat_id, 100)
            self.assertEqual(db.get_job(b).chat_id, 200)

    def test_summary_data_for_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            job_id = db.create_job(5, 1, 1, ["x.zip"])
            summary = {"files_scanned": 3, "findings": 1, "by_type": {"aws_access_key_id": 1}}
            db.mark_completed(job_id, "/tmp/report.txt", "/tmp/summary.json", summary)
            data = db.summary_data_for_job(job_id)
            self.assertEqual(data["files_scanned"], 3)
            self.assertEqual(data["findings"], 1)

    def test_stopped_job_not_resurrected(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            job_id = db.create_job(7, 0, 0, [], "channel-link", "https://t.me/x/1")
            db.mark_failed(job_id, "Stopped by operator")
            self.assertFalse(db.set_job_files_if_active(job_id, ["a.zip"]))
            self.assertEqual(db.get_job(job_id).status, "failed")
            # Conflict update must not reopen a failed row.
            db.create_job(7, 0, 0, ["a.zip"], "channel-link", "https://t.me/x/1")
            self.assertEqual(db.get_job(job_id).status, "failed")

    def test_download_status_transitions_pending_running_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            job_id = db.create_job(8, 0, 0, [], "channel-link", "https://t.me/x/8")
            self.assertEqual(db.get_job(job_id).status, "pending")
            self.assertTrue(db.mark_fetching_if_pending(job_id))
            self.assertEqual(db.get_job(job_id).status, "running")
            self.assertEqual(db.progress_for_job(job_id)["stage"], "fetching")
            self.assertTrue(db.set_job_files_if_active(job_id, ["/tmp/a.rar"]))
            self.assertEqual(db.get_job(job_id).status, "pending")

    def test_restore_splits_download_and_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            download_id = db.create_job(11, 0, 0, [], "channel-link", "https://t.me/channel/11")
            db.update_progress(download_id, "queued", 0, 0, "waiting", 0, 0)
            extract_id = db.create_job(12, 0, 0, ["/data/inbox/12/a.zip"], "channel-link", "https://t.me/channel/12")
            download_jobs, extract_jobs = db.restore_interrupted_work()
            self.assertEqual(download_jobs, [])
            self.assertEqual([j.id for j in extract_jobs], [extract_id])
            self.assertEqual(db.count_queued_channel_downloads(), 1)
            pending = db.pending_channel_downloads()
            self.assertEqual([j["job_id"] for j in pending], [download_id])
            self.assertEqual(pending[0]["url"], "https://t.me/channel/11")
            claimed = db.claim_next_channel_download()
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed["job_id"], download_id)
            self.assertEqual(claimed["url"], "https://t.me/channel/11")
            progress = db.progress_for_job(download_id)
            self.assertEqual(progress["stage"], "fetching")


if __name__ == "__main__":
    unittest.main()
