from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from database_manager import DatabaseManager
from extractor import ArchiveProcessor, validate_member, sanitize_member, ExtractionError, is_rar
from parse_credentials import scan_tree, write_results, extract_raw_credentials, _is_aws_credentials_target
from parse_credit_cards import (
    extract_credit_cards,
    format_credit_card_line,
    write_credit_cards_file,
    _is_credit_card_target,
)
from parse_passwords import (
    extract_passwords,
    format_password_line,
    write_passwords_file,
    _is_password_target,
)


class SecurityTests(unittest.TestCase):
    def test_traversal_rejected(self):
        with self.assertRaises(ExtractionError):
            validate_member("../secret.txt")
        # Absolute members are rewritten into the extract root instead of failing the archive.
        self.assertEqual(sanitize_member("/dados.TXT"), "dados.TXT")
        self.assertEqual(sanitize_member(r"C:\Windows\file.txt"), "Windows/file.txt")

    def test_is_rar_detects_rar_names(self):
        self.assertTrue(is_rar(Path("logs.rar")))
        self.assertTrue(is_rar(Path("@Channel Logs.part1.rar")))
        self.assertFalse(is_rar(Path("logs.zip")))

    def test_valid_zip_falls_back_when_7z_listing_is_unrecognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "valid.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("wallets/data.txt", "valid-data")
            processor = object.__new__(ArchiveProcessor)
            processor.s = SimpleNamespace(max_archive_files=100)
            processor._run = lambda args: SimpleNamespace(returncode=0, stdout="unexpected listing format")
            count, expanded = processor._inspect(archive, None)
            self.assertEqual(count, 1)
            self.assertEqual(expanded, len("valid-data"))

    def test_native_zip_fallback_skips_traversal_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("../escape.txt", "no")
                zipped.writestr("ok.txt", "yes")
            processor = object.__new__(ArchiveProcessor)
            processor.s = SimpleNamespace(max_archive_files=100)
            count, expanded = processor._inspect_zip_native(archive)
            self.assertEqual(count, 1)
            self.assertEqual(expanded, 3)

    def test_extract_ok_accepts_headers_error_with_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "out"
            destination.mkdir()
            (destination / "a.txt").write_text("ok", encoding="utf-8")
            processor = object.__new__(ArchiveProcessor)
            result = SimpleNamespace(returncode=2, stdout="ERRORS:\nHeaders Error\n")
            self.assertTrue(processor._extract_ok(result, destination))
            empty = Path(tmp) / "empty"
            empty.mkdir()
            self.assertFalse(processor._extract_ok(result, empty))

    def test_unrar_extract_ok_accepts_create_errors_with_files(self):
        """Correct passwords must not be discarded when unrar exits 9/10 for a few paths."""
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "out"
            destination.mkdir()
            (destination / "passwords.txt").write_text("ok", encoding="utf-8")
            processor = object.__new__(ArchiveProcessor)
            ok = SimpleNamespace(returncode=9, stdout="Total errors: 2\n")
            self.assertTrue(processor._unrar_extract_ok(ok, destination))
            wrong = SimpleNamespace(returncode=11, stdout="Incorrect password\n")
            self.assertFalse(processor._unrar_extract_ok(wrong, destination))
            empty = Path(tmp) / "empty"
            empty.mkdir()
            self.assertFalse(processor._unrar_extract_ok(ok, empty))

    def test_nested_archive_password_failure_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = SimpleNamespace(
                data_root=root,
                work_dir=root / "work",
                max_nesting_depth=2,
                max_archive_files=0,
                max_expanded_bytes=0,
                min_free_bytes=1,
                extraction_timeout_seconds=30,
            )
            settings.work_dir.mkdir()
            processor = object.__new__(ArchiveProcessor)
            processor.s = settings
            processor.password_provider = lambda: ["@LOGACTIVE"]
            processor.unrar = "/usr/bin/unrar"

            def fake_passwords(files):
                return [None, "@LOGACTIVE"]

            calls = []

            def fake_extract(archive, destination, passwords):
                calls.append(archive.name)
                if "nested" in archive.name:
                    raise ExtractionError(f"Could not safely extract {archive.name} with unrar: wrong password")
                destination.mkdir(parents=True, exist_ok=True)
                (destination / "All Passwords.txt").write_text("user:pass", encoding="utf-8")
                nested = destination / "junk-nested.rar"
                nested.write_bytes(b"Rar!\x00")

            processor._passwords = fake_passwords
            processor._extract = fake_extract
            processor._post_validate = lambda work: (1, 1)

            primary = root / "pack.rar"
            primary.write_bytes(b"Rar!\x00")
            out = processor.process(42, [primary])
            self.assertTrue((out / "archive-0" / "All Passwords.txt").exists())
            self.assertIn("junk-nested.rar", calls)
            self.assertIn("pack.rar", calls)

    @staticmethod
    def _write_aws_credentials(root: Path, relative_dir: str, body: str) -> Path:
        path = root.joinpath(*relative_dir.split("/")) / "credentials"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def test_aws_credentials_path_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = self._write_aws_credentials(root, "host/Soft/Azure/aws", "x")
            new_aws = self._write_aws_credentials(root, "host/Applications/Azure/.aws", "x")
            new_plain = self._write_aws_credentials(root, "host/Applications/Azure/stealer", "x")
            noise = root / "Chrome" / "Default" / "Passwords.txt"
            noise.parent.mkdir(parents=True)
            noise.write_text("aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
            other = root / "random" / "credentials"
            other.parent.mkdir(parents=True)
            other.write_text("aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
            self.assertTrue(_is_aws_credentials_target(old))
            self.assertTrue(_is_aws_credentials_target(new_aws))
            self.assertTrue(_is_aws_credentials_target(new_plain))
            self.assertFalse(_is_aws_credentials_target(noise))
            self.assertFalse(_is_aws_credentials_target(other))

    def test_scanner_redacts_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_id = "AKIAABCDEFGHIJKLMNOP"
            fake_secret = "A" * 40
            self._write_aws_credentials(
                root,
                "victim/Soft/Azure/aws",
                f"aws_access_key_id={fake_id}\naws_secret_access_key={fake_secret}\n",
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
            self._write_aws_credentials(
                root,
                "victim/Applications/Azure/.aws",
                f"aws_access_key_id={fake_id}\n"
                f'aws_secret_access_key="{fake_secret}"\n'
                f"aws_session_token = {fake_token}\n",
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
            self._write_aws_credentials(
                root,
                "victim/Applications/Azure/.aws",
                "aws_session_token=" + "D" * 40 + "\n",
            )
            findings, summary = scan_tree(root, 100_000, b"test-key")
            self.assertEqual(summary["by_type"]["aws_session_token"], 0)

    def test_large_file_scanned_when_unlimited(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Build a file larger than a tiny cap would allow; max_file_bytes=0 must not skip it.
            payload = "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=" + ("A" * 40) + "\n"
            self._write_aws_credentials(root, "victim/Soft/Azure/aws", payload * 1000)
            findings, summary = scan_tree(root, 0, b"test-key")
            self.assertEqual(summary["files_scanned"], 1)
            self.assertEqual(summary["findings"], 2000)
            self.assertEqual(summary.get("files_skipped", 0), 0)

    def test_large_file_skipped_when_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_aws_credentials(
                root,
                "victim/Soft/Azure/aws",
                "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n" + ("x" * 5000),
            )
            findings, summary = scan_tree(root, 100, b"test-key")
            self.assertEqual(summary["files_scanned"], 0)
            self.assertEqual(summary["findings"], 0)

    def test_extract_raw_respects_unlimited_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_aws_credentials(
                root,
                "victim/Applications/Azure/.aws",
                "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n"
                "aws_secret_access_key=" + ("Z" * 40) + "\n"
                "region=us-east-1\n",
            )
            creds = extract_raw_credentials(root, max_workers=2, max_file_bytes=0)
            self.assertEqual(len(creds), 1)
            self.assertEqual(creds[0]["access_key"], "AKIAABCDEFGHIJKLMNOP")

    def test_passwords_txt_and_other_files_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            noise = root / "Chrome" / "Default" / "Passwords.txt"
            noise.parent.mkdir(parents=True)
            noise.write_text(
                "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n"
                "aws_secret_access_key=" + ("Z" * 40) + "\n",
                encoding="utf-8",
            )
            (root / "notes.md").write_text("aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n")
            findings, summary = scan_tree(root, 100_000, b"test-key")
            self.assertEqual(summary["files_scanned"], 0)
            self.assertEqual(summary["findings"], 0)
            self.assertEqual(extract_raw_credentials(root, max_workers=2), [])

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

    def test_find_job_by_input_basename(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            first = db.create_job(1, 0, 0, ["/data/inbox/1/LOGS_CENTER.rar"])
            second = db.create_job(2, 0, 0, ["/data/inbox/2/other.zip"])
            self.assertEqual(db.find_job_id_by_input_basename("logs_center.rar"), first)
            self.assertEqual(db.find_job_id_by_input_basename("LOGS_CENTER.rar", exclude_job_id=first), None)
            self.assertEqual(db.find_job_id_by_input_basename("missing.rar"), None)
            self.assertEqual(db.find_job_id_by_input_basename("other.zip"), second)

    def test_delete_all_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            a = db.create_job(1, 0, 0, ["a.rar"])
            b = db.create_job(2, 0, 0, ["b.rar"])
            db.save_credentials(a, [{"access_key": "AKIATEST", "secret_key": "x" * 40, "region": "us-east-1"}])
            self.assertEqual(db.delete_all_jobs(), 2)
            self.assertEqual(db.stats(), {"pending": 0, "running": 0, "completed": 0, "failed": 0})
            self.assertEqual(db.get_all_credentials(), [])
            self.assertIsNone(db.get_job(a))
            self.assertIsNone(db.get_job(b))

    def test_recent_limit_and_status_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            for i in range(5):
                job_id = db.create_job(i + 1, 0, 0, [f"{i}.rar"])
                if i % 2 == 0:
                    db.mark_failed(job_id, "boom")
            recent = db.recent(3)
            self.assertEqual(len(recent), 3)
            self.assertIn("metrics", recent[0])
            failed = db.recent(10, status="failed")
            self.assertTrue(failed)
            self.assertTrue(all(row["status"] == "failed" for row in failed))

    def test_recent_embeds_completed_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            job_id = db.create_job(9, 0, 0, ["a.rar"])
            db.mark_completed(job_id, "/tmp/r.txt", "/tmp/s.json", {"files_scanned": 12, "findings": 3})
            row = db.recent(1)[0]
            self.assertEqual(row["metrics"]["files_scanned"], 12)
            self.assertEqual(row["metrics"]["findings"], 3)

    def test_live_jobs_returns_active_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            pending = db.create_job(1, 0, 0, [], "channel-link", "https://t.me/x/1")
            db.update_progress(pending, "queued", 0, 0, "waiting", 0, 0)
            running = db.create_job(2, 0, 0, [], "channel-link", "https://t.me/x/2")
            db.mark_fetching_if_pending(running)
            done = db.create_job(3, 0, 0, ["a.rar"])
            db.mark_completed(done, "r", "s", {"files_scanned": 1, "findings": 0})
            live = db.live_jobs()
            ids = {item["id"] for item in live}
            self.assertIn(pending, ids)
            self.assertIn(running, ids)
            self.assertNotIn(done, ids)

    def test_failed_retry_links_skips_permanent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            a = db.create_job(1, 0, 0, [], "channel-link", "https://t.me/lezgsjjs/100")
            b = db.create_job(2, 0, 0, [], "channel-link", "https://t.me/lezgsjjs/101")
            c = db.create_job(3, 0, 0, [], "channel-link", "https://t.me/other/50")
            d = db.create_job(4, 0, 0, [], "channel-link", "https://t.me/lezgsjjs/102")
            db.mark_failed(a, "Stopped by operator")
            db.mark_failed(b, "ValueError: Message 101 was deleted or is not visible (channel latest is 200)")
            db.mark_failed(c, "Stopped by operator")
            db.mark_failed(d, "ExtractionError: wrong password")
            all_retry = db.failed_retry_links()
            self.assertEqual(
                all_retry["retry"],
                ["https://t.me/other/50", "https://t.me/lezgsjjs/100", "https://t.me/lezgsjjs/102"],
            )
            self.assertEqual(all_retry["skipped"], 1)
            self.assertEqual(all_retry["total_failed"], 4)
            filtered = db.failed_retry_links("lezgsjjs")
            self.assertEqual(
                filtered["retry"],
                ["https://t.me/lezgsjjs/100", "https://t.me/lezgsjjs/102"],
            )
            self.assertEqual(filtered["skipped"], 1)
            self.assertEqual(filtered["total_failed"], 3)

    def test_unlimited_archive_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "many.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                for i in range(5):
                    zipped.writestr(f"file-{i}.txt", "data")
            processor = object.__new__(ArchiveProcessor)
            processor.s = SimpleNamespace(max_archive_files=0)
            count, _expanded = processor._inspect_zip_native(archive)
            self.assertEqual(count, 5)

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

    @staticmethod
    def _write_credit_card_file(root: Path, relative_dir: str, body: str) -> Path:
        path = root.joinpath(*relative_dir.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def test_credit_card_path_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cc_dir = self._write_credit_card_file(root, "victim/CreditCards/Chrome_Default.txt", "Card: 4111111111111111\n")
            cc_folder = self._write_credit_card_file(root, "victim/CC/Edge_Default.txt", "Card: 4111111111111111\n")
            noise = root / "Passwords.txt"
            noise.write_text("Card: 4111111111111111\n", encoding="utf-8")
            self.assertTrue(_is_credit_card_target(cc_dir))
            self.assertTrue(_is_credit_card_target(cc_folder))
            self.assertFalse(_is_credit_card_target(noise))

    def test_credit_card_stealer_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_credit_card_file(
                root,
                "host/CreditCards/Chrome_Default.txt",
                "\nHolder: Test User\nCardType: Unknown\nCard: 4111111111111111\nExpire: 10/2031\nCVV: 123\n",
            )
            cards = extract_credit_cards(root)
            self.assertEqual(len(cards), 1)
            self.assertEqual(cards[0]["card_number"], "4111111111111111")
            self.assertEqual(cards[0]["exp_month"], "10")
            self.assertEqual(cards[0]["exp_year"], "2031")
            self.assertEqual(cards[0]["cvv"], "123")
            self.assertEqual(format_credit_card_line(cards[0]), "4111111111111111|10|2031|123")

    def test_credit_card_pipe_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_credit_card_file(
                root,
                "host/CC/Chrome_Default.txt",
                "4111111111111111|03|2028|456\n",
            )
            cards = extract_credit_cards(root)
            self.assertEqual(len(cards), 1)
            self.assertEqual(format_credit_card_line(cards[0]), "4111111111111111|03|2028|456")

    def test_credit_card_db_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            job_id = db.create_job(99, 0, 0, ["pack.zip"])
            db.save_credit_cards(
                job_id,
                [
                    {
                        "card_number": "4111111111111111",
                        "exp_month": "10",
                        "exp_year": "2031",
                        "cvv": "123",
                        "file": "host/CreditCards/Chrome_Default.txt",
                        "line": 4,
                    }
                ],
            )
            rows = db.get_all_credit_cards()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["card_number"], "4111111111111111")
            self.assertEqual(rows[0]["cvv"], "123")
            db.delete_job(job_id)
            self.assertEqual(db.get_all_credit_cards(), [])

    def test_credit_card_export_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "cards.txt"
            write_credit_cards_file(
                [
                    {
                        "card_number": "4111111111111111",
                        "exp_month": "10",
                        "exp_year": "2031",
                        "cvv": "123",
                    }
                ],
                out,
            )
            self.assertEqual(out.read_text(encoding="utf-8"), "4111111111111111|10|2031|123\n")

    @staticmethod
    def _write_text_file(root: Path, relative: str, body: str) -> Path:
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def test_password_path_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            passwords = self._write_text_file(root, "host/Passwords.txt", "URL: https://a.com\nUSER: a\nPASS: secret1\n")
            all_passwords = self._write_text_file(root, "host/All Passwords.txt", "URL: https://b.com\nUSER: b\nPASS: secret2\n")
            folder = self._write_text_file(root, "host/Passwords/Chrome.txt", "URL: https://c.com\nUSER: c\nPASS: secret3\n")
            cookies = self._write_text_file(root, "host/Cookies.txt", "URL: https://d.com\nUSER: d\nPASS: secret4\n")
            notes = self._write_text_file(root, "host/readme.txt", "just a note\n")
            sniffed = self._write_text_file(root, "host/Desktop/notes.txt", "Username: eve\nPassword: SniffPass1\n")
            self.assertTrue(_is_password_target(passwords))
            self.assertTrue(_is_password_target(all_passwords))
            self.assertTrue(_is_password_target(folder))
            self.assertTrue(_is_password_target(sniffed))
            self.assertFalse(_is_password_target(cookies))
            self.assertFalse(_is_password_target(notes))

    def test_password_stealer_block_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_text_file(
                root,
                "host/Passwords.txt",
                "SOFT: Chrome\nURL: https://accounts.google.com/signin\nUSER: user@gmail.com\nPASS: MyP@ss1\n\n"
                "Host: facebook.com\nLogin: john\nPassword: hunter2\n",
            )
            records = extract_passwords(root)
            lines = {format_password_line(r) for r in records}
            self.assertIn("https://accounts.google.com/signin|user@gmail.com|MyP@ss1", lines)
            self.assertIn("facebook.com|john|hunter2", lines)

    def test_password_inline_and_json_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_text_file(
                root,
                "host/All Passwords.txt",
                "https://example.com:alice:S3cret!\n"
                "bob@mail.com:InboxPass9\n"
                "https://shop.test|carol|PipePass\n"
                '{"url":"https://json.test","username":"dave","password":"JsonPass1"}\n'
                "URL: https://skip.test\nUSER: nobody\nPASS: ****\n",
            )
            records = extract_passwords(root)
            lines = {format_password_line(r) for r in records}
            self.assertIn("https://example.com|alice|S3cret!", lines)
            self.assertIn("|bob@mail.com|InboxPass9", lines)
            self.assertIn("https://shop.test|carol|PipePass", lines)
            self.assertIn("https://json.test|dave|JsonPass1", lines)
            self.assertTrue(all("****" not in line for line in lines))

    def test_password_db_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "jobs.sqlite3")
            db.initialize()
            job_id = db.create_job(42, 0, 0, ["pack.zip"])
            db.save_passwords(
                job_id,
                [
                    {
                        "url": "https://a.test",
                        "username": "ada",
                        "password": "pw-one",
                        "file": "host/Passwords.txt",
                        "line": 3,
                    },
                    {
                        "url": "https://a.test",
                        "username": "ada",
                        "password": "pw-one",
                        "file": "dup.txt",
                        "line": 1,
                    },
                ],
            )
            rows, total = db.get_passwords(100)
            self.assertEqual(total, 1)
            self.assertEqual(rows[0]["username"], "ada")
            self.assertEqual(format_password_line(rows[0]), "https://a.test|ada|pw-one")
            db.delete_job(job_id)
            self.assertEqual(db.count_passwords(), 0)

    def test_password_export_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "passwords.txt"
            write_passwords_file(
                [{"url": "https://a.test", "username": "ada", "password": "pw-one"}],
                out,
            )
            self.assertEqual(out.read_text(encoding="utf-8"), "https://a.test|ada|pw-one\n")


if __name__ == "__main__":
    unittest.main()
