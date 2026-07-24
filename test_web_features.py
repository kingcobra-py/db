from __future__ import annotations

import logging
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from cryptography.fernet import Fernet
from main_pipeline import Pipeline
from password_store import PasswordStore
from secure_logging import configure_logging, recent_activity_logs

class WebFeatureTests(unittest.TestCase):
    def test_encrypted_password_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'passwords.enc'; store=PasswordStore(path,Fernet.generate_key())
            self.assertTrue(store.add('example-password')); self.assertFalse(store.add('example-password'))
            self.assertNotIn(b'example-password',path.read_bytes())
            masked=store.list_masked(); self.assertEqual(len(masked),1)
            self.assertTrue(store.delete(masked[0]['id'])); self.assertEqual(store.list_plain(),[])

    def test_activity_logs_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / 'activity-logs.json'
            configure_logging('INFO', log_path)
            logging.getLogger('pipeline').info('Download finished', extra={'stage': 'download'})
            logs = recent_activity_logs(10)
            self.assertTrue(any('Download finished' in str(item.get('message', '')) for item in logs))
            self.assertTrue(log_path.exists())

class IngestSchedulingTests(unittest.IsolatedAsyncioTestCase):
    async def test_supervisor_starts_bounded_parallel_jobs(self):
        class FakeDB:
            def __init__(self):
                self.listed = False
                self.progress = []

            def pending_channel_downloads(self):
                if self.listed:
                    return []
                self.listed = True
                return [
                    {'job_id': n, 'job_key': n * 10, 'url': f'https://t.me/channel/{n}'}
                    for n in range(1, 5)
                ]

            def get_job(self, job_id):
                return SimpleNamespace(status='pending', input_files=[])

            def update_progress(self, *args):
                self.progress.append(args)

            def mark_fetching_if_pending(self, job_id):
                self.progress.append((job_id, 'fetching'))
                return True

        pipeline = object.__new__(Pipeline)
        pipeline.db = FakeDB()
        pipeline._stop_requested = __import__('asyncio').Event()
        pipeline.ingest_workers = 3
        pipeline._ingest_tasks = {}
        pipeline._ingest_supervisor_task = None
        pipeline._ingest_worker_heartbeat = 0.0
        pipeline._ingest_job_timeout = 300
        pipeline._ingest_job_start_times = {}
        started = []
        release = __import__('asyncio').Event()

        async def fake_ingest(url, job_id, job_key):
            started.append((url, job_id, job_key))
            await release.wait()

        pipeline.ingest_channel_link = fake_ingest
        await pipeline._schedule_pending_ingests()
        for _ in range(100):
            if len(started) == 3:
                break
            await __import__('asyncio').sleep(0.01)
        self.assertEqual(len(pipeline._ingest_tasks), 3)
        self.assertEqual([item[1] for item in started], [1, 2, 3])
        self.assertTrue(all(args[1] == 'fetching' for args in pipeline.db.progress))
        tasks = list(pipeline._ingest_tasks.values())
        release.set()
        await __import__('asyncio').gather(*tasks)


if __name__=='__main__': unittest.main()
