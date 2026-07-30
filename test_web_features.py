from __future__ import annotations

import logging
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from cryptography.fernet import Fernet
from main_pipeline import Pipeline, LiveSession
from password_store import PasswordStore
from session_store import SessionStore
from secure_logging import configure_logging, recent_activity_logs

class WebFeatureTests(unittest.TestCase):
    def test_encrypted_password_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'passwords.enc'; store=PasswordStore(path,Fernet.generate_key())
            self.assertTrue(store.add('example-password')); self.assertFalse(store.add('example-password'))
            self.assertNotIn(b'example-password',path.read_bytes())
            masked=store.list_masked(); self.assertEqual(len(masked),1)
            self.assertTrue(store.delete(masked[0]['id'])); self.assertEqual(store.list_plain(),[])

    def test_encrypted_session_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sessions.enc'
            key = Fernet.generate_key()
            store = SessionStore(path, key)
            self.assertTrue(store.seed_if_empty('A' * 40, label='Primary'))
            self.assertFalse(store.seed_if_empty('B' * 40, label='Other'))
            second = store.add('C' * 40, 'Worker', user_id=99, username='alice', first_name='Alice')
            public = store.public_list()
            self.assertEqual(len(public), 2)
            self.assertTrue(all('session_string' not in item for item in public))
            self.assertNotIn(b'AAAAAAAA', path.read_bytes())
            store.update_profile(second['id'], first_name='Alice B')
            self.assertEqual(store.get(second['id'])['first_name'], 'Alice B')
            store.delete(second['id'])
            self.assertEqual(len(store.list_raw()), 1)
            with self.assertRaises(ValueError):
                store.delete(store.list_raw()[0]['id'])

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
        # 2 per session × 2 online sessions => capacity 4, but only 4 pending also.
        pipeline.ingest_workers = 2
        pipeline._ingest_tasks = {}
        pipeline._ingest_supervisor_task = None
        pipeline._ingest_worker_heartbeat = 0.0
        pipeline._session_rr = 0
        pipeline.sessions = {
            'a': LiveSession(id='a', label='A', session_string='x', client=object(), online=True),
            'b': LiveSession(id='b', label='B', session_string='y', client=object(), online=True),
        }
        started = []
        release = __import__('asyncio').Event()

        async def fake_run(job_id, job_key, url, session_id):
            started.append((url, job_id, job_key, session_id))
            await release.wait()
            pipeline.sessions[session_id].active_jobs = max(
                0, pipeline.sessions[session_id].active_jobs - 1
            )

        pipeline._run_ingest_job = fake_run
        await pipeline._schedule_pending_ingests()
        for _ in range(100):
            if len(started) == 4:
                break
            await __import__('asyncio').sleep(0.01)
        self.assertEqual(pipeline._ingest_capacity(), 4)
        self.assertEqual(len(pipeline._ingest_tasks), 4)
        self.assertEqual([item[1] for item in started], [1, 2, 3, 4])
        self.assertTrue(all(item[3] in {'a', 'b'} for item in started))
        # Both sessions should be used (spread), each at most 2 reserved slots.
        used = {item[3] for item in started}
        self.assertEqual(used, {'a', 'b'})
        self.assertLessEqual(pipeline.sessions['a'].active_jobs, 2)
        self.assertLessEqual(pipeline.sessions['b'].active_jobs, 2)
        self.assertTrue(all(args[1] == 'fetching' for args in pipeline.db.progress))
        tasks = list(pipeline._ingest_tasks.values())
        release.set()
        await __import__('asyncio').gather(*tasks)


if __name__=='__main__': unittest.main()
