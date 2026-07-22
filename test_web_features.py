from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path
from cryptography.fernet import Fernet
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

if __name__=='__main__': unittest.main()
