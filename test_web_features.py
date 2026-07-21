from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from cryptography.fernet import Fernet
from password_store import PasswordStore

class WebFeatureTests(unittest.TestCase):
    def test_encrypted_password_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'passwords.enc'; store=PasswordStore(path,Fernet.generate_key())
            self.assertTrue(store.add('example-password')); self.assertFalse(store.add('example-password'))
            self.assertNotIn(b'example-password',path.read_bytes())
            masked=store.list_masked(); self.assertEqual(len(masked),1)
            self.assertTrue(store.delete(masked[0]['id'])); self.assertEqual(store.list_plain(),[])

if __name__=='__main__': unittest.main()
