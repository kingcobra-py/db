from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


class PasswordStore:
    """Encrypted-at-rest archive password storage. Plaintext is returned only to the extractor."""
    def __init__(self, path: Path, key: bytes):
        self.path = path; self.fernet = Fernet(key); self.lock = threading.Lock()

    @staticmethod
    def identifier(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()[:12]

    def _load_unlocked(self) -> list[str]:
        if not self.path.exists(): return []
        try:
            payload = self.fernet.decrypt(self.path.read_bytes())
            values = json.loads(payload)
        except (InvalidToken, json.JSONDecodeError) as exc:
            raise RuntimeError("Encrypted password store cannot be decrypted") from exc
        return [str(x) for x in values if isinstance(x, str) and x]

    def list_plain(self) -> list[str]:
        with self.lock: return self._load_unlocked()

    def list_masked(self) -> list[dict[str, str]]:
        return [{"id": self.identifier(p), "masked": f"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022 ({len(p)} chars)"} for p in self.list_plain()]

    def _save_unlocked(self, values: list[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(self.fernet.encrypt(json.dumps(values).encode()))
        os.chmod(tmp, 0o600); tmp.replace(self.path)

    def add(self, password: str) -> bool:
        password = password.strip("\r\n")
        if not password or len(password) > 512: raise ValueError("Password must be 1-512 characters")
        with self.lock:
            values = self._load_unlocked()
            if password in values: return False
            values.append(password); self._save_unlocked(values); return True

    def add_many(self, raw: str) -> tuple[int, int]:
        """Add newline-separated passwords in one write. Returns (added, skipped)."""
        candidates: list[str] = []
        for line in raw.splitlines():
            pw = line.strip("\r\n")
            if not pw:
                continue
            if len(pw) > 512:
                raise ValueError("A password exceeds 512 characters")
            candidates.append(pw)
        if not candidates:
            raise ValueError("No passwords provided")
        added = 0
        with self.lock:
            values = self._load_unlocked()
            existing = set(values)
            for pw in candidates:
                if pw in existing:
                    continue
                values.append(pw); existing.add(pw); added += 1
            if added:
                self._save_unlocked(values)
        return added, len(candidates) - added

    def clear(self) -> int:
        """Delete all stored passwords. Returns the number removed."""
        with self.lock:
            values = self._load_unlocked()
            if values:
                self._save_unlocked([])
            return len(values)

    def delete(self, identifier: str) -> bool:
        with self.lock:
            values = self._load_unlocked(); updated = [p for p in values if self.identifier(p) != identifier]
            if len(updated) == len(values): return False
            self._save_unlocked(updated); return True