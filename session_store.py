from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from cryptography.fernet import Fernet, InvalidToken


class SessionStore:
    """Encrypted-at-rest Telegram string-session pool (one entry per account)."""

    def __init__(self, path: Path, key: bytes):
        self.path = path
        self.fernet = Fernet(key)
        self.lock = threading.Lock()

    @staticmethod
    def fingerprint(session_string: str) -> str:
        return hashlib.sha256(session_string.strip().encode()).hexdigest()[:16]

    def _load_unlocked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            payload = self.fernet.decrypt(self.path.read_bytes())
            values = json.loads(payload)
        except (InvalidToken, json.JSONDecodeError, OSError) as exc:
            raise RuntimeError("Encrypted session store cannot be decrypted") from exc
        if not isinstance(values, list):
            return []
        out: list[dict[str, Any]] = []
        for item in values:
            if isinstance(item, dict) and item.get("session_string"):
                out.append(item)
        return out

    def _save_unlocked(self, values: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(self.fernet.encrypt(json.dumps(values).encode()))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def list_raw(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(item) for item in self._load_unlocked()]

    def get(self, session_id: str) -> dict[str, Any] | None:
        with self.lock:
            for item in self._load_unlocked():
                if item.get("id") == session_id:
                    return dict(item)
        return None

    def seed_if_empty(self, session_string: str, label: str = "Primary") -> bool:
        """Import the env/bootstrap session once when the store is empty."""
        session_string = (session_string or "").strip()
        if not session_string:
            return False
        with self.lock:
            values = self._load_unlocked()
            if values:
                return False
            values.append({
                "id": uuid.uuid4().hex[:12],
                "label": label,
                "session_string": session_string,
                "fingerprint": self.fingerprint(session_string),
                "user_id": None,
                "username": None,
                "first_name": None,
                "phone": None,
                "enabled": True,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            self._save_unlocked(values)
            return True

    def add(
        self,
        session_string: str,
        label: str = "",
        *,
        user_id: int | None = None,
        username: str | None = None,
        first_name: str | None = None,
        phone: str | None = None,
    ) -> dict[str, Any]:
        session_string = session_string.strip()
        if not session_string or len(session_string) < 20:
            raise ValueError("Session string looks invalid")
        if len(session_string) > 10000:
            raise ValueError("Session string is too long")
        label = (label or "").strip()[:64]
        fp = self.fingerprint(session_string)
        with self.lock:
            values = self._load_unlocked()
            for item in values:
                if item.get("fingerprint") == fp:
                    raise ValueError("This session string is already stored")
                if user_id and item.get("user_id") == user_id:
                    raise ValueError("An account with this Telegram user ID is already stored")
            entry = {
                "id": uuid.uuid4().hex[:12],
                "label": label or (first_name or username or f"Account {len(values) + 1}"),
                "session_string": session_string,
                "fingerprint": fp,
                "user_id": user_id,
                "username": username,
                "first_name": first_name,
                "phone": phone,
                "enabled": True,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            values.append(entry)
            self._save_unlocked(values)
            return dict(entry)

    def update_profile(
        self,
        session_id: str,
        *,
        user_id: int | None = None,
        username: str | None = None,
        first_name: str | None = None,
        phone: str | None = None,
        label: str | None = None,
    ) -> bool:
        with self.lock:
            values = self._load_unlocked()
            for item in values:
                if item.get("id") != session_id:
                    continue
                if user_id is not None:
                    item["user_id"] = user_id
                if username is not None:
                    item["username"] = username
                if first_name is not None:
                    item["first_name"] = first_name
                if phone is not None:
                    item["phone"] = phone
                if label is not None and label.strip():
                    item["label"] = label.strip()[:64]
                self._save_unlocked(values)
                return True
        return False

    def delete(self, session_id: str) -> bool:
        with self.lock:
            values = self._load_unlocked()
            next_values = [item for item in values if item.get("id") != session_id]
            if len(next_values) == len(values):
                return False
            if not next_values:
                raise ValueError("Cannot delete the last Telegram session")
            self._save_unlocked(next_values)
            return True

    def public_list(self) -> list[dict[str, Any]]:
        """Safe metadata for the dashboard (never includes session_string)."""
        out = []
        for item in self.list_raw():
            out.append({
                "id": item.get("id"),
                "label": item.get("label") or "Account",
                "user_id": item.get("user_id"),
                "username": item.get("username"),
                "first_name": item.get("first_name"),
                "phone": item.get("phone"),
                "enabled": bool(item.get("enabled", True)),
                "created_at": item.get("created_at"),
            })
        return out
