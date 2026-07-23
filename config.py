from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv 

load_dotenv()
def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def positive_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0: raise RuntimeError(f"{name} must be positive")
    return value


def non_negative_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value < 0:
        raise RuntimeError(f"{name} must be >= 0")
    return value


def parse_users() -> frozenset[int]:
    try:
        users = frozenset(int(x.strip()) for x in required("ALLOWED_USERS").split(",") if x.strip())
    except ValueError as exc:
        raise RuntimeError("ALLOWED_USERS must contain numeric Telegram user IDs") from exc
    if not users: raise RuntimeError("ALLOWED_USERS cannot be empty")
    return users


@dataclass(frozen=True, slots=True)
class Settings:
    api_id: int; api_hash: str; string_session: str
    allowed_users: frozenset[int]
    data_root: Path
    max_download_bytes: int; max_expanded_bytes: int
    max_archive_files: int; max_scan_file_bytes: int
    max_nesting_depth: int; min_free_bytes: int
    extraction_timeout_seconds: int
    extraction_workers: int
    fingerprint_key: bytes
    dashboard_password: str; dashboard_secret: bytes
    password_encryption_key: bytes
    host: str; port: int; log_level: str

    @property
    def inbox_dir(self): return self.data_root / "inbox"
    @property
    def work_dir(self): return self.data_root / "work"
    @property
    def output_dir(self): return self.data_root / "output"
    @property
    def database_path(self): return self.data_root / "jobs.sqlite3"
    @property
    def password_store_path(self): return self.data_root / "archive-passwords.enc"
    @property
    def session_file_path(self): return self.data_root / "telegram_session.txt"
    @property
    def session_lock_path(self): return self.data_root / "telegram_session.lock"

    def prepare(self) -> None:
        self.data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in (self.inbox_dir, self.work_dir, self.output_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)


def load_settings() -> Settings:
    s = Settings(
        api_id=int(required("TELEGRAM_API_ID")), api_hash=required("TELEGRAM_API_HASH"),
        string_session=required("TELEGRAM_STRING_SESSION"), allowed_users=parse_users(),
        data_root=Path(os.getenv("DATA_ROOT", "/data")).resolve(),
        # 0 disables the download size cap (recommended for large Telegram archives).
        max_download_bytes=non_negative_int("MAX_DOWNLOAD_BYTES", 0),
        max_expanded_bytes=positive_int("MAX_EXPANDED_BYTES", 50 * 1024**3),
        max_archive_files=positive_int("MAX_ARCHIVE_FILES", 50_000),
        max_scan_file_bytes=positive_int("MAX_SCAN_FILE_BYTES", 100 * 1024**2),
        max_nesting_depth=positive_int("MAX_NESTING_DEPTH", 3),
        min_free_bytes=positive_int("MIN_FREE_BYTES", 1024**3),
        extraction_timeout_seconds=positive_int("EXTRACTION_TIMEOUT_SECONDS", 1800),
        extraction_workers=min(positive_int("EXTRACTION_WORKERS", 1), 24),
        fingerprint_key=required("FINGERPRINT_KEY").encode(),
        dashboard_password=required("DASHBOARD_PASSWORD"), dashboard_secret=required("DASHBOARD_SECRET").encode(),
        password_encryption_key=required("PASSWORD_ENCRYPTION_KEY").encode(),
        host=os.getenv("HOST", "0.0.0.0"), port=positive_int("PORT", 8000),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )
    s.prepare(); return s
