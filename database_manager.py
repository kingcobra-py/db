from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

@dataclass(frozen=True, slots=True)
class Job:
    id: int; message_id: int; chat_id: int; user_id: int
    input_files: list[str]; status: str; attempts: int

class DatabaseManager:
    def __init__(self, path: Path): self.path = path

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30); db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA synchronous=FULL"); db.execute("PRAGMA busy_timeout=30000")
        return db

    @contextmanager
    def connect(self):
        """Commit-or-rollback like sqlite3's own context manager, then always close.

        `with sqlite3.Connection` only manages the transaction, not the handle.
        Leaving handles open leaks WAL/SHM files and locks the database on Windows.
        """
        with closing(self._connect()) as db:
            with db:
                yield db

    def initialize(self):
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS jobs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,message_id INTEGER NOT NULL UNIQUE,
                chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,input_files_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN('pending','running','completed','failed')),
                attempts INTEGER NOT NULL DEFAULT 0,source TEXT NOT NULL DEFAULT 'telegram',
                source_link TEXT,output_text TEXT,summary_json TEXT,summary_data TEXT,error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,started_at TEXT,completed_at TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
            columns = {r[1] for r in db.execute("PRAGMA table_info(jobs)")}
            if "source" not in columns: db.execute("ALTER TABLE jobs ADD COLUMN source TEXT NOT NULL DEFAULT 'telegram'")
            if "source_link" not in columns: db.execute("ALTER TABLE jobs ADD COLUMN source_link TEXT")
            db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status,created_at)")

    def _job(self, r): return Job(int(r['id']),int(r['message_id']),int(r['chat_id']),int(r['user_id']),json.loads(r['input_files_json']),str(r['status']),int(r['attempts']))

    def create_job(self,message_id,chat_id,user_id,files,source='telegram',source_link=None):
        with self.connect() as db:
            db.execute("""INSERT INTO jobs(message_id,chat_id,user_id,input_files_json,status,source,source_link)
                VALUES(?,?,?,?,'pending',?,?) ON CONFLICT(message_id) DO UPDATE SET
                input_files_json=excluded.input_files_json,status=CASE WHEN jobs.status='completed' THEN jobs.status ELSE 'pending' END,
                source=excluded.source,source_link=excluded.source_link,updated_at=CURRENT_TIMESTAMP""",
                (message_id,chat_id,user_id,json.dumps(files),source,source_link))
            return int(db.execute("SELECT id FROM jobs WHERE message_id=?",(message_id,)).fetchone()['id'])

    def get_job(self,job_id):
        with self.connect() as db:
            r=db.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone(); return self._job(r) if r else None

    def restore_interrupted_jobs(self):
        with self.connect() as db:
            db.execute("UPDATE jobs SET status='pending',error='Worker restarted',updated_at=CURRENT_TIMESTAMP WHERE status='running'")
            return [self._job(r) for r in db.execute("SELECT * FROM jobs WHERE status='pending' ORDER BY created_at,id")]

    def mark_running(self,job_id):
        with self.connect() as db: db.execute("UPDATE jobs SET status='running',attempts=attempts+1,started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,error=NULL WHERE id=?",(job_id,))

    def mark_completed(self,job_id,text,summary_json,summary):
        with self.connect() as db: db.execute("UPDATE jobs SET status='completed',output_text=?,summary_json=?,summary_data=?,completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,error=NULL WHERE id=?",(text,summary_json,json.dumps(summary),job_id))

    def mark_failed(self,job_id,error):
        with self.connect() as db: db.execute("UPDATE jobs SET status='failed',error=?,completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?",(str(error)[:2000],job_id))

    def stats(self):
        with self.connect() as db:
            counts={r['status']:int(r['n']) for r in db.execute("SELECT status,COUNT(*) n FROM jobs GROUP BY status")}
        return {k:counts.get(k,0) for k in ('pending','running','completed','failed')}

    def recent(self,limit=25):
        with self.connect() as db:
            rows=db.execute("SELECT id,message_id,status,source,source_link,output_text,summary_json,error,created_at,updated_at FROM jobs ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
            return [dict(r) for r in rows]

    def output_for_job(self,job_id,kind):
        if kind not in {"report", "summary"}:
            raise ValueError(f"Unknown output kind: {kind!r}")
        column = "output_text" if kind == "report" else "summary_json"
        with self.connect() as db:
            r=db.execute(f"SELECT {column} AS path FROM jobs WHERE id=? AND status='completed'",(job_id,)).fetchone()
            return str(r['path']) if r and r['path'] else None