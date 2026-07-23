from __future__ import annotations

import json
import shutil
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
    def __init__(self, path: Path, inbox_dir: Path | None = None, work_dir: Path | None = None, output_dir: Path | None = None):
        self.path = path; self.inbox_dir = inbox_dir; self.work_dir = work_dir; self.output_dir = output_dir
        self.config_path = self.path.parent / "config.json"

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

    def _migrate_job_uniqueness(self, db: sqlite3.Connection) -> None:
        """Ensure uniqueness is (chat_id, message_id), not message_id alone."""
        indexes = list(db.execute("PRAGMA index_list(jobs)"))
        has_composite = False
        for idx in indexes:
            name = idx[1]
            unique = idx[2]
            cols = [row[2] for row in db.execute(f"PRAGMA index_info('{name}')")]
            if unique and cols == ["chat_id", "message_id"]:
                has_composite = True
                break
        if has_composite:
            return
        db.execute("DROP TABLE IF EXISTS jobs_migrated")
        db.execute("""CREATE TABLE jobs_migrated(
            id INTEGER PRIMARY KEY AUTOINCREMENT,message_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,input_files_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN('pending','running','completed','failed')),
            attempts INTEGER NOT NULL DEFAULT 0,source TEXT NOT NULL DEFAULT 'telegram',
            source_link TEXT,output_text TEXT,summary_json TEXT,summary_data TEXT,error TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,started_at TEXT,completed_at TEXT,
            progress_stage TEXT,progress_done INTEGER NOT NULL DEFAULT 0,progress_total INTEGER NOT NULL DEFAULT 0,
            progress_file TEXT,progress_index INTEGER NOT NULL DEFAULT 0,progress_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(chat_id, message_id))""")
        cols = {r[1] for r in db.execute("PRAGMA table_info(jobs)")}
        select_cols = [
            "id", "message_id", "chat_id", "user_id", "input_files_json", "status", "attempts",
            "source" if "source" in cols else "'telegram'",
            "source_link" if "source_link" in cols else "NULL",
            "output_text", "summary_json", "summary_data", "error",
            "created_at", "started_at", "completed_at",
            "progress_stage" if "progress_stage" in cols else "NULL",
            "progress_done" if "progress_done" in cols else "0",
            "progress_total" if "progress_total" in cols else "0",
            "progress_file" if "progress_file" in cols else "NULL",
            "progress_index" if "progress_index" in cols else "0",
            "progress_count" if "progress_count" in cols else "0",
            "updated_at",
        ]
        # Deduplicate by chat_id+message_id keeping newest id
        db.execute(f"""INSERT OR IGNORE INTO jobs_migrated(
            id,message_id,chat_id,user_id,input_files_json,status,attempts,source,source_link,
            output_text,summary_json,summary_data,error,created_at,started_at,completed_at,
            progress_stage,progress_done,progress_total,progress_file,progress_index,progress_count,updated_at)
            SELECT {', '.join(select_cols)} FROM jobs
            WHERE id IN (
                SELECT MAX(id) FROM jobs GROUP BY chat_id, message_id
            )""")
        db.execute("DROP TABLE jobs")
        db.execute("ALTER TABLE jobs_migrated RENAME TO jobs")
        db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status,created_at)")

    def initialize(self):
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS jobs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,message_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,input_files_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN('pending','running','completed','failed')),
                attempts INTEGER NOT NULL DEFAULT 0,source TEXT NOT NULL DEFAULT 'telegram',
                source_link TEXT,output_text TEXT,summary_json TEXT,summary_data TEXT,error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,started_at TEXT,completed_at TEXT,
                progress_stage TEXT,progress_done INTEGER NOT NULL DEFAULT 0,progress_total INTEGER NOT NULL DEFAULT 0,
                progress_file TEXT,progress_index INTEGER NOT NULL DEFAULT 0,progress_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(chat_id, message_id))""")
            # Migrate legacy UNIQUE(message_id) schemas
            self._migrate_job_uniqueness(db)
            columns = {r[1] for r in db.execute("PRAGMA table_info(jobs)")}
            if "source" not in columns: db.execute("ALTER TABLE jobs ADD COLUMN source TEXT NOT NULL DEFAULT 'telegram'")
            if "source_link" not in columns: db.execute("ALTER TABLE jobs ADD COLUMN source_link TEXT")
            for col, ddl in (
                ("progress_stage", "progress_stage TEXT"),
                ("progress_done", "progress_done INTEGER NOT NULL DEFAULT 0"),
                ("progress_total", "progress_total INTEGER NOT NULL DEFAULT 0"),
                ("progress_file", "progress_file TEXT"),
                ("progress_index", "progress_index INTEGER NOT NULL DEFAULT 0"),
                ("progress_count", "progress_count INTEGER NOT NULL DEFAULT 0"),
            ):
                if col not in columns: db.execute(f"ALTER TABLE jobs ADD COLUMN {ddl}")
            db.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status,created_at)")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_chat_message ON jobs(chat_id, message_id)")
            db.execute('''CREATE TABLE IF NOT EXISTS extracted_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER, access_key TEXT, 
                secret_key TEXT, region TEXT, file_path TEXT, line_number INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    def _job(self, r): return Job(int(r['id']),int(r['message_id']),int(r['chat_id']),int(r['user_id']),json.loads(r['input_files_json']),str(r['status']),int(r['attempts']))

    def create_job(self,message_id,chat_id,user_id,files,source='telegram',source_link=None):
        with self.connect() as db:
            db.execute("""INSERT INTO jobs(message_id,chat_id,user_id,input_files_json,status,source,source_link)
                VALUES(?,?,?,?,'pending',?,?) ON CONFLICT(chat_id, message_id) DO UPDATE SET
                input_files_json=excluded.input_files_json,
                status=CASE
                    WHEN jobs.status IN ('completed','failed') THEN jobs.status
                    ELSE 'pending'
                END,
                error=CASE WHEN jobs.status IN ('completed','failed') THEN jobs.error ELSE NULL END,
                source=excluded.source,source_link=excluded.source_link,updated_at=CURRENT_TIMESTAMP""",
                (message_id,chat_id,user_id,json.dumps(files),source,source_link))
            return int(db.execute("SELECT id FROM jobs WHERE chat_id=? AND message_id=?",(chat_id,message_id)).fetchone()['id'])

    def set_job_files_if_active(self, job_id: int, files: list[str]) -> bool:
        """Attach downloaded files only when the job is still pending/running."""
        with self.connect() as db:
            cursor = db.execute(
                """UPDATE jobs SET input_files_json=?, status='pending', error=NULL,
                    updated_at=CURRENT_TIMESTAMP
                    WHERE id=? AND status IN ('pending','running')""",
                (json.dumps(files), job_id),
            )
            return cursor.rowcount > 0

    def get_job(self,job_id):
        with self.connect() as db:
            r=db.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone(); return self._job(r) if r else None

    def restore_interrupted_jobs(self):
        """Legacy helper: pending jobs that already have downloaded files (ready to extract)."""
        _, extract_jobs = self.restore_interrupted_work()
        return extract_jobs

    def restore_interrupted_work(self) -> tuple[list[dict[str, Any]], list[Job]]:
        """Prepare interrupted rows after restart.

        Channel-link downloads are claimed from the DB by the ingest worker (no
        in-memory queue). Stale fetching/downloading rows with no files are reset
        to queued. Only jobs that already have files are returned for extraction.
        """
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET status='pending',error='Worker restarted',updated_at=CURRENT_TIMESTAMP "
                "WHERE status='running'"
            )
            # Re-open downloads that were mid-fetch when the process died.
            db.execute(
                """UPDATE jobs SET progress_stage='queued', progress_done=0, progress_total=0,
                    progress_file='waiting', progress_index=0, progress_count=0,
                    updated_at=CURRENT_TIMESTAMP
                    WHERE status='pending' AND source='channel-link'
                      AND progress_stage IN ('fetching','downloading')
                      AND (input_files_json='[]' OR input_files_json='' OR input_files_json IS NULL)"""
            )
            rows = list(db.execute("SELECT * FROM jobs WHERE status='pending' ORDER BY created_at,id"))
        extract_jobs: list[Job] = []
        for r in rows:
            files = json.loads(r["input_files_json"] or "[]")
            source = str(r["source"] or "telegram")
            source_link = r["source_link"]
            if files:
                extract_jobs.append(self._job(r))
                continue
            if source == "channel-link" and source_link:
                # Ensure claimable by ingest worker.
                with self.connect() as db:
                    db.execute(
                        """UPDATE jobs SET progress_stage='queued', progress_file='waiting',
                            updated_at=CURRENT_TIMESTAMP
                            WHERE id=? AND status='pending'
                              AND (progress_stage IS NULL OR progress_stage NOT IN ('queued','fetching','downloading'))""",
                        (int(r["id"]),),
                    )
                continue
            with self.connect() as db:
                db.execute(
                    "UPDATE jobs SET status='failed', error=?, completed_at=CURRENT_TIMESTAMP, "
                    "updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    ("Interrupted before download completed", int(r["id"])),
                )
        return [], extract_jobs

    def claim_next_channel_download(self) -> dict[str, Any] | None:
        """Atomically claim the oldest queued channel-link download.

        Marks it fetching in the same transaction so the dashboard updates even if
        Telegram resolution hangs afterward.
        """
        with self.connect() as db:
            # Recover claims stuck forever (process crash mid-fetch).
            db.execute(
                """UPDATE jobs SET progress_stage='queued', progress_file='waiting',
                    progress_done=0, progress_total=0, updated_at=CURRENT_TIMESTAMP
                    WHERE status='pending' AND source='channel-link'
                      AND progress_stage IN ('fetching','downloading')
                      AND updated_at < datetime('now', '-10 minutes')"""
            )
            # Pull a small batch and filter in Python — avoids brittle SQL on input_files_json.
            rows = list(db.execute(
                """SELECT id, message_id, source_link, input_files_json, progress_stage
                   FROM jobs
                   WHERE status='pending' AND source='channel-link'
                     AND source_link IS NOT NULL AND TRIM(source_link) != ''
                   ORDER BY id ASC LIMIT 50"""
            ))
            target = None
            waiting = 0
            for row in rows:
                try:
                    files = json.loads(row["input_files_json"] or "[]")
                except (TypeError, ValueError):
                    files = []
                if files:
                    continue
                stage = (row["progress_stage"] or "queued").strip().lower()
                if stage in {"fetching", "downloading"}:
                    continue
                # Treat NULL/empty/waiting/queued as claimable.
                if target is None:
                    target = row
                else:
                    waiting += 1
            if target is None:
                return None
            job_id = int(target["id"])
            cur = db.execute(
                """UPDATE jobs SET progress_stage='fetching', progress_file='resolving message',
                    progress_done=0, progress_total=0, progress_index=0, progress_count=0,
                    updated_at=CURRENT_TIMESTAMP
                    WHERE id=? AND status='pending'
                      AND (progress_stage IS NULL OR LOWER(progress_stage) NOT IN ('fetching','downloading'))""",
                (job_id,),
            )
            if cur.rowcount != 1:
                return None
            return {
                "job_id": job_id,
                "job_key": int(target["message_id"]),
                "url": str(target["source_link"]).strip(),
                "waiting": waiting,
            }

    def ingest_status(self) -> dict[str, Any]:
        """Snapshot for dashboard/health: queued vs active download rows."""
        with self.connect() as db:
            rows = list(db.execute(
                """SELECT id, progress_stage, input_files_json, source_link
                   FROM jobs WHERE status='pending' AND source='channel-link'
                   ORDER BY id ASC"""
            ))
        queued = 0
        active = None
        for row in rows:
            try:
                files = json.loads(row["input_files_json"] or "[]")
            except (TypeError, ValueError):
                files = []
            if files:
                continue
            stage = (row["progress_stage"] or "queued").strip().lower()
            if stage in {"fetching", "downloading"}:
                active = {"job_id": int(row["id"]), "stage": stage}
            else:
                queued += 1
        return {"queued": queued, "active": active}

    def count_queued_channel_downloads(self) -> int:
        return int(self.ingest_status()["queued"])

    def mark_running(self,job_id):
        with self.connect() as db: db.execute("UPDATE jobs SET status='running',attempts=attempts+1,started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,error=NULL WHERE id=?",(job_id,))

    def update_progress(self,job_id,stage,done,total,filename,index,count):
        with self.connect() as db:
            db.execute("""UPDATE jobs SET progress_stage=?,progress_done=?,progress_total=?,progress_file=?,
                progress_index=?,progress_count=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (stage,int(done),int(total),filename,int(index),int(count),job_id))

    def clear_progress(self,job_id):
        with self.connect() as db:
            db.execute("""UPDATE jobs SET progress_stage=NULL,progress_done=0,progress_total=0,
                progress_file=NULL,progress_index=0,progress_count=0,updated_at=CURRENT_TIMESTAMP WHERE id=?""",(job_id,))

    def progress_for_job(self,job_id):
        with self.connect() as db:
            r=db.execute("""SELECT status,progress_stage,progress_done,progress_total,progress_file,
                progress_index,progress_count FROM jobs WHERE id=?""",(job_id,)).fetchone()
        if not r: return None
        return {'status':r['status'],'stage':r['progress_stage'],'done':int(r['progress_done']),
                'total':int(r['progress_total']),'file':r['progress_file'],
                'index':int(r['progress_index']),'count':int(r['progress_count'])}

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

    def summary_data_for_job(self, job_id: int) -> dict[str, Any] | None:
        with self.connect() as db:
            r = db.execute(
                "SELECT summary_data, summary_json FROM jobs WHERE id=? AND status='completed'",
                (job_id,),
            ).fetchone()
        if not r:
            return None
        if r["summary_data"]:
            try:
                data = json.loads(r["summary_data"])
                if isinstance(data, dict):
                    return data
            except (TypeError, ValueError):
                pass
        path_value = r["summary_json"]
        if path_value:
            try:
                path = Path(path_value)
                if path.is_file():
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        return data
            except (OSError, TypeError, ValueError):
                pass
        return None

    def get_total_compressed_size(self) -> int:
        """Sum the on-disk size of every input (compressed) file referenced by any job."""
        with self.connect() as db:
            rows=db.execute("SELECT input_files_json FROM jobs").fetchall()
        total=0
        for row in rows:
            try: files=json.loads(row['input_files_json'])
            except (TypeError, ValueError): continue
            for file_path in files:
                try: total+=Path(file_path).stat().st_size
                except OSError: continue
        return total

    def cleanup_all_files(self) -> dict[str, Any]:
        """Remove everything in inbox_dir and work_dir, and clear output_dir.

        Returns a summary dict with the number of files removed and bytes freed.
        Also clears output path pointers on job rows so downloads do not 404 on deleted files.
        """
        files_removed=0; bytes_freed=0
        for directory in (self.inbox_dir, self.work_dir, self.output_dir):
            if not directory or not directory.exists(): continue
            for entry in directory.iterdir():
                try:
                    if entry.is_file() or entry.is_symlink():
                        bytes_freed+=entry.stat().st_size; files_removed+=1
                        entry.unlink(missing_ok=True)
                    elif entry.is_dir():
                        for sub in entry.rglob('*'):
                            if sub.is_file():
                                bytes_freed+=sub.stat().st_size; files_removed+=1
                        shutil.rmtree(entry, ignore_errors=True)
                except OSError: continue
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET output_text=NULL, summary_json=NULL, updated_at=CURRENT_TIMESTAMP "
                "WHERE output_text IS NOT NULL OR summary_json IS NOT NULL"
            )
        return {'files_removed': files_removed, 'bytes_freed': bytes_freed}

    def _read_config(self) -> dict[str, Any]:
        if not self.config_path.exists(): return {}
        try:
            with self.config_path.open('r', encoding='utf-8') as fh: return json.load(fh)
        except (OSError, ValueError): return {}

    def _write_config(self, data: dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp_path = self.config_path.with_suffix('.json.tmp')
        with tmp_path.open('w', encoding='utf-8') as fh: json.dump(data, fh)
        tmp_path.replace(self.config_path)

    def store_config(self, key: str, value: Any) -> None:
        data = self._read_config(); data[key] = value; self._write_config(data)

    def get_config(self, key: str, default: Any = None) -> Any:
        return self._read_config().get(key, default)

    def get_extraction_workers(self, default: int = 1) -> int:
        try: return int(self.get_config('extraction_workers', default))
        except (TypeError, ValueError): return default

    def save_credentials(self, job_id: int, credentials: list) -> None:
        with self.connect() as db:
            for cred in credentials:
                db.execute('''INSERT INTO extracted_credentials 
                    (job_id, access_key, secret_key, region, file_path, line_number)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (job_id, cred['access_key'], cred['secret_key'], cred.get('region', 'unknown'),
                     cred.get('file', ''), cred.get('line', 0)))

    def get_all_credentials(self, *, mask_secrets: bool = False) -> list:
        with self.connect() as db:
            cursor = db.execute(
                '''SELECT access_key, secret_key, region, created_at 
                   FROM extracted_credentials ORDER BY created_at DESC''')
            rows = []
            for r in cursor:
                secret = r[1] or ''
                if mask_secrets and secret:
                    secret = secret[:16] + ('…' if len(secret) > 16 else '')
                rows.append({'access_key': r[0], 'secret_key': secret, 'region': r[2], 'created_at': r[3]})
            return rows

    def clear_all_credentials(self) -> int:
        with self.connect() as db:
            cursor = db.execute('DELETE FROM extracted_credentials')
            return cursor.rowcount

    def stop_all_jobs(self) -> int:
        """Mark all pending and running jobs as failed. Returns count updated."""
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE jobs SET status='failed', error='Stopped by operator', "
                "completed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP "
                "WHERE status IN ('pending', 'running')")
            return cursor.rowcount
