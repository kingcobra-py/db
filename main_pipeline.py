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
from password_store import PasswordStore
from secure_logging import configure_logging
from webapp import Dashboard

LOG=logging.getLogger('pipeline')

@dataclass(frozen=True,slots=True)
class QueueItem: job_id:int

class Pipeline:
    def __init__(self,s:Settings):
        self.s=s
        self.db=DatabaseManager(s.database_path,s.inbox_dir,s.work_dir,s.output_dir)
        self.queue:asyncio.Queue[QueueItem]=asyncio.Queue(maxsize=100)
        self.ingest_queue:asyncio.Queue[str]=asyncio.Queue(maxsize=500)
        self._lock_file=None
        self._acquire_session_lock()
        self.client=TelegramClient(StringSession(self._load_session_string()),s.api_id,s.api_hash)
        self.passwords=PasswordStore(s.password_store_path,s.password_encryption_key)
        self.extractor=ArchiveProcessor(s,self.passwords.list_plain)
        workers=max(1, min(24, self.db.get_extraction_workers(s.extraction_workers)))
        self.semaphore=asyncio.Semaphore(workers)
        self._stop_requested=asyncio.Event()
        self._active_tasks:set[asyncio.Task]=set()

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
            session_string=session_string or self.client.session.save()
            self.s.session_file_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            self.s.session_file_path.write_text(session_string,encoding='utf-8')
            self.db.store_config('TELEGRAM_STRING_SESSION', session_string)
        except Exception:
            LOG.exception('Failed to persist Telegram session file',extra={'stage':'startup'})

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
        if not chat_id: return None
        try: return await self.client.send_message(chat_id,text,reply_to=reply_to)
        except Exception: LOG.exception('Progress notification failed',extra={'message_id':reply_to,'stage':'notification'}); return None

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

    async def queue_messages(self,*,messages:list,job_key:int,chat_id:int,user_id:int,source:str,source_link:str|None=None,notify:bool=True):
        inbox=self.s.inbox_dir/str(job_key); inbox.mkdir(parents=True,exist_ok=True,mode=0o700)
        media_messages=[m for m in messages if m.media]
        file_count=len(media_messages)
        progress=None
        if notify:
            progress=await self.notify(chat_id,f'📥 Authorized upload received. Downloading {file_count} file(s)…',messages[0].id if messages else None)
        # Create the job row up front (empty files, still 'pending') so the web
        # dashboard has something to poll while the download is running.
        job_id=await asyncio.to_thread(self.db.create_job,job_key,chat_id,user_id,[],source,source_link)
        files=[]; total=0
        try:
            if self._stop_requested.is_set():
                raise ValueError('Stopped by operator')
            available = shutil.disk_usage(self.s.inbox_dir).free
            if available <= self.s.min_free_bytes:
                raise ValueError('Insufficient disk space before download')
            for index,message in enumerate(media_messages,1):
                if self._stop_requested.is_set():
                    raise ValueError('Stopped by operator')
                filename=Path(getattr(message.file,'name',None) or f'upload-{index}.bin').name
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
                await asyncio.to_thread(self.db.update_progress,job_id,'downloading',0,0,filename,index,file_count)
                await message.download_media(
                    file=str(destination),
                    progress_callback=self._make_progress_callback(progress,job_id,index,file_count,filename),
                )
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
            if not files: raise ValueError('Telegram message has no downloadable media')
            # Fill in the downloaded files and re-queue as pending for the worker.
            await asyncio.to_thread(self.db.create_job,job_key,chat_id,user_id,files,source,source_link)
            await asyncio.to_thread(self.db.clear_progress,job_id)
            await self.queue.put(QueueItem(job_id))
            if notify: await self.notify(chat_id,f'✅ Downloaded {len(files)} file(s); queued.',messages[0].id)
            LOG.info(
                'Download finished and queued for extraction (%s file(s), %s)',
                len(files), self._human(total),
                extra={'job_id': job_id, 'message_id': job_key, 'stage': 'download'},
            )
            return job_id
        except Exception:
            await asyncio.to_thread(self.db.clear_progress,job_id)
            shutil.rmtree(inbox,ignore_errors=True); raise

    async def enqueue_channel_link(self, url: str) -> None:
        await self.ingest_queue.put(url)

    async def ingest_channel_link(self,url:str):
        job_key=self.web_job_id(url)
        try:
            target,message_id=self.validate_channel_link(url)
            entity=await self.client.get_entity(PeerChannel(int(target[2:]))) if target.startswith('c:') else await self.client.get_entity(target)
            message=await self.client.get_messages(entity,ids=message_id)
            if not message: raise ValueError('Message is unavailable to the signed-in Telegram account')
            messages=[message]
            if message.grouped_id:
                # Pull a wider nearby window so large albums are not truncated.
                nearby=await self.client.get_messages(entity,limit=100,offset_id=message_id+50)
                messages=sorted({m.id:m for m in [message,*nearby] if m and m.grouped_id==message.grouped_id and m.media}.values(),key=lambda m:m.id)
            await self.queue_messages(messages=messages,job_key=job_key,chat_id=0,user_id=0,source='channel-link',source_link=url,notify=False)
            LOG.info('Channel link queued',extra={'message_id':job_key,'stage':'web-ingest'})
        except FloodWaitError as exc:
            LOG.warning('Flood wait during channel ingest; sleeping %ss', exc.seconds, extra={'message_id':job_key,'stage':'web-ingest'})
            await asyncio.sleep(exc.seconds + 1)
            job_id=await asyncio.to_thread(self.db.create_job,job_key,0,0,[],'channel-link',url)
            await asyncio.to_thread(self.db.mark_failed,job_id,f'FloodWaitError: retry after {exc.seconds}s')
        except Exception as exc:
            LOG.exception('Channel link ingest failed',extra={'message_id':job_key,'stage':'web-ingest'})
            job_id=await asyncio.to_thread(self.db.create_job,job_key,0,0,[],'channel-link',url)
            await asyncio.to_thread(self.db.mark_failed,job_id,f'{type(exc).__name__}: {exc}')

    async def ingest_worker(self):
        """Serialize channel-link downloads to avoid Telegram flood / retry storms."""
        while True:
            url = await self.ingest_queue.get()
            try:
                if self._stop_requested.is_set():
                    job_key = self.web_job_id(url)
                    job_id = await asyncio.to_thread(self.db.create_job, job_key, 0, 0, [], 'channel-link', url)
                    await asyncio.to_thread(self.db.mark_failed, job_id, 'Stopped by operator')
                else:
                    await self.ingest_channel_link(url)
                    # Small pacing gap between channel fetches.
                    await asyncio.sleep(1.25)
            finally:
                self.ingest_queue.task_done()

    def register(self):
        @self.client.on(events.Album)
        async def album(event):
            uid=int(event.sender_id or 0)
            if uid not in self.s.allowed_users: return
            try: await self.queue_messages(messages=list(event.messages),job_key=min(m.id for m in event.messages),chat_id=int(event.chat_id),user_id=uid,source='telegram')
            except Exception as exc: await self.notify(int(event.chat_id),f'❌ Download failed: {type(exc).__name__}: {exc}',min(m.id for m in event.messages))
        @self.client.on(events.NewMessage(incoming=True))
        async def message(event):
            if not event.message.media or event.message.grouped_id is not None: return
            uid=int(event.sender_id or 0)
            if uid not in self.s.allowed_users: return
            try: await self.queue_messages(messages=[event.message],job_key=int(event.message.id),chat_id=int(event.chat_id),user_id=uid,source='telegram')
            except Exception as exc: await self.notify(int(event.chat_id),f'❌ Download failed: {type(exc).__name__}: {exc}',event.message.id)

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
            
            # Extract raw credentials and send to Telegram
            await self.notify(job.chat_id,'🔑 Extracting raw AWS credentials…',job.message_id)
            raw_creds=await asyncio.to_thread(extract_raw_credentials, root, 8, self.s.output_dir)
            
            if raw_creds:
                await asyncio.to_thread(self.db.save_credentials,job.id,raw_creds)
            
            if raw_creds and job.chat_id:
                creds_file=self.s.output_dir/f'credentials-{job.message_id}.txt'
                creds_lines=[f"{c['access_key']}:{c['secret_key']}:{c['region']}" for c in raw_creds]
                creds_file.write_text('\n'.join(creds_lines)+'\n',encoding='utf-8')
                creds_file.chmod(0o600)
                
                # Count files with credentials
                unique_files=len(set(c['file'] for c in raw_creds))
                creds_msg=(
                    f"🔑 AWS Credentials Extracted (key:secret:region)\n"
                    f"📊 Total credentials found: {len(raw_creds)}\n"
                    f"📁 Files containing credentials: {unique_files}\n"
                    f"✅ Credentials file ready to download"
                )
                await self.notify(job.chat_id,creds_msg,job.message_id)
                await self.client.send_file(job.chat_id,str(creds_file),caption=creds_msg,reply_to=job.message_id)
                LOG.info('Credentials extracted and sent',extra={'job_id':job.id,'message_id':job.message_id,'creds_count':len(raw_creds),'files_with_creds':unique_files,'stage':'processing'})
            else:
                if job.chat_id:
                    await self.notify(job.chat_id,'⚠️ No raw AWS credentials found in extracted files',job.message_id)
                LOG.info('No raw credentials found',extra={'job_id':job.id,'message_id':job.message_id,'stage':'processing'})
            
            # Send redacted reports
            if job.chat_id:
                await self.client.send_file(job.chat_id,str(text),caption=f"📄 Redacted Report (Files: {summary['files_scanned']}, Findings: {summary['findings']})",reply_to=job.message_id)
                await self.client.send_file(job.chat_id,str(summary_json),caption='📊 Machine-readable summary (JSON)',reply_to=job.message_id)
                
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
        self._stop_requested.set()
        count = await asyncio.to_thread(self.db.stop_all_jobs)
        for task in list(self._active_tasks):
            task.cancel()
        # Allow new work after the stop request has been applied.
        self._stop_requested.clear()
        LOG.info('Stop-all requested', extra={'stage': 'control', 'stopped': count})
        return count

    async def run(self):
        await asyncio.to_thread(self.db.initialize); self.register()
        try:
            await self.client.start()
        except AuthKeyDuplicatedError:
            LOG.error('Session was used from another instance simultaneously; removing local session file so it regenerates on restart',extra={'stage':'startup'})
            try: self.s.session_file_path.unlink(missing_ok=True)
            except OSError: pass
            raise
        self._persist_session_string()
        for job in await asyncio.to_thread(self.db.restore_interrupted_jobs): await self.queue.put(QueueItem(job.id))
        dashboard=Dashboard(self.s,self.db,self.passwords,self)
        server=uvicorn.Server(uvicorn.Config(dashboard.app,host=self.s.host,port=self.s.port,log_config=None,access_log=False))
        worker=asyncio.create_task(self.worker(),name='job-dispatcher')
        ingest=asyncio.create_task(self.ingest_worker(),name='channel-ingest-worker')
        web=asyncio.create_task(server.serve(),name='web-dashboard')
        LOG.info('Telegram scanner and web dashboard started', extra={'stage': 'startup'})
        try: await self.client.run_until_disconnected()
        finally:
            server.should_exit=True
            worker.cancel(); ingest.cancel()
            await asyncio.gather(worker,ingest,web,return_exceptions=True)
            await self.client.disconnect()
            self._release_session_lock()

async def main():
    s = load_settings()
    configure_logging(s.log_level, s.data_root / 'activity-logs.json')
    pipeline = Pipeline(s)
    loop = asyncio.get_running_loop()

    def request_shutdown() -> None:
        loop.call_soon_threadsafe(lambda: asyncio.ensure_future(pipeline.client.disconnect()))

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
