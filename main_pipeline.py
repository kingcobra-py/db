from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
import uvicorn
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.tl.types import PeerChannel
from config import Settings, load_settings
from database_manager import DatabaseManager, Job
from extractor import ArchiveProcessor
from parse_credentials import scan_tree, write_results
from password_store import PasswordStore
from secure_logging import configure_logging
from webapp import Dashboard

LOG=logging.getLogger('pipeline')

@dataclass(frozen=True,slots=True)
class QueueItem: job_id:int

class Pipeline:
    def __init__(self,s:Settings):
        self.s=s; self.db=DatabaseManager(s.database_path); self.queue:asyncio.Queue[QueueItem]=asyncio.Queue(maxsize=100)
        self.client=TelegramClient(StringSession(s.string_session),s.api_id,s.api_hash)
        self.passwords=PasswordStore(s.password_store_path,s.password_encryption_key)
        self.extractor=ArchiveProcessor(s,self.passwords.list_plain)

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
        if not chat_id: return
        try: await self.client.send_message(chat_id,text,reply_to=reply_to)
        except Exception: LOG.exception('Progress notification failed',extra={'message_id':reply_to,'stage':'notification'})

    async def queue_messages(self,*,messages:list,job_key:int,chat_id:int,user_id:int,source:str,source_link:str|None=None,notify:bool=True):
        inbox=self.s.inbox_dir/str(job_key); inbox.mkdir(parents=True,exist_ok=True,mode=0o700)
        if notify: await self.notify(chat_id,'📥 Authorized upload received. Downloading…',messages[0].id if messages else None)
        files=[]; total=0
        try:
            for index,message in enumerate(messages,1):
                if not message.media: continue
                filename=Path(getattr(message.file,'name',None) or f'upload-{index}.bin').name
                destination=inbox/filename
                if destination.exists(): destination=inbox/f'{index}-{filename}'
                await message.download_media(file=str(destination))
                total+=destination.stat().st_size
                if total>self.s.max_download_bytes: raise ValueError('Download exceeds MAX_DOWNLOAD_BYTES')
                files.append(str(destination))
            if not files: raise ValueError('Telegram message has no downloadable media')
            job_id=await asyncio.to_thread(self.db.create_job,job_key,chat_id,user_id,files,source,source_link)
            await self.queue.put(QueueItem(job_id))
            if notify: await self.notify(chat_id,f'✅ Downloaded {len(files)} file(s); queued.',messages[0].id)
            return job_id
        except Exception:
            shutil.rmtree(inbox,ignore_errors=True); raise

    async def ingest_channel_link(self,url:str):
        job_key=self.web_job_id(url)
        try:
            target,message_id=self.validate_channel_link(url)
            entity=await self.client.get_entity(PeerChannel(int(target[2:]))) if target.startswith('c:') else await self.client.get_entity(target)
            message=await self.client.get_messages(entity,ids=message_id)
            if not message: raise ValueError('Message is unavailable to the signed-in Telegram account')
            messages=[message]
            if message.grouped_id:
                nearby=await self.client.get_messages(entity,limit=40,offset_id=message_id+20)
                messages=sorted({m.id:m for m in [message,*nearby] if m and m.grouped_id==message.grouped_id and m.media}.values(),key=lambda m:m.id)
            await self.queue_messages(messages=messages,job_key=job_key,chat_id=0,user_id=0,source='channel-link',source_link=url,notify=False)
            LOG.info('Channel link queued',extra={'message_id':job_key,'stage':'web-ingest'})
        except Exception as exc:
            LOG.exception('Channel link ingest failed',extra={'message_id':job_key,'stage':'web-ingest'})
            job_id=await asyncio.to_thread(self.db.create_job,job_key,0,0,[],'channel-link',url)
            await asyncio.to_thread(self.db.mark_failed,job_id,f'{type(exc).__name__}: {exc}')

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
        await asyncio.to_thread(self.db.mark_running,job.id); await self.notify(job.chat_id,'🧰 Validating and extracting archive…',job.message_id)
        try:
            root=await asyncio.to_thread(self.extractor.process,job.message_id,[Path(p) for p in job.input_files])
            await self.notify(job.chat_id,'🔎 Scanning .txt, .csv, and .log files…',job.message_id)
            findings,summary=await asyncio.to_thread(scan_tree,root,self.s.max_scan_file_bytes,self.s.fingerprint_key)
            text,summary_json=await asyncio.to_thread(write_results,self.s.output_dir,job.message_id,findings,summary)
            await asyncio.to_thread(self.db.mark_completed,job.id,str(text),str(summary_json),summary)
            if job.chat_id:
                await self.client.send_file(job.chat_id,str(text),caption=f"✅ Scan complete. Files: {summary['files_scanned']}; redacted findings: {summary['findings']}.",reply_to=job.message_id)
                await self.client.send_file(job.chat_id,str(summary_json),caption='Machine-readable summary.',reply_to=job.message_id)
        except Exception as exc:
            LOG.exception('Job failed',extra={'job_id':job.id,'message_id':job.message_id,'user_id':job.user_id,'stage':'processing'})
            await asyncio.to_thread(self.db.mark_failed,job.id,f'{type(exc).__name__}: {exc}')
            await self.notify(job.chat_id,f'❌ Processing failed safely: {type(exc).__name__}: {exc}',job.message_id)

    async def worker(self):
        while True:
            item=await self.queue.get()
            try:
                job=await asyncio.to_thread(self.db.get_job,item.job_id)
                if job and job.status in {'pending','running'}: await self.process(job)
            finally: self.queue.task_done()

    async def run(self):
        await asyncio.to_thread(self.db.initialize); self.register(); await self.client.start()
        for job in await asyncio.to_thread(self.db.restore_interrupted_jobs): await self.queue.put(QueueItem(job.id))
        dashboard=Dashboard(self.s,self.db,self.passwords,self)
        server=uvicorn.Server(uvicorn.Config(dashboard.app,host=self.s.host,port=self.s.port,log_config=None,access_log=False))
        worker=asyncio.create_task(self.worker(),name='single-job-worker'); web=asyncio.create_task(server.serve(),name='web-dashboard')
        LOG.info('Telegram scanner and web dashboard started')
        try: await self.client.run_until_disconnected()
        finally:
            server.should_exit=True; worker.cancel(); await asyncio.gather(worker,web,return_exceptions=True); await self.client.disconnect()

async def main():
    s = load_settings()
    configure_logging(s.log_level)
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