from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import os
import aiohttp
from pathlib import Path
from urllib.parse import quote_plus
from typing import Any
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import (
    PhoneNumberInvalidError,
    CodeInvalidError,
    PasswordHashInvalidError,
    SessionPasswordNeededError,
)
from secure_logging import recent_activity_logs

LOG = logging.getLogger('dashboard')
SESSION_MAX_AGE = 12 * 60 * 60


def _human(n: float) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB': return f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} GB'


class Dashboard:
    def __init__(self, settings, db, password_store, pipeline: Any):
        self.s=settings; self.db=db; self.passwords=password_store; self.pipeline=pipeline
        base=Path(__file__).parent
        self.templates=Jinja2Templates(directory=str(base/'templates'))
        self.app=FastAPI(title='Archive Scanner', docs_url=None, redoc_url=None)
        self.app.mount('/static', StaticFiles(directory=str(base/'static')), name='static')
        self._routes(); self._middleware()

    def _sign(self, payload: str) -> str:
        return hmac.new(self.s.dashboard_secret, payload.encode(), hashlib.sha256).hexdigest()

    def _issue_session(self) -> str:
        issued = str(int(time.time()))
        nonce = secrets.token_hex(8)
        return f"{issued}.{nonce}.{self._sign('dashboard-session:' + issued + ':' + nonce)}"

    def _valid_session(self, token: str) -> bool:
        if not token:
            return False
        try:
            issued_str, nonce, mac = token.split('.', 2)
            issued = int(issued_str)
        except ValueError:
            return False
        expected = self._sign('dashboard-session:' + issued_str + ':' + nonce)
        if not hmac.compare_digest(mac, expected):
            return False
        age = time.time() - issued
        return 0 <= age <= SESSION_MAX_AGE

    def _csrf(self, request: Request) -> str:
        session = request.cookies.get('scanner_session', '')
        return hmac.new(self.s.dashboard_secret, f'dashboard-csrf:{session}'.encode(), hashlib.sha256).hexdigest()

    def _authorized(self, request: Request): return self._valid_session(request.cookies.get('scanner_session',''))
    def _require(self, request: Request):
        if not self._authorized(request): raise HTTPException(401,'Authentication required')
    def _require_post(self, request: Request, csrf: str):
        self._require(request)
        expected = self._csrf(request)
        if not csrf or not hmac.compare_digest(csrf, expected):
            raise HTTPException(403,'Invalid CSRF token')

    def _expand_message_range(self, url: str) -> list[str]:
        """
        Expand message range URLs into individual message URLs.

        Examples:
        - https://t.me/channel/100-105 -> [https://t.me/channel/100, .../101, .../102, .../103, .../104, .../105]
        - https://t.me/c/12345/50-52 -> [https://t.me/c/12345/50, .../51, .../52]
        - https://t.me/channel/100 -> [https://t.me/channel/100]
        """
        from urllib.parse import urlparse

        parsed = urlparse(url.strip())
        if parsed.scheme != 'https' or parsed.hostname not in {'t.me', 'www.t.me', 'telegram.me', 'www.telegram.me'}:
            raise ValueError('Use an https://t.me message link')

        parts = [p for p in parsed.path.split('/') if p]
        if len(parts) < 2:
            raise ValueError('Invalid message link format')

        message_part = parts[-1]

        # Check if it's a range (contains dash with numbers on both sides)
        if '-' in message_part:
            range_parts = message_part.split('-')
            if len(range_parts) != 2:
                raise ValueError('Invalid range format. Use: channel/START-END')

            try:
                start = int(range_parts[0])
                end = int(range_parts[1])
            except ValueError:
                raise ValueError('Range must be numbers only (e.g., 100-105)')

            if start > end:
                raise ValueError('Range start must be <= end')

            if end - start + 1 > 500:
                raise ValueError('Range too large (max 500 messages at once)')

            # Build base URL
            base_parts = parts[:-1]
            base_url = f"https://t.me/{'/'.join(base_parts)}"

            # Expand to individual URLs and validate each
            urls = []
            for msg_id in range(start, end + 1):
                candidate = f"{base_url}/{msg_id}"
                self.pipeline.validate_channel_link(candidate)
                urls.append(candidate)
            return urls
        else:
            # Single message, validate and return as-is
            if not message_part.isdigit():
                raise ValueError('Message ID must be a number')

            # Validate the URL format using pipeline validator
            self.pipeline.validate_channel_link(url)
            return [url]

    def _middleware(self):
        self.app.add_middleware(SessionMiddleware, secret_key=self.s.dashboard_secret.hex(), max_age=900)

        @self.app.middleware('http')
        async def security_headers(request, call_next):
            response=await call_next(request)
            response.headers['X-Content-Type-Options']='nosniff'
            response.headers['X-Frame-Options']='DENY'
            response.headers['Referrer-Policy']='no-referrer'
            response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
            response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:"
            response.headers['Cache-Control']='no-store'
            return response

    def _routes(self):
        @self.app.get('/health')
        async def health():
            payload = {'ok': True}
            if self.pipeline is not None:
                ingest = await asyncio.to_thread(self.db.ingest_status)
                hb = getattr(self.pipeline, '_ingest_worker_heartbeat', 0.0) or 0.0
                payload.update({
                    'ingest_queued': ingest.get('queued', 0),
                    'ingest_active': ingest.get('active'),
                    'ingest_heartbeat_age_s': (None if not hb else round(max(0.0, time.monotonic() - hb), 2)),
                })
            return payload

        @self.app.get('/login')
        async def login_page(request: Request):
            if self._authorized(request): return RedirectResponse('/',303)
            return self.templates.TemplateResponse(request=request,name='login.html',context={'error':None})

        @self.app.post('/login')
        async def login(request: Request,password: str=Form(...)):
            # Hash both sides so compare_digest stays constant-time across length mismatches.
            provided = hashlib.sha256(password.encode('utf-8')).hexdigest()
            expected = hashlib.sha256(self.s.dashboard_password.encode('utf-8')).hexdigest()
            if not hmac.compare_digest(provided, expected):
                await asyncio.sleep(0.75)
                return self.templates.TemplateResponse(request=request,name='login.html',context={'error':'Incorrect password'},status_code=401)
            response=RedirectResponse('/',303)
            secure=request.headers.get('x-forwarded-proto',request.url.scheme)=='https'
            response.set_cookie('scanner_session',self._issue_session(),httponly=True,secure=secure,samesite='strict',max_age=SESSION_MAX_AGE,path='/')
            return response

        @self.app.post('/logout')
        async def logout(request: Request,csrf: str=Form(...)):
            self._require_post(request,csrf); response=RedirectResponse('/login',303); response.delete_cookie('scanner_session',path='/'); return response

        @self.app.get('/')
        async def home(request: Request,notice: str|None=None,error: str|None=None):
            if not self._authorized(request): return RedirectResponse('/login',303)
            if self.pipeline is not None:
                self.pipeline.kick_ingest()
            stats=await asyncio.to_thread(self.db.stats); jobs=await asyncio.to_thread(self.db.recent,30)
            passwords=await asyncio.to_thread(self.passwords.list_masked)
            storage_bytes=await asyncio.to_thread(self.db.get_total_compressed_size)
            extraction_workers=await asyncio.to_thread(self.db.get_extraction_workers,self.s.extraction_workers)
            ingest=await asyncio.to_thread(self.db.ingest_status)
            return self.templates.TemplateResponse(request=request,name='dashboard.html',context={'stats':stats,'jobs':jobs,'passwords':passwords,'csrf':self._csrf(request),'notice':notice,'error':error,'storage_bytes':storage_bytes,'storage_human':_human(storage_bytes),'extraction_workers':extraction_workers,'ingest':ingest})

        @self.app.get('/storage-info')
        async def storage_info(request: Request):
            self._require(request)
            total_bytes=await asyncio.to_thread(self.db.get_total_compressed_size)
            return {'total_bytes':total_bytes,'total_human_readable':_human(total_bytes)}

        @self.app.post('/cleanup-files')
        async def cleanup_files(request: Request,csrf: str=Form(...)):
            self._require_post(request,csrf)
            try:
                summary=await asyncio.to_thread(self.db.cleanup_all_files)
                files_removed=summary['files_removed']; freed=_human(summary['bytes_freed'])
                LOG.info('Cleanup performed',extra={'files_removed':files_removed,'bytes_freed':summary['bytes_freed'],'stage':'cleanup'})
                notice=f'Cleanup complete: removed {files_removed} file(s), freed {freed}'
                return RedirectResponse(f'/?notice={quote_plus(notice)}',303)
            except Exception as exc:
                LOG.exception('Cleanup failed',extra={'stage':'cleanup'})
                return RedirectResponse(f'/?error={quote_plus(f"Cleanup failed: {exc}")}',303)

        @self.app.post('/passwords')
        async def add_password(request: Request,password: str=Form(...),csrf: str=Form(...)):
            self._require_post(request,csrf)
            try: added=await asyncio.to_thread(self.passwords.add,password)
            except ValueError as exc: return RedirectResponse(f'/?error={quote_plus(str(exc))}',303)
            return RedirectResponse('/?notice=Password+added' if added else '/?notice=Password+already+exists',303)

        @self.app.post('/passwords/bulk')
        async def add_passwords_bulk(request: Request,passwords: str=Form(...),csrf: str=Form(...)):
            self._require_post(request,csrf)
            try: added,skipped=await asyncio.to_thread(self.passwords.add_many,passwords)
            except ValueError as exc: return RedirectResponse(f'/?error={quote_plus(str(exc))}',303)
            return RedirectResponse(f'/?notice={quote_plus(f"Added {added}, skipped {skipped} duplicate(s)")}',303)

        @self.app.post('/passwords/clear')
        async def clear_passwords(request: Request,csrf: str=Form(...)):
            self._require_post(request,csrf)
            removed=await asyncio.to_thread(self.passwords.clear)
            return RedirectResponse(f'/?notice={quote_plus(f"Removed {removed} password(s)")}',303)

        @self.app.post('/passwords/{password_id}/delete')
        async def delete_password(password_id: str,request: Request,csrf: str=Form(...)):
            self._require_post(request,csrf); await asyncio.to_thread(self.passwords.delete,password_id)
            return RedirectResponse('/?notice=Password+removed',303)

        @self.app.post('/config/extraction-workers')
        async def set_extraction_workers(request: Request,workers: int=Form(...),csrf: str=Form(...)):
            self._require_post(request,csrf)
            if workers<1 or workers>24:
                return RedirectResponse(f'/?error={quote_plus("Workers must be between 1 and 24")}',303)
            await asyncio.to_thread(self.db.store_config,'extraction_workers',workers)
            if self.pipeline is not None and hasattr(self.pipeline, 'set_extraction_workers'):
                self.pipeline.set_extraction_workers(workers)
            LOG.info('Extraction workers updated',extra={'workers':workers,'stage':'config'})
            return RedirectResponse(f'/?notice={quote_plus(f"Extraction workers set to {workers}")}',303)

        @self.app.post('/channel-links')
        async def add_link(request: Request, url: str=Form(...), csrf: str=Form(...)):
            self._require_post(request, csrf)

            # Parse and expand range URLs
            urls_to_submit = []
            try:
                urls_to_submit = await asyncio.to_thread(self._expand_message_range, url)
            except ValueError as exc:
                return RedirectResponse(f'/?error={quote_plus(str(exc))}', 303)

            if not urls_to_submit:
                return RedirectResponse(f'/?error={quote_plus("No valid URLs to submit")}', 303)

            # Queue sequentially via ingest worker to avoid Telegram flood failures.
            # Each URL creates a pending job immediately so it appears in Recent jobs.
            for submit_url in urls_to_submit:
                await self.pipeline.enqueue_channel_link(submit_url)

            count = len(urls_to_submit)
            msg = f"Queued {count} download(s)" if count > 1 else "Channel download queued"
            LOG.info('Channel links accepted', extra={'stage': 'web-ingest', 'count': count})
            return RedirectResponse(f'/?notice={quote_plus(msg)}', 303)

        @self.app.post('/jobs/stop-all')
        async def stop_all_jobs(request: Request, csrf: str = Form(...)):
            """Stop all running and pending jobs."""
            self._require_post(request, csrf)
            if hasattr(self.pipeline, 'request_stop_all'):
                count = await self.pipeline.request_stop_all()
            else:
                count = await asyncio.to_thread(self.db.stop_all_jobs)
            return RedirectResponse(f'/?notice={quote_plus(f"Stopped {count} job(s)")}', 303)

        @self.app.get('/jobs/{job_id}/progress')
        async def job_progress(job_id: int,request: Request):
            self._require(request)
            if self.pipeline is not None:
                self.pipeline.kick_ingest()
            data=await asyncio.to_thread(self.db.progress_for_job,job_id)
            if data is None: raise HTTPException(404,'Job not found')
            pct=int(data['done']*100/data['total']) if data['total'] else 0
            return {
                'status':data['status'],'stage':data['stage'],
                'done':data['done'],'total':data['total'],'percent':pct,
                'file':data['file'],'index':data['index'],'count':data['count'],
            }

        @self.app.get('/jobs/{job_id}/scan-metrics')
        async def job_scan_metrics(job_id: int, request: Request):
            """Return scan metrics (files_scanned, findings) for a completed job."""
            self._require(request)
            summary_json = await asyncio.to_thread(self.db.summary_data_for_job, job_id)
            if not summary_json:
                raise HTTPException(404, 'Job not found or summary unavailable')
            return {
                'files_scanned': summary_json.get('files_scanned', 0),
                'findings': summary_json.get('findings', 0),
                'by_type': summary_json.get('by_type', {})
            }

        @self.app.get('/jobs/{job_id}/{kind}')
        async def download(job_id: int,kind: str,request: Request):
            self._require(request)
            if kind not in {'report','summary'}: raise HTTPException(404)
            value=await asyncio.to_thread(self.db.output_for_job,job_id,kind)
            if not value: raise HTTPException(404,'Output unavailable')
            path=Path(value).resolve()
            try: path.relative_to(self.s.output_dir.resolve())
            except ValueError: raise HTTPException(403,'Invalid output path')
            if not path.is_file(): raise HTTPException(404,'File missing')
            return FileResponse(path,filename=path.name,media_type='application/json' if kind=='summary' else 'text/plain')

        @self.app.get('/logs')
        async def get_logs(request: Request):
            """Return recent activity logs."""
            self._require(request)
            return await asyncio.to_thread(recent_activity_logs, 30)

        @self.app.get('/credentials')
        async def get_credentials(request: Request):
            self._require(request)
            return await asyncio.to_thread(self.db.get_all_credentials, mask_secrets=True)

        @self.app.post('/credentials/clear-all')
        async def clear_creds(request: Request, csrf: str = Form(...)):
            self._require_post(request, csrf)
            count = await asyncio.to_thread(self.db.clear_all_credentials)
            return RedirectResponse(f'/?notice=Deleted+{count}+credentials', 303)

        @self.app.get('/credentials/export')
        async def export_creds(request: Request):
            self._require(request)
            creds = await asyncio.to_thread(self.db.get_all_credentials, mask_secrets=False)
            lines = []
            for c in creds:
                line = f"{c['access_key']}:{c['secret_key']}:{c['region']}"
                lines.append(line)
            content = '\n'.join(lines) + '\n' if lines else ''
            return Response(content, media_type='text/plain',
                            headers={'Content-Disposition': 'attachment; filename=credentials.txt'})

        @self.app.get('/session-regenerate')
        async def session_regenerate(request: Request):
            self._require(request)
            return self.templates.TemplateResponse(
                request=request,
                name='session_regenerate.html',
                context={'csrf': self._csrf(request), 'step': 1}
            )

        @self.app.post('/session-regenerate/send-code')
        async def send_code(request: Request, phone_number: str = Form(...), csrf: str = Form(...)):
            self._require_post(request, csrf)
            try:
                temp_client = TelegramClient(StringSession(), self.s.api_id, self.s.api_hash)
                await temp_client.connect()
                result = await temp_client.send_code_request(phone_number)

                request.session['phone_hash'] = result.phone_code_hash
                request.session['phone_number'] = phone_number

                await temp_client.disconnect()
                return self.templates.TemplateResponse(
                    request=request,
                    name='session_regenerate.html',
                    context={'csrf': self._csrf(request), 'step': 2, 'phone': phone_number}
                )
            except PhoneNumberInvalidError:
                return RedirectResponse(f'/?error={quote_plus("Invalid phone number")}', 303)
            except Exception as e:
                LOG.exception('Failed to send code')
                return RedirectResponse(f'/?error={quote_plus(str(e))}', 303)

        @self.app.post('/session-regenerate/verify-code')
        async def verify_code(request: Request, code: str = Form(...), password: str = Form(''), csrf: str = Form(...)):
            self._require_post(request, csrf)
            try:
                phone_hash = request.session.get('phone_hash')
                phone_number = request.session.get('phone_number')

                if not phone_hash:
                    return RedirectResponse('/?error=Session+expired', 303)

                temp_client = TelegramClient(StringSession(), self.s.api_id, self.s.api_hash)
                await temp_client.connect()

                # Retry logic: sometimes first attempt times out
                max_attempts = 3
                signed_in = False

                for attempt in range(max_attempts):
                    try:
                        await temp_client.sign_in(phone_number, code, phone_code_hash=phone_hash)
                        signed_in = True
                        break
                    except SessionPasswordNeededError:
                        if not password:
                            await temp_client.disconnect()
                            return RedirectResponse(
                                f'/?error={quote_plus("2FA password required")}', 303
                            )
                        await temp_client.sign_in(password=password)
                        signed_in = True
                        break
                    except CodeInvalidError:
                        raise
                    except PasswordHashInvalidError:
                        raise
                    except Exception as e:
                        if attempt < max_attempts - 1:
                            LOG.warning(f'Sign-in attempt {attempt + 1} failed: {e}, retrying...')
                            await asyncio.sleep(0.5)
                            continue
                        raise

                if not signed_in:
                    raise RuntimeError('Sign-in did not complete')

                new_session = temp_client.session.save()
                # Persist where the pipeline actually loads from on restart.
                await asyncio.to_thread(self.pipeline._persist_session_string, new_session)

                await temp_client.disconnect()
                request.session.pop('phone_hash', None)
                request.session.pop('phone_number', None)

                # AUTO-REDEPLOY (optional)
                try:
                    api_token = os.getenv('RAILWAY_API_TOKEN')
                    service_id = os.getenv('RAILWAY_SERVICE_ID', '').strip()

                    if api_token and service_id:
                        async with aiohttp.ClientSession() as session:
                            headers = {'Authorization': f'Bearer {api_token}'}
                            mutation = f"""
                            mutation {{
                              deploymentTrigger(input: {{
                                serviceId: "{service_id}"
                              }}) {{
                                deployment {{
                                  id
                                }}
                              }}
                            }}
                            """

                            async with session.post(
                                'https://api.railway.app/graphql',
                                json={'query': mutation},
                                headers=headers,
                                timeout=aiohttp.ClientTimeout(total=10)
                            ) as resp:
                                if resp.status == 200:
                                    LOG.info('Redeploy triggered', extra={'stage': 'session'})
                                else:
                                    LOG.error(f'Redeploy failed: {resp.status}', extra={'stage': 'session'})
                    elif api_token and not service_id:
                        LOG.warning('RAILWAY_API_TOKEN set but RAILWAY_SERVICE_ID missing; skip redeploy', extra={'stage': 'session'})
                except Exception as e:
                    LOG.error(f'Redeploy error: {e}', extra={'stage': 'session'})

                LOG.info('Telegram session regenerated', extra={'stage': 'session'})
                notice = 'Session updated. Restart or redeploy the service to apply it.'
                return RedirectResponse(f'/?notice={quote_plus(notice)}', 303)

            except CodeInvalidError:
                return RedirectResponse(f'/?error={quote_plus("Invalid code - check digits and try again")}', 303)
            except PasswordHashInvalidError:
                return RedirectResponse(f'/?error={quote_plus("Wrong 2FA password")}', 303)
            except Exception as e:
                error_msg = str(e)
                if "expired" in error_msg.lower():
                    error_msg = "Code expired. Request a new code and try again."
                LOG.exception('Failed to verify code', extra={'stage': 'session'})
                return RedirectResponse(f'/?error={quote_plus(error_msg)}', 303)
