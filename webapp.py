from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from pathlib import Path
from urllib.parse import quote_plus
from typing import Any
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

SESSION_MAX_AGE = 12 * 60 * 60


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
        return f"{issued}.{self._sign('dashboard-session:' + issued)}"

    def _valid_session(self, token: str) -> bool:
        if not token:
            return False
        try:
            issued_str, mac = token.split('.', 1)
            issued = int(issued_str)
        except ValueError:
            return False
        if not secrets.compare_digest(mac, self._sign('dashboard-session:' + issued_str)):
            return False
        age = time.time() - issued
        return 0 <= age <= SESSION_MAX_AGE

    def _csrf(self): return hmac.new(self.s.dashboard_secret,b'dashboard-csrf',hashlib.sha256).hexdigest()
    def _authorized(self, request: Request): return self._valid_session(request.cookies.get('scanner_session',''))
    def _require(self, request: Request):
        if not self._authorized(request): raise HTTPException(401,'Authentication required')
    def _require_post(self, request: Request, csrf: str):
        self._require(request)
        if not secrets.compare_digest(csrf,self._csrf()): raise HTTPException(403,'Invalid CSRF token')

    def _middleware(self):
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
        async def health(): return {'ok':True}

        @self.app.get('/login')
        async def login_page(request: Request):
            if self._authorized(request): return RedirectResponse('/',303)
            return self.templates.TemplateResponse(request=request,name='login.html',context={'error':None})

        @self.app.post('/login')
        async def login(request: Request,password: str=Form(...)):
            if not secrets.compare_digest(password,self.s.dashboard_password):
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
            stats=await asyncio.to_thread(self.db.stats); jobs=await asyncio.to_thread(self.db.recent,30)
            passwords=await asyncio.to_thread(self.passwords.list_masked)
            return self.templates.TemplateResponse(request=request,name='dashboard.html',context={'stats':stats,'jobs':jobs,'passwords':passwords,'csrf':self._csrf(),'notice':notice,'error':error})

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

        @self.app.post('/channel-links')
        async def add_link(request: Request,url: str=Form(...),max_files: str=Form('0'),csrf: str=Form(...)):
            self._require_post(request,csrf)
            try: self.pipeline.validate_channel_link(url)
            except ValueError as exc: return RedirectResponse(f'/?error={quote_plus(str(exc))}',303)
            try: limit=max(0,min(int(max_files),40))
            except ValueError: limit=0
            asyncio.create_task(self.pipeline.ingest_channel_link(url,limit),name='channel-link-ingest')
            return RedirectResponse('/?notice=Channel+download+submitted',303)

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