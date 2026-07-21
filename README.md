# Telegram Archive Scanner — Web Dashboard Edition

A responsive web dashboard plus the original single-worker Telegram pipeline. Use only for channels and files you own or are authorized to inspect.

## What changed

- Responsive HTML/CSS dashboard for desktop and mobile
- Password-protected login with HttpOnly, SameSite session cookie
- CSRF protection and strict browser security headers
- Encrypted archive-password storage using Fernet
- Authorized `https://t.me/.../<message>` and private `https://t.me/c/.../...` downloads
- Recent job status, report download, and JSON summary download
- Railway health endpoint at `/health`

The Telegram account represented by `TELEGRAM_STRING_SESSION` must already be able to view a submitted channel message. Invite links and access-control bypasses are not supported.

## Generate secrets

```bash
python -c "import secrets; print(secrets.token_hex(32))" # DASHBOARD_SECRET
python -c "import secrets; print(secrets.token_hex(32))" # FINGERPRINT_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" # PASSWORD_ENCRYPTION_KEY
```

Use a long unique `DASHBOARD_PASSWORD`. Treat all four values as secrets.

## Telegram session

On a trusted local machine:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python generate_session.py
```

Store the resulting value as `TELEGRAM_STRING_SESSION`.

## Local run

Install 7-Zip first (`p7zip-full` on Debian/Ubuntu), then:

```bash
cp .env.example .env
# Fill in .env
set -a; source .env; set +a
python main_pipeline.py
```

Open `http://localhost:8000`. Local HTTP cookies work when no `X-Forwarded-Proto: https` header is present; Railway uses secure HTTPS cookies.

## Railway

1. Push this project to GitHub.
2. Create a Railway service from the repository.
3. Mount a persistent volume at `/data`.
4. Add all variables from `.env.example`.
5. Keep exactly one replica.
6. Deploy. Railway exposes the `PORT` used by the dashboard.
7. Generate a Railway domain and open it over HTTPS.

The same process runs Uvicorn, Telethon, and one sequential `asyncio.Queue` consumer. Do not launch `uvicorn` separately.

## Dashboard use

### Add a channel message

Paste a specific message URL, for example:

```text
https://t.me/example_channel/123
https://t.me/c/1234567890/456
```

The account must already have access. If the target belongs to a Telegram media album, nearby media with the same album ID is downloaded together.

### Add archive passwords

Passwords entered in the dashboard are encrypted in `/data/archive-passwords.enc`. The encryption key stays in `PASSWORD_ENCRYPTION_KEY`. The UI shows only a masked length. Passwords from uploaded `passwords.txt` and `file/passwords.txt` are still supported.

Changing `PASSWORD_ENCRYPTION_KEY` makes the existing password store unreadable. Delete the encrypted file only if intentionally resetting it.

### Download results

Completed jobs expose:

- Redacted text report
- `summary.json`

Raw AWS secret access keys and session tokens are not written to either output.

## Tests

```bash
python -m compileall -q .
python -m unittest -v test_scanner.py
```

## Security notes

- The dashboard does not grant Telegram channel access.
- Do not submit scraped, stolen, or unauthorized channel links.
- Use a dedicated Telegram account and restrict `ALLOWED_USERS`.
- Rotate confirmed AWS credentials; do not attempt to validate them with this tool.
- Keep one Railway replica because the queue is in memory and state is in SQLite.
- Configure retention for `/data/inbox` and `/data/work`.
