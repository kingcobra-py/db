from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

LOG = logging.getLogger("passwords")

URL_KEYS = {"url", "host", "hostname", "origin", "website", "site", "href"}
USER_KEYS = {"user", "username", "user_name", "login", "email", "login_name", "account", "userid", "user_id"}
PASS_KEYS = {"pass", "password", "passwd", "pwd", "pass_word"}
SOFT_KEYS = {"soft", "application", "app", "browser", "profile"}

LABEL_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 _-]{0,40})\s*[:=]\s*(?P<value>.+?)\s*$"
)
SEP_RE = re.compile(r"^\s*[=*#\-_]{3,}\s*$")
EMAIL_RE = re.compile(r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$", re.I)
HTTP_URL_RE = re.compile(r"^https?://", re.I)
URL_TRIPLE_RE = re.compile(
    r"^(?P<url>https?://[^\s|:]+)\s*[:|]\s*(?P<user>[^:|\s][^:|]*)\s*[:|]\s*(?P<password>.+)$",
    re.I,
)
EMAIL_PASS_RE = re.compile(
    r"^(?P<user>[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})\s*[:|;]\s*(?P<password>.+)$",
    re.I,
)
PIPE_TRIPLE_RE = re.compile(r"^(?P<url>[^|\n]{3,400})\|(?P<user>[^|\n]{0,300})\|(?P<password>.+)$")
JSON_OBJ_RE = re.compile(r"\{[^{}]{8,8000}\}")
SNIFF_RE = re.compile(r"(?im)^\s*(?:pass(?:word|wd)?|pwd)\s*[:=]")

SKIP_NAME_PARTS = (
    "cookie",
    "history",
    "autofill",
    "credit",
    "discord",
    "token",
    "screenshot",
    "processlist",
    "clipboard",
    "wallet",
)
PASSWORD_NAME_TOKENS = {
    "password",
    "passwords",
    "passwd",
    "userpass",
    "login",
    "logins",
    "brute",
    "account",
    "accounts",
    "credential",
    "credentials",
}
PASSWORD_FOLDERS = ("/passwords/", "/password/", "/logins/", "/login/")
PLACEHOLDERS = {
    "",
    "*",
    "-",
    "--",
    "n/a",
    "na",
    "null",
    "none",
    "nil",
    "undefined",
    "empty",
    "unknown",
    "not saved",
    "[not_saved]",
    "not_saved",
    "********",
    "****",
    "true",
    "false",
    "password",
    "pass",
    "pwd",
    "changeme",
    "secret",
}


def format_password_line(record: dict) -> str:
    """Export format: url|username|password."""
    return "|".join(
        (
            str(record.get("url") or ""),
            str(record.get("username") or ""),
            str(record.get("password") or ""),
        )
    )


def _over_size_limit(size: int, max_file_bytes: int) -> bool:
    return max_file_bytes > 0 and size > max_file_bytes


def _normalize_key(raw: str) -> str:
    return re.sub(r"[\s\-]+", "_", raw.strip().lower())


def _looks_like_url(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if HTTP_URL_RE.match(value):
        return True
    if "://" in value:
        return True
    if "." in value and " " not in value and len(value) < 256:
        return True
    return False


def _is_placeholder(value: str) -> bool:
    compact = value.strip().lower()
    if compact in PLACEHOLDERS:
        return True
    if set(compact) <= {"*", "•", "x", "."}:
        return True
    return False


def _valid_password(password: str) -> bool:
    password = password.strip()
    if len(password) < 2 or len(password) > 512:
        return False
    if _is_placeholder(password):
        return False
    if password.count(" ") > 12:
        return False
    if re.fullmatch(r"[A-Za-z0-9+/]{80,}={0,2}", password) and len(password) > 80:
        return False
    if password.count(".") == 2 and password.startswith("eyJ"):
        return False
    return True


def _valid_username(username: str) -> bool:
    username = username.strip()
    if not username:
        return True
    if len(username) > 300:
        return False
    if _is_placeholder(username):
        return False
    return True


def _normalize_record(url: str, username: str, password: str) -> Tuple[str, str, str] | None:
    url = (url or "").strip()
    username = (username or "").strip()
    password = (password or "").strip()
    if not _valid_password(password) or not _valid_username(username):
        return None
    if not url and not username:
        return None
    if username and username == password and not EMAIL_RE.match(username):
        return None
    if url and not username and not _looks_like_url(url):
        return None
    return url, username, password


def _is_password_name(path: Path) -> bool:
    name = path.name.lower()
    compact = re.sub(r"[\s_\-]+", "", name)
    if any(part in compact for part in SKIP_NAME_PARTS):
        return False
    if compact in {
        "passwords.txt",
        "password.txt",
        "allpasswords.txt",
        "allpasswordslist.txt",
        "logins.txt",
        "login.txt",
        "brute.txt",
        "userpass.txt",
        "accounts.txt",
    }:
        return True
    if compact.endswith("passwords.txt") or compact.endswith("password.txt"):
        return True
    tokens = set(re.findall(r"[a-z0-9]+", name))
    return bool(tokens & PASSWORD_NAME_TOKENS) and path.suffix.lower() in {
        ".txt",
        ".csv",
        ".json",
        ".log",
    }


def _in_password_folder(path: Path) -> bool:
    normalized = str(path).lower().replace("\\", "/")
    return any(folder in normalized for folder in PASSWORD_FOLDERS)


def _sniff_password_text(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            chunk = handle.read(16384)
    except OSError:
        return False
    if not chunk:
        return False
    text = _decode_bytes(chunk)
    return bool(SNIFF_RE.search(text))


def _is_password_target(path: Path) -> bool:
    if not path.is_file():
        return False
    suffix = path.suffix.lower()
    if suffix not in {".txt", ".csv", ".json", ".log", ""}:
        return False
    if path.name.lower() == "credentials" and suffix == "":
        return False
    if _is_password_name(path) or _in_password_folder(path):
        return True
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if suffix in {".txt", ".csv", ".json"} and size <= 1_000_000:
        compact = re.sub(r"[\s_\-]+", "", path.name.lower())
        if any(part in compact for part in SKIP_NAME_PARTS):
            return False
        return _sniff_password_text(path)
    return False


def _should_scan_file(path: Path, output_dir: Path | None = None) -> bool:
    if not _is_password_target(path):
        return False
    if output_dir is not None:
        try:
            path.resolve().relative_to(output_dir.resolve())
            return False
        except ValueError:
            pass
    return True


def _iter_password_files(root: Path, output_dir: Path | None = None):
    root = root.resolve()
    seen: Set[Path] = set()
    try:
        for path in root.rglob("*"):
            if not path.is_file() or path in seen:
                continue
            if not _should_scan_file(path, output_dir):
                continue
            seen.add(path)
            yield path
    except OSError:
        return


def _decode_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le", errors="ignore")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be", errors="ignore")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8", errors="replace")
    sample = data[:200]
    if sample.count(b"\x00") > 40:
        return data.decode("utf-16-le", errors="ignore")
    return data.decode("utf-8", errors="replace")


def _read_text(path: Path) -> str:
    return _decode_bytes(path.read_bytes())


def _append_record(
    records: List[dict],
    seen: Set[Tuple[str, str, str]],
    *,
    url: str,
    username: str,
    password: str,
    rel_path: str,
    line: int,
) -> None:
    normalized = _normalize_record(url, username, password)
    if not normalized:
        return
    url, username, password = normalized
    key = (url, username, password)
    if key in seen:
        return
    seen.add(key)
    records.append(
        {
            "url": url,
            "username": username,
            "password": password,
            "file": rel_path,
            "line": line,
        }
    )


def _parse_labeled_line(line: str) -> Tuple[str, str] | None:
    match = LABEL_RE.match(line)
    if not match:
        return None
    key = _normalize_key(match.group("key"))
    value = match.group("value").strip()
    if key in URL_KEYS:
        return "url", value
    if key in USER_KEYS:
        return "user", value
    if key in PASS_KEYS:
        return "pass", value
    if key in SOFT_KEYS:
        return "soft", value
    return None


def _parse_inline_line(line: str) -> Tuple[str, str, str] | None:
    triple = URL_TRIPLE_RE.match(line)
    if triple:
        return triple.group("url"), triple.group("user"), triple.group("password")
    email = EMAIL_PASS_RE.match(line)
    if email:
        return "", email.group("user"), email.group("password")
    pipe = PIPE_TRIPLE_RE.match(line)
    if pipe and _looks_like_url(pipe.group("url")):
        return pipe.group("url").strip(), pipe.group("user").strip(), pipe.group("password")
    return None


def _parse_json_objects(text: str, rel_path: str, records: List[dict], seen: Set[Tuple[str, str, str]]) -> None:
    for match in JSON_OBJ_RE.finditer(text):
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        lowered = {_normalize_key(str(k)): v for k, v in payload.items()}
        url = ""
        username = ""
        password = ""
        for key, value in lowered.items():
            if not isinstance(value, (str, int)):
                continue
            text_value = str(value)
            if key in URL_KEYS and not url:
                url = text_value
            elif key in USER_KEYS and not username:
                username = text_value
            elif key in PASS_KEYS and not password:
                password = text_value
        _append_record(records, seen, url=url, username=username, password=password, rel_path=rel_path, line=1)


def _flush_block(
    records: List[dict],
    seen: Set[Tuple[str, str, str]],
    block: dict,
    rel_path: str,
    line: int,
) -> None:
    _append_record(
        records,
        seen,
        url=str(block.get("url") or ""),
        username=str(block.get("user") or ""),
        password=str(block.get("pass") or ""),
        rel_path=rel_path,
        line=line,
    )
    block.clear()


def _parse_file(path: Path, root: Path) -> List[dict]:
    rel_path = str(path.relative_to(root))
    records: List[dict] = []
    seen: Set[Tuple[str, str, str]] = set()
    try:
        text = _read_text(path)
    except OSError:
        return records

    _parse_json_objects(text, rel_path, records, seen)

    block: dict = {}
    block_line = 1
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or SEP_RE.match(line):
            if block.get("pass"):
                _flush_block(records, seen, block, rel_path, block_line)
            else:
                block.clear()
            continue

        labeled = _parse_labeled_line(line)
        if labeled:
            field, value = labeled
            if field == "url" and block.get("pass"):
                _flush_block(records, seen, block, rel_path, block_line)
            elif field == "pass" and block.get("pass"):
                _flush_block(records, seen, block, rel_path, block_line)
            if field != "soft":
                if not block:
                    block_line = line_no
                block[field] = value
            continue

        inline = _parse_inline_line(line)
        if inline:
            if block.get("pass"):
                _flush_block(records, seen, block, rel_path, block_line)
            url, username, password = inline
            _append_record(
                records,
                seen,
                url=url,
                username=username,
                password=password,
                rel_path=rel_path,
                line=line_no,
            )
            continue

    if block.get("pass"):
        _flush_block(records, seen, block, rel_path, block_line)
    return records


def extract_passwords(
    root: Path,
    max_workers: int = 8,
    output_dir: Path | None = None,
    max_file_bytes: int = 0,
) -> List[dict]:
    """Extract unique url|username|password records from an extracted archive tree."""
    root = root.resolve()
    file_paths: List[Path] = []
    for path in _iter_password_files(root, output_dir):
        try:
            if _over_size_limit(path.stat().st_size, max_file_bytes):
                continue
        except OSError:
            continue
        file_paths.append(path)

    by_key: Dict[Tuple[str, str, str], dict] = {}

    def _process_one(filepath: Path) -> List[dict]:
        return _parse_file(filepath, root)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_one, fp): fp for fp in file_paths}
        for future in as_completed(futures):
            try:
                for record in future.result():
                    key = (record["url"], record["username"], record["password"])
                    if key not in by_key:
                        by_key[key] = record
            except Exception as exc:
                LOG.debug("Password parse error: %s", exc)

    result = list(by_key.values())
    LOG.info(
        "Password extraction complete: %s passwords from %s files",
        len(result),
        len(file_paths),
        extra={"stage": "password-extraction", "passwords_found": len(result), "files_scanned": len(file_paths)},
    )
    return result


def write_passwords_file(records: List[dict], output_path: Path) -> None:
    lines = sorted({format_password_line(record) for record in records if record.get("password")})
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    output_path.chmod(0o600)


def scan_summary(records: List[dict], files_scanned: int) -> dict:
    hosts: Set[str] = set()
    for record in records:
        url = str(record.get("url") or "")
        if not url:
            continue
        host = urlparse(url).hostname or url
        hosts.add(host.lower())
    return {
        "passwords_found": len(records),
        "password_files_scanned": files_scanned,
        "unique_hosts": len(hosts),
    }


def _count_scannable_files(root: Path, max_file_bytes: int, output_dir: Path | None = None) -> int:
    count = 0
    for path in _iter_password_files(root, output_dir):
        try:
            if not _over_size_limit(path.stat().st_size, max_file_bytes):
                count += 1
        except OSError:
            continue
    return count


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan extracted stealer logs for browser/app passwords.")
    parser.add_argument("root", type=Path, help="Extracted archive root directory")
    parser.add_argument("-o", "--output", type=Path, help="Write url|username|password lines to this file")
    parser.add_argument("--json", action="store_true", help="Print full JSON records to stdout")
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=0,
        help="Skip files larger than this many bytes (0 = unlimited)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2

    files_scanned = _count_scannable_files(root, args.max_file_bytes)
    records = extract_passwords(root, max_file_bytes=args.max_file_bytes)
    summary = scan_summary(records, files_scanned)

    if args.output:
        write_passwords_file(records, args.output)
        print(f"Wrote {len(records)} passwords to {args.output}")

    if args.json:
        print(json.dumps({"summary": summary, "passwords": records}, indent=2))
    else:
        for record in records:
            print(format_password_line(record))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
