from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path

# Which folders are considered valid
FOLDER_PATTERN_OLD = re.compile(r"soft.*azure.*aws", re.IGNORECASE)
FOLDER_PATTERN_NEW = re.compile(r"applications.*azure", re.IGNORECASE)

# Only files named exactly 'credentials' (case‑insensitive)
TARGET_NAME = "credentials"

# Regex patterns (same as before, plus session token)
AWS_ID = re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16})(?![A-Z0-9])")
AWS_SECRET = re.compile(r'''(?ix)\b(aws_secret_access_key|secret_access_key|aws_secret_key)\b\s*[:=,]\s*[\"']?([A-Za-z0-9/+=]{40,128})[\"']?''')
AWS_TOKEN = re.compile(r'''(?ix)\b(aws_session_token|session_token|aws_security_token)\b\s*[:=,]\s*[\"']?([A-Za-z0-9/+=]{80,4096})[\"']?''')

PATTERNS = (
    (AWS_ID, "aws_access_key_id", 1),
    (AWS_SECRET, "aws_secret_access_key", 2),
    (AWS_TOKEN, "aws_session_token", 2),
)


def _fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:16]


def _should_scan_file(path: Path) -> bool:
    """Check if this 'credentials' file sits in a matching folder."""
    # Case‑insensitive name check
    if path.name.lower() != TARGET_NAME:
        return False
    parent = str(path.parent).lower()
    # Old pattern: soft + azure + aws
    if FOLDER_PATTERN_OLD.search(parent):
        return True
    # New pattern: applications + azure (and either .aws or credentials in path)
    if FOLDER_PATTERN_NEW.search(parent):
        # Additional check: either ".aws" appears in the path or the file itself is 'credentials'
        if ".aws" in parent or path.name.lower() == TARGET_NAME:
            return True
    return False


def scan_tree(root: Path, max_file_bytes: int, fingerprint_key: bytes):
    findings: list[dict] = []
    files_scanned = 0
    root = root.resolve()

    # Recursively find all 'credentials' files in matching folders
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if not _should_scan_file(path):
            continue
        # Skip huge files (honour max_file_bytes)
        if path.stat().st_size > max_file_bytes:
            continue

        files_scanned += 1
        rel_path = str(path.relative_to(root))

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue  # skip unreadable files

        for line_no, line in enumerate(lines, 1):
            for pattern, kind, group in PATTERNS:
                for match in pattern.finditer(line):
                    secret = match.group(group)
                    findings.append({
                        "type": kind,
                        "file": rel_path,
                        "line": line_no,
                        "fingerprint": _fingerprint(secret, fingerprint_key),
                    })

    # Build summary
    summary = {
        "files_scanned": files_scanned,
        "findings": len(findings),
        "by_type": {
            kind: sum(1 for f in findings if f["type"] == kind)
            for _, kind, _ in PATTERNS
        },
    }
    return findings, summary


def write_results(out_dir: Path, message_id: int, findings, summary):
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    text_path = out_dir / f"report-{message_id}.txt"
    json_path = out_dir / f"summary-{message_id}.json"

    lines = [
        f"Files scanned: {summary['files_scanned']}",
        f"Findings: {summary['findings']}",
        "",
    ]
    for kind, n in summary["by_type"].items():
        lines.append(f"  {kind}: {n}")
    lines.append("")
    for f in findings:
        lines.append(f"[{f['type']}] {f['file']}:{f['line']} fingerprint={f['fingerprint']}")

    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return text_path, json_path


def extract_raw_credentials(root: Path) -> list[dict]:
    """Extract actual AWS credentials from scanned files.
    
    Returns list of dicts: [{"access_key": "...", "secret_key": "...", "region": "...", "file": "...", "line": ...}, ...]
    Deduplicates by access_key.
    """
    creds_dict = {}
    region_pattern = re.compile(
        r'\b(us-east-1|us-east-2|us-west-1|us-west-2|eu-west-1|eu-west-2|eu-central-1|'
        r'ap-southeast-1|ap-southeast-2|ap-northeast-1|ap-northeast-2|ap-south-1|'
        r'ca-central-1|sa-east-1|us-gov-west-1|us-gov-east-1|cn-north-1|cn-northwest-1)\b',
        re.IGNORECASE
    )
    
    root = root.resolve()
    
    for path in root.rglob("*"):
        if not path.is_file() or not _should_scan_file(path) or path.stat().st_size > 1024 * 1024:
            continue
        
        rel_path = str(path.relative_to(root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
        except Exception:
            continue
        
        # Extract access keys with line context
        access_keys = {}
        for line_no, line in enumerate(lines, 1):
            for match in AWS_ID.finditer(line):
                key = match.group(1)
                if key not in access_keys:
                    access_keys[key] = (rel_path, line_no, line)
        
        # Extract secrets with line context
        secrets = {}
        for line_no, line in enumerate(lines, 1):
            for match in AWS_SECRET.finditer(line):
                secret = match.group(2)
                if secret not in secrets:
                    secrets[secret] = (rel_path, line_no, line)
            for match in AWS_TOKEN.finditer(line):
                token = match.group(2)
                if token not in secrets:
                    secrets[token] = (rel_path, line_no, line)
        
        # Combine keys with secrets
        for key, (key_file, key_line, key_line_text) in access_keys.items():
            for secret, (sec_file, sec_line, sec_line_text) in secrets.items():
                region = "unknown"
                for line_text in (key_line_text, sec_line_text):
                    m = region_pattern.search(line_text)
                    if m:
                        region = m.group(1)
                        break
                
                if key not in creds_dict:
                    creds_dict[key] = {
                        "access_key": key,
                        "secret_key": secret,
                        "region": region,
                        "file": key_file,
                        "line": key_line,
                    }
    
    return list(creds_dict.values())
