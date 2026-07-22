from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from pathlib import Path

LOG = logging.getLogger('credentials')

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
    """Check if file should be scanned for credentials.
    
    Scans: .txt, .csv, .log, .conf, .json, .yaml, .yml, 'credentials' files
    in folders containing 'aws', 'azure', 'credentials', 'secret', or similar keywords
    """
    if not path.is_file():
        return False
    
    # File extensions to scan
    valid_extensions = {'.txt', '.csv', '.log', '.conf', '.json', '.yaml', '.yml', ''}
    file_ext = path.suffix.lower()
    file_name = path.name.lower()
    
    # Allow files with valid extensions OR files named 'credentials'
    if file_ext not in valid_extensions and file_name != 'credentials':
        return False
    
    # Check folder path for relevant keywords
    parent_path = str(path.parent).lower()
    keywords = {'aws', 'azure', 'credentials', 'secret', 'config', 'keys', 'tokens', '.aws'}
    
    return any(keyword in parent_path for keyword in keywords)


def _count_scannable_files(root: Path) -> int:
    """Count how many files will be scanned before scanning starts."""
    count = 0
    root = root.resolve()
    
    try:
        for path in root.rglob("*"):
            if _should_scan_file(path):
                if path.stat().st_size <= 100 * 1024 * 1024:  # 100MB limit
                    count += 1
    except Exception:
        pass
    
    return count


def scan_tree(root: Path, max_file_bytes: int, fingerprint_key: bytes):
    findings: list[dict] = []
    files_scanned = 0
    root = root.resolve()

    # Log how many scannable files we found
    scannable_count = _count_scannable_files(root)
    LOG.info(f'Starting credential scan on {scannable_count} scannable files', extra={'stage': 'scanning', 'scannable_files': scannable_count})

    # Recursively find all scannable files
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
    
    LOG.info(f'Scan complete: {files_scanned} files scanned, {len(findings)} total findings', 
             extra={'stage': 'scanning', 'files_scanned': files_scanned, 'findings': len(findings)})
    
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
    Deduplicates by access_key and logs progress.
    """
    creds_dict = {}
    region_pattern = re.compile(
        r'\b(us-east-1|us-east-2|us-west-1|us-west-2|eu-west-1|eu-west-2|eu-central-1|'
        r'ap-southeast-1|ap-southeast-2|ap-northeast-1|ap-northeast-2|ap-south-1|'
        r'ca-central-1|sa-east-1|us-gov-west-1|us-gov-east-1|cn-north-1|cn-northwest-1)\b',
        re.IGNORECASE
    )
    
    root = root.resolve()
    files_with_creds = set()
    region_counts = {}
    
    # Count scannable files first
    scannable_count = _count_scannable_files(root)
    LOG.info(f'Starting raw credential extraction on {scannable_count} scannable files', 
             extra={'stage': 'credential-extraction', 'scannable_files': scannable_count})
    
    for path in root.rglob("*"):
        if not _should_scan_file(path):
            continue
        if path.stat().st_size > 1024 * 1024:  # Skip files > 1MB
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
                
                region_counts[region] = region_counts.get(region, 0) + 1
                
                if key not in creds_dict:
                    creds_dict[key] = {
                        "access_key": key,
                        "secret_key": secret,
                        "region": region,
                        "file": key_file,
                        "line": key_line,
                    }
                    files_with_creds.add(key_file)
    
    result = list(creds_dict.values())
    LOG.info(f'Credential extraction complete: {len(result)} credentials extracted from {len(files_with_creds)} files. Regions: {region_counts}',
             extra={'stage': 'credential-extraction', 'credentials_found': len(result), 
                    'files_with_creds': len(files_with_creds), 'region_distribution': region_counts})
    
    return result
