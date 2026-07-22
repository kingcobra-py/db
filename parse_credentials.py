from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

LOG = logging.getLogger('credentials')

# Console debug logger
def debug_log(msg: str, level: str = "INFO"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] [{level}] {msg}"
    print(formatted)
    if level == "HIT":
        LOG.info(msg, extra={'stage': 'scanning', 'event': 'credential_found'})
    elif level == "ERROR":
        LOG.error(msg, extra={'stage': 'scanning', 'event': 'scan_error'})
    else:
        LOG.info(msg)

# Regex patterns
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
    if not path.is_file():
        return False
    valid_extensions = {'.txt', '.csv', '.log', '.conf', '.json', '.yaml', '.yml', ''}
    file_ext = path.suffix.lower()
    file_name = path.name.lower()
    if file_ext not in valid_extensions and file_name != 'credentials':
        return False
    try:
        path.resolve().relative_to(Path('/data/output'))
        return False
    except ValueError:
        pass
    return True

def _count_scannable_files(root: Path) -> int:
    count = 0
    root = root.resolve()
    try:
        for path in root.rglob("*"):
            if _should_scan_file(path):
                if path.stat().st_size <= 100 * 1024 * 1024:
                    count += 1
    except Exception:
        pass
    return count

def _scan_file(path: Path, root: Path, max_file_bytes: int, fingerprint_key: bytes) -> Tuple[List[dict], str]:
    findings = []
    rel_path = str(path.relative_to(root))
    debug_info = f"{rel_path}"
    
    try:
        if path.stat().st_size > max_file_bytes:
            return findings, debug_info + " → SKIPPED"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        return findings, debug_info + f" → ERROR: {str(e)[:30]}"
    
    hits = 0
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
                hits += 1
    
    if hits:
        return findings, debug_info + f" → HIT ({hits})"
    else:
        return findings, debug_info + " → NO_CRED"

def scan_tree(root: Path, max_file_bytes: int, fingerprint_key: bytes, max_workers: int = 8):
    findings: List[dict] = []
    root = root.resolve()
    
    scannable_count = _count_scannable_files(root)
    LOG.info(f'Starting credential scan on {scannable_count} scannable files', extra={'stage': 'scanning', 'scannable_files': scannable_count})
    debug_log(f"SCAN START: {scannable_count} files in {root.name}", "START")
    
    file_paths = []
    for path in root.rglob("*"):
        if _should_scan_file(path):
            file_paths.append(path)
    
    files_scanned = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_file, fp, root, max_file_bytes, fingerprint_key): fp for fp in file_paths}
        
        for future in as_completed(futures):
            try:
                file_findings, info = future.result()
                findings.extend(file_findings)
                files_scanned += 1
                
                if "HIT" in info:
                    debug_log(info, "HIT")
                elif "ERROR" in info:
                    debug_log(info, "ERROR")
                else:
                    debug_log(info, "NO_CRED")
            except Exception as e:
                debug_log(f"Thread error: {e}", "ERROR")
    
    summary = {
        "files_scanned": files_scanned,
        "findings": len(findings),
        "by_type": {kind: sum(1 for f in findings if f["type"] == kind) for _, kind, _ in PATTERNS},
    }
    
    debug_log(f"SCAN DONE: {files_scanned} files, {len(findings)} findings", "SUMMARY")
    LOG.info(f'Scan complete: {files_scanned} files scanned, {len(findings)} total findings', 
             extra={'stage': 'scanning', 'files_scanned': files_scanned, 'findings': len(findings)})
    
    return findings, summary

def write_results(out_dir: Path, message_id: int, findings, summary):
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    text_path = out_dir / f"report-{message_id}.txt"
    json_path = out_dir / f"summary-{message_id}.json"
    
    lines = [f"Files scanned: {summary['files_scanned']}", f"Findings: {summary['findings']}", ""]
    for kind, n in summary["by_type"].items():
        lines.append(f"  {kind}: {n}")
    lines.append("")
    for f in findings:
        lines.append(f"[{f['type']}] {f['file']}:{f['line']} fingerprint={f['fingerprint']}")
    
    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return text_path, json_path

def write_raw_credentials_file(credentials: List[dict], output_path: Path):
    """Write key:secret:region format (one per line)."""
    lines_set: Set[str] = set()
    for cred in credentials:
        lines_set.add(f"{cred['access_key']}:{cred['secret_key']}:{cred['region']}")
    
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(output_path, "w", encoding="utf-8") as f:
        for line in sorted(lines_set):
            f.write(line + "\n")
    
    debug_log(f"Raw credentials exported: {output_path} ({len(lines_set)} entries)", "RESULT")
    LOG.info(f"Raw credentials written: {len(lines_set)} unique credentials", extra={'stage': 'export', 'count': len(lines_set)})

def extract_raw_credentials(root: Path, max_workers: int = 8) -> List[dict]:
    creds_dict: Dict[str, dict] = {}
    region_pattern = re.compile(
        r'\b(us-east-1|us-east-2|us-west-1|us-west-2|eu-west-1|eu-west-2|eu-central-1|'
        r'ap-southeast-1|ap-southeast-2|ap-northeast-1|ap-northeast-2|ap-south-1|'
        r'ca-central-1|sa-east-1|us-gov-west-1|us-gov-east-1|cn-north-1|cn-northwest-1)\b',
        re.IGNORECASE
    )
    
    root = root.resolve()
    files_with_creds: Set[str] = set()
    region_counts: Dict[str, int] = {}
    
    file_paths = []
    for path in root.rglob("*"):
        if _should_scan_file(path) and path.stat().st_size <= 1024 * 1024:
            file_paths.append(path)
    
    scannable_count = len(file_paths)
    LOG.info(f'Starting raw credential extraction on {scannable_count} files', 
             extra={'stage': 'credential-extraction', 'scannable_files': scannable_count})
    debug_log(f"EXTRACT START: {scannable_count} files", "START")
    
    def _process_one(filepath: Path):
        local_creds = []
        rel_path = str(filepath.relative_to(root))
        try:
            lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return local_creds
        
        keys_in_file = []
        secrets_in_file = []
        
        for line_no, line in enumerate(lines, 1):
            for match in AWS_ID.finditer(line):
                keys_in_file.append((line_no, match.group(1), line))
            for match in AWS_SECRET.finditer(line):
                secrets_in_file.append((line_no, match.group(2), line))
            for match in AWS_TOKEN.finditer(line):
                secrets_in_file.append((line_no, match.group(2), line))
        
        for i in range(min(len(keys_in_file), len(secrets_in_file))):
            key_line, key, key_text = keys_in_file[i]
            sec_line, secret, sec_text = secrets_in_file[i]
            
            region = "unknown"
            for txt in (key_text, sec_text):
                m = region_pattern.search(txt)
                if m:
                    region = m.group(1)
                    break
            
            local_creds.append({
                "access_key": key,
                "secret_key": secret,
                "region": region,
                "file": rel_path,
                "line": key_line,
            })
        
        return local_creds
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_one, fp): fp for fp in file_paths}
        
        for future in as_completed(futures):
            try:
                creds_from_file = future.result()
                for cred in creds_from_file:
                    key = cred["access_key"]
                    if key not in creds_dict:
                        creds_dict[key] = cred
                        files_with_creds.add(cred["file"])
                        region = cred["region"]
                        region_counts[region] = region_counts.get(region, 0) + 1
                        debug_log(f"Found credential: {key[:8]}... → {region}", "HIT")
            except Exception as e:
                debug_log(f"Extract error: {e}", "ERROR")
    
    result = list(creds_dict.values())
    regions_str = ", ".join(f"{r}({c})" for r, c in sorted(region_counts.items()))
    debug_log(f"EXTRACT DONE: {len(result)} credentials from {len(files_with_creds)} files. Regions: {regions_str}", "SUMMARY")
    LOG.info(f'Credential extraction complete: {len(result)} credentials from {len(files_with_creds)} files. Regions: {region_counts}',
             extra={'stage': 'credential-extraction', 'credentials_found': len(result), 
                    'files_with_creds': len(files_with_creds), 'region_distribution': region_counts})
    
    return result
