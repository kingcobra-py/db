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
AWS_SECRET = re.compile(r'''(?ix)\b(aws_secret_access_key|secret_access_key|aws_secret_key)\b\s*[:=,]\s*["']?([A-Za-z0-9/+=]{40,128})["']?''')
AWS_TOKEN = re.compile(r'''(?ix)\b(aws_session_token|session_token|aws_security_token)\b\s*[:=,]\s*["']?([A-Za-z0-9/+=]{80,4096})["']?''')

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


# write_results() stays exactly as it was – no changes needed.
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