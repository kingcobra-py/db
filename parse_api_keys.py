from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set

LOG = logging.getLogger("api_keys")

PATTERNS = {
    "sendgrid": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "stripe_live": re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "stripe_restricted": re.compile(r"rk_live_[A-Za-z0-9]{24,}"),
}

NAME_HINTS = (
    "api",
    "key",
    "token",
    "secret",
    "auth",
    "credential",
    "payment",
    "sendgrid",
    "stripe",
)


def format_api_key_line(key: dict) -> str:
    return str(key.get("secret_value") or "")


def _over_size_limit(size: int, max_file_bytes: int) -> bool:
    return max_file_bytes > 0 and size > max_file_bytes


def _is_api_key_target(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() != ".txt":
        return False
    name = path.name.lower()
    if name == "passwords.txt":
        return True
    return any(hint in name for hint in NAME_HINTS)


def _should_scan_file(path: Path, output_dir: Path | None = None) -> bool:
    if not _is_api_key_target(path):
        return False
    if output_dir is not None:
        try:
            path.resolve().relative_to(output_dir.resolve())
            return False
        except ValueError:
            pass
    return True


def _iter_api_key_files(root: Path, output_dir: Path | None = None):
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


def _parse_file(path: Path, root: Path) -> List[dict]:
    rel_path = str(path.relative_to(root))
    hits: List[dict] = []
    try:
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            return hits
        text = data.decode("utf-8", errors="ignore")
    except OSError:
        return hits

    for line_no, line in enumerate(text.splitlines(), 1):
        for key_type, pattern in PATTERNS.items():
            for match in pattern.finditer(line):
                hits.append(
                    {
                        "key_type": key_type,
                        "secret_value": match.group(0),
                        "file": rel_path,
                        "line": line_no,
                    }
                )
    return hits


def extract_api_keys(
    root: Path,
    max_workers: int = 8,
    output_dir: Path | None = None,
    max_file_bytes: int = 0,
) -> List[dict]:
    """Extract unique SendGrid and Stripe keys from an extracted archive tree."""
    root = root.resolve()
    file_paths: List[Path] = []
    for path in _iter_api_key_files(root, output_dir):
        try:
            if _over_size_limit(path.stat().st_size, max_file_bytes):
                continue
        except OSError:
            continue
        file_paths.append(path)

    by_value: Dict[tuple[str, str], dict] = {}

    def _process_one(filepath: Path) -> List[dict]:
        return _parse_file(filepath, root)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_one, fp): fp for fp in file_paths}
        for future in as_completed(futures):
            try:
                for key in future.result():
                    dedupe = (key["key_type"], key["secret_value"])
                    if dedupe not in by_value:
                        by_value[dedupe] = key
            except Exception as exc:
                LOG.debug("API key parse error: %s", exc)

    result = list(by_value.values())
    LOG.info(
        "API key extraction complete: %s keys from %s files",
        len(result),
        len(file_paths),
        extra={"stage": "api-key-extraction", "keys_found": len(result), "files_scanned": len(file_paths)},
    )
    return result


def write_api_keys_file(keys: List[dict], output_path: Path) -> None:
    lines = sorted({format_api_key_line(key) for key in keys if key.get("secret_value")})
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    output_path.chmod(0o600)


def scan_summary(keys: List[dict], files_scanned: int) -> dict:
    by_type: Dict[str, int] = {}
    for key in keys:
        key_type = str(key.get("key_type") or "")
        by_type[key_type] = by_type.get(key_type, 0) + 1
    return {
        "api_keys_found": len(keys),
        "api_key_files_scanned": files_scanned,
        "by_type": by_type,
    }


def _count_scannable_files(root: Path, max_file_bytes: int, output_dir: Path | None = None) -> int:
    count = 0
    for path in _iter_api_key_files(root, output_dir):
        try:
            if not _over_size_limit(path.stat().st_size, max_file_bytes):
                count += 1
        except OSError:
            continue
    return count


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan extracted stealer logs for SendGrid and Stripe keys.")
    parser.add_argument("root", type=Path, help="Extracted archive root directory")
    parser.add_argument("-o", "--output", type=Path, help="Write one key per line to this file")
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
    keys = extract_api_keys(root, max_file_bytes=args.max_file_bytes)
    summary = scan_summary(keys, files_scanned)

    if args.output:
        write_api_keys_file(keys, args.output)
        print(f"Wrote {len(keys)} keys to {args.output}")

    if args.json:
        print(json.dumps({"summary": summary, "keys": keys}, indent=2))
    else:
        for key in keys:
            print(format_api_key_line(key))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
