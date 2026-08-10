from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set, Tuple

LOG = logging.getLogger("credit_cards")

CARD_FIELD = re.compile(r"(?i)^\s*(?:Card(?:Number)?|CC(?:Number)?|PAN)\s*[:=]\s*([0-9 \-]{12,23})\s*$")
EXPIRE_FIELD = re.compile(r"(?i)^\s*(?:Expire|Expiry|Exp(?:iration)?(?:Date)?)\s*[:=]\s*(\d{1,2})\s*[/\-]\s*(\d{2,4})\s*$")
CVV_FIELD = re.compile(r"(?i)^\s*(?:CVV2?|CVC2?|CID)\s*[:=]\s*(\d{3,4})\s*$")
PIPE_LINE = re.compile(
    r"^\s*(\d{13,19})\s*\|\s*(\d{1,2})\s*\|\s*(\d{2,4})\s*\|\s*(\d{3,4})?\s*$"
)


def _over_size_limit(size: int, max_file_bytes: int) -> bool:
    return max_file_bytes > 0 and size > max_file_bytes


def _luhn(pan: str) -> bool:
    if not pan.isdigit():
        return False
    total = 0
    alt = False
    for ch in reversed(pan):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _normalize_year(raw: str) -> str:
    raw = raw.strip()
    if not raw.isdigit():
        return raw
    if len(raw) == 2:
        value = int(raw)
        return str(2000 + value if value < 100 else value)
    return raw


def _normalize_month(raw: str) -> str:
    raw = raw.strip()
    if raw.isdigit():
        return str(int(raw)).zfill(2)
    return raw


def format_credit_card_line(card: dict) -> str:
    """Export format: cardnum|month|year|cvv"""
    return "|".join(
        [
            str(card.get("card_number") or ""),
            str(card.get("exp_month") or ""),
            str(card.get("exp_year") or ""),
            str(card.get("cvv") or ""),
        ]
    )


def _is_credit_card_target(path: Path) -> bool:
    if not path.is_file():
        return False
    normalized = str(path).lower().replace(" ", "").replace("\\", "/")
    if "/creditcards/" in normalized or "/credit_cards/" in normalized:
        return True
    if re.search(r"(?:^|/)cc(?:/|$)", normalized):
        return True
    name = path.name.lower()
    if name.startswith("cc_") and name.endswith(".txt"):
        return True
    return False


def _should_scan_file(path: Path, output_dir: Path | None = None) -> bool:
    if not _is_credit_card_target(path):
        return False
    if output_dir is not None:
        try:
            path.resolve().relative_to(output_dir.resolve())
            return False
        except ValueError:
            pass
    return True


def _iter_credit_card_files(root: Path, output_dir: Path | None = None):
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


def _iter_lines(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            yield line_no, line.rstrip("\n\r")


def _append_card(
    cards: List[dict],
    seen: Set[str],
    *,
    pan: str,
    month: str,
    year: str,
    cvv: str,
    rel_path: str,
    line: int,
) -> None:
    pan = re.sub(r"\D", "", pan)
    if not (13 <= len(pan) <= 19) or not _luhn(pan):
        return
    if pan in seen:
        return
    seen.add(pan)
    cards.append(
        {
            "card_number": pan,
            "exp_month": _normalize_month(month) if month else "",
            "exp_year": _normalize_year(year) if year else "",
            "cvv": cvv.strip() if cvv else "",
            "file": rel_path,
            "line": line,
        }
    )


def _parse_file(path: Path, root: Path) -> List[dict]:
    rel_path = str(path.relative_to(root))
    cards: List[dict] = []
    seen: Set[str] = set()
    try:
        lines = [line for _, line in _iter_lines(path)]
    except OSError:
        return cards

    for line_no, line in enumerate(lines, 1):
        pipe = PIPE_LINE.match(line)
        if pipe:
            _append_card(
                cards,
                seen,
                pan=pipe.group(1),
                month=pipe.group(2),
                year=pipe.group(3),
                cvv=pipe.group(4) or "",
                rel_path=rel_path,
                line=line_no,
            )

    for line_no, line in enumerate(lines, 1):
        card_match = CARD_FIELD.match(line)
        if not card_match:
            continue
        month = ""
        year = ""
        cvv = ""
        for j in range(line_no - 1, min(line_no + 7, len(lines))):
            nearby = lines[j]
            expire_match = EXPIRE_FIELD.match(nearby)
            if expire_match:
                month = expire_match.group(1)
                year = expire_match.group(2)
            cvv_match = CVV_FIELD.match(nearby)
            if cvv_match:
                cvv = cvv_match.group(1)
        _append_card(
            cards,
            seen,
            pan=card_match.group(1),
            month=month,
            year=year,
            cvv=cvv,
            rel_path=rel_path,
            line=line_no,
        )

    return cards


def extract_credit_cards(
    root: Path,
    max_workers: int = 8,
    output_dir: Path | None = None,
    max_file_bytes: int = 0,
) -> List[dict]:
    """Extract unique credit cards from an extracted archive tree."""
    root = root.resolve()
    file_paths: List[Path] = []
    for path in _iter_credit_card_files(root, output_dir):
        try:
            if _over_size_limit(path.stat().st_size, max_file_bytes):
                continue
        except OSError:
            continue
        file_paths.append(path)

    by_pan: Dict[str, dict] = {}

    def _process_one(filepath: Path) -> List[dict]:
        return _parse_file(filepath, root)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_one, fp): fp for fp in file_paths}
        for future in as_completed(futures):
            try:
                for card in future.result():
                    pan = card["card_number"]
                    if pan not in by_pan:
                        by_pan[pan] = card
            except Exception as exc:
                LOG.debug("Credit card parse error: %s", exc)

    result = list(by_pan.values())
    LOG.info(
        "Credit card extraction complete: %s cards from %s files",
        len(result),
        len(file_paths),
        extra={"stage": "credit-card-extraction", "cards_found": len(result), "files_scanned": len(file_paths)},
    )
    return result


def write_credit_cards_file(cards: List[dict], output_path: Path) -> None:
    lines = sorted({format_credit_card_line(card) for card in cards})
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    output_path.chmod(0o600)


def scan_summary(cards: List[dict], files_scanned: int) -> dict:
    return {
        "credit_cards_found": len(cards),
        "credit_card_files_scanned": files_scanned,
    }


def _count_scannable_files(root: Path, max_file_bytes: int, output_dir: Path | None = None) -> int:
    count = 0
    for path in _iter_credit_card_files(root, output_dir):
        try:
            if not _over_size_limit(path.stat().st_size, max_file_bytes):
                count += 1
        except OSError:
            continue
    return count


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan extracted stealer logs for credit cards.")
    parser.add_argument("root", type=Path, help="Extracted archive root directory")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write cardnum|month|year|cvv lines to this file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON records to stdout",
    )
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
    cards = extract_credit_cards(root, max_file_bytes=args.max_file_bytes)
    summary = scan_summary(cards, files_scanned)

    if args.output:
        write_credit_cards_file(cards, args.output)
        print(f"Wrote {len(cards)} cards to {args.output}")

    if args.json:
        print(json.dumps({"summary": summary, "cards": cards}, indent=2))
    else:
        for card in cards:
            print(format_credit_card_line(card))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
