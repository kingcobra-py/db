from __future__ import annotations

import re
from typing import Iterable, List

LABEL_RE = re.compile(
    r"(?ixm)"
    r"(?:^|(?<=[\s\[\(\"'`|•·\-–—]))"
    r"(?:archive\s*)?(?:rar|zip|7z|file|extract(?:ion)?|un(?:zip|rar))?\s*"
    r"(?:pass(?:word|wd)?|pwd|пароль|senha|clave|kennwort)"
    r"\s*(?:is|for\s+(?:this|the)\s+(?:file|archive|rar|zip))?"
    r"\s*(?:[:＝=|\-–—>]|»|→)+\s*"
    r"[\"'`“”‘’]*"
    r"([^\s\"'`“”‘’]{1,128})"
    r"[\"'`“”‘’]*"
    r"(?=\s|$)"
)

LABEL_ONLY_RE = re.compile(
    r"(?ix)"
    r"^(?:archive\s*)?(?:rar|zip|7z|file)?\s*"
    r"(?:pass(?:word|wd)?|pwd|пароль|senha)\s*(?:[:＝=|\-–—>]|»|→)?\s*$"
)

EMOJI_PASS_RE = re.compile(
    r"(?ix)"
    r"(?:🔐|🔑|🗝|🔏|🔓)\s*(?:pass(?:word|wd)?|pwd)?\s*(?:[:＝=|\-–—>]|»|→)?\s*"
    r"[\"'`“”‘’]*"
    r"([^\s\"'`“”‘’]{1,128})"
    r"[\"'`“”‘’]*"
)

BARE_AT_RE = re.compile(r"(?<![A-Za-z0-9_])(@[A-Za-z][A-Za-z0-9_]{2,31})\b")

SKIP_VALUES = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "none",
    "null",
    "n/a",
    "na",
    "empty",
    "unknown",
    "here",
    "this",
    "file",
    "archive",
    "rar",
    "zip",
    "logs",
    "log",
    "channel",
    "telegram",
    "media",
    "download",
    "below",
    "above",
    "description",
}

SKIP_PREFIXES = ("http://", "https://", "t.me/", "tg://")


def _clean_candidate(raw: str) -> str:
    value = (raw or "").strip()
    value = value.strip(" \t\r\n\"'`“”‘’[](){}<>.,;")
    value = re.sub(r"\s+", " ", value)
    if value.endswith((".", ",", ";", "!", "?", "|")):
        value = value[:-1].strip()
    return value


def _looks_like_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(SKIP_PREFIXES) or "://" in value


def _is_usable_password(value: str) -> bool:
    if not value or len(value) < 2 or len(value) > 128:
        return False
    if _looks_like_url(value):
        return False
    if value.lower() in SKIP_VALUES:
        return False
    if value.count(" ") > 3:
        return False
    if re.fullmatch(r"[\W_]+", value):
        return False
    letters = sum(ch.isalnum() or ch in "@#_-+." for ch in value)
    if letters < 2:
        return False
    return True


def extract_archive_passwords(*texts: str | None) -> List[str]:
    """Pull archive-unlock passwords from Telegram post text/captions."""
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        value = _clean_candidate(raw)
        if not _is_usable_password(value):
            return
        if value in seen:
            return
        seen.add(value)
        found.append(value)

    for text in texts:
        if not text:
            continue
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = normalized.splitlines()

        for match in LABEL_RE.finditer(normalized):
            add(match.group(1))
        for match in EMOJI_PASS_RE.finditer(normalized):
            add(match.group(1))

        for index, line in enumerate(lines):
            stripped = line.strip()
            if LABEL_ONLY_RE.match(stripped) and index + 1 < len(lines):
                add(lines[index + 1])

        # Common stealer-channel style: a lone @Token used as the archive password.
        if re.search(r"(?i)\b(?:pass(?:word|wd)?|pwd|пароль|senha)\b", normalized) or "🔐" in normalized or "🔑" in normalized:
            for match in BARE_AT_RE.finditer(normalized):
                add(match.group(1))

    return found


def extract_archive_passwords_from_messages(messages: Iterable[object]) -> List[str]:
    texts: list[str] = []
    for message in messages:
        if message is None:
            continue
        for attr in ("raw_text", "message", "text"):
            value = getattr(message, attr, None)
            if isinstance(value, str) and value.strip():
                texts.append(value)
    return extract_archive_passwords(*texts)
