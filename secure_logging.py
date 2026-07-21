from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

AWS_ID = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b")
ASSIGNMENT = re.compile(r"(?i)(authorization|password|passwd|secret|session|token|api[_-]?hash)\s*[:=]\s*([^\s,;]+)")
SENSITIVE_KEYS = ("password", "secret", "token", "session", "api_hash")


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if any(s in str(k).lower() for s in SENSITIVE_KEYS) else sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize(v) for v in value]
    text = AWS_ID.sub("[REDACTED_AWS_ID]", str(value))
    return ASSIGNMENT.sub(r"\1=[REDACTED]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize(record.getMessage()),
        }
        for key in ("job_id", "message_id", "user_id", "stage"):
            if hasattr(record, key):
                payload[key] = sanitize(getattr(record, key))
        if record.exc_info:
            payload["exception"] = sanitize(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("telethon.network").setLevel(logging.WARNING)
