from __future__ import annotations

import json
import logging
import re
import threading
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AWS_ID = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b")
ASSIGNMENT = re.compile(r"(?i)(authorization|password|passwd|secret|session|token|api[_-]?hash)\s*[:=]\s*([^\s,;]+)")
SENSITIVE_KEYS = ("password", "secret", "token", "session", "api_hash")

_MAX_ACTIVITY_LOGS = 200
_activity_path: Path | None = None
_activity_lock = threading.Lock()
_activity_buffer: deque[dict[str, Any]] = deque(maxlen=_MAX_ACTIVITY_LOGS)


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


class ActivityLogHandler(logging.Handler):
    """Persist recent log records for the dashboard /logs endpoint."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname.lower(),
                "message": str(sanitize(record.getMessage())),
                "logger": record.name,
            }
            stage = getattr(record, "stage", None)
            if stage:
                entry["stage"] = str(sanitize(stage))
            with _activity_lock:
                _activity_buffer.append(entry)
                if _activity_path is not None:
                    _activity_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    tmp = _activity_path.with_suffix(".tmp")
                    tmp.write_text(json.dumps(list(_activity_buffer), ensure_ascii=False), encoding="utf-8")
                    tmp.replace(_activity_path)
        except Exception:
            self.handleError(record)


def recent_activity_logs(limit: int = 30) -> list[dict[str, Any]]:
    with _activity_lock:
        if _activity_buffer:
            return list(_activity_buffer)[-limit:]
        if _activity_path and _activity_path.exists():
            try:
                data = json.loads(_activity_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data[-limit:]
            except (OSError, ValueError):
                pass
    return []


def configure_logging(level: str, activity_log_path: Path | None = None) -> None:
    global _activity_path
    _activity_path = activity_log_path
    if activity_log_path and activity_log_path.exists():
        try:
            data = json.loads(activity_log_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                with _activity_lock:
                    _activity_buffer.clear()
                    for item in data[-_MAX_ACTIVITY_LOGS:]:
                        if isinstance(item, dict):
                            _activity_buffer.append(item)
        except (OSError, ValueError):
            pass

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    if activity_log_path is not None:
        activity = ActivityLogHandler()
        activity.setLevel(logging.INFO)
        root.addHandler(activity)
    root.setLevel(level)
    # Telethon "Got difference for channel…" is background sync noise, not job activity.
    logging.getLogger("telethon").setLevel(logging.WARNING)
    logging.getLogger("telethon.network").setLevel(logging.WARNING)
    logging.getLogger("telethon.client.updates").setLevel(logging.WARNING)
