from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class LogFormat(str, Enum):
    JSON = "json"
    TEXT = "text"


@dataclass(frozen=True)
class _LogContext:
    service: str = "log-anonymizer"
    pid: int = os.getpid()


class JsonFormatter(logging.Formatter):
    def __init__(self, context: _LogContext) -> None:
        super().__init__()
        self._context = context

    def format(self, record: logging.LogRecord) -> str:
        extras = _extract_extras(record)
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "service": self._context.service,
            "pid": self._context.pid,
        }
        if extras:
            payload.update(extras)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(*, level: str = "INFO", log_format: LogFormat = LogFormat.JSON) -> None:
    # Avoid noisy "BrokenPipeError" stack traces when output is piped (e.g., to `head`).
    logging.raiseExceptions = False

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())

    handler = logging.StreamHandler(stream=sys.stdout)
    if log_format == LogFormat.JSON:
        handler.setFormatter(JsonFormatter(_LogContext()))
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )

    root.addHandler(handler)

    # Reduce noisy third-party loggers if present.
    for noisy in ("urllib3",):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _extract_extras(record: logging.LogRecord) -> dict[str, Any]:
    # Include values added via logging's `extra={...}` while avoiding internal fields.
    reserved = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
    }
    out: dict[str, Any] = {}
    for k, v in record.__dict__.items():
        if k in reserved or k.startswith("_"):
            continue
        # Keep JSON-safe basic types; stringify anything else.
        if v is None or isinstance(v, (bool, int, float, str, list, dict)):
            out[k] = v
        else:
            out[k] = str(v)
    return out
