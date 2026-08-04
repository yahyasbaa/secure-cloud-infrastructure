"""Structured JSON logging.

Every security-relevant event is emitted as one JSON object per line with a
stable ``event`` field. CloudWatch Logs metric filters match on these fields
(e.g. ``{ $.event = "auth_failure" }``), so renaming an event is a breaking
change for the alarms defined in terraform/modules/monitoring.
"""

from __future__ import annotations

import json
import logging
import sys
import time

_RESERVED = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


def security_event(logger: logging.Logger, event: str, **fields: object) -> None:
    """Emit a security event. Callers must never pass secret material."""
    logger.warning(event, extra={"event": event, **fields})
