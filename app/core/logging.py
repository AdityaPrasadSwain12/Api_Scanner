import logging
import re
import sys
from collections.abc import Mapping
from typing import Any

import structlog

SECRET_KEYS = re.compile(
    r"(authorization|proxy-authorization|api[-_]?key|token|password|secret|cookie|set-cookie)",
    re.IGNORECASE,
)
BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")


def redact(value: Any, key: str = "") -> Any:
    """Recursively remove common credential forms from structured data."""
    if SECRET_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, str):
        return BEARER.sub(r"\1 [REDACTED]", value)
    if isinstance(value, Mapping):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [redact(v) for v in value]
    return value


def redact_known(value: Any, secrets: dict[str, Any] | None) -> Any:
    """Redact configured secrets even if a target echoes them under an unknown key."""
    safe = redact(value)
    if not secrets:
        return safe
    known = {
        str(secrets[name])
        for name in ("token", "key", "password")
        if secrets.get(name) is not None and len(str(secrets[name])) >= 3
    }

    def replace(item: Any) -> Any:
        if isinstance(item, str):
            for secret in known:
                item = item.replace(secret, "[REDACTED]")
            return item
        if isinstance(item, Mapping):
            return {str(key): replace(child) for key, child in item.items()}
        if isinstance(item, list | tuple | set):
            return [replace(child) for child in item]
        return item

    return replace(safe)


def redact_known_values(value: Any, secrets: dict[str, Any] | None) -> Any:
    """Redact exact runtime credentials without changing specification field structure."""
    known = {
        str(secrets[name])
        for name in ("token", "key", "password")
        if secrets and secrets.get(name) is not None and len(str(secrets[name])) >= 3
    }

    def replace(item: Any) -> Any:
        if isinstance(item, str):
            item = BEARER.sub(r"\1 [REDACTED]", item)
            for secret in known:
                item = item.replace(secret, "[REDACTED]")
            return item
        if isinstance(item, Mapping):
            return {str(key): replace(child) for key, child in item.items()}
        if isinstance(item, list | tuple | set):
            return [replace(child) for child in item]
        return item

    return replace(value)


def _redact_processor(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    return redact(event_dict)


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _redact_processor,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


logger = structlog.get_logger()
