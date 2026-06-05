"""Structured logging with secret redaction.

Logs are always rendered as JSON in non-development environments so they can
be shipped to Log Analytics without further transformation. In development
the console renderer adds colors for readability.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from aegis.settings import get_settings

_SECRET_KEYS = {
    "azure_openai_api_key",
    "openai_api_key",
    "azure_content_safety_key",
    "aegis_jwt_secret",
    "aegis_demo_password",
    "presented_token",
    "authorization",
    "api_key",
    "secret",
    "password",
    "token",
}


def _redact_secrets(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Walk the event dict and replace anything that smells like a secret."""

    def _walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: ("***REDACTED***" if k.lower() in _SECRET_KEYS else _walk(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    return _walk(event_dict)  # type: ignore[return-value]


_CONFIGURED = False

# Third-party loggers that flood stdout with per-request HTTP traffic and
# exporter chatter. Left at INFO they bury AEGIS's own verdict log lines -
# fatal during a live demo. We pin them to WARNING unless AEGIS_LOG_LEVEL is
# explicitly DEBUG (a developer asking for everything).
_NOISY_LOGGERS = (
    "azure",  # azure.core http_logging_policy + azure.monitor exporter
    "azure.core.pipeline.policies.http_logging_policy",
    "azure.monitor.opentelemetry.exporter",
    "azure.identity",
    "msal",
    "opentelemetry",
    "urllib3",
    "httpx",
    "httpcore",
    "openai",
)


def _quiet_noisy_loggers(aegis_level: str) -> None:
    """Silence verbose third-party loggers so the AEGIS demo output is clean."""

    if aegis_level == "DEBUG":
        return  # developer explicitly wants the firehose
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def configure_logging() -> None:
    """Idempotent. Call once at process boot."""

    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    settings = get_settings()

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.aegis_log_level),
    )
    _quiet_noisy_loggers(settings.aegis_log_level)

    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_secrets,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if settings.aegis_env == "development":
        processors.append(structlog.dev.ConsoleRenderer(colors=True))
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.aegis_log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    configure_logging()
    return structlog.get_logger(name)
