"""OpenTelemetry tracing wired to Azure AI Foundry / App Insights.

Design notes:
* A single tracer ('aegis') is used across the codebase.
* When the Foundry-side connection string (or App Insights connection string,
  which Foundry projects expose) is configured, traces are exported via
  azure-monitor-opentelemetry. Otherwise a ConsoleSpanExporter is installed so
  developers can still see the spans.
* `trace_guardian_decision` and `trace_verdict` are convenience context
  managers that record the structured payloads judges will want to inspect
  in the Foundry trace viewer.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.trace import Status, StatusCode, Tracer

from aegis.settings import get_settings
from aegis.telemetry.logging import get_logger

_log = get_logger(__name__)
_INITIALIZED = False
_TRACER_NAME = "aegis"


def init_telemetry() -> Tracer:
    """Configure the global tracer provider exactly once.

    Returns the AEGIS tracer. Safe to call from many entry points.
    """

    global _INITIALIZED
    if _INITIALIZED:
        return trace.get_tracer(_TRACER_NAME)

    settings = get_settings()
    resource = Resource.create(
        {
            "service.name": "aegis",
            "service.version": "0.1.0",
            "service.namespace": "aegis.guard",
            "deployment.environment": settings.aegis_env,
        }
    )
    provider = TracerProvider(resource=resource)

    exporter_attached = False
    if settings.has_foundry_tracing:
        try:
            # azure-monitor-opentelemetry attaches the right exporters and
            # samples when given the App Insights connection string Foundry
            # surfaces on the project's Tracing tab.
            from azure.monitor.opentelemetry import configure_azure_monitor

            configure_azure_monitor(
                connection_string=(
                    settings.azure_ai_foundry_connection_string
                    or settings.applicationinsights_connection_string
                ),
                resource=resource,
                disable_offline_storage=False,
            )
            exporter_attached = True
            # configure_azure_monitor re-enables verbose Azure SDK HTTP logging;
            # re-pin the noisy loggers so they don't drown the demo output.
            from aegis.telemetry.logging import _quiet_noisy_loggers

            _quiet_noisy_loggers(settings.aegis_log_level)
            _log.info("telemetry.foundry_exporter.attached")
        except Exception as exc:  # pragma: no cover - dev safety net
            _log.warning(
                "telemetry.foundry_exporter.failed",
                error=str(exc),
                fallback="console",
            )

    if not exporter_attached:
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        _log.info("telemetry.console_exporter.attached")

    # Always also keep a batch console exporter in dev for human-readable spans.
    if settings.aegis_env == "development" and exporter_attached:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _INITIALIZED = True
    return trace.get_tracer(_TRACER_NAME)


def get_tracer() -> Tracer:
    if not _INITIALIZED:
        return init_telemetry()
    return trace.get_tracer(_TRACER_NAME)


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)[:8192]
    except Exception:
        return repr(value)[:8192]


@contextlib.contextmanager
def trace_guardian_decision(
    guardian: str,
    action_id: str,
    correlation_id: str,
    *,
    inputs: dict[str, Any] | None = None,
) -> Iterator[trace.Span]:
    """Wrap one guardian's per-action decision in a Foundry trace span.

    Add the resulting GuardianSignal via `span.set_attribute("aegis.signal",
    signal.model_dump_json())` inside the with block (the guardian classes
    do this for you).
    """

    tracer = get_tracer()
    with tracer.start_as_current_span(f"guardian.{guardian}.decision") as span:
        span.set_attribute("aegis.guardian", guardian)
        span.set_attribute("aegis.action_id", action_id)
        span.set_attribute("aegis.correlation_id", correlation_id)
        if inputs is not None:
            span.set_attribute("aegis.inputs_json", _safe_json(inputs))
        try:
            yield span
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.record_exception(exc)
            raise


@contextlib.contextmanager
def trace_verdict(
    correlation_id: str,
    target_action_id: str,
) -> Iterator[trace.Span]:
    tracer = get_tracer()
    with tracer.start_as_current_span("verdict.arbiter.decide") as span:
        span.set_attribute("aegis.correlation_id", correlation_id)
        span.set_attribute("aegis.target_action_id", target_action_id)
        try:
            yield span
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.record_exception(exc)
            raise
