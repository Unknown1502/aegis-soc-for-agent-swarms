"""AEGIS telemetry: Foundry tracing, Azure Monitor metrics, structured logs.

Every guardian decision and every verdict must be traceable. This module
wires three things:

1. OpenTelemetry tracer that exports to Azure AI Foundry / App Insights
   when credentials are present; otherwise emits to console.
2. Counter / gauge metric emitter that exports to Azure Monitor when
   configured; otherwise updates an in-memory store the dashboard can read.
3. Structured logging via structlog with redaction of secret-like fields.

All three degrade silently with a clear boot-time integration report so
nothing about the runtime depends on Azure being reachable.
"""

from aegis.telemetry.logging import configure_logging, get_logger
from aegis.telemetry.metrics import MetricsEmitter, get_metrics
from aegis.telemetry.tracing import (
    get_tracer,
    init_telemetry,
    trace_guardian_decision,
    trace_verdict,
)

__all__ = [
    "MetricsEmitter",
    "configure_logging",
    "get_logger",
    "get_metrics",
    "get_tracer",
    "init_telemetry",
    "trace_guardian_decision",
    "trace_verdict",
]
