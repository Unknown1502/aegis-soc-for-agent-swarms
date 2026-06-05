"""AEGIS middleware interceptor.

Public surface:

    Interceptor.intercept(action) -> InterceptionResult

The caller (the victim swarm wrapper in aegis.victim) emits an AgentAction
for every operation it is about to perform and awaits an InterceptionResult.
If the result is ALLOW, the swarm proceeds. If BLOCK or QUARANTINE, the
swarm raises a SafeRefusal to the agent runtime so the agent receives an
explicit refusal message instead of silently failing.

This module is intentionally Agent-Framework-agnostic at the boundary - the
wrapper layer in aegis.victim.intercept_wrap binds it to Microsoft Agent
Framework's middleware pipeline. That keeps the interceptor unit-testable
without spinning up an Agent Framework workflow.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from aegis.bus import TOPIC_ACTION, TOPIC_OUTCOME, TOPIC_TRUST, TOPIC_VERDICT, get_bus
from aegis.core import (
    AgentAction,
    AgentId,
    ExecutionOutcome,
    Verdict,
    VerdictDecision,
)
from aegis.telemetry.logging import get_logger
from aegis.telemetry.metrics import MetricsEmitter, get_metrics
from aegis.telemetry.tracing import get_tracer

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# DecisionProvider abstraction
# ---------------------------------------------------------------------------


class DecisionProvider(Protocol):
    """Anything that turns an AgentAction into a Verdict + outcome.

    The Verdict Arbiter is the production implementation. The middleware
    treats DecisionProvider as a black box so we can:

      * run the victim swarm by itself (AlwaysAllowDecisionProvider)
      * run unit tests against the interceptor with hand-crafted verdicts
      * later replace the in-process Arbiter with a remote service
    """

    async def decide(self, action: AgentAction) -> Verdict: ...


@dataclass
class AlwaysAllowDecisionProvider:
    """Used when AEGIS is intentionally disabled (default victim-only mode)."""

    arbiter_version: str = "always-allow-0.1.0"

    async def decide(self, action: AgentAction) -> Verdict:
        from aegis.core import Severity

        return Verdict(
            correlation_id=action.correlation_id,
            target_action_id=action.action_id,
            target_agent_id=action.source_agent_id,
            decision=VerdictDecision.FALSE_POSITIVE,
            severity=Severity.INFO,
            confidence=1.0,
            explanation="AEGIS guard disabled - allowing all actions (developer mode).",
            sequence_action_ids=[action.action_id],
            standards_tags=[],
            suggested_outcome=ExecutionOutcome.ALLOW,
            arbiter_version=self.arbiter_version,
        )


# ---------------------------------------------------------------------------
# Quarantine registry
# ---------------------------------------------------------------------------


@dataclass
class QuarantineRegistry:
    """Tracks agents the Arbiter has quarantined.

    Once an agent is in this set, all subsequent actions from it default-
    block until an analyst clears it. The registry is process-local; in
    production this is backed by durable storage.
    """

    _members: set[AgentId] = field(default_factory=set)
    _reasons: dict[AgentId, str] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def quarantine(self, agent_id: AgentId, reason: str) -> None:
        with self._lock:
            self._members.add(agent_id)
            self._reasons[agent_id] = reason

    def release(self, agent_id: AgentId) -> None:
        with self._lock:
            self._members.discard(agent_id)
            self._reasons.pop(agent_id, None)

    def is_quarantined(self, agent_id: AgentId) -> bool:
        with self._lock:
            return agent_id in self._members

    def snapshot(self) -> dict[AgentId, str]:
        with self._lock:
            return dict(self._reasons)


# ---------------------------------------------------------------------------
# Result returned to the swarm wrapper
# ---------------------------------------------------------------------------


@dataclass
class InterceptionResult:
    action: AgentAction
    verdict: Verdict
    outcome: ExecutionOutcome
    refusal_message: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is ExecutionOutcome.ALLOW


# ---------------------------------------------------------------------------
# Interceptor
# ---------------------------------------------------------------------------


class Interceptor:
    """Wraps the victim swarm.

    Construct ONE Interceptor per AegisGuard process. Pass it the
    DecisionProvider you want it to consult and (optionally) a side-effect
    hook that runs after each decision (e.g. to record into the audit log).
    """

    def __init__(
        self,
        *,
        decision_provider: DecisionProvider,
        quarantine_registry: QuarantineRegistry | None = None,
        post_decision_hooks: list[Callable[[InterceptionResult], Awaitable[None]]] | None = None,
        metrics: MetricsEmitter | None = None,
    ) -> None:
        self._decision_provider = decision_provider
        self._quarantine = quarantine_registry or QuarantineRegistry()
        self._hooks = post_decision_hooks or []
        self._metrics = metrics or get_metrics()
        self._bus = get_bus()

    @property
    def quarantine_registry(self) -> QuarantineRegistry:
        return self._quarantine

    def add_hook(
        self, hook: Callable[[InterceptionResult], Awaitable[None]]
    ) -> None:
        self._hooks.append(hook)

    async def intercept(self, action: AgentAction) -> InterceptionResult:
        tracer = get_tracer()
        with tracer.start_as_current_span("middleware.intercept") as span:
            span.set_attribute("aegis.action_id", action.action_id)
            span.set_attribute("aegis.correlation_id", action.correlation_id)
            span.set_attribute("aegis.action_type", action.action_type.value)
            span.set_attribute("aegis.source_agent_id", action.source_agent_id)

            await self._bus.publish(TOPIC_ACTION, action)

            # ------ default-block quarantined agents ---------------------
            if self._quarantine.is_quarantined(action.source_agent_id):
                from aegis.core import Severity

                verdict = Verdict(
                    correlation_id=action.correlation_id,
                    target_action_id=action.action_id,
                    target_agent_id=action.source_agent_id,
                    decision=VerdictDecision.CONFIRMED,
                    severity=Severity.HIGH,
                    confidence=1.0,
                    explanation=(
                        f"Agent '{action.source_agent_id}' is in quarantine; "
                        "blocking by default until an analyst clears it."
                    ),
                    sequence_action_ids=[action.action_id],
                    standards_tags=[],
                    suggested_outcome=ExecutionOutcome.BLOCK,
                )
                return await self._finalize(action, verdict, ExecutionOutcome.BLOCK)

            # ------ delegate to the Arbiter ----------------------------
            t0 = time.perf_counter()
            verdict = await self._decision_provider.decide(action)
            span.set_attribute("aegis.verdict.decision", verdict.decision.value)
            span.set_attribute("aegis.verdict.outcome", verdict.suggested_outcome.value)
            span.set_attribute("aegis.verdict.confidence", verdict.confidence)
            span.set_attribute("aegis.decide.latency_ms", int((time.perf_counter() - t0) * 1000))

            outcome = verdict.suggested_outcome
            if outcome is ExecutionOutcome.QUARANTINE:
                self._quarantine.quarantine(
                    action.source_agent_id,
                    reason=verdict.explanation[:240],
                )
                self._metrics.set_trust(
                    action.source_agent_id,
                    0.0,
                    reason="quarantine",
                )
                await self._bus.publish(
                    TOPIC_TRUST,
                    {
                        "agent_id": action.source_agent_id,
                        "score": 0.0,
                        "event": "quarantine",
                    },
                )
            return await self._finalize(action, verdict, outcome)

    async def _finalize(
        self,
        action: AgentAction,
        verdict: Verdict,
        outcome: ExecutionOutcome,
    ) -> InterceptionResult:
        refusal = self._refusal_message(outcome, verdict) if outcome is not ExecutionOutcome.ALLOW else None
        result = InterceptionResult(
            action=action, verdict=verdict, outcome=outcome, refusal_message=refusal
        )
        await self._bus.publish(TOPIC_VERDICT, verdict)
        await self._bus.publish(
            TOPIC_OUTCOME,
            {
                "action_id": action.action_id,
                "correlation_id": action.correlation_id,
                "outcome": outcome.value,
                "verdict_id": verdict.verdict_id,
                "agent_id": action.source_agent_id,
            },
        )
        _log.info(
            "middleware.decision",
            action=action.short_repr(),
            decision=verdict.decision.value,
            outcome=outcome.value,
            confidence=round(verdict.confidence, 3),
            chain_len=len(verdict.sequence_action_ids),
        )
        # Hooks (e.g. audit) run after we publish so the dashboard sees the
        # verdict immediately.
        for hook in self._hooks:
            try:
                await hook(result)
            except Exception as exc:  # never let a hook break interception
                _log.warning("middleware.hook_failed", error=str(exc))
        return result

    @staticmethod
    def _refusal_message(outcome: ExecutionOutcome, verdict: Verdict) -> str:
        chips = ", ".join(verdict.to_chip_tags())
        suffix = f" [{chips}]" if chips else ""
        if outcome is ExecutionOutcome.QUARANTINE:
            return (
                "AEGIS: action blocked AND originating agent quarantined."
                f" Reason: {verdict.explanation}{suffix}"
            )
        return f"AEGIS: action blocked. {verdict.explanation}{suffix}"


# ---------------------------------------------------------------------------
# Convenience: a DecisionProvider that delegates to the full guardian swarm
# ---------------------------------------------------------------------------


class SwarmDecisionProvider:
    """A DecisionProvider that runs the three pattern guardians in parallel,
    then asks the VerdictArbiter to fuse their signals.

    The swarm wiring is intentionally kept here rather than inside the
    Interceptor so the Interceptor never needs to know about specific
    guardians. AegisGuard instantiates this and hands it to the Interceptor.
    """

    def __init__(
        self,
        *,
        threat_classifier: "ThreatClassifierGuardian",
        payload_analyzer: "PayloadAnalyzerGuardian",
        comms_monitor: "CommsMonitorGuardian",
        audit: "AuditProvenanceGuardian",
        arbiter: "VerdictArbiter",
    ) -> None:
        from aegis.agents import (
            AuditProvenanceGuardian,
            CommsMonitorGuardian,
            PayloadAnalyzerGuardian,
            ThreatClassifierGuardian,
            VerdictArbiter,
        )

        assert isinstance(threat_classifier, ThreatClassifierGuardian)
        assert isinstance(payload_analyzer, PayloadAnalyzerGuardian)
        assert isinstance(comms_monitor, CommsMonitorGuardian)
        assert isinstance(audit, AuditProvenanceGuardian)
        assert isinstance(arbiter, VerdictArbiter)

        self._classifier = threat_classifier
        self._payload = payload_analyzer
        self._comms = comms_monitor
        self._audit = audit
        self._arbiter = arbiter
        self._bus = get_bus()

    async def decide(self, action: AgentAction) -> Verdict:
        # Record the action in the audit chain first so the Arbiter can
        # reconstruct the cross-agent sequence including this action.
        self._audit.record_action(action)

        # Run the three pattern guardians in parallel.
        signals = await asyncio.gather(
            self._classifier.classify(action),
            self._payload.analyze(action),
            self._comms.inspect(action),
        )

        from aegis.bus import TOPIC_SIGNAL

        for sig in signals:
            self._audit.record_signal(sig, action.correlation_id)
            await self._bus.publish(TOPIC_SIGNAL, sig)

        verdict = await self._arbiter.arbitrate(target_action=action, signals=list(signals))
        return verdict


# Type imports just for type-checkers (avoid runtime cycles).
if False:  # pragma: no cover - import only for type hints
    from aegis.agents import (
        AuditProvenanceGuardian,
        CommsMonitorGuardian,
        PayloadAnalyzerGuardian,
        ThreatClassifierGuardian,
        VerdictArbiter,
    )
