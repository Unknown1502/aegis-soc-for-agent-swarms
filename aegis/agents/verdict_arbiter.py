"""Verdict Arbiter - the differentiator.

The Arbiter is the only guardian that judges sequences. It consumes:

  * the GuardianSignals other guardians produced for the target action
  * the ordered cross-agent action sequence from the Audit guardian
  * provenance findings from the Audit guardian (data flow internal->external)
  * any Defender corroboration in the same correlation window
  * the per-agent trust score from the Comms Monitor

and returns ONE Verdict whose decision drives the middleware's
ALLOW / BLOCK / QUARANTINE outcome.

The escalation rule is intentionally simple and tunable so reviewers can
read and reason about it:

  1.  CONFIRMED requires CORROBORATION:
        * >= 2 guardians agree on a malicious label, OR
        * 1 high-confidence (>= 0.85) malicious guardian AND a supporting
          piece of sequence evidence (provenance leak OR a corroborating
          Defender alert OR a cross-agent chain length >= 2).

  2.  PROBABLE is "real concern but evidence is thin":
        * 1 actionable signal at moderate-to-high confidence (>= 0.6), OR
        * mixed evidence that does not meet CONFIRMED corroboration.
        PROBABLE blocks the specific action and escalates but does NOT
        quarantine the agent.

  3.  FALSE_POSITIVE is "sensors flagged but corroboration failed":
        * Every actionable signal is at low confidence (< 0.55) and there
          is no provenance leak, no Defender corroboration, and chain
          length < 2.

In the demo, the EchoLeak chain reaches CONFIRMED because the Payload
Analyzer is high-confidence malicious (provenance leak) AND the Threat
Classifier reports at least SUSPICIOUS - two-guardian agreement plus
sequence evidence.

The AdaptiveThresholdController tightens the SUSPICIOUS->MALICIOUS cutoff
for the Threat Classifier after N CONFIRMED malicious findings for the
same source agent, and decays it back after a quiet period. All threshold
movement is recorded on the metrics emitter so the dashboard can chart it.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque

from aegis.agents.audit_provenance import AuditProvenanceGuardian, ProvenanceQuery
from aegis.core import (
    AgentAction,
    AgentId,
    ExecutionOutcome,
    GuardianKind,
    GuardianSignal,
    Severity,
    SignalLabel,
    Verdict,
    VerdictDecision,
)
from aegis.core.standards import (
    DIRECT_PROMPT_INJECTION_TAG,
    IDENTITY_SPOOFING_TAG,
    INDIRECT_INJECTION_EXFIL_TAG,
    MEMORY_POISONING_TAG,
    StandardsTag,
)
from aegis.sensors.defender import DefenderSensor, get_defender_sensor
from aegis.telemetry.logging import get_logger
from aegis.telemetry.metrics import MetricsEmitter, get_metrics
from aegis.telemetry.tracing import trace_verdict

_log = get_logger(__name__)


def _has_pattern(sensor_data: dict, pattern_name: str) -> bool:
    """Check if `pattern_name` appears anywhere in a guardian's sensor_data.

    Each guardian shapes its sensor_data differently:
      * ThreatClassifier: {"heuristics": {"patterns": [...]}, "llm": {"patterns": [...]}}
      * PayloadAnalyzer:  {"findings": [{"pattern": "...", "snippet": "..."}, ...]}
      * CommsMonitor:     {"findings": ["string1", "string2", ...]}
    This walks both shapes and returns True on any hit.
    """

    if not sensor_data:
        return False
    # Threat Classifier shape
    for key in ("heuristics", "llm"):
        sub = sensor_data.get(key) or {}
        if pattern_name in (sub.get("patterns") or []):
            return True
    # Payload Analyzer shape (list of dicts) or Comms Monitor shape (list of strings)
    findings = sensor_data.get("findings") or []
    for f in findings:
        if isinstance(f, dict):
            if pattern_name in (f.get("pattern") or ""):
                return True
        elif isinstance(f, str):
            if pattern_name in f:
                return True
    return False


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass
class ArbiterPolicy:
    """The full set of tunable thresholds used by the Arbiter.

    Keeping them in one dataclass makes the adaptive controller easy to
    reason about: it only ever mutates fields here, and every mutation is
    recorded in metrics.threshold_history.
    """

    high_confidence_threshold: float = 0.85
    moderate_confidence_threshold: float = 0.6
    low_confidence_threshold: float = 0.55
    corroboration_min_guardians: int = 2
    chain_length_for_corroboration: int = 2
    trust_quarantine_floor: float = 0.25

    # Adaptive defense
    confirmed_attacks_before_tighten: int = 2
    tighten_step: float = 0.07
    tightest_high_confidence: float = 0.65
    recovery_after_quiet_seconds: int = 600

    # Severity calibration
    base_severity_for_confirmed: Severity = Severity.HIGH
    base_severity_for_probable: Severity = Severity.MEDIUM
    severity_floor_on_exfil: Severity = Severity.CRITICAL


# ---------------------------------------------------------------------------
# Adaptive controller
# ---------------------------------------------------------------------------


@dataclass
class _AgentAttackHistory:
    confirmed_count: int = 0
    last_confirmed_unix: int = 0


class AdaptiveThresholdController:
    """After N CONFIRMED malicious verdicts for a source agent within a
    window, tighten the high-confidence threshold by `tighten_step` (floor
    at `tightest_high_confidence`). After `recovery_after_quiet_seconds`
    of no CONFIRMED, relax one step.
    """

    def __init__(self, policy: ArbiterPolicy, metrics: MetricsEmitter) -> None:
        self._policy = policy
        self._metrics = metrics
        self._history: dict[AgentId, _AgentAttackHistory] = defaultdict(_AgentAttackHistory)
        self._lock = threading.RLock()
        self._last_recovery_check = int(time.time())

    def record_confirmed(self, agent_id: AgentId) -> None:
        with self._lock:
            h = self._history[agent_id]
            h.confirmed_count += 1
            h.last_confirmed_unix = int(time.time())
            if h.confirmed_count >= self._policy.confirmed_attacks_before_tighten:
                self._tighten()
                h.confirmed_count = 0

    def maybe_relax(self) -> None:
        with self._lock:
            now = int(time.time())
            if now - self._last_recovery_check < 60:
                return
            self._last_recovery_check = now
            quiet = all(
                (now - h.last_confirmed_unix) > self._policy.recovery_after_quiet_seconds
                for h in self._history.values()
            )
            if quiet and self._policy.high_confidence_threshold < 0.85:
                old = self._policy.high_confidence_threshold
                self._policy.high_confidence_threshold = min(
                    0.85, old + self._policy.tighten_step
                )
                self._metrics.record_threshold_change(
                    "high_confidence_threshold",
                    old=old,
                    new=self._policy.high_confidence_threshold,
                    reason="recovery_after_quiet_window",
                )

    def _tighten(self) -> None:
        old = self._policy.high_confidence_threshold
        new = max(self._policy.tightest_high_confidence, old - self._policy.tighten_step)
        if new < old:
            self._policy.high_confidence_threshold = new
            self._metrics.record_threshold_change(
                "high_confidence_threshold",
                old=old,
                new=new,
                reason="confirmed_attacks_threshold",
            )


# ---------------------------------------------------------------------------
# The Arbiter itself
# ---------------------------------------------------------------------------


@dataclass
class _ArbitrationContext:
    target_action: AgentAction
    signals: list[GuardianSignal]
    sequence: list[AgentAction]
    leak: ProvenanceQuery
    defender_corroborating: bool
    defender_alert_ids: list[str] = field(default_factory=list)
    trust_score: float = 1.0


class VerdictArbiter:
    name = GuardianKind.VERDICT_ARBITER

    def __init__(
        self,
        audit: AuditProvenanceGuardian,
        *,
        policy: ArbiterPolicy | None = None,
        metrics: MetricsEmitter | None = None,
        defender: DefenderSensor | None = None,
    ) -> None:
        self._audit = audit
        self._policy = policy or ArbiterPolicy()
        self._metrics = metrics or get_metrics()
        self._defender = defender or get_defender_sensor()
        self.adaptive = AdaptiveThresholdController(self._policy, self._metrics)

    @property
    def policy(self) -> ArbiterPolicy:
        return self._policy

    async def arbitrate(
        self,
        *,
        target_action: AgentAction,
        signals: list[GuardianSignal],
    ) -> Verdict:
        with trace_verdict(
            correlation_id=target_action.correlation_id,
            target_action_id=target_action.action_id,
        ):
            ctx = await self._build_context(target_action, signals)
            decision, severity, confidence, explanation, suppressed = self._decide(ctx)
            outcome = self._outcome_for(decision, ctx)
            tags = self._tags_for(ctx, decision)

            # End-to-end time to verdict: from the moment the action was
            # observed (created at intercept) to the moment the Arbiter renders
            # its verdict. This spans audit provenance reconstruction + all
            # guardian inference + fusion - i.e. the real detection latency,
            # not just the Arbiter's sub-millisecond fusion step. clamp to >=1
            # so a genuinely fast verdict never reads as a broken "0 ms".
            now_ms = int(time.time() * 1000)
            ttv = max(1, now_ms - target_action.created_at_unix_ms)
            verdict = Verdict(
                correlation_id=target_action.correlation_id,
                target_action_id=target_action.action_id,
                target_agent_id=target_action.source_agent_id,
                decision=decision,
                severity=severity,
                confidence=confidence,
                explanation=explanation,
                contributing_signals=signals,
                sequence_action_ids=[a.action_id for a in ctx.sequence],
                standards_tags=tags,
                suggested_outcome=outcome,
                time_to_verdict_ms=ttv,
                suppressed_signal_ids=suppressed,
                extra={
                    "defender_corroborating": ctx.defender_corroborating,
                    "defender_alert_ids": ctx.defender_alert_ids,
                    "trust_score_at_decision": ctx.trust_score,
                    "policy_snapshot": {
                        "high_confidence_threshold": self._policy.high_confidence_threshold,
                        "moderate_confidence_threshold": self._policy.moderate_confidence_threshold,
                        "low_confidence_threshold": self._policy.low_confidence_threshold,
                    },
                },
            )

            self._metrics.record_verdict(decision.value, ttv)
            self._metrics.record_action_outcome(outcome.value)
            if suppressed:
                self._metrics.record_suppression(len(suppressed))
            self._audit.record_verdict(verdict)

            if decision is VerdictDecision.CONFIRMED:
                self.adaptive.record_confirmed(target_action.source_agent_id)
            self.adaptive.maybe_relax()

            return verdict

    # ----- context assembly --------------------------------------------
    async def _build_context(
        self, action: AgentAction, signals: list[GuardianSignal]
    ) -> _ArbitrationContext:
        sequence = self._audit.sequence_for(action.correlation_id)
        leak = self._audit.check_outbound_leak(action)

        defender_alerts = await self._defender.recent_alerts_for(
            agent_id=action.source_agent_id,
            correlation_id=action.correlation_id,
        )
        corroborating = bool(
            [a for a in defender_alerts if a.severity in ("medium", "high")]
        )
        trust = self._metrics.get_trust(action.source_agent_id)
        return _ArbitrationContext(
            target_action=action,
            signals=signals,
            sequence=sequence,
            leak=leak,
            defender_corroborating=corroborating,
            defender_alert_ids=[a.alert_id for a in defender_alerts],
            trust_score=trust,
        )

    # ----- decision logic ----------------------------------------------
    def _decide(
        self, ctx: _ArbitrationContext
    ) -> tuple[VerdictDecision, Severity, float, str, list[str]]:
        actionable = [s for s in ctx.signals if s.is_actionable()]
        malicious = [s for s in actionable if s.label is SignalLabel.MALICIOUS]
        suspicious = [s for s in actionable if s.label is SignalLabel.SUSPICIOUS]
        suppressed: list[str] = []

        high_conf = self._policy.high_confidence_threshold
        moderate_conf = self._policy.moderate_confidence_threshold
        low_conf = self._policy.low_confidence_threshold

        has_high_conf_malicious = any(s.confidence >= high_conf for s in malicious)
        guardian_corroboration = (
            len({s.guardian for s in malicious}) >= self._policy.corroboration_min_guardians
        )
        guardian_mixed_corroboration = (
            len({s.guardian for s in actionable}) >= self._policy.corroboration_min_guardians
        )
        # Sequence evidence is the load-bearing concept: the chain shows
        # something meaningful happened across agents, not just that a chain
        # exists. Chain length alone is NOT evidence (that would mass-flag
        # every benign multi-step task). Real evidence is provenance leak,
        # Defender corroboration, or prior CONFIRMED verdicts in this
        # correlation indicating the chain is already known-bad.
        sequence_evidence = (
            ctx.leak.leak_suspected or ctx.defender_corroborating
        )

        # ---- CONFIRMED -------------------------------------------------
        if guardian_corroboration or (has_high_conf_malicious and sequence_evidence):
            decision = VerdictDecision.CONFIRMED
            sev = (
                self._policy.severity_floor_on_exfil
                if ctx.leak.leak_suspected
                else self._policy.base_severity_for_confirmed
            )
            confidence = max((s.confidence for s in malicious), default=0.85)
            confidence = min(0.99, confidence + (0.05 if sequence_evidence else 0))
            explanation = self._explain_confirmed(ctx, malicious, suspicious)
            return decision, sev, confidence, explanation, suppressed

        # ---- PROBABLE --------------------------------------------------
        # A single high-confidence MALICIOUS signal WITHOUT corroboration is
        # only PROBABLE if there is some supporting evidence (sequence /
        # Defender / cross-guardian agreement). This is the load-bearing
        # AEGIS-vs-single-point-filter principle: we don't act on one
        # detector's hunch; we wait for corroboration. Otherwise we'd be
        # just another aggressive single-point detector.
        has_moderate_malicious = malicious and any(
            s.confidence >= moderate_conf for s in malicious
        )
        if has_moderate_malicious and (
            sequence_evidence or guardian_mixed_corroboration
        ):
            decision = VerdictDecision.PROBABLE
            sev = self._policy.base_severity_for_probable
            confidence = max(s.confidence for s in malicious)
            explanation = self._explain_probable(ctx, malicious, suspicious)
            return decision, sev, confidence, explanation, suppressed

        # ---- FALSE_POSITIVE -------------------------------------------
        # Anything actionable that fell through is suppressed.
        if actionable:
            suppressed = [s.signal_id for s in actionable if s.confidence < low_conf]
            explanation = self._explain_false_positive(ctx, actionable)
            return (
                VerdictDecision.FALSE_POSITIVE,
                Severity.INFO,
                1.0 - max((s.confidence for s in actionable), default=0.0),
                explanation,
                suppressed,
            )

        # ---- nothing actionable: clean allow ---------------------------
        return (
            VerdictDecision.FALSE_POSITIVE,
            Severity.INFO,
            0.95,
            "No guardian raised an actionable signal; action allowed.",
            suppressed,
        )

    def _outcome_for(
        self, decision: VerdictDecision, ctx: _ArbitrationContext
    ) -> ExecutionOutcome:
        if decision is VerdictDecision.CONFIRMED:
            if ctx.trust_score <= self._policy.trust_quarantine_floor or ctx.leak.leak_suspected:
                return ExecutionOutcome.QUARANTINE
            # identity-failure cases always quarantine
            if any(
                s.guardian is GuardianKind.COMMS_MONITOR
                and s.label is SignalLabel.MALICIOUS
                for s in ctx.signals
            ):
                return ExecutionOutcome.QUARANTINE
            return ExecutionOutcome.BLOCK
        if decision is VerdictDecision.PROBABLE:
            return ExecutionOutcome.BLOCK
        return ExecutionOutcome.ALLOW

    def _tags_for(
        self, ctx: _ArbitrationContext, decision: VerdictDecision
    ) -> list[StandardsTag]:
        if decision is VerdictDecision.FALSE_POSITIVE:
            return []
        tags: list[StandardsTag] = []
        # identity failures -> spoofing
        if any(
            s.guardian is GuardianKind.COMMS_MONITOR
            and s.label is SignalLabel.MALICIOUS
            for s in ctx.signals
        ):
            tags.append(IDENTITY_SPOOFING_TAG)
        # exfil chain -> indirect injection -> data exfil
        if ctx.leak.leak_suspected:
            tags.append(INDIRECT_INJECTION_EXFIL_TAG)
        # generic prompt injection finding
        if any(
            _has_pattern(s.sensor_data, "instruction_smuggling")
            or _has_pattern(s.sensor_data, "role_override")
            or _has_pattern(s.sensor_data, "indirect_prompt_injection")
            for s in ctx.signals
        ):
            if DIRECT_PROMPT_INJECTION_TAG not in tags:
                tags.append(DIRECT_PROMPT_INJECTION_TAG)
        if any(_has_pattern(s.sensor_data, "memory_poisoning") for s in ctx.signals):
            tags.append(MEMORY_POISONING_TAG)

        # Always include at least one tag for an escalation so the dashboard
        # has something to render.
        if not tags:
            tags.append(DIRECT_PROMPT_INJECTION_TAG)
        return tags

    # ----- explanation builders ----------------------------------------
    @staticmethod
    def _explain_confirmed(
        ctx: _ArbitrationContext,
        malicious: list[GuardianSignal],
        suspicious: list[GuardianSignal],
    ) -> str:
        guardian_summary = ", ".join(
            f"{s.guardian.value}(conf={s.confidence:.2f})" for s in (malicious + suspicious)[:3]
        )
        seq = f" Cross-agent chain length {len(ctx.sequence)}."
        leak = f" Provenance leak: {ctx.leak.rationale}" if ctx.leak.leak_suspected else ""
        defender = " Defender corroborated." if ctx.defender_corroborating else ""
        return (
            f"CONFIRMED via guardian corroboration ({guardian_summary})."
            f"{seq}{leak}{defender} "
            "Operator: review quarantined agent and notify the data owner."
        )

    @staticmethod
    def _explain_probable(
        ctx: _ArbitrationContext,
        malicious: list[GuardianSignal],
        suspicious: list[GuardianSignal],
    ) -> str:
        bits = []
        if malicious:
            bits.append(
                f"{len(malicious)} guardian(s) reported malicious"
                f" (peak conf {max(s.confidence for s in malicious):.2f})"
            )
        if suspicious:
            bits.append(f"{len(suspicious)} additional suspicious signal(s)")
        chain = f" Chain length {len(ctx.sequence)}."
        return (
            "PROBABLE: " + "; ".join(bits)
            + chain
            + " Blocking this action and escalating; agent NOT yet quarantined."
        )

    @staticmethod
    def _explain_false_positive(
        ctx: _ArbitrationContext, actionable: list[GuardianSignal]
    ) -> str:
        names = ", ".join(sorted({s.guardian.value for s in actionable}))
        peak = max(s.confidence for s in actionable)
        return (
            f"Sensors flagged this action ({names}, peak conf {peak:.2f}) but "
            "corroboration failed: no provenance leak, no Defender alert, no "
            "cross-agent chain evidence. Suppressed and allowed."
        )
