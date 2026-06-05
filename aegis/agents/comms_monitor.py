"""Inter-Agent Comms Monitor guardian.

Watches inter-agent messages and tool calls for:
  * identity spoofing (Entra Agent ID token missing / invalid / mismatched)
  * replay (jti seen in the replay window)
  * privilege anomalies (non-orchestrator emitting orchestrator-level tasks)
  * trust decay (per-agent score, consumed by the Arbiter and the dashboard
    trust graph)

The Entra check is delegated to aegis.sensors.entra_agent_id which uses
real PyJWT + Entra JWKS when Entra is configured, and a HMAC-signed
dev-mock token (identical in shape) when it is not. The Comms Monitor
itself never knows which mode is in use - that's the entire point of the
sensor abstraction.
"""

from __future__ import annotations

import re
import time
from typing import Iterable

from aegis.core import (
    ActionType,
    AgentAction,
    GuardianKind,
    GuardianSignal,
    SignalLabel,
)
from aegis.sensors.entra_agent_id import (
    EntraAgentIdSensor,
    EntraVerificationResult,
    get_entra_sensor,
)
from aegis.telemetry.logging import get_logger
from aegis.telemetry.metrics import MetricsEmitter, get_metrics
from aegis.telemetry.tracing import trace_guardian_decision

_log = get_logger(__name__)


_ORCHESTRATOR_ROLE_PATTERN = re.compile(r"(?i)\borchestrator\b|\bsupervisor\b|\bcoordinator\b")
_HIGH_PRIVILEGE_TOOL_PATTERN = re.compile(
    r"(?i)export_(?:customers|users|secrets|all)"
    r"|delete_(?:all|users|database)"
    r"|drop_table"
    r"|grant_admin"
    r"|wire_transfer"
)
_HIGH_PRIVILEGE_VERB_PATTERN = re.compile(
    r"(?i)export (?:the )?(?:customer|user|secrets) (?:table|list|database)"
    r"|delete (?:the )?(?:database|production)"
    r"|drop (?:the )?table"
)


class CommsMonitorGuardian:
    name = GuardianKind.COMMS_MONITOR

    def __init__(
        self,
        *,
        orchestrator_agent_ids: Iterable[str] = (),
        entra: EntraAgentIdSensor | None = None,
        metrics: MetricsEmitter | None = None,
        trust_decay_per_offense: float = 0.25,
    ) -> None:
        self._orchestrators = set(orchestrator_agent_ids)
        self._entra = entra or get_entra_sensor()
        self._metrics = metrics or get_metrics()
        self._trust_decay = trust_decay_per_offense

    async def inspect(self, action: AgentAction) -> GuardianSignal:
        t0 = time.perf_counter()
        with trace_guardian_decision(
            "comms_monitor",
            action_id=action.action_id,
            correlation_id=action.correlation_id,
        ):
            findings: list[str] = []
            severity_score = 0.0

            # ---- Identity verification ---------------------------------
            entra_result: EntraVerificationResult | None = None
            if action.identity_claim is not None:
                entra_result = await self._entra.verify(
                    claimed_agent_id=action.identity_claim.claimed_agent_id,
                    token=action.identity_claim.presented_token,
                )
                if entra_result.status == "missing":
                    findings.append("identity_missing")
                    severity_score += 0.8
                elif entra_result.status == "invalid":
                    findings.append(f"identity_invalid:{entra_result.reason}")
                    severity_score += 0.9
                elif entra_result.status == "expired":
                    findings.append("identity_expired")
                    severity_score += 0.7
                elif entra_result.status == "replay":
                    findings.append("identity_replayed_jti")
                    severity_score += 0.9
                # source agent vs claimed agent mismatch is a strong spoof flag
                if (
                    entra_result.valid
                    and entra_result.verified_agent_id
                    and entra_result.verified_agent_id != action.source_agent_id
                ):
                    findings.append("orchestrator_observed_source_differs_from_verified")
                    severity_score += 0.7
            else:
                findings.append("identity_claim_absent")
                severity_score += 0.5

            # ---- Privilege anomaly -------------------------------------
            if self._is_orchestrator_privileged(action) and not self._is_orchestrator(
                action, entra_result
            ):
                findings.append("orchestrator_impersonation_attempt")
                severity_score += 0.7

            label, confidence = self._score(findings, severity_score)

            # ---- Trust decay -------------------------------------------
            current_trust = self._metrics.get_trust(action.source_agent_id)
            if label is SignalLabel.MALICIOUS and current_trust > 0:
                new_trust = self._metrics.adjust_trust(
                    action.source_agent_id,
                    -self._trust_decay,
                    reason=f"comms_monitor:{','.join(findings)[:80]}",
                )
            elif label is SignalLabel.SUSPICIOUS and current_trust > 0:
                new_trust = self._metrics.adjust_trust(
                    action.source_agent_id,
                    -self._trust_decay / 2,
                    reason=f"comms_monitor_susp:{','.join(findings)[:80]}",
                )
            else:
                new_trust = current_trust

            evidence = self._evidence_sentence(findings, entra_result, current_trust, new_trust)
            return GuardianSignal(
                guardian=self.name,
                action_id=action.action_id,
                target_agent=action.source_agent_id,
                label=label,
                confidence=confidence,
                evidence=evidence,
                sensor_data={
                    "entra": entra_result.to_sensor_data() if entra_result else None,
                    "findings": findings,
                    "trust_before": current_trust,
                    "trust_after": new_trust,
                    "is_orchestrator_privileged_action": self._is_orchestrator_privileged(action),
                },
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )

    # ----- helpers ------------------------------------------------------
    def _is_orchestrator(
        self, action: AgentAction, entra: EntraVerificationResult | None
    ) -> bool:
        if action.source_agent_id in self._orchestrators:
            return True
        if entra and entra.raw_claims:
            role = (entra.raw_claims.get("role") or "").lower()
            if _ORCHESTRATOR_ROLE_PATTERN.search(role):
                return True
        if action.identity_claim and _ORCHESTRATOR_ROLE_PATTERN.search(
            action.identity_claim.claimed_role or ""
        ):
            # The CLAIMED role being orchestrator is suspicious unless Entra
            # confirms it. We return False here so the impersonation check
            # fires.
            return False
        return False

    @staticmethod
    def _is_orchestrator_privileged(action: AgentAction) -> bool:
        if action.action_type is ActionType.TOOL_CALL:
            if action.tool_name and _HIGH_PRIVILEGE_TOOL_PATTERN.search(action.tool_name):
                return True
        text = action.text_content or ""
        if _HIGH_PRIVILEGE_VERB_PATTERN.search(text):
            return True
        return False

    @staticmethod
    def _score(findings: list[str], severity_score: float) -> tuple[SignalLabel, float]:
        score = min(1.0, severity_score)
        if not findings:
            return SignalLabel.BENIGN, 0.9
        if score >= 0.7:
            return SignalLabel.MALICIOUS, score
        if score >= 0.4:
            return SignalLabel.SUSPICIOUS, score
        return SignalLabel.BENIGN, 1.0 - score

    @staticmethod
    def _evidence_sentence(
        findings: list[str],
        entra: EntraVerificationResult | None,
        trust_before: float,
        trust_after: float,
    ) -> str:
        bits: list[str] = []
        if entra:
            bits.append(
                f"Entra status={entra.status} backend={entra.backend}"
                + (f" reason={entra.reason}" if entra.reason else "")
            )
        if findings:
            bits.append(f"findings: {', '.join(findings)}")
        if trust_after != trust_before:
            bits.append(f"trust {trust_before:.2f} -> {trust_after:.2f}")
        if not bits:
            bits.append("identity verified, no anomalies")
        return "; ".join(bits)
