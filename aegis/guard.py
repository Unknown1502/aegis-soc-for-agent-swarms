"""AegisGuard - the top-level runtime.

One object. Wires the audit store, the four pattern guardians + the Verdict
Arbiter, the three sensors, the middleware interceptor, and the victim
swarm. The CLI, the API, the demo attack scripts, and the eval harness all
go through `AegisGuard.build(...)`.

Boot order:
    settings -> telemetry -> sensors -> audit -> guardians -> arbiter
    -> middleware (SwarmDecisionProvider) -> victim swarm
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from aegis.agents import (
    AuditProvenanceGuardian,
    CommsMonitorGuardian,
    PayloadAnalyzerGuardian,
    ThreatClassifierGuardian,
    VerdictArbiter,
)
from aegis.bus import TOPIC_AUDIT, get_bus
from aegis.middleware import (
    AlwaysAllowDecisionProvider,
    Interceptor,
    InterceptionResult,
    QuarantineRegistry,
)
from aegis.middleware.interceptor import SwarmDecisionProvider
from aegis.sensors.defender import DefenderSensor, get_defender_sensor
from aegis.sensors.entra_agent_id import EntraAgentIdSensor, get_entra_sensor
from aegis.sensors.prompt_shields import PromptShieldsSensor, get_prompt_shields
from aegis.settings import Settings, get_settings
from aegis.telemetry import configure_logging, get_logger, get_metrics, init_telemetry
from aegis.victim.agent_base import SwarmConfig, VictimSwarm
from aegis.victim.agents import (
    EmailTriageAgent,
    SummarizerAgent,
    ToolExecutorAgent,
)
from aegis.victim.memory import SharedMemoryStore
from aegis.victim.tools import InternalDocumentStore, OutboundMailbox

_log = get_logger(__name__)


@dataclass
class AegisGuard:
    """Composed runtime. Hold a reference to this for the lifetime of the
    process - it owns the audit store and metrics emitter.
    """

    settings: Settings
    audit: AuditProvenanceGuardian
    threat_classifier: ThreatClassifierGuardian
    payload_analyzer: PayloadAnalyzerGuardian
    comms_monitor: CommsMonitorGuardian
    arbiter: VerdictArbiter
    interceptor: Interceptor
    prompt_shields: PromptShieldsSensor
    entra: EntraAgentIdSensor
    defender: DefenderSensor
    swarm: VictimSwarm
    internal_docs: InternalDocumentStore
    mailbox: OutboundMailbox
    memory: SharedMemoryStore
    quarantine: QuarantineRegistry
    integration_report: dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        *,
        enable_guard: bool = True,
        orchestrator_agent_ids: tuple[str, ...] = ("victim.orchestrator",),
    ) -> AegisGuard:
        configure_logging()
        settings = get_settings()
        init_telemetry()

        report = settings.integration_report()
        _log.info("aegis.boot.integration_report", **report)

        # ----- sensors ------------------------------------------------
        prompt_shields = get_prompt_shields()
        entra = get_entra_sensor()
        defender = get_defender_sensor()

        # ----- audit + metrics ---------------------------------------
        audit = AuditProvenanceGuardian()
        metrics = get_metrics()

        # ----- guardians ---------------------------------------------
        classifier = ThreatClassifierGuardian()
        analyzer = PayloadAnalyzerGuardian(audit=audit)
        comms = CommsMonitorGuardian(
            orchestrator_agent_ids=orchestrator_agent_ids,
            entra=entra,
            metrics=metrics,
        )

        # ----- arbiter ------------------------------------------------
        arbiter = VerdictArbiter(audit=audit, metrics=metrics, defender=defender)

        # ----- middleware decision provider --------------------------
        if enable_guard:
            provider = SwarmDecisionProvider(
                threat_classifier=classifier,
                payload_analyzer=analyzer,
                comms_monitor=comms,
                audit=audit,
                arbiter=arbiter,
            )
        else:
            provider = AlwaysAllowDecisionProvider()

        quarantine = QuarantineRegistry()

        async def _audit_outcome_hook(result: InterceptionResult) -> None:
            await get_bus().publish(
                TOPIC_AUDIT,
                {
                    "event": "outcome",
                    "action_id": result.action.action_id,
                    "outcome": result.outcome.value,
                    "verdict_id": result.verdict.verdict_id,
                },
            )

        interceptor = Interceptor(
            decision_provider=provider,
            quarantine_registry=quarantine,
            post_decision_hooks=[_audit_outcome_hook],
            metrics=metrics,
        )

        # ----- victim swarm ------------------------------------------
        internal_docs = InternalDocumentStore()
        mailbox = OutboundMailbox()
        memory = SharedMemoryStore()

        # Token provider for the victim swarm. When AEGIS is fully live
        # (entra.configured == Settings.has_entra_live), each agent acquires a
        # REAL Entra-signed token from its app registration via the issuer.
        # Otherwise it mints a dev-mock HMAC token the dev-mock verifier
        # accepts. The two stay in lockstep because both branch on the same
        # has_entra_live gate, so the swarm never presents a token the active
        # verifier would reject.
        from aegis.sensors.entra_agent_id import get_entra_token_issuer

        token_issuer = get_entra_token_issuer()

        def _token_provider(agent_id: str, role: str) -> str | None:
            if entra.configured:
                return token_issuer.token_for(agent_id, role)
            return entra.mint_dev_token(agent_id=agent_id, role=role, ttl_seconds=900)

        triage = EmailTriageAgent(
            agent_id="victim.email_triage",
            role="triage",
            interceptor=interceptor,
            identity_token_provider=_token_provider,
            memory=memory,
        )
        summarizer = SummarizerAgent(
            agent_id="victim.summarizer",
            role="summarizer",
            interceptor=interceptor,
            identity_token_provider=_token_provider,
            internal_docs=internal_docs,
            memory=memory,
            provenance_register=audit,
        )
        executor = ToolExecutorAgent(
            agent_id="victim.tool_executor",
            role="executor",
            interceptor=interceptor,
            identity_token_provider=_token_provider,
            internal_docs=internal_docs,
            mailbox=mailbox,
        )
        swarm = VictimSwarm(
            triage_agent=triage,
            summarizer_agent=summarizer,
            executor_agent=executor,
            internal_docs=internal_docs,
            mailbox=mailbox,
            memory=memory,
            interceptor=interceptor,
            orchestrator_identity_token_provider=_token_provider,
        )

        guard = cls(
            settings=settings,
            audit=audit,
            threat_classifier=classifier,
            payload_analyzer=analyzer,
            comms_monitor=comms,
            arbiter=arbiter,
            interceptor=interceptor,
            prompt_shields=prompt_shields,
            entra=entra,
            defender=defender,
            swarm=swarm,
            internal_docs=internal_docs,
            mailbox=mailbox,
            memory=memory,
            quarantine=quarantine,
            integration_report=report,
        )
        _log.info("aegis.boot.ready", enable_guard=enable_guard)
        return guard

    # ----- convenience ---------------------------------------------
    def now_unix_ms(self) -> int:
        return int(time.time() * 1000)

    def snapshot(self) -> dict[str, Any]:
        return {
            "integration_report": self.integration_report,
            "metrics": get_metrics().snapshot(),
            "audit_size": len(self.audit.snapshot(limit=10_000)),
            "quarantine": self.quarantine.snapshot(),
            "outbound_sent": len(self.mailbox.sent),
            "outbound_blocked": len(self.mailbox.blocked),
        }
