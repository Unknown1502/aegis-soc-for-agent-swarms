"""GuardianSignal - what one guardian agent concluded about one AgentAction.

A guardian never decides BLOCK or QUARANTINE on its own. It emits a signal,
the Verdict Arbiter cross-validates signals across guardians and across the
cross-agent sequence, and only then is an outcome chosen. This separation is
the entire reason AEGIS suppresses false positives instead of producing them.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.events import ActionId, AgentId


class GuardianKind(str, Enum):
    """The five guardian roles in the SIFT-REFLECT lineage."""

    THREAT_CLASSIFIER = "threat_classifier"
    PAYLOAD_ANALYZER = "payload_analyzer"
    COMMS_MONITOR = "comms_monitor"
    AUDIT_PROVENANCE = "audit_provenance"
    VERDICT_ARBITER = "verdict_arbiter"


class SignalLabel(str, Enum):
    """Per-action label a guardian assigns.

    BENIGN / SUSPICIOUS / MALICIOUS are the headline labels. UNAVAILABLE is
    used when a sensor the guardian relies on (e.g. Prompt Shields) is down -
    the Arbiter must know the difference between "saw nothing" and "couldn't
    look".
    """

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNAVAILABLE = "unavailable"


class EvidenceSpan(BaseModel):
    """A specific snippet of the action that justified the signal.

    Used by the dashboard to highlight the offending substring and by the
    Arbiter to weight signals (a signal with a concrete span beats a
    signal with only vibes).
    """

    model_config = ConfigDict(frozen=True)

    start: int
    end: int
    snippet: str
    note: str | None = None


class GuardianSignal(BaseModel):
    """A guardian's per-action conclusion.

    The confidence field is intentionally a float in [0,1] rather than a
    discrete level so the Arbiter can apply weighted-corroboration rules
    (see Verdict Arbiter docs in aegis.agents.verdict_arbiter).
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    signal_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    guardian: GuardianKind
    action_id: ActionId
    target_agent: AgentId | None = None

    label: SignalLabel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    """Plain-English one-sentence justification. Will appear on the dashboard
    verdict card. Must be safe to show to a non-technical analyst.
    """

    spans: list[EvidenceSpan] = Field(default_factory=list)
    sensor_data: dict[str, Any] = Field(default_factory=dict)
    """Raw outputs from any external sensor (Prompt Shields verdict, Entra
    verification result, Defender alert id, etc.) so the Arbiter can audit
    and the trace can cite them.
    """

    latency_ms: int = 0

    def is_actionable(self) -> bool:
        """Does this signal carry enough weight to influence escalation?

        UNAVAILABLE signals are recorded but never push toward escalation -
        the Arbiter treats them as missing data, not evidence.
        """

        return self.label in {SignalLabel.SUSPICIOUS, SignalLabel.MALICIOUS}
