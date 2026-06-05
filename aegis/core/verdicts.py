"""Verdict - the Arbiter's final, human-legible conclusion about an action.

A Verdict is the single object that:
* drives the middleware's ALLOW / BLOCK / QUARANTINE decision,
* appears on the analyst dashboard as a card,
* is recorded in the hash-chained audit log,
* is exported as an Azure Monitor metric / Foundry trace span,
* maps the case to OWASP / MAESTRO / MITRE ATLAS standards.

Every field on this object exists because some downstream consumer needs it.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.events import ActionId, AgentId, CorrelationId, ExecutionOutcome
from aegis.core.signals import GuardianSignal
from aegis.core.standards import StandardsTag


class VerdictDecision(str, Enum):
    """The Arbiter's three-state output.

    CONFIRMED       - Strong corroboration. Block + analyst paged. The
                      rogue agent is quarantined.
    PROBABLE        - Real concern but evidence is partial. Block the
                      specific action and escalate for review; do NOT
                      quarantine the agent yet.
    FALSE_POSITIVE  - Sensors flagged something but corroboration failed.
                      Allow. Recorded for the "noise we removed" metric.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    FALSE_POSITIVE = "false_positive"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(BaseModel):
    """The Arbiter's per-action verdict.

    sequence_action_ids holds the ordered list of AgentAction ids that
    constituted the case - this is the *cross-agent sequence* that justified
    the decision. The dashboard renders it as a timeline; the audit log
    persists it; without it AEGIS would be just another single-point filter.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    verdict_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: CorrelationId
    target_action_id: ActionId
    target_agent_id: AgentId | None = None

    decision: VerdictDecision
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)

    explanation: str
    """One or two sentences a human analyst can act on. Required.

    Style guide: lead with WHAT happened (the chain summary), follow with
    WHY this was escalated above single-point sensors, end with the
    suggested operator next step (e.g. 'review quarantine, notify owner').
    """

    contributing_signals: list[GuardianSignal] = Field(default_factory=list)
    sequence_action_ids: list[ActionId] = Field(default_factory=list)
    standards_tags: list[StandardsTag] = Field(default_factory=list)
    suggested_outcome: ExecutionOutcome

    # Operational metadata
    arbiter_version: str = "1.0.0"
    decided_at_unix_ms: int = Field(default_factory=lambda: int(time.time() * 1000))
    time_to_verdict_ms: int = 0
    suppressed_signal_ids: list[str] = Field(default_factory=list)
    """Signals the Arbiter chose to ignore (the 'noise we removed'). Drives
    the false-positive-suppression panel on the dashboard.
    """

    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def decided_at(self) -> datetime:
        return datetime.fromtimestamp(self.decided_at_unix_ms / 1000.0, tz=timezone.utc)

    @property
    def is_escalation(self) -> bool:
        return self.decision in {VerdictDecision.CONFIRMED, VerdictDecision.PROBABLE}

    def to_chip_tags(self) -> list[str]:
        chips: list[str] = []
        for tag in self.standards_tags:
            chips.extend(tag.as_chip_labels())
        return chips

    def short_repr(self) -> str:
        return (
            f"[{self.decision.value.upper()}] sev={self.severity.value} "
            f"conf={self.confidence:.2f} action={self.target_action_id[:8]} "
            f"chain_len={len(self.sequence_action_ids)} -> {self.suggested_outcome.value}"
        )
