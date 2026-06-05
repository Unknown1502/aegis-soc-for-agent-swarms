"""AgentAction - the unit of observation that flows through the AEGIS pipeline.

Every message, tool call, and llm prompt emitted by the protected swarm is
captured as an AgentAction before it executes. Each action carries a
correlation id so the Audit & Provenance guardian can later reconstruct the
*cross-agent sequence* the Verdict Arbiter judges.

Rationale: the EchoLeak attack class proved that single-action inspection is
insufficient. Detection in AEGIS therefore happens on sequences, and the
AgentAction object is intentionally rich enough that a sequence reconstructed
from these events can be reasoned about without re-fetching state.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ActionType(str, Enum):
    """The three intercept points AEGIS cares about.

    MESSAGE       - agent-to-agent message on the orchestrator's bus
    TOOL_CALL     - an agent invoking a registered tool (potential side effect)
    LLM_PROMPT    - an agent dispatching a prompt to a model (potential
                    indirect-prompt-injection vector)
    """

    MESSAGE = "message"
    TOOL_CALL = "tool_call"
    LLM_PROMPT = "llm_prompt"


class ExecutionOutcome(str, Enum):
    """What the middleware decided to do with an intercepted action.

    The decision is supplied by the Verdict Arbiter through a pluggable
    decision-provider interface (see aegis.middleware).
    """

    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class AgentIdentityClaim(BaseModel):
    """What an agent CLAIMS its identity to be on a message.

    The Inter-Agent Comms Monitor cross-checks this against the verified
    Entra Agent ID token to detect spoofing and replay. The presented_token
    field carries the raw JWT for verification - never log it.
    """

    model_config = ConfigDict(frozen=True)

    claimed_agent_id: str
    claimed_role: str = "worker"
    presented_token: str | None = Field(default=None, repr=False)
    token_nonce: str | None = None  # jti / nonce claim if available

    def redacted(self) -> dict[str, Any]:
        """Safe-to-log projection."""

        return {
            "claimed_agent_id": self.claimed_agent_id,
            "claimed_role": self.claimed_role,
            "token_present": self.presented_token is not None,
            "token_nonce": self.token_nonce,
        }


class AgentAction(BaseModel):
    """A single intercepted action awaiting a verdict.

    Conventions:
    * action_id is a globally unique ULID-like string (here uuid4 for
      simplicity). Used by the audit log.
    * correlation_id ties together every action that belongs to a single
      cross-agent business task (e.g. handling one inbound email). It is THE
      key by which the Audit agent reconstructs sequences.
    * causation_id (optional) points at the immediate parent AgentAction.
      Together with correlation_id this builds a per-task action DAG.
    * source_agent_id is the orchestrator's view of who emitted the action.
      identity_claim.claimed_agent_id is what the action itself asserts. A
      mismatch is a strong spoofing signal.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str
    causation_id: str | None = None

    action_type: ActionType
    source_agent_id: str
    target_agent_id: str | None = None  # destination for MESSAGE/TOOL_CALL
    tool_name: str | None = None         # set for TOOL_CALL

    payload: dict[str, Any] = Field(default_factory=dict)
    """Structured representation of the action. For MESSAGE: {"text": "..."}.
    For TOOL_CALL: the tool arguments dict. For LLM_PROMPT: the rendered
    prompt + any reference documents. Never put credentials in here.
    """

    text_content: str | None = None
    """Flattened text view used by the Threat Classifier and Payload
    Analyzer. Helpful so guardians don't have to know every payload shape.
    """

    identity_claim: AgentIdentityClaim | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    created_at_unix_ms: int = Field(default_factory=lambda: int(time.time() * 1000))

    @property
    def created_at(self) -> datetime:
        return datetime.fromtimestamp(self.created_at_unix_ms / 1000.0, tz=timezone.utc)

    def short_repr(self) -> str:
        """One-line debug-friendly description; never includes secrets."""

        target = f"->{self.target_agent_id}" if self.target_agent_id else ""
        tool = f" tool={self.tool_name}" if self.tool_name else ""
        snippet = (self.text_content or "")[:60].replace("\n", " ")
        return (
            f"[{self.action_type.value}] {self.source_agent_id}{target}{tool} "
            f"cid={self.correlation_id[:8]} aid={self.action_id[:8]} :: {snippet!r}"
        )


def new_correlation_id() -> str:
    """Mint a correlation id for a new business task entering the swarm."""

    return str(uuid.uuid4())


# Convenience type aliases used in interfaces.
ActionId = str
CorrelationId = str
AgentId = str
