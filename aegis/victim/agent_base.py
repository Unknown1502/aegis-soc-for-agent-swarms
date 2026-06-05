"""Base class for victim agents + the swarm orchestrator.

VictimAgent is the parent for all three productivity agents. It exposes one
async method - `_emit_action` - that every operation an agent performs runs
through. _emit_action constructs an AgentAction, hands it to the AEGIS
Interceptor, and obeys the verdict.

This is the entire interception surface. The agents themselves contain
none of the security logic; the agents do not even know AEGIS exists. That
is what "AEGIS is a wrapper, not surgery" means in code.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from aegis.core import (
    ActionType,
    AgentAction,
    AgentIdentityClaim,
    ExecutionOutcome,
)
from aegis.core.events import new_correlation_id
from aegis.middleware import Interceptor
from aegis.telemetry.logging import get_logger
from aegis.victim.memory import SharedMemoryStore
from aegis.victim.tools import (
    EmailMessage,
    InternalDocumentStore,
    OutboundMailbox,
)

_log = get_logger(__name__)


class SafeRefusal(Exception):
    """Raised inside an agent when AEGIS blocks one of its actions.

    The agent catches its own SafeRefusal at the top of its turn and
    converts the refusal_message into a clean reply.
    """

    def __init__(self, message: str, verdict_id: str) -> None:
        super().__init__(message)
        self.verdict_id = verdict_id


@dataclass
class AgentRunContext:
    correlation_id: str
    orchestrator_agent_id: str
    causation_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class SwarmConfig:
    orchestrator_agent_id: str = "victim.orchestrator"
    triage_agent_id: str = "victim.email_triage"
    summarizer_agent_id: str = "victim.summarizer"
    executor_agent_id: str = "victim.tool_executor"


class VictimAgent:
    """Base class. Subclasses implement `handle(message, ctx)`."""

    def __init__(
        self,
        *,
        agent_id: str,
        role: str,
        interceptor: Interceptor | None,
        identity_token_provider: Callable[[str, str], str | None] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self._interceptor = interceptor
        self._identity_token_provider = identity_token_provider

    @property
    def has_guard(self) -> bool:
        return self._interceptor is not None

    def attach_interceptor(self, interceptor: Interceptor) -> None:
        self._interceptor = interceptor

    # ---- intercept helpers --------------------------------------------
    def _identity(self) -> AgentIdentityClaim:
        token = (
            self._identity_token_provider(self.agent_id, self.role)
            if self._identity_token_provider
            else None
        )
        return AgentIdentityClaim(
            claimed_agent_id=self.agent_id,
            claimed_role=self.role,
            presented_token=token,
        )

    async def _emit_action(
        self,
        *,
        ctx: AgentRunContext,
        action_type: ActionType,
        target_agent_id: str | None,
        tool_name: str | None,
        payload: dict[str, Any],
        text_content: str | None,
    ) -> AgentAction:
        action = AgentAction(
            correlation_id=ctx.correlation_id,
            causation_id=ctx.causation_id,
            action_type=action_type,
            source_agent_id=self.agent_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            payload=payload,
            text_content=text_content,
            identity_claim=self._identity(),
        )

        if not self._interceptor:
            # Unguarded mode (developer / victim-only) - no AEGIS in the loop.
            return action

        result = await self._interceptor.intercept(action)
        if not result.allowed:
            raise SafeRefusal(
                result.refusal_message or "AEGIS blocked this action.",
                verdict_id=result.verdict.verdict_id,
            )
        return action

    # ---- subclass API --------------------------------------------------
    async def handle(self, message: dict[str, Any], ctx: AgentRunContext) -> dict[str, Any]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Swarm orchestrator
# ---------------------------------------------------------------------------


class VictimSwarm:
    """Wires the three victim agents and runs one task end-to-end.

    The orchestrator itself is conceptually a fourth (privileged) agent. It
    emits inter-agent messages so the Comms Monitor can verify identity on
    every hop.
    """

    def __init__(
        self,
        *,
        triage_agent: VictimAgent,
        summarizer_agent: VictimAgent,
        executor_agent: VictimAgent,
        internal_docs: InternalDocumentStore,
        mailbox: OutboundMailbox,
        memory: SharedMemoryStore,
        config: SwarmConfig | None = None,
        interceptor: Interceptor | None = None,
        orchestrator_identity_token_provider: Callable[[str, str], str | None] | None = None,
    ) -> None:
        self.config = config or SwarmConfig()
        self.triage = triage_agent
        self.summarizer = summarizer_agent
        self.executor = executor_agent
        self.internal_docs = internal_docs
        self.mailbox = mailbox
        self.memory = memory
        self._interceptor = interceptor
        self._orch_token_provider = orchestrator_identity_token_provider

        # Wire interceptor into agents that don't already have one.
        for agent in (self.triage, self.summarizer, self.executor):
            if interceptor and not agent.has_guard:
                agent.attach_interceptor(interceptor)

    # ----- orchestrator messages ----------------------------------------
    async def _orchestrator_emit(
        self,
        ctx: AgentRunContext,
        target_agent_id: str,
        text: str,
        payload: dict[str, Any] | None = None,
    ) -> AgentAction:
        token = (
            self._orch_token_provider(self.config.orchestrator_agent_id, "orchestrator")
            if self._orch_token_provider
            else None
        )
        identity = AgentIdentityClaim(
            claimed_agent_id=self.config.orchestrator_agent_id,
            claimed_role="orchestrator",
            presented_token=token,
        )
        action = AgentAction(
            correlation_id=ctx.correlation_id,
            causation_id=ctx.causation_id,
            action_type=ActionType.MESSAGE,
            source_agent_id=self.config.orchestrator_agent_id,
            target_agent_id=target_agent_id,
            payload=payload or {"text": text},
            text_content=text,
            identity_claim=identity,
        )
        if self._interceptor:
            result = await self._interceptor.intercept(action)
            if not result.allowed:
                raise SafeRefusal(
                    result.refusal_message or "AEGIS blocked orchestrator message.",
                    verdict_id=result.verdict.verdict_id,
                )
        return action

    # ----- public entrypoints -------------------------------------------
    async def handle_inbound_email(self, email: EmailMessage) -> dict[str, Any]:
        """Run the full pipeline for one inbound email."""

        correlation_id = new_correlation_id()
        ctx = AgentRunContext(
            correlation_id=correlation_id,
            orchestrator_agent_id=self.config.orchestrator_agent_id,
        )
        result: dict[str, Any] = {
            "correlation_id": correlation_id,
            "sent": False,
            "refusal": None,
            "steps": [],
        }
        try:
            # ---- 1. Triage ----
            triage_msg = await self._orchestrator_emit(
                ctx, self.config.triage_agent_id,
                f"Handle inbound email '{email.subject}' from {email.from_address}",
                payload={"email_id": email.message_id},
            )
            ctx.causation_id = triage_msg.action_id
            triage_out = await self.triage.handle(
                {"email": email}, ctx
            )
            result["steps"].append({"agent": self.triage.agent_id, "output": triage_out})

            if not triage_out.get("needs_reply"):
                return result

            # ---- 2. Summarize ----
            ctx.causation_id = triage_out.get("action_id", ctx.causation_id)
            summ_msg = await self._orchestrator_emit(
                ctx, self.config.summarizer_agent_id,
                "Summarize the thread and assemble reply context",
                payload={"email_id": email.message_id},
            )
            ctx.causation_id = summ_msg.action_id
            summ_out = await self.summarizer.handle(
                {"email": email, "triage": triage_out}, ctx
            )
            result["steps"].append({"agent": self.summarizer.agent_id, "output": summ_out})

            # ---- 3. Execute (compose + send reply) ----
            ctx.causation_id = summ_out.get("action_id", ctx.causation_id)
            exec_msg = await self._orchestrator_emit(
                ctx, self.config.executor_agent_id,
                "Compose and send the reply",
                payload={"email_id": email.message_id},
            )
            ctx.causation_id = exec_msg.action_id
            exec_out = await self.executor.handle(
                {"email": email, "triage": triage_out, "summary": summ_out}, ctx
            )
            result["steps"].append({"agent": self.executor.agent_id, "output": exec_out})
            result["sent"] = bool(exec_out.get("sent"))
        except SafeRefusal as refusal:
            result["refusal"] = {"message": str(refusal), "verdict_id": refusal.verdict_id}
        return result
