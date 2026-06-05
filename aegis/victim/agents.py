"""Concrete victim agents.

Each agent emits AgentActions through self._emit_action for everything it
does. The agents are deliberately a mix of LLM-augmented and rule-based so
the demo runs offline with no model credentials, but plugs into the LLM
backend trivially if you want richer behavior (replace the body of
`_compose_reply` etc. with a model call).
"""

from __future__ import annotations

from typing import Any

from aegis.core import ActionType
from aegis.telemetry.logging import get_logger
from aegis.victim.agent_base import AgentRunContext, VictimAgent
from aegis.victim.memory import SharedMemoryStore
from aegis.victim.tools import (
    EmailMessage,
    InternalDocument,
    InternalDocumentStore,
    OutboundMailbox,
)

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# 1. Email-Triage agent
# ---------------------------------------------------------------------------


class EmailTriageAgent(VictimAgent):
    """Looks at an inbound email and decides whether it needs a reply.

    Writes a small note into shared memory ("triage hint for <message_id>")
    so later sessions can pick it up; this is what the memory-poisoning
    attack abuses (an attacker plants a malicious 'hint' via this path in
    one session and a later planner consumes it).
    """

    def __init__(self, *, memory: SharedMemoryStore, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._memory = memory

    async def handle(self, message: dict[str, Any], ctx: AgentRunContext) -> dict[str, Any]:
        email: EmailMessage = message["email"]
        prompt_text = (
            f"From: {email.from_address}\nSubject: {email.subject}\n\n{email.body}"
        )

        # Treat the inbound text as an LLM prompt -> intercept point.
        await self._emit_action(
            ctx=ctx,
            action_type=ActionType.LLM_PROMPT,
            target_agent_id=None,
            tool_name=None,
            payload={"intent": "triage_classification"},
            text_content=prompt_text,
        )

        # Heuristic: anything not from an auto-mailer needs a reply.
        needs_reply = not any(
            tag in (email.from_address or "").lower()
            for tag in ("noreply", "no-reply", "donotreply", "mailer-daemon")
        )

        # Persist a triage note into shared memory (legitimate behavior; this
        # is also the abuse surface the memory-poisoning attack uses).
        if needs_reply:
            self._memory.put(
                key=f"triage_hint:{email.message_id}",
                value=email.body[:512],
                written_by=self.agent_id,
                correlation_id=ctx.correlation_id,
                origin_note=f"derived from inbound email from {email.from_address}",
                sensitivity="public" if not email.is_external else "internal",
            )

        result = {
            "needs_reply": needs_reply,
            "category": "external_outreach" if email.is_external else "internal_thread",
            "note_key": f"triage_hint:{email.message_id}",
        }

        # Send the result as an inter-agent message - intercept point.
        msg = await self._emit_action(
            ctx=ctx,
            action_type=ActionType.MESSAGE,
            target_agent_id="victim.summarizer",
            tool_name=None,
            payload={"triage_result": result, "email_id": email.message_id},
            text_content=f"Triage: needs_reply={needs_reply} category={result['category']}",
        )
        result["action_id"] = msg.action_id
        return result


# ---------------------------------------------------------------------------
# 2. Summarizer agent
# ---------------------------------------------------------------------------


class SummarizerAgent(VictimAgent):
    """Summarizes the email + any referenced internal documents.

    Looks up referenced documents and includes their content in its
    reasoning context. THIS is the step where internal-doc text first
    flows into the swarm; the Audit guardian's `register_provenance` is
    called here so any later attempt to leak that text is detectable.
    """

    def __init__(
        self,
        *,
        internal_docs: InternalDocumentStore,
        memory: SharedMemoryStore,
        provenance_register: Any = None,  # AuditProvenanceGuardian; injected
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._docs = internal_docs
        self._memory = memory
        self._provenance_register = provenance_register

    async def handle(self, message: dict[str, Any], ctx: AgentRunContext) -> dict[str, Any]:
        email: EmailMessage = message["email"]
        triage = message["triage"]

        # Pull any triage note from shared memory - this is also where the
        # memory-poisoning chain's planner reads the malicious instruction.
        note = self._memory.get(triage.get("note_key", ""))

        # Naive doc lookup: search internal docs for any token in the subject.
        referenced_docs: list[InternalDocument] = []
        for token in (email.subject or "").lower().split():
            if len(token) < 4:
                continue
            referenced_docs.extend(self._docs.search(token))
        # de-duplicate
        seen: set[str] = set()
        referenced_docs = [d for d in referenced_docs if not (d.doc_id in seen or seen.add(d.doc_id))]

        # If we read internal docs, record their provenance so any later
        # exfiltration attempt is detectable.
        for doc in referenced_docs:
            # Emit a tool-call for reading; the Payload Analyzer will see this
            # but a read of an internal doc is not, by itself, suspicious.
            read_action = await self._emit_action(
                ctx=ctx,
                action_type=ActionType.TOOL_CALL,
                target_agent_id=None,
                tool_name="read_internal_doc",
                payload={"doc_id": doc.doc_id, "title": doc.title},
                text_content=doc.body,
            )
            if self._provenance_register is not None:
                self._provenance_register.register_provenance(
                    data_id=f"internal_doc:{doc.doc_id}",
                    label=doc.title,
                    origin_action=read_action,
                    sensitivity=doc.sensitivity,
                )

        # Build a SANITIZED summary - intent only, not verbatim payload.
        # A real LLM-driven summarizer would never paste raw inbound text into
        # downstream messages; it summarizes intent. This makes the inter-agent
        # message body safe to log while still carrying the structured
        # follow_up_instruction in the typed payload field for the executor.
        summary_pieces: list[str] = [
            f"Email from {email.from_address}: {email.subject}.",
            f"Inbound length: {len(email.body)} chars; sender is "
            f"{'external' if email.is_external else 'internal'}.",
        ]
        if note:
            summary_pieces.append(
                f"Follow-up note attached ({len(note.value)} chars, origin: {note.origin_note})."
            )
        if referenced_docs:
            summary_pieces.append(
                "Referenced internal documents: "
                + ", ".join(d.title for d in referenced_docs)
            )

        summary_text = " ".join(summary_pieces)

        # Pass summary on to executor.
        msg = await self._emit_action(
            ctx=ctx,
            action_type=ActionType.MESSAGE,
            target_agent_id="victim.tool_executor",
            tool_name=None,
            payload={
                "summary_text": summary_text,
                "referenced_doc_ids": [d.doc_id for d in referenced_docs],
                "referenced_doc_titles": [d.title for d in referenced_docs],
                "follow_up_instruction": (note.value if note else ""),
            },
            text_content=summary_text,
        )
        return {
            "summary_text": summary_text,
            "referenced_doc_ids": [d.doc_id for d in referenced_docs],
            "referenced_doc_titles": [d.title for d in referenced_docs],
            "follow_up_instruction": (note.value if note else ""),
            "action_id": msg.action_id,
        }


# ---------------------------------------------------------------------------
# 3. Tool-Executor agent
# ---------------------------------------------------------------------------


class ToolExecutorAgent(VictimAgent):
    """Composes and 'sends' the reply.

    The send_email tool call is the load-bearing intercept point. If a
    chained injection causes this agent to attach internal-doc content to
    an external recipient, AEGIS's Payload Analyzer (provenance check) and
    Verdict Arbiter will block the action and the email is NEVER
    appended to OutboundMailbox.sent. The dashboard renders the blocked
    attempt instead.
    """

    def __init__(
        self,
        *,
        internal_docs: InternalDocumentStore,
        mailbox: OutboundMailbox,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._docs = internal_docs
        self._mailbox = mailbox

    async def handle(self, message: dict[str, Any], ctx: AgentRunContext) -> dict[str, Any]:
        email: EmailMessage = message["email"]
        summary = message["summary"]
        instruction = summary.get("follow_up_instruction", "") or ""

        # Naive composer: reply with a polite acknowledgement + any
        # follow-up instruction the planner extracted. The injection
        # surface is the `instruction` text - that is the only place an
        # attacker can sneak content into the outbound.
        body = (
            f"Hi,\n\nThanks for your message regarding '{email.subject}'.\n"
            f"{instruction.strip()}\n\nBest regards,\nAEGIS Demo Bot"
        )

        # Attachments default to none. The chained injection's payload
        # asks the agent to attach an internal doc; if it does so, we add
        # that doc body to the outbound payload text so the Payload
        # Analyzer's provenance check catches the leak.
        attachments: list[str] = []
        attachment_body_text = ""
        # A real LLM-driven executor would interpret any "include this doc"
        # intent, not just the literal word "attach". This mirrors that.
        lower = instruction.lower()
        wants_attach = any(
            kw in lower for kw in ("attach", "forward", "include", "share", "send the")
        )
        if wants_attach:
            # Naive parser: attach any referenced internal doc by id.
            for doc_id in summary.get("referenced_doc_ids", []):
                doc = self._docs.get(doc_id)
                if doc:
                    attachments.append(doc.doc_id)
                    attachment_body_text += "\n\n[ATTACHED CONTENT BEGIN]\n" + doc.body + "\n[ATTACHED CONTENT END]"

        # Compose the outbound EmailMessage.
        outbound = EmailMessage(
            from_address="assistant@internal.company.local",
            to_addresses=[email.from_address],
            subject=f"Re: {email.subject}",
            body=body + attachment_body_text,
            attachments=attachments,
        )

        # The single load-bearing tool call.
        payload = {
            "to": outbound.to_addresses,
            "subject": outbound.subject,
            "body": outbound.body,
            "attachments": outbound.attachments,
        }
        try:
            await self._emit_action(
                ctx=ctx,
                action_type=ActionType.TOOL_CALL,
                target_agent_id=None,
                tool_name="send_email",
                payload=payload,
                text_content=outbound.body,
            )
        except Exception:
            # SafeRefusal bubbles up to the swarm orchestrator.
            self._mailbox.record_block(outbound)
            raise

        # If we reached here AEGIS allowed it.
        self._mailbox.record_send(outbound)
        return {
            "sent": True,
            "to": outbound.to_addresses,
            "attached_doc_ids": outbound.attachments,
            "outbound_message_id": outbound.message_id,
        }
