"""Mock backends and tools for the victim swarm.

Everything here is fake-but-realistic so an exfiltration attempt would have
real meaning if AEGIS didn't catch it. None of these tools touch the network
or a real mail server; they record actions in in-memory stores that the
dashboard can show.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class EmailMessage:
    from_address: str
    to_addresses: list[str]
    subject: str
    body: str
    received_unix_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    headers: dict[str, str] = field(default_factory=dict)
    attachments: list[str] = field(default_factory=list)

    @property
    def is_external(self) -> bool:
        external_domains = ("internal.", "corp.", "company.local")
        return not any(
            d in (self.from_address or "") for d in external_domains
        )


@dataclass
class InternalDocument:
    doc_id: str
    title: str
    body: str
    sensitivity: Literal["public", "internal", "confidential"] = "internal"


class InternalDocumentStore:
    """In-memory pretend SharePoint."""

    def __init__(self) -> None:
        self._docs: dict[str, InternalDocument] = {}
        self._lock = threading.RLock()

    def add(self, doc: InternalDocument) -> None:
        with self._lock:
            self._docs[doc.doc_id] = doc

    def get(self, doc_id: str) -> InternalDocument | None:
        with self._lock:
            return self._docs.get(doc_id)

    def list_titles(self) -> list[str]:
        with self._lock:
            return sorted(d.title for d in self._docs.values())

    def search(self, query: str) -> list[InternalDocument]:
        with self._lock:
            ql = query.lower()
            return [
                d
                for d in self._docs.values()
                if ql in d.title.lower() or ql in d.body.lower()
            ]


@dataclass
class OutboundMailbox:
    """Captures every send_email tool execution.

    The Tool-Executor's send_email tool appends here ONLY if the interceptor
    allowed the action. If AEGIS blocked, nothing is ever appended - that is
    the visible evidence the system worked.
    """

    sent: list[EmailMessage] = field(default_factory=list)
    blocked: list[EmailMessage] = field(default_factory=list)

    def record_send(self, msg: EmailMessage) -> None:
        self.sent.append(msg)

    def record_block(self, msg: EmailMessage) -> None:
        self.blocked.append(msg)


@dataclass
class AgentTool:
    """Description of a tool exposed to a victim agent."""

    name: str
    description: str


send_email_tool = AgentTool(
    name="send_email",
    description=(
        "Send an outbound email. Args: to (str|list[str]), subject (str), "
        "body (str), attachments (list[str], doc_ids only)."
    ),
)

read_internal_doc_tool = AgentTool(
    name="read_internal_doc",
    description="Fetch the body of an internal document by doc_id.",
)
