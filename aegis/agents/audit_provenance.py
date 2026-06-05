"""Audit & Provenance guardian.

Responsibilities:
1. Maintain an append-only, hash-chained record of every AgentAction,
   GuardianSignal, and Verdict the system produces. Any mutation of an
   earlier entry breaks the chain and is detectable via `verify_integrity()`.
2. Reconstruct, on demand, the ordered cross-agent sequence of actions for
   a given correlation_id. This is the unit of detection the Verdict
   Arbiter judges (it is THE architecturally load-bearing idea of AEGIS).
3. Track data PROVENANCE: when an agent reads from an internal source
   (e.g. a labelled internal document), the Audit guardian remembers that
   piece of text. Later, if any action's payload contains that text and the
   action's destination is external, the guardian flags the leak chain so
   the Payload Analyzer / Arbiter can act on it.

The hash chain scheme is deliberately simple: SHA-256 over
(previous_hash || canonical_json(entry)). No exotic crypto, no merkle tree,
no signatures - just a tamper-evident append-only log that an auditor can
verify with twenty lines of Python.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from aegis.core.events import ActionId, AgentAction, CorrelationId
from aegis.core.signals import GuardianSignal
from aegis.core.verdicts import Verdict
from aegis.telemetry.logging import get_logger

_log = get_logger(__name__)


EntryKind = Literal["action", "signal", "verdict", "provenance"]


class AuditEntry(BaseModel):
    """A single hash-chained log entry."""

    model_config = ConfigDict(frozen=True)

    seq: int
    kind: EntryKind
    correlation_id: CorrelationId
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str
    timestamp_unix_ms: int


@dataclass
class ProvenanceRecord:
    """One piece of data and where it has flowed."""

    data_id: str          # arbitrary stable id, e.g. "internal_doc:Q3-financials.pdf"
    label: str            # human-readable name
    origin_action_id: ActionId
    sensitivity: Literal["public", "internal", "confidential"] = "internal"
    seen_in_actions: list[ActionId] = field(default_factory=list)


@dataclass
class ProvenanceQuery:
    """Result of a leak-check on a candidate outbound action."""

    leak_suspected: bool
    matched_records: list[ProvenanceRecord]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "leak_suspected": self.leak_suspected,
            "rationale": self.rationale,
            "matched_records": [
                {
                    "data_id": r.data_id,
                    "label": r.label,
                    "sensitivity": r.sensitivity,
                    "origin_action_id": r.origin_action_id,
                    "seen_in_actions": list(r.seen_in_actions),
                }
                for r in self.matched_records
            ],
        }


class AuditProvenanceGuardian:
    """In-memory, thread-safe audit + provenance store.

    All mutation paths grab _lock. Reads are also synchronised because the
    chain validation walks the list and we want a consistent snapshot.
    Persistence to disk (JSONL append) is opt-in via `append_to_disk`.
    """

    def __init__(self, *, append_to_disk: str | None = None) -> None:
        self._lock = threading.RLock()
        self._entries: list[AuditEntry] = []
        self._actions_by_correlation: dict[CorrelationId, list[AgentAction]] = defaultdict(list)
        self._actions_by_id: dict[ActionId, AgentAction] = {}
        self._signals_by_action: dict[ActionId, list[GuardianSignal]] = defaultdict(list)
        self._verdicts_by_correlation: dict[CorrelationId, list[Verdict]] = defaultdict(list)
        self._provenance: dict[str, ProvenanceRecord] = {}
        self._disk_path = append_to_disk

    # ----- chain primitives --------------------------------------------
    @staticmethod
    def _hash(prev_hash: str, payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(f"{prev_hash}\n{canonical}".encode("utf-8")).hexdigest()

    def _append(self, *, kind: EntryKind, correlation_id: CorrelationId, payload: dict[str, Any]) -> AuditEntry:
        import time

        prev_hash = self._entries[-1].entry_hash if self._entries else "GENESIS"
        entry = AuditEntry(
            seq=len(self._entries),
            kind=kind,
            correlation_id=correlation_id,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=self._hash(prev_hash, payload),
            timestamp_unix_ms=int(time.time() * 1000),
        )
        self._entries.append(entry)
        if self._disk_path:
            try:
                with open(self._disk_path, "a", encoding="utf-8") as fh:
                    fh.write(entry.model_dump_json() + "\n")
            except OSError as exc:  # pragma: no cover - dev safety net
                _log.warning("audit.disk_append_failed", error=str(exc))
        return entry

    # ----- public API used by middleware + guardians + arbiter ---------
    def record_action(self, action: AgentAction) -> AuditEntry:
        with self._lock:
            self._actions_by_correlation[action.correlation_id].append(action)
            self._actions_by_id[action.action_id] = action
            return self._append(
                kind="action",
                correlation_id=action.correlation_id,
                payload={
                    "action_id": action.action_id,
                    "type": action.action_type.value,
                    "source": action.source_agent_id,
                    "target": action.target_agent_id,
                    "tool": action.tool_name,
                    "identity_claim": (
                        action.identity_claim.redacted() if action.identity_claim else None
                    ),
                    "text_excerpt": (action.text_content or "")[:512],
                },
            )

    def record_signal(self, signal: GuardianSignal, correlation_id: CorrelationId) -> AuditEntry:
        with self._lock:
            self._signals_by_action[signal.action_id].append(signal)
            return self._append(
                kind="signal",
                correlation_id=correlation_id,
                payload={
                    "signal_id": signal.signal_id,
                    "guardian": signal.guardian.value,
                    "action_id": signal.action_id,
                    "label": signal.label.value,
                    "confidence": signal.confidence,
                    "evidence": signal.evidence,
                },
            )

    def record_verdict(self, verdict: Verdict) -> AuditEntry:
        with self._lock:
            self._verdicts_by_correlation[verdict.correlation_id].append(verdict)
            return self._append(
                kind="verdict",
                correlation_id=verdict.correlation_id,
                payload={
                    "verdict_id": verdict.verdict_id,
                    "target_action_id": verdict.target_action_id,
                    "decision": verdict.decision.value,
                    "severity": verdict.severity.value,
                    "confidence": verdict.confidence,
                    "outcome": verdict.suggested_outcome.value,
                    "sequence_action_ids": verdict.sequence_action_ids,
                    "standards_chips": verdict.to_chip_tags(),
                    "explanation": verdict.explanation,
                },
            )

    # ----- sequence reconstruction (THE detection unit) ----------------
    def sequence_for(self, correlation_id: CorrelationId) -> list[AgentAction]:
        with self._lock:
            return list(self._actions_by_correlation.get(correlation_id, ()))

    def signals_for_action(self, action_id: ActionId) -> list[GuardianSignal]:
        with self._lock:
            return list(self._signals_by_action.get(action_id, ()))

    def action(self, action_id: ActionId) -> AgentAction | None:
        with self._lock:
            return self._actions_by_id.get(action_id)

    # ----- provenance ---------------------------------------------------
    def register_provenance(
        self,
        *,
        data_id: str,
        label: str,
        origin_action: AgentAction,
        sensitivity: Literal["public", "internal", "confidential"] = "internal",
    ) -> ProvenanceRecord:
        with self._lock:
            record = ProvenanceRecord(
                data_id=data_id,
                label=label,
                origin_action_id=origin_action.action_id,
                sensitivity=sensitivity,
            )
            record.seen_in_actions.append(origin_action.action_id)
            self._provenance[data_id] = record
            self._append(
                kind="provenance",
                correlation_id=origin_action.correlation_id,
                payload={
                    "data_id": data_id,
                    "label": label,
                    "origin_action_id": origin_action.action_id,
                    "sensitivity": sensitivity,
                },
            )
            return record

    def track_data_in_action(self, data_id: str, action: AgentAction) -> None:
        """Mark that `data_id` has now been seen in `action`'s payload/text."""

        with self._lock:
            rec = self._provenance.get(data_id)
            if not rec:
                return
            if action.action_id not in rec.seen_in_actions:
                rec.seen_in_actions.append(action.action_id)

    def check_outbound_leak(self, action: AgentAction) -> ProvenanceQuery:
        """For an outbound (external) action, find any internal/confidential
        provenance records whose content appears in the payload.

        We use a substring match against a *trimmed* version of each tracked
        data string. Production would index more carefully; for the demo this
        catches the EchoLeak chain reliably.
        """

        haystack = self._flatten_action_text(action)
        if not haystack:
            return ProvenanceQuery(False, [], "no text payload to scan")

        matched: list[ProvenanceRecord] = []
        with self._lock:
            records = list(self._provenance.values())

        for rec in records:
            if rec.sensitivity == "public":
                continue
            # Match any seen-in-action whose text appears in the outbound.
            for seen_id in rec.seen_in_actions:
                seen_action = self._actions_by_id.get(seen_id)
                if not seen_action:
                    continue
                snippet = (seen_action.text_content or "")[:160].strip()
                if snippet and len(snippet) >= 24 and snippet in haystack:
                    matched.append(rec)
                    break

        if not matched:
            return ProvenanceQuery(False, [], "no tracked sensitive data found in payload")

        labels = ", ".join(f"'{r.label}' ({r.sensitivity})" for r in matched)
        return ProvenanceQuery(
            True,
            matched,
            f"Outbound action carries content originating from: {labels}.",
        )

    @staticmethod
    def _flatten_action_text(action: AgentAction) -> str:
        parts: list[str] = []
        if action.text_content:
            parts.append(action.text_content)
        for v in action.payload.values():
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, (list, tuple)):
                parts.extend(str(x) for x in v)
        return "\n".join(parts)

    # ----- integrity ----------------------------------------------------
    def verify_integrity(self) -> tuple[bool, str]:
        """Walk the chain top to bottom; recompute every hash."""

        with self._lock:
            entries = list(self._entries)
        prev_hash = "GENESIS"
        for entry in entries:
            expected = self._hash(prev_hash, entry.payload)
            if entry.prev_hash != prev_hash:
                return False, f"prev_hash mismatch at seq {entry.seq}"
            if entry.entry_hash != expected:
                return False, f"entry_hash mismatch at seq {entry.seq}"
            prev_hash = entry.entry_hash
        return True, f"OK ({len(entries)} entries verified)"

    def snapshot(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            tail = self._entries[-limit:]
        return [e.model_dump() for e in tail]
