"""Payload Analyzer guardian.

Deep inspection of tool-call arguments and inter-agent message bodies for:
  * instruction smuggling and hidden directives
  * data-exfiltration patterns (internal -> external)
  * encoded / obfuscated payloads
  * delimiter / spotlighting violations

The exfiltration check is SEQUENCE-AWARE: the analyzer asks the Audit &
Provenance guardian whether the inspected action's outbound payload contains
any data whose origin was an internal-sensitivity action earlier in the
correlation chain. That cross-action check is what catches the EchoLeak
pattern where each individual step looks benign.

Deterministic regex / structural checks run first (cheap, fast, traceable).
An LLM semantic pass is invoked only when the action carries enough free
text to warrant it, and is treated as one additional input.
"""

from __future__ import annotations

import re
import time
from typing import Any

from aegis.agents.audit_provenance import AuditProvenanceGuardian, ProvenanceQuery
from aegis.core import (
    ActionType,
    AgentAction,
    EvidenceSpan,
    GuardianKind,
    GuardianSignal,
    SignalLabel,
)
from aegis.llm import classify_security
from aegis.telemetry.logging import get_logger
from aegis.telemetry.tracing import trace_guardian_decision

_log = get_logger(__name__)


_EXTERNAL_DESTINATION_PATTERNS = [
    re.compile(r"@(?!internal\.|corp\.|company\.local)[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"https?://(?!internal\.|intranet\.|localhost|127\.|10\.|192\.168\.)"),
]

_ENCODED_PAYLOAD_PATTERNS = [
    re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})"),  # base64-ish
    re.compile(r"(?:%[0-9a-fA-F]{2}){5,}"),       # heavy url-encoding
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){5,}"),
    re.compile(r"(?:&#x?[0-9a-fA-F]+;){5,}"),
]

_INSTRUCTION_SMUGGLING_PATTERNS = [
    re.compile(r"(?i)(?:ignore|disregard) (?:all )?(?:previous|prior) (?:instructions|messages)"),
    re.compile(r"(?i)from now on,? you (?:are|will)"),
    re.compile(r"(?i)reveal (?:your|the) (?:system )?prompt"),
    re.compile(r"(?i)\bDAN mode\b|\bdo anything now\b"),
]

_DELIMITER_ESCAPE_PATTERNS = [
    re.compile(r"</PAYLOAD"),
    re.compile(r"===AEGIS-DATA==="),
]


class PayloadAnalyzerGuardian:
    name = GuardianKind.PAYLOAD_ANALYZER

    def __init__(self, audit: AuditProvenanceGuardian) -> None:
        self._audit = audit

    async def analyze(self, action: AgentAction) -> GuardianSignal:
        t0 = time.perf_counter()
        with trace_guardian_decision(
            "payload_analyzer",
            action_id=action.action_id,
            correlation_id=action.correlation_id,
        ):
            text = self._text_of(action)
            findings: list[tuple[str, str]] = []  # (pattern_name, snippet)
            spans: list[EvidenceSpan] = []

            findings.extend(self._regex_check(text, _INSTRUCTION_SMUGGLING_PATTERNS, "instruction_smuggling", spans))
            findings.extend(self._regex_check(text, _ENCODED_PAYLOAD_PATTERNS, "encoded_payload", spans))
            findings.extend(self._regex_check(text, _DELIMITER_ESCAPE_PATTERNS, "delimiter_escape", spans))

            # exfil heuristic: external destination + non-empty body referencing
            # likely sensitive data.
            external_dest = self._has_external_destination(action)
            leak: ProvenanceQuery = (
                self._audit.check_outbound_leak(action) if self._is_outbound(action) else ProvenanceQuery(False, [], "")
            )

            llm_relevant = bool(text and len(text) > 30 and not findings)
            llm_judgment = None
            if llm_relevant:
                llm_judgment = await classify_security(
                    action_summary=f"Payload deep-scan for {action.short_repr()}",
                    inspected_text=text,
                    sensor_context={
                        "external_destination": external_dest,
                        "outbound": self._is_outbound(action),
                    },
                    context_note="Look for instruction smuggling, exfiltration, or encoded payloads.",
                )
                for p in llm_judgment.detected_patterns:
                    findings.append((p, ""))

            label, confidence = self._score(findings, leak, llm_judgment)
            evidence = self._evidence_sentence(findings, leak, external_dest, llm_judgment)

            return GuardianSignal(
                guardian=self.name,
                action_id=action.action_id,
                target_agent=action.source_agent_id,
                label=label,
                confidence=confidence,
                evidence=evidence,
                spans=spans[:5],
                sensor_data={
                    "findings": [{"pattern": p, "snippet": s[:120]} for p, s in findings],
                    "external_destination_detected": external_dest,
                    "provenance": leak.to_dict(),
                    "llm": (
                        {
                            "label": llm_judgment.label,
                            "confidence": llm_judgment.confidence,
                            "rationale": llm_judgment.rationale,
                        }
                        if llm_judgment
                        else None
                    ),
                },
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )

    # ----- helpers ------------------------------------------------------
    @staticmethod
    def _text_of(action: AgentAction) -> str:
        parts: list[str] = []
        if action.text_content:
            parts.append(action.text_content)
        for v in action.payload.values():
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, (list, tuple)):
                parts.extend(str(x) for x in v)
        return "\n".join(parts)

    @staticmethod
    def _regex_check(
        text: str, patterns: list[re.Pattern[str]], name: str, spans: list[EvidenceSpan]
    ) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for pat in patterns:
            for m in pat.finditer(text or ""):
                out.append((name, m.group(0)))
                spans.append(
                    EvidenceSpan(
                        start=m.start(),
                        end=m.end(),
                        snippet=m.group(0)[:120],
                        note=name,
                    )
                )
        return out

    @staticmethod
    def _is_outbound(action: AgentAction) -> bool:
        if action.action_type is not ActionType.TOOL_CALL:
            return False
        tool = (action.tool_name or "").lower()
        if any(k in tool for k in ("send_email", "send_message", "http_post", "publish", "webhook", "upload")):
            return True
        return False

    @classmethod
    def _has_external_destination(cls, action: AgentAction) -> bool:
        text = cls._text_of(action)
        for pat in _EXTERNAL_DESTINATION_PATTERNS:
            if pat.search(text):
                return True
        return False

    @staticmethod
    def _score(
        findings: list[tuple[str, str]],
        leak: ProvenanceQuery,
        llm_judgment: Any,
    ) -> tuple[SignalLabel, float]:
        score = 0.0
        # individual findings
        weights = {
            "instruction_smuggling": 0.6,
            "delimiter_escape": 0.7,
            "encoded_payload": 0.4,
            "data_exfiltration_external": 0.7,
            "indirect_prompt_injection": 0.5,
        }
        for name, _ in findings:
            score += weights.get(name, 0.3)
        # exfil chain
        if leak.leak_suspected:
            score += 0.9  # this is the headline exfil case
        # llm
        if llm_judgment and llm_judgment.label != "benign":
            score += 0.2 * llm_judgment.confidence

        score = max(0.0, min(1.0, score))

        if score >= 0.7 or leak.leak_suspected:
            return SignalLabel.MALICIOUS, max(score, 0.8 if leak.leak_suspected else score)
        if score >= 0.3:
            return SignalLabel.SUSPICIOUS, score
        return SignalLabel.BENIGN, 1.0 - score

    @staticmethod
    def _evidence_sentence(
        findings: list[tuple[str, str]],
        leak: ProvenanceQuery,
        external_dest: bool,
        llm_judgment: Any,
    ) -> str:
        bits: list[str] = []
        if leak.leak_suspected:
            bits.append(f"EXFIL chain: {leak.rationale}")
        if findings:
            names = sorted({n for n, _ in findings})
            bits.append(f"pattern hits: {', '.join(names)}")
        if external_dest:
            bits.append("external destination detected on outbound")
        if llm_judgment and llm_judgment.label != "benign":
            bits.append(f"LLM deep-scan: {llm_judgment.rationale}")
        if not bits:
            bits.append("no payload anomalies detected")
        return "; ".join(bits)
