"""Azure AI Content Safety - Prompt Shields client.

Endpoint contract (current as of 2026 Q1 - re-verify the week of the build):

    POST {endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01
    Body:
      {
        "userPrompt": "<the prompt text or null>",
        "documents":  ["<doc1>", "<doc2>", ...]   # for indirect / XPIA
      }
    Response:
      {
        "userPromptAnalysis":   {"attackDetected": bool},
        "documentsAnalysis":    [{"attackDetected": bool}, ...]
      }

Failure modes (network, auth, 5xx) return a result with `available=False`
and `degraded_reason` populated. Guardians treat that as missing data, not
as a "benign" verdict.

A demo-honesty note (see strategy doc Section 4 / Beat 2): the EchoLeak-style
payload we exhibit is phrased "for the human reader" and Prompt Shields
correctly returns LOW risk for it. That is the entire point of the demo: the
shield passes, AEGIS still catches.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from aegis.settings import get_settings
from aegis.telemetry.logging import get_logger
from aegis.telemetry.tracing import get_tracer

_log = get_logger(__name__)

_API_VERSION = "2024-09-01"
_DEFAULT_TIMEOUT_S = 4.0


@dataclass
class PromptShieldsResult:
    """Normalised output the Threat Classifier consumes."""

    available: bool
    direct_attack_detected: bool = False
    indirect_attack_detected: bool = False
    indirect_doc_count: int = 0
    indirect_attack_doc_indices: list[int] = field(default_factory=list)
    raw_response: dict[str, Any] | None = None
    degraded_reason: str | None = None
    latency_ms: int = 0

    @property
    def risk_level(self) -> str:
        if not self.available:
            return "unavailable"
        if self.direct_attack_detected:
            return "high"
        if self.indirect_attack_detected:
            return "medium"
        return "low"

    def to_sensor_data(self) -> dict[str, Any]:
        return {
            "sensor": "azure_content_safety_prompt_shields",
            "available": self.available,
            "risk_level": self.risk_level,
            "direct_attack_detected": self.direct_attack_detected,
            "indirect_attack_detected": self.indirect_attack_detected,
            "indirect_doc_count": self.indirect_doc_count,
            "indirect_attack_doc_indices": list(self.indirect_attack_doc_indices),
            "degraded_reason": self.degraded_reason,
            "latency_ms": self.latency_ms,
        }


class PromptShieldsSensor:
    """Async client. Reuses a single httpx.AsyncClient."""

    def __init__(self, *, timeout_s: float = _DEFAULT_TIMEOUT_S) -> None:
        self._settings = get_settings()
        self._timeout_s = timeout_s
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            async with self._client_lock:
                if self._client is None:
                    self._client = httpx.AsyncClient(timeout=self._timeout_s)
        return self._client

    @property
    def configured(self) -> bool:
        return self._settings.has_prompt_shields

    async def shield_prompt(
        self,
        *,
        user_prompt: str | None,
        documents: list[str] | None = None,
    ) -> PromptShieldsResult:
        """Call Prompt Shields. Returns a degraded result on any failure."""

        import time

        documents = documents or []
        if not self.configured:
            return PromptShieldsResult(
                available=False,
                degraded_reason="content_safety_not_configured",
                indirect_doc_count=len(documents),
            )

        endpoint = (self._settings.azure_content_safety_endpoint or "").rstrip("/")
        url = f"{endpoint}/contentsafety/text:shieldPrompt"
        headers = {
            "Ocp-Apim-Subscription-Key": self._settings.azure_content_safety_key or "",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {}
        if user_prompt is not None:
            body["userPrompt"] = user_prompt[:10000]
        if documents:
            body["documents"] = [d[:10000] for d in documents]

        tracer = get_tracer()
        with tracer.start_as_current_span("sensor.prompt_shields.call") as span:
            span.set_attribute("aegis.sensor", "prompt_shields")
            span.set_attribute("aegis.input.has_user_prompt", user_prompt is not None)
            span.set_attribute("aegis.input.doc_count", len(documents))

            t0 = time.perf_counter()
            try:
                client = await self._get_client()
                resp = await client.post(
                    url,
                    headers=headers,
                    params={"api-version": _API_VERSION},
                    json=body,
                )
                latency = int((time.perf_counter() - t0) * 1000)
                if resp.status_code != 200:
                    return PromptShieldsResult(
                        available=False,
                        degraded_reason=f"http_{resp.status_code}",
                        latency_ms=latency,
                        indirect_doc_count=len(documents),
                    )
                data = resp.json()
                return self._parse_response(data, len(documents), latency)
            except Exception as exc:  # network, JSON, anything
                _log.warning("prompt_shields.call_failed", error=str(exc))
                latency = int((time.perf_counter() - t0) * 1000)
                return PromptShieldsResult(
                    available=False,
                    degraded_reason=f"exception:{type(exc).__name__}",
                    latency_ms=latency,
                    indirect_doc_count=len(documents),
                )

    @staticmethod
    def _parse_response(
        data: dict[str, Any], doc_count: int, latency_ms: int
    ) -> PromptShieldsResult:
        user = data.get("userPromptAnalysis") or {}
        docs = data.get("documentsAnalysis") or []
        bad_indices = [i for i, d in enumerate(docs) if (d or {}).get("attackDetected")]
        return PromptShieldsResult(
            available=True,
            direct_attack_detected=bool(user.get("attackDetected")),
            indirect_attack_detected=bool(bad_indices),
            indirect_doc_count=doc_count,
            indirect_attack_doc_indices=bad_indices,
            raw_response=data,
            latency_ms=latency_ms,
        )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


_GLOBAL: PromptShieldsSensor | None = None


def get_prompt_shields() -> PromptShieldsSensor:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = PromptShieldsSensor()
    return _GLOBAL
