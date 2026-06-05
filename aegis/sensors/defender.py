"""Microsoft Defender for Cloud - AI Threat Protection ingestion.

Defender publishes AI-workload alerts (jailbreak, direct prompt injection,
suspicious tool invocation, etc.) on the Foundry agent service. Two paths
are commonly available:

1. Log Analytics workspace polling (KQL over SecurityAlert table)
2. Microsoft Defender Alerts REST API

For the hackathon MVP we treat Defender as a corroborating signal: any
matching alert is normalised into a `DefenderAlert` and surfaced to the
Verdict Arbiter. The Arbiter can CONFIRM the alert with cross-agent
sequence evidence, or SUPPRESS it as a false positive - the "we reduce
Defender's noise" story the strategy doc highlights.

When Defender ingestion is disabled (default), `recent_alerts_for` returns
empty so the Arbiter behaves as if Defender saw nothing. When enabled but
unreachable, the call returns empty with a logged warning - never raises.

A `seed_alert` helper exists for the demo path so the spoof attack can
visibly drive Defender corroboration without requiring a live Defender
subscription. Any seeded alert is clearly tagged origin="seeded" so the
audit log shows it was injected for demonstration.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Literal

import httpx

from aegis.settings import get_settings
from aegis.telemetry.logging import get_logger

_log = get_logger(__name__)


@dataclass
class DefenderAlert:
    alert_id: str
    title: str
    severity: Literal["informational", "low", "medium", "high"]
    mitre_techniques: list[str] = field(default_factory=list)
    affected_agent_id: str | None = None
    correlation_id: str | None = None
    detected_unix_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    origin: Literal["live", "seeded"] = "live"
    raw: dict[str, Any] = field(default_factory=dict)


class DefenderSensor:
    def __init__(self, *, retention: int = 200) -> None:
        self._settings = get_settings()
        self._alerts: Deque[DefenderAlert] = deque(maxlen=retention)
        self._lock = asyncio.Lock()
        self._last_pull_unix_ms = 0

    @property
    def configured(self) -> bool:
        return self._settings.has_defender

    async def pull(self) -> int:
        """Pull the latest Defender alerts into the local buffer.

        Returns the number of new alerts ingested. No-op (returns 0) if the
        sensor is not configured. Live integration is intentionally pluggable
        via `_pull_live` - swap that method for the real Defender REST or
        Log Analytics call in production.
        """

        if not self.configured:
            return 0
        try:
            new_alerts = await self._pull_live()
        except Exception as exc:
            _log.warning("defender.pull_failed", error=str(exc))
            return 0
        async with self._lock:
            for alert in new_alerts:
                self._alerts.append(alert)
            self._last_pull_unix_ms = int(time.time() * 1000)
        return len(new_alerts)

    async def seed_alert(self, alert: DefenderAlert) -> None:
        """For demos: inject a clearly-tagged alert into the buffer.

        Used by the spoofing attack to visibly drive Defender corroboration
        without requiring a live subscription. The Arbiter still does its job
        of correlating the alert with cross-agent evidence.
        """

        alert.origin = "seeded"
        async with self._lock:
            self._alerts.append(alert)
        _log.info(
            "defender.alert_seeded",
            alert_id=alert.alert_id,
            severity=alert.severity,
            agent=alert.affected_agent_id,
        )

    async def recent_alerts_for(
        self,
        *,
        agent_id: str | None = None,
        correlation_id: str | None = None,
        window_seconds: int = 300,
    ) -> list[DefenderAlert]:
        cutoff = int(time.time() * 1000) - window_seconds * 1000
        async with self._lock:
            buf = list(self._alerts)
        out: list[DefenderAlert] = []
        for a in buf:
            if a.detected_unix_ms < cutoff:
                continue
            if agent_id and a.affected_agent_id and a.affected_agent_id != agent_id:
                continue
            if correlation_id and a.correlation_id and a.correlation_id != correlation_id:
                continue
            out.append(a)
        return out

    # ----- live integration ------------------------------------------
    async def _pull_live(self) -> list[DefenderAlert]:
        """Pull live Defender for Cloud security alerts at subscription scope.

            GET https://management.azure.com/subscriptions/{sub}/providers/
                Microsoft.Security/alerts?api-version=2022-01-01

        Auth is an AAD bearer token from `DefaultAzureCredential`, so it works
        with `az login`, a managed identity, or an
        AZURE_CLIENT_ID/SECRET/TENANT service principal (needs *Security
        Reader* on the subscription). Read-only and fully fail-safe: any auth,
        network, or schema problem logs a warning and returns an empty list, so
        the Arbiter simply behaves as if Defender saw nothing. Only alerts not
        already in the buffer are returned (dedup by alert id).
        """

        sub = self._settings.azure_subscription_id
        if not sub:
            _log.warning("defender.pull_live_skipped", reason="no_subscription_id")
            return []

        try:
            # Sync credential off-loaded to a thread - avoids the aiohttp
            # dependency the azure.identity.aio variant pulls in.
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
            try:
                token = await asyncio.to_thread(
                    credential.get_token, "https://management.azure.com/.default"
                )
            finally:
                credential.close()

            url = (
                f"https://management.azure.com/subscriptions/{sub}"
                "/providers/Microsoft.Security/alerts?api-version=2022-01-01"
            )
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    url, headers={"Authorization": f"Bearer {token.token}"}
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            _log.warning("defender.pull_live_failed", error=str(exc))
            return []

        async with self._lock:
            seen = {a.alert_id for a in self._alerts}
        fresh: list[DefenderAlert] = []
        for item in data.get("value", []):
            try:
                alert = self.normalize(item)
            except Exception as exc:  # one bad record must not drop the batch
                _log.warning("defender.normalize_failed", error=str(exc))
                continue
            if alert.alert_id in seen:
                continue
            fresh.append(alert)
        _log.info("defender.pull_live_ok", new_alerts=len(fresh))
        return fresh

    @staticmethod
    def normalize(alert: dict[str, Any]) -> DefenderAlert:
        """Translate a raw Defender SecurityAlert dict into a DefenderAlert."""

        props = alert.get("properties", {}) or {}
        mitre = []
        for tactic in props.get("intent", "").split(","):
            tactic = tactic.strip()
            if tactic:
                mitre.append(tactic)
        return DefenderAlert(
            alert_id=alert.get("name") or props.get("systemAlertId") or "unknown",
            title=props.get("alertDisplayName", "Defender AI alert"),
            severity=(props.get("severity") or "informational").lower(),  # type: ignore[arg-type]
            mitre_techniques=mitre,
            affected_agent_id=(
                (props.get("entities") or [{}])[0].get("agentId")
                if props.get("entities")
                else None
            ),
            correlation_id=props.get("correlationKey"),
            raw=alert,
        )


_GLOBAL: DefenderSensor | None = None


def get_defender_sensor() -> DefenderSensor:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = DefenderSensor()
    return _GLOBAL
