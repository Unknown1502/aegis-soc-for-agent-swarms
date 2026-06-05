"""Live metrics for the SOC dashboard + Azure Monitor.

The dashboard reads the in-memory snapshot directly via the API for low
latency. The same metric updates are also pushed to Azure Monitor when the
App Insights connection string is configured, so they appear in the portal
and can drive alerts (defined in /aegis/telemetry/azure_alerts.bicep at a
later stage if/when an alert rule is required).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from opentelemetry import metrics as otel_metrics
from opentelemetry.metrics import Counter, Histogram, Meter

from aegis.settings import get_settings
from aegis.telemetry.logging import get_logger

_log = get_logger(__name__)

_METRIC_NAMES = {
    "verdicts_confirmed": "aegis.verdicts.confirmed",
    "verdicts_probable": "aegis.verdicts.probable",
    "verdicts_false_positive": "aegis.verdicts.false_positive",
    "false_positives_suppressed": "aegis.signals.false_positives_suppressed",
    "quarantines": "aegis.actions.quarantines",
    "blocks": "aegis.actions.blocks",
    "allows": "aegis.actions.allows",
    "time_to_verdict_ms": "aegis.verdicts.time_to_verdict_ms",
}


@dataclass
class TrustScore:
    agent_id: str
    score: float = 1.0  # 1.0 = full trust, 0.0 = quarantined
    last_change_unix_ms: int = field(default_factory=lambda: int(time.time() * 1000))


@dataclass
class ThresholdSnapshot:
    """Captured each time the adaptive controller tightens a threshold."""

    when_unix_ms: int
    name: str
    old: float
    new: float
    reason: str


class MetricsEmitter:
    """In-memory + Azure Monitor metric store.

    The dashboard reads from `.snapshot()`. Guardian / arbiter / middleware
    callers use the `record_*` methods. Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters: dict[str, int] = defaultdict(int)
        self._ttv_window: deque[int] = deque(maxlen=200)
        self._trust: dict[str, TrustScore] = {}
        self._threshold_history: deque[ThresholdSnapshot] = deque(maxlen=200)
        self._fp_rate_window: deque[bool] = deque(maxlen=200)  # True = FP

        # Azure Monitor (OTel meter) only attaches if we configured a
        # provider. configure_azure_monitor() in tracing.py covers metrics
        # alongside traces when the connection string is set.
        meter: Meter = otel_metrics.get_meter("aegis")
        self._otel_counters: dict[str, Counter] = {
            metric_key: meter.create_counter(metric_name, unit="1")
            for metric_key, metric_name in _METRIC_NAMES.items()
            if metric_key != "time_to_verdict_ms"
        }
        self._ttv_histogram: Histogram = meter.create_histogram(
            _METRIC_NAMES["time_to_verdict_ms"], unit="ms"
        )

        settings = get_settings()
        if settings.has_azure_monitor:
            _log.info("metrics.azure_monitor.attached")
        else:
            _log.info("metrics.in_memory_only", reason="azure_monitor_disabled")

    # ---------- counters ------------------------------------------------
    def _inc(self, key: str, value: int = 1, attrs: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._counters[key] += value
        counter = self._otel_counters.get(key)
        if counter is not None:
            counter.add(value, attributes=attrs or {})

    def record_verdict(self, decision: str, time_to_verdict_ms: int) -> None:
        decision = decision.lower()
        if decision == "confirmed":
            self._inc("verdicts_confirmed")
            self._fp_rate_window.append(False)
        elif decision == "probable":
            self._inc("verdicts_probable")
            self._fp_rate_window.append(False)
        elif decision == "false_positive":
            self._inc("verdicts_false_positive")
            self._fp_rate_window.append(True)
        with self._lock:
            self._ttv_window.append(time_to_verdict_ms)
        self._ttv_histogram.record(
            time_to_verdict_ms, attributes={"decision": decision}
        )

    def record_suppression(self, count: int = 1) -> None:
        self._inc("false_positives_suppressed", value=count)

    def record_action_outcome(self, outcome: str) -> None:
        outcome = outcome.lower()
        if outcome == "allow":
            self._inc("allows")
        elif outcome == "block":
            self._inc("blocks")
        elif outcome == "quarantine":
            self._inc("quarantines")

    # ---------- trust scores --------------------------------------------
    def get_trust(self, agent_id: str) -> float:
        with self._lock:
            return self._trust.setdefault(agent_id, TrustScore(agent_id=agent_id)).score

    def adjust_trust(self, agent_id: str, delta: float, reason: str) -> float:
        with self._lock:
            ts = self._trust.setdefault(agent_id, TrustScore(agent_id=agent_id))
            ts.score = max(0.0, min(1.0, ts.score + delta))
            ts.last_change_unix_ms = int(time.time() * 1000)
            _log.info(
                "metrics.trust_adjusted",
                agent_id=agent_id,
                new_score=ts.score,
                delta=delta,
                reason=reason,
            )
            return ts.score

    def set_trust(self, agent_id: str, score: float, reason: str = "set") -> None:
        with self._lock:
            self._trust[agent_id] = TrustScore(
                agent_id=agent_id, score=max(0.0, min(1.0, score))
            )
            _log.info(
                "metrics.trust_set",
                agent_id=agent_id,
                score=score,
                reason=reason,
            )

    # ---------- adaptive thresholds -------------------------------------
    def record_threshold_change(
        self, name: str, old: float, new: float, reason: str
    ) -> None:
        with self._lock:
            self._threshold_history.append(
                ThresholdSnapshot(
                    when_unix_ms=int(time.time() * 1000),
                    name=name,
                    old=old,
                    new=new,
                    reason=reason,
                )
            )

    # ---------- read paths ---------------------------------------------
    def fp_rate(self) -> float:
        with self._lock:
            window = list(self._fp_rate_window)
        return (sum(1 for x in window if x) / len(window)) if window else 0.0

    def mean_time_to_verdict_ms(self) -> int:
        with self._lock:
            window = list(self._ttv_window)
        return int(sum(window) / len(window)) if window else 0

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "fp_rate": self.fp_rate(),
                "mean_time_to_verdict_ms": self.mean_time_to_verdict_ms(),
                "trust_scores": [
                    {
                        "agent_id": ts.agent_id,
                        "score": ts.score,
                        "last_change_unix_ms": ts.last_change_unix_ms,
                    }
                    for ts in self._trust.values()
                ],
                "threshold_history": [
                    {
                        "when_unix_ms": t.when_unix_ms,
                        "name": t.name,
                        "old": t.old,
                        "new": t.new,
                        "reason": t.reason,
                    }
                    for t in self._threshold_history
                ],
            }


_GLOBAL: MetricsEmitter | None = None
_GLOBAL_LOCK = threading.Lock()


def get_metrics() -> MetricsEmitter:
    global _GLOBAL
    if _GLOBAL is None:
        with _GLOBAL_LOCK:
            if _GLOBAL is None:
                _GLOBAL = MetricsEmitter()
    return _GLOBAL
