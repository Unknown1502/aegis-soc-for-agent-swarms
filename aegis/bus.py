"""In-process async event bus.

A simple async fan-out bus. The middleware publishes intercepted
AgentAction events; guardians subscribe to ActionEvent topics; the API
publishes Verdicts and signals to the dashboard via the same channel.

In a distributed deployment this would be Service Bus or Event Hubs. The
contract here is deliberately small so swapping in either is a one-file
change.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from aegis.telemetry.logging import get_logger

_log = get_logger(__name__)

T = TypeVar("T")


@dataclass
class Event(Generic[T]):
    topic: str
    payload: T
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_unix_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    attrs: dict[str, Any] = field(default_factory=dict)


class _Subscriber:
    __slots__ = ("queue", "topic_filter", "id")

    def __init__(self, topic_filter: str | None) -> None:
        self.id = str(uuid.uuid4())
        self.queue: asyncio.Queue[Event[Any]] = asyncio.Queue(maxsize=1000)
        self.topic_filter = topic_filter

    def matches(self, topic: str) -> bool:
        return self.topic_filter is None or self.topic_filter == topic

    async def stream(self) -> AsyncIterator[Event[Any]]:
        while True:
            yield await self.queue.get()


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[_Subscriber] = []
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, payload: Any, **attrs: Any) -> None:
        event: Event[Any] = Event(topic=topic, payload=payload, attrs=attrs)
        async with self._lock:
            subs = [s for s in self._subscribers if s.matches(topic)]
        for sub in subs:
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                _log.warning(
                    "bus.subscriber_overflow",
                    topic=topic,
                    subscriber_id=sub.id,
                )

    async def subscribe(self, topic: str | None = None) -> _Subscriber:
        sub = _Subscriber(topic_filter=topic)
        async with self._lock:
            self._subscribers.append(sub)
        return sub

    async def unsubscribe(self, sub: _Subscriber) -> None:
        async with self._lock:
            self._subscribers = [s for s in self._subscribers if s.id != sub.id]


_GLOBAL_BUS: EventBus | None = None


def get_bus() -> EventBus:
    global _GLOBAL_BUS
    if _GLOBAL_BUS is None:
        _GLOBAL_BUS = EventBus()
    return _GLOBAL_BUS


# Canonical topic names.
TOPIC_ACTION = "aegis.action"
TOPIC_SIGNAL = "aegis.signal"
TOPIC_VERDICT = "aegis.verdict"
TOPIC_OUTCOME = "aegis.outcome"
TOPIC_TRUST = "aegis.trust"
TOPIC_THRESHOLD = "aegis.threshold"
TOPIC_AUDIT = "aegis.audit"
