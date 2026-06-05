"""Shared long-term memory store for the victim swarm.

A small key->value store the planner consults at the start of each task and
that downstream agents can append to. This is the canonical target for the
memory-poisoning attack: an attacker writes a benign-looking instruction
in one session; a later session reads it and acts on it.

We track the WRITE provenance so the Audit guardian can later say "the
instruction your planner is about to follow was written by an external
sender during a prior task" - the delayed-trigger detection story.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class MemoryEntry:
    key: str
    value: str
    written_by: str            # source agent id at write time
    written_unix_ms: int
    correlation_id_at_write: str
    origin_note: str = ""      # e.g. "extracted from inbound email"
    sensitivity: str = "internal"


class SharedMemoryStore:
    def __init__(self) -> None:
        self._entries: dict[str, MemoryEntry] = {}
        self._lock = threading.RLock()

    def put(
        self,
        *,
        key: str,
        value: str,
        written_by: str,
        correlation_id: str,
        origin_note: str = "",
        sensitivity: str = "internal",
    ) -> MemoryEntry:
        entry = MemoryEntry(
            key=key,
            value=value,
            written_by=written_by,
            written_unix_ms=int(time.time() * 1000),
            correlation_id_at_write=correlation_id,
            origin_note=origin_note,
            sensitivity=sensitivity,
        )
        with self._lock:
            self._entries[key] = entry
        return entry

    def get(self, key: str) -> MemoryEntry | None:
        with self._lock:
            return self._entries.get(key)

    def items(self) -> Iterator[MemoryEntry]:
        with self._lock:
            return iter(list(self._entries.values()))

    def keys(self) -> list[str]:
        with self._lock:
            return list(self._entries.keys())
