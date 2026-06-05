"""LLM access for AEGIS guardians.

Guardians call a single function - `classify_security(...)` - to get a
structured security judgment from a language model. The implementation picks
the strongest available backend at runtime:

    Azure OpenAI (preferred)  ->  vanilla OpenAI  ->  deterministic offline mock

The offline mock is NOT a stub - it implements real heuristics so the demo
runs end-to-end without any cloud credentials, and the eval harness can still
produce comparable numbers. When Azure or OpenAI is configured, the guardian
LLM calls become real Foundry-traced model invocations.
"""

from aegis.llm.provider import (
    LLMUnavailable,
    SecurityJudgment,
    classify_security,
    describe_active_backend,
)

__all__ = [
    "LLMUnavailable",
    "SecurityJudgment",
    "classify_security",
    "describe_active_backend",
]
