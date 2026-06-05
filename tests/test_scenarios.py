"""Headline integration tests.

These tests are the spec for AEGIS's promise: each named scenario reaches
the verdict it must reach for the demo to be honest. They run against the
offline backend so CI does not need Azure.
"""

import pytest

from aegis.attacks import (
    run_benign_baseline,
    run_echoleak_chain,
    run_memory_poison,
    run_orchestrator_spoof,
)
from aegis.guard import AegisGuard


@pytest.mark.asyncio
async def test_benign_baseline_is_allowed() -> None:
    guard = AegisGuard.build()
    result = await run_benign_baseline(guard)
    assert result["sent"] is True
    assert result.get("refusal") is None
    # Outbound mailbox must have a sent record; no blocks.
    assert len(guard.mailbox.sent) == 1
    assert len(guard.mailbox.blocked) == 0


@pytest.mark.asyncio
async def test_echoleak_chain_is_blocked_at_send_email() -> None:
    guard = AegisGuard.build()
    result = await run_echoleak_chain(guard)
    assert result["sent"] is False
    assert result["refusal"] is not None
    # No outbound email was sent (the whole point of the demo).
    assert len(guard.mailbox.sent) == 0
    # Tool-Executor was quarantined.
    assert any(
        "victim.tool_executor" in q for q in guard.quarantine.snapshot()
    )


@pytest.mark.asyncio
async def test_orchestrator_spoof_is_quarantined() -> None:
    guard = AegisGuard.build()
    result = await run_orchestrator_spoof(guard)
    assert result["decision"] == "confirmed"
    assert result["outcome"] in {"quarantine", "block"}
    assert result["is_quarantined"] is True


@pytest.mark.asyncio
async def test_memory_poison_trigger_is_blocked() -> None:
    guard = AegisGuard.build()
    result = await run_memory_poison(guard)
    # Step 2 is the trigger; its exec attempt must have been blocked.
    step2 = result["step2"]
    assert step2["sent"] is False or step2.get("refusal") is not None


@pytest.mark.asyncio
async def test_audit_chain_integrity_after_run() -> None:
    guard = AegisGuard.build()
    await run_echoleak_chain(guard)
    ok, message = guard.audit.verify_integrity()
    assert ok, f"audit chain failed: {message}"
