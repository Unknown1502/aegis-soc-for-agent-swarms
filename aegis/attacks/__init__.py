"""Sandboxed demo attacks.

Each attack targets the LOCAL victim swarm only, with deliberately benign
content - the goal is to demonstrate AEGIS's detection, never to ship an
exploit. The payloads are constructed to mirror the published failure
modes (EchoLeak / CVE-2025-32711, A2A orchestrator spoofing, OWASP
memory poisoning) so judges instantly recognize them.
"""

from aegis.attacks.benign_baseline import run_benign_baseline
from aegis.attacks.echoleak_chain import EchoLeakScenario, run_echoleak_chain
from aegis.attacks.memory_poison import run_memory_poison
from aegis.attacks.spoof_orchestrator import run_orchestrator_spoof

__all__ = [
    "EchoLeakScenario",
    "run_benign_baseline",
    "run_echoleak_chain",
    "run_memory_poison",
    "run_orchestrator_spoof",
]
