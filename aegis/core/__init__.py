"""AEGIS core domain types.

Every other module in AEGIS is glue around these contracts. Three primitives
move through the system:

    AgentAction      - something a protected agent wants to do (intercepted
                       before execution)
    GuardianSignal   - what a single guardian agent decided about an action
    Verdict          - what the Verdict Arbiter concluded after correlating
                       all guardian signals AND the cross-agent sequence

Plus the standards tags (OWASP Agentic Top-10 / MAESTRO / MITRE ATLAS) that
make every verdict speak the same language as Microsoft Defender, Entra, and
Foundry teams.
"""

from aegis.core.events import (
    ActionId,
    ActionType,
    AgentAction,
    AgentId,
    AgentIdentityClaim,
    CorrelationId,
    ExecutionOutcome,
)
from aegis.core.signals import (
    EvidenceSpan,
    GuardianKind,
    GuardianSignal,
    SignalLabel,
)
from aegis.core.standards import (
    MaestroLayer,
    MitreAtlasTechnique,
    OwaspAgenticRisk,
    StandardsTag,
)
from aegis.core.verdicts import (
    Severity,
    Verdict,
    VerdictDecision,
)

__all__ = [
    "ActionId",
    "ActionType",
    "AgentAction",
    "AgentId",
    "AgentIdentityClaim",
    "CorrelationId",
    "EvidenceSpan",
    "ExecutionOutcome",
    "GuardianKind",
    "GuardianSignal",
    "MaestroLayer",
    "MitreAtlasTechnique",
    "OwaspAgenticRisk",
    "Severity",
    "SignalLabel",
    "StandardsTag",
    "Verdict",
    "VerdictDecision",
]
