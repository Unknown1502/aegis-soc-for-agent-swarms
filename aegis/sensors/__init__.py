"""Thin clients for Microsoft sensor services.

Each sensor wraps an Azure / Microsoft service with the same shape so that
guardians do not have to special-case missing credentials. Every sensor:

* exposes an async API
* fails safe (returns a clearly-marked degraded result on error/timeout)
* never raises out of its public surface
* records its decision into the Foundry trace

The four sensors are:
    aegis.sensors.prompt_shields  - Azure AI Content Safety (Prompt Shields)
    aegis.sensors.entra_agent_id  - Microsoft Entra Agent ID token verifier
    aegis.sensors.defender         - Defender for Cloud AI alert ingestion
    aegis.sensors.azure_monitor    - metric / alert rule helpers
"""

from aegis.sensors.entra_agent_id import (
    EntraAgentIdSensor,
    EntraVerificationResult,
)
from aegis.sensors.prompt_shields import (
    PromptShieldsResult,
    PromptShieldsSensor,
)

__all__ = [
    "EntraAgentIdSensor",
    "EntraVerificationResult",
    "PromptShieldsResult",
    "PromptShieldsSensor",
]
