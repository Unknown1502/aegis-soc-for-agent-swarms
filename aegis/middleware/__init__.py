"""AEGIS middleware - the interception layer.

The middleware sits between the protected ("victim") swarm and the rest of
the world. Every inter-agent message, every tool call, and every llm prompt
the swarm wants to emit is captured here BEFORE execution. The middleware
asks the Verdict Arbiter (via a pluggable DecisionProvider) what to do,
then ALLOWS, BLOCKS, or QUARANTINEs.

Architectural choices:
* The DecisionProvider interface lets us swap the Arbiter for a default
  "always allow" provider when running the victim swarm in isolation (to
  prove AEGIS is a wrapper, not surgery).
* QUARANTINE both blocks the current action and zeros out the source
  agent's trust score so subsequent actions from that agent default-block
  until an analyst clears it.
* The interceptor publishes onto the global event bus so the API server
  (FastAPI / WebSocket) and the dashboard see every action and outcome
  live, without polling.
"""

from aegis.middleware.interceptor import (
    AlwaysAllowDecisionProvider,
    DecisionProvider,
    InterceptionResult,
    Interceptor,
    QuarantineRegistry,
)

__all__ = [
    "AlwaysAllowDecisionProvider",
    "DecisionProvider",
    "InterceptionResult",
    "Interceptor",
    "QuarantineRegistry",
]
