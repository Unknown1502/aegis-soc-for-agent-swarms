"""The "victim" swarm AEGIS protects.

A deliberately simple, realistic 3-agent productivity pipeline:

    Email-Triage Agent  ->  Summarizer Agent  ->  Tool-Executor Agent

The agents are written in plain async Python with the exact same shape
Microsoft Agent Framework exposes (Agent, message-passing, tool calls,
shared memory). When Azure/Agent-Framework credentials are present the
wiring in aegis.victim.agent_framework_bridge maps these agents onto
Agent Framework's `ChatAgent` + `WorkflowBuilder` primitives. Until then
the swarm runs as-is and is fully exercise-able by the AEGIS guardians.

The interceptor sees every inter-agent message and every tool call BEFORE
it executes via VictimAgent._emit_action(...), which awaits the
InterceptionResult. If the interceptor refuses, the agent receives a
SafeRefusal it includes verbatim in its reply.
"""

from aegis.victim.agent_base import (
    AgentRunContext,
    SafeRefusal,
    SwarmConfig,
    VictimAgent,
    VictimSwarm,
)
from aegis.victim.memory import SharedMemoryStore
from aegis.victim.tools import (
    AgentTool,
    EmailMessage,
    InternalDocument,
    InternalDocumentStore,
    OutboundMailbox,
    send_email_tool,
)

__all__ = [
    "AgentRunContext",
    "AgentTool",
    "EmailMessage",
    "InternalDocument",
    "InternalDocumentStore",
    "OutboundMailbox",
    "SafeRefusal",
    "SharedMemoryStore",
    "SwarmConfig",
    "VictimAgent",
    "VictimSwarm",
    "send_email_tool",
]
