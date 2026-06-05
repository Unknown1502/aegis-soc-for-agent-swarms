"""Standards tags - OWASP Agentic Top-10, CSA MAESTRO, MITRE ATLAS.

Every verdict AEGIS emits carries one or more standards tags. This is what
makes our output legible to Microsoft Defender, Entra, and Foundry teams -
they already speak these languages. It is also the cheapest possible source
of credibility for hackathon judges.

Tag identifiers and short descriptions are taken from the published OWASP
Top-10 for Agentic Applications (2026), CSA's MAESTRO 7-layer threat model,
and MITRE ATLAS. Re-verify the IDs the week of submission - they shift.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class OwaspAgenticRisk(str, Enum):
    """OWASP Top-10 for Agentic Applications (2026).

    Codes use the published AAI-* prefix. We map only the categories AEGIS
    can demonstrably detect today; expand as additional attack surfaces are
    covered.
    """

    PROMPT_INJECTION = "AAI01:2026"          # Prompt Injection (incl. indirect/XPIA)
    SENSITIVE_INFO_DISCLOSURE = "AAI02:2026"  # Data exfiltration via the agent
    EXCESSIVE_AGENCY = "AAI03:2026"          # Tool misuse, over-broad scope
    MEMORY_POISONING = "AAI04:2026"          # Long-term memory corruption
    IDENTITY_SPOOFING = "AAI05:2026"         # Agent / orchestrator impersonation
    INSECURE_TOOL_USE = "AAI06:2026"
    CASCADING_FAILURE = "AAI07:2026"         # Delayed-trigger cross-session compromise
    HALLUCINATED_INSTRUCTION = "AAI08:2026"
    UNTRUSTED_OUTPUT = "AAI09:2026"
    OBSERVABILITY_GAP = "AAI10:2026"


class MaestroLayer(str, Enum):
    """CSA MAESTRO 7 layers - which layer the attack lives at.

    L1 Foundation Model · L2 Data Operations · L3 Agent Frameworks ·
    L4 Deployment & Infrastructure · L5 Evaluation & Observability ·
    L6 Compliance & Security · L7 Multi-Agent / Ecosystem.
    """

    L1_FOUNDATION_MODEL = "MAESTRO-L1"
    L2_DATA_OPERATIONS = "MAESTRO-L2"
    L3_AGENT_FRAMEWORK = "MAESTRO-L3"
    L4_DEPLOYMENT = "MAESTRO-L4"
    L5_EVAL_OBSERVABILITY = "MAESTRO-L5"
    L6_COMPLIANCE = "MAESTRO-L6"
    L7_MULTI_AGENT = "MAESTRO-L7"


class MitreAtlasTechnique(str, Enum):
    """A pragmatic subset of MITRE ATLAS techniques AEGIS uses.

    Only the techniques we can defensibly cite are listed. Adding one means
    the codebase actually detects it - we never decorate verdicts with tags
    we can't justify.
    """

    INITIAL_ACCESS_LLM_PROMPT = "AML.T0051"          # LLM Prompt Injection
    INITIAL_ACCESS_PHISHING_LLM = "AML.T0052"        # User-Aided LLM Prompt Injection
    ML_ENABLED_PRODUCT = "AML.T0044"                 # Full ML-enabled product exploitation
    EXFILTRATION_VIA_LLM = "AML.T0057"               # Exfiltration via LLM
    LLM_DATA_LEAKAGE = "AML.T0024.002"               # Sensitive data leakage from LLM
    LLM_TRUSTED_OUTPUT_COMPONENT_MANIPULATION = "AML.T0061"
    LLM_JAILBREAK = "AML.T0054"
    AGENT_TOOL_INVOCATION = "AML.T0053"              # Tool invocation abuse


class StandardsTag(BaseModel):
    """A single standards-aligned label attached to a verdict."""

    model_config = ConfigDict(frozen=True)

    owasp: OwaspAgenticRisk | None = None
    maestro: MaestroLayer | None = None
    mitre_atlas: MitreAtlasTechnique | None = None
    note: str | None = None

    def as_chip_labels(self) -> list[str]:
        """Render as ['AAI01:2026', 'MAESTRO-L7', 'AML.T0051'] for the UI."""

        labels: list[str] = []
        if self.owasp:
            labels.append(self.owasp.value)
        if self.maestro:
            labels.append(self.maestro.value)
        if self.mitre_atlas:
            labels.append(self.mitre_atlas.value)
        return labels


# Pre-baked tag bundles for the two canonical AEGIS scenarios. Used by the
# Verdict Arbiter so the demo verdicts always carry consistent, accurate
# standards mapping.

INDIRECT_INJECTION_EXFIL_TAG = StandardsTag(
    owasp=OwaspAgenticRisk.SENSITIVE_INFO_DISCLOSURE,
    maestro=MaestroLayer.L7_MULTI_AGENT,
    mitre_atlas=MitreAtlasTechnique.EXFILTRATION_VIA_LLM,
    note="Indirect prompt injection chained to data exfiltration across agents (EchoLeak class).",
)

DIRECT_PROMPT_INJECTION_TAG = StandardsTag(
    owasp=OwaspAgenticRisk.PROMPT_INJECTION,
    maestro=MaestroLayer.L1_FOUNDATION_MODEL,
    mitre_atlas=MitreAtlasTechnique.INITIAL_ACCESS_LLM_PROMPT,
)

IDENTITY_SPOOFING_TAG = StandardsTag(
    owasp=OwaspAgenticRisk.IDENTITY_SPOOFING,
    maestro=MaestroLayer.L7_MULTI_AGENT,
    mitre_atlas=MitreAtlasTechnique.AGENT_TOOL_INVOCATION,
    note="Agent identity not verified by Entra Agent ID; orchestrator impersonation suspected.",
)

MEMORY_POISONING_TAG = StandardsTag(
    owasp=OwaspAgenticRisk.MEMORY_POISONING,
    maestro=MaestroLayer.L2_DATA_OPERATIONS,
    mitre_atlas=MitreAtlasTechnique.LLM_TRUSTED_OUTPUT_COMPONENT_MANIPULATION,
    note="Malicious instruction persisted in shared/long-term memory and triggered later.",
)
