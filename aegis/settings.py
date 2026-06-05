"""Centralized runtime configuration.

One Settings object, validated at import, fed by environment variables and
optionally a .env file. Every Microsoft integration in AEGIS reads its
credentials from here and degrades safely if they are absent (the loaders
in aegis.sensors and aegis.telemetry inspect feature flags / required keys
before going to the wire).
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ModelBackend(str, Enum):
    AZURE_OPENAI = "azure_openai"
    OPENAI = "openai"
    OFFLINE_MOCK = "offline_mock"


class Settings(BaseSettings):
    """All AEGIS runtime configuration in one place.

    Defaults are safe-for-offline: AEGIS will boot, run the victim swarm, run
    the guardians with the deterministic offline model backend, and serve
    the dashboard - without any Azure resources provisioned. Each real
    integration unlocks as you fill its env vars.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Runtime ----------------------------------------------------------
    aegis_env: Literal["development", "staging", "production"] = "development"
    aegis_log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    aegis_api_host: str = "127.0.0.1"
    aegis_api_port: int = 8088
    aegis_dashboard_origin: str = "http://localhost:5173"

    # --- Model backend ---------------------------------------------------
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_deployment: str = "gpt-4o-mini"
    azure_openai_api_version: str = "2024-10-21"

    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"

    aegis_force_offline_mock: bool = False

    # --- Azure AI Foundry ------------------------------------------------
    azure_ai_foundry_project_endpoint: str | None = None
    azure_ai_foundry_connection_string: str | None = None
    azure_subscription_id: str | None = None
    azure_resource_group: str | None = None
    azure_tenant_id: str | None = None

    # --- Content Safety / Prompt Shields ---------------------------------
    azure_content_safety_endpoint: str | None = None
    azure_content_safety_key: str | None = None

    # --- Entra Agent ID --------------------------------------------------
    entra_tenant_id: str | None = None
    entra_client_id: str | None = None
    entra_agent_audience: str = "api://aegis-agents"
    entra_jwks_uri: str | None = None
    entra_issuer: str | None = None
    # Per-agent app-registration credentials that let the victim swarm acquire
    # REAL Entra-signed tokens (client-credentials flow) instead of dev-mock
    # HMAC tokens. JSON map: {"victim.orchestrator": {"client_id": "...",
    # "client_secret": "..."}, "victim.email_triage": {...}, ...}. When present
    # AND entra_client_id/jwks/issuer are set, AEGIS flips to genuinely live
    # identity verification. When absent, the swarm stays in dev-mock safely.
    entra_agent_credentials: str | None = None
    # Hard kill-switch: force dev-mock identity even if live creds are present.
    # The escape hatch if real-token verification misbehaves at demo time.
    aegis_force_entra_mock: bool = False

    # --- Defender for Cloud ----------------------------------------------
    azure_log_analytics_workspace_id: str | None = None
    defender_alerts_resource_id: str | None = None

    # --- Azure Monitor / App Insights ------------------------------------
    applicationinsights_connection_string: str | None = None

    # --- Demo auth -------------------------------------------------------
    aegis_demo_username: str = "demo"
    aegis_demo_password: str = "aegis-demo"
    aegis_jwt_secret: str = "development-only-secret-do-not-ship"

    # --- Feature flags ---------------------------------------------------
    aegis_enable_defender_ingest: bool = False
    aegis_enable_azure_monitor: bool = False
    aegis_enable_foundry_tracing: bool = False

    # ---------- Convenience flags ----------------------------------------
    def resolve_model_backend(self) -> ModelBackend:
        """Pick the highest-fidelity model backend that is fully configured.

        Order: Azure OpenAI -> OpenAI -> offline mock. If the offline-mock
        override is set, returns it regardless.
        """

        if self.aegis_force_offline_mock:
            return ModelBackend.OFFLINE_MOCK
        if self.azure_openai_endpoint and self.azure_openai_api_key:
            return ModelBackend.AZURE_OPENAI
        if self.openai_api_key:
            return ModelBackend.OPENAI
        return ModelBackend.OFFLINE_MOCK

    @property
    def has_prompt_shields(self) -> bool:
        return bool(self.azure_content_safety_endpoint and self.azure_content_safety_key)

    @property
    def has_entra_agent_id(self) -> bool:
        # Requires the app registration (client_id) too, not just the tenant
        # metadata. Otherwise victim-swarm dev-mock tokens would be rejected
        # by the real Entra verifier before per-agent app regs exist.
        return bool(
            self.entra_jwks_uri and self.entra_issuer and self.entra_client_id
        )

    def entra_agent_credential_map(self) -> dict[str, dict[str, str]]:
        """Parse entra_agent_credentials into {agent_id: {client_id, client_secret}}.

        Returns an empty map (never raises) if unset or malformed, so a bad
        value degrades safely to dev-mock instead of crashing boot.
        """

        if not self.entra_agent_credentials:
            return {}
        import json

        try:
            data = json.loads(self.entra_agent_credentials)
        except (json.JSONDecodeError, TypeError):
            return {}
        if not isinstance(data, dict):
            return {}
        out: dict[str, dict[str, str]] = {}
        for agent_id, creds in data.items():
            if (
                isinstance(creds, dict)
                and creds.get("client_id")
                and creds.get("client_secret")
            ):
                out[agent_id] = {
                    "client_id": str(creds["client_id"]),
                    "client_secret": str(creds["client_secret"]),
                }
        return out

    @property
    def has_entra_live(self) -> bool:
        """True only when AEGIS can both verify (JWKS/issuer/client_id) AND issue
        real per-agent Entra tokens. This is the single gate that flips both the
        verifier and the swarm's token provider together, so they never disagree
        (a half-live state would reject every message and self-quarantine the
        swarm). The kill-switch forces dev-mock regardless."""

        return (
            not self.aegis_force_entra_mock
            and self.has_entra_agent_id
            and len(self.entra_agent_credential_map()) > 0
        )

    @property
    def has_defender(self) -> bool:
        return self.aegis_enable_defender_ingest and bool(
            self.azure_log_analytics_workspace_id or self.defender_alerts_resource_id
        )

    @property
    def has_azure_monitor(self) -> bool:
        return self.aegis_enable_azure_monitor and bool(
            self.applicationinsights_connection_string
        )

    @property
    def has_foundry_tracing(self) -> bool:
        return self.aegis_enable_foundry_tracing and bool(
            self.azure_ai_foundry_connection_string
            or self.applicationinsights_connection_string
        )

    def integration_report(self) -> dict[str, str]:
        """Used at boot to print a clear table of what's live vs degraded."""

        def fmt(active: bool, label: str) -> str:
            return "LIVE" if active else f"DEGRADED ({label})"

        return {
            "model_backend": self.resolve_model_backend().value,
            "prompt_shields": fmt(self.has_prompt_shields, "mock"),
            "entra_agent_id": fmt(self.has_entra_live, "mock"),
            "defender": fmt(self.has_defender, "disabled"),
            "azure_monitor": fmt(self.has_azure_monitor, "disabled"),
            "foundry_tracing": fmt(self.has_foundry_tracing, "console-only"),
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
