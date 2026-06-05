"""Microsoft Entra Agent ID - per-message identity verification.

Each inter-agent message carries an OIDC token signed by the issuing
agent's Entra Agent ID app registration. The Inter-Agent Comms Monitor
calls `EntraAgentIdSensor.verify(...)` for every message. Outcomes:

    valid     - signature OK, issuer matches, audience matches, not expired,
                jti not seen before (replay window)
    invalid   - signature failed or claims wrong
    missing   - no token presented
    expired   - exp claim in the past
    replay    - jti already seen within the replay window

We never invent crypto - JWKS is fetched from Entra's discovery endpoint
and PyJWT verifies. When Entra is not configured (no JWKS URI), the sensor
runs in DEV-MOCK mode: it implements a HMAC-signed token format identical
in shape to the Entra payload so the demo can exercise the full code path
without a tenant. The mock and the real verifier produce indistinguishable
EntraVerificationResult shapes for downstream code.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
import jwt
from jwt import PyJWKClient

from aegis.settings import get_settings
from aegis.telemetry.logging import get_logger
from aegis.telemetry.tracing import get_tracer

_log = get_logger(__name__)

VerificationStatus = Literal["valid", "invalid", "missing", "expired", "replay", "unavailable"]
_DEFAULT_REPLAY_WINDOW_SECONDS = 600


@dataclass
class EntraVerificationResult:
    status: VerificationStatus
    verified_agent_id: str | None = None
    issuer: str | None = None
    audience: str | None = None
    jti: str | None = None
    expires_at_unix: int | None = None
    backend: Literal["entra", "dev_mock", "unavailable"] = "unavailable"
    reason: str | None = None
    raw_claims: dict[str, Any] | None = field(default=None, repr=False)

    @property
    def valid(self) -> bool:
        return self.status == "valid"

    def to_sensor_data(self) -> dict[str, Any]:
        return {
            "sensor": "entra_agent_id",
            "status": self.status,
            "verified_agent_id": self.verified_agent_id,
            "issuer": self.issuer,
            "audience": self.audience,
            "jti": self.jti,
            "backend": self.backend,
            "reason": self.reason,
            "expires_at_unix": self.expires_at_unix,
        }


class EntraAgentIdSensor:
    def __init__(self, *, replay_window_seconds: int = _DEFAULT_REPLAY_WINDOW_SECONDS) -> None:
        self._settings = get_settings()
        self._replay_window = replay_window_seconds
        self._seen_jtis: OrderedDict[str, int] = OrderedDict()
        self._lock = asyncio.Lock()
        self._jwk_client: PyJWKClient | None = None

    @property
    def configured(self) -> bool:
        # Switch to the real RS256 verifier only when AEGIS is fully live (real
        # per-agent tokens are also being issued). Otherwise stay in dev-mock so
        # the swarm's HMAC tokens still verify - a half-live state would reject
        # every message and self-quarantine the swarm.
        return self._settings.has_entra_live

    def _client_id_to_agent(self) -> dict[str, str]:
        """Reverse map {client_id: agent_id} built from the per-agent creds.

        Real Entra client-credentials tokens identify the caller by its app id
        (the ``azp`` / ``appid`` claim), not by a human agent name. We map that
        back to the canonical agent id the rest of AEGIS reasons about.
        """

        return {
            creds["client_id"]: agent_id
            for agent_id, creds in self._settings.entra_agent_credential_map().items()
        }

    # ------ public API --------------------------------------------------
    async def verify(
        self, *, claimed_agent_id: str, token: str | None
    ) -> EntraVerificationResult:
        tracer = get_tracer()
        with tracer.start_as_current_span("sensor.entra.verify") as span:
            span.set_attribute("aegis.sensor", "entra_agent_id")
            span.set_attribute("aegis.identity.claimed_agent_id", claimed_agent_id)
            span.set_attribute("aegis.identity.token_present", token is not None)

            if not token:
                result = EntraVerificationResult(
                    status="missing",
                    backend=("entra" if self.configured else "dev_mock"),
                    reason="no_token_presented",
                )
                span.set_attribute("aegis.identity.status", result.status)
                return result

            if self.configured:
                result = await self._verify_entra(claimed_agent_id, token)
            else:
                result = self._verify_dev_mock(claimed_agent_id, token)

            if result.valid and result.jti:
                if not await self._record_jti(result.jti):
                    result = EntraVerificationResult(
                        status="replay",
                        verified_agent_id=result.verified_agent_id,
                        issuer=result.issuer,
                        audience=result.audience,
                        jti=result.jti,
                        expires_at_unix=result.expires_at_unix,
                        backend=result.backend,
                        reason="jti_seen_within_replay_window",
                        raw_claims=result.raw_claims,
                    )
            span.set_attribute("aegis.identity.status", result.status)
            return result

    # ------ Entra (real) ------------------------------------------------
    def _get_jwk_client(self) -> PyJWKClient | None:
        if not self._settings.entra_jwks_uri:
            return None
        if self._jwk_client is None:
            self._jwk_client = PyJWKClient(self._settings.entra_jwks_uri, cache_keys=True)
        return self._jwk_client

    async def _verify_entra(self, claimed_agent_id: str, token: str) -> EntraVerificationResult:
        try:
            jwk_client = self._get_jwk_client()
            if jwk_client is None:
                return EntraVerificationResult(
                    status="unavailable",
                    backend="entra",
                    reason="jwks_uri_missing",
                )
            signing_key = await asyncio.to_thread(jwk_client.get_signing_key_from_jwt, token)
            claims = await asyncio.to_thread(
                jwt.decode,
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._settings.entra_agent_audience,
                issuer=self._settings.entra_issuer,
            )
        except jwt.ExpiredSignatureError:
            return EntraVerificationResult(
                status="expired", backend="entra", reason="exp_in_past"
            )
        except jwt.InvalidTokenError as exc:
            return EntraVerificationResult(
                status="invalid", backend="entra", reason=str(exc)
            )
        except (httpx.HTTPError, Exception) as exc:  # JWKS fetch / unexpected
            _log.warning("entra.verify_failed", error=str(exc))
            return EntraVerificationResult(
                status="unavailable",
                backend="entra",
                reason=f"backend_error:{type(exc).__name__}",
            )

        # Resolve the caller's canonical agent id. Preference order:
        #   1. an explicit custom "agent_id" claim (if a claims-mapping policy
        #      was configured on the app registration), then
        #   2. the app id (azp / appid) mapped back through the per-agent creds,
        #   3. raw sub / oid as a last resort.
        app_id = claims.get("azp") or claims.get("appid")
        verified_agent = (
            claims.get("agent_id")
            or self._client_id_to_agent().get(app_id or "")
            or claims.get("sub")
            or claims.get("oid")
        )
        if verified_agent != claimed_agent_id:
            return EntraVerificationResult(
                status="invalid",
                backend="entra",
                reason="claimed_agent_id_mismatch",
                verified_agent_id=verified_agent,
                raw_claims=claims,
            )
        return EntraVerificationResult(
            status="valid",
            verified_agent_id=verified_agent,
            issuer=claims.get("iss"),
            audience=claims.get("aud"),
            jti=claims.get("jti"),
            expires_at_unix=claims.get("exp"),
            backend="entra",
            raw_claims=claims,
        )

    # ------ dev mock: HMAC-signed JWT-like token ------------------------
    def _dev_mock_secret(self) -> bytes:
        return (self._settings.aegis_jwt_secret or "dev-mock").encode("utf-8")

    def _verify_dev_mock(self, claimed_agent_id: str, token: str) -> EntraVerificationResult:
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
            signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
            expected_sig = hmac.new(
                self._dev_mock_secret(), signing_input, hashlib.sha256
            ).digest()
            actual_sig = _b64url_decode(signature_b64)
            if not hmac.compare_digest(expected_sig, actual_sig):
                return EntraVerificationResult(
                    status="invalid", backend="dev_mock", reason="bad_signature"
                )
            claims = json.loads(_b64url_decode(payload_b64))
        except (ValueError, json.JSONDecodeError) as exc:
            return EntraVerificationResult(
                status="invalid", backend="dev_mock", reason=f"malformed:{exc}"
            )

        now = int(time.time())
        if claims.get("exp", 0) < now:
            return EntraVerificationResult(
                status="expired", backend="dev_mock", reason="exp_in_past"
            )

        verified_agent = claims.get("agent_id") or claims.get("sub")
        if verified_agent != claimed_agent_id:
            return EntraVerificationResult(
                status="invalid",
                backend="dev_mock",
                reason="claimed_agent_id_mismatch",
                verified_agent_id=verified_agent,
                raw_claims=claims,
            )
        return EntraVerificationResult(
            status="valid",
            verified_agent_id=verified_agent,
            issuer=claims.get("iss"),
            audience=claims.get("aud"),
            jti=claims.get("jti"),
            expires_at_unix=claims.get("exp"),
            backend="dev_mock",
            raw_claims=claims,
        )

    def mint_dev_token(
        self,
        *,
        agent_id: str,
        role: str = "worker",
        ttl_seconds: int = 600,
    ) -> str:
        """Mint a dev-mock token for the victim swarm to present.

        This is ONLY available in dev-mock mode. Production agents obtain
        their tokens from Entra Agent ID directly.
        """

        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT", "kid": "dev-mock-1"}
        claims = {
            "iss": self._settings.entra_issuer or "https://aegis-dev/issuer",
            "aud": self._settings.entra_agent_audience,
            "sub": agent_id,
            "agent_id": agent_id,
            "role": role,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": hashlib.sha1(
                f"{agent_id}|{now}|{role}|{uuid.uuid4()}".encode()
            ).hexdigest(),
        }
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(self._dev_mock_secret(), signing_input, hashlib.sha256).digest()
        return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"

    # ------ replay window ----------------------------------------------
    async def _record_jti(self, jti: str) -> bool:
        async with self._lock:
            now = int(time.time())
            # prune
            cutoff = now - self._replay_window
            while self._seen_jtis and next(iter(self._seen_jtis.values())) < cutoff:
                self._seen_jtis.popitem(last=False)
            if jti in self._seen_jtis:
                return False
            self._seen_jtis[jti] = now
            return True


def _b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return urlsafe_b64decode(data + pad)


class EntraTokenIssuer:
    """Acquires REAL Entra-signed tokens for victim agents.

    One Azure AD app registration per agent; each agent authenticates via the
    OAuth2 client-credentials flow and presents the resulting RS256 token on
    its inter-agent messages. MSAL caches each app's token in-process and
    refreshes it automatically near expiry, so `token_for` is a fast lookup
    after the first call. This is the production counterpart to the sensor's
    `mint_dev_token`; the two are mutually exclusive and selected together by
    `Settings.has_entra_live`.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._apps: dict[str, Any] = {}

    @property
    def available(self) -> bool:
        return self._settings.has_entra_live

    def _authority(self) -> str:
        tenant = self._settings.entra_tenant_id or self._settings.azure_tenant_id
        return f"https://login.microsoftonline.com/{tenant}"

    def _app_for(self, agent_id: str) -> Any | None:
        if agent_id in self._apps:
            return self._apps[agent_id]
        creds = self._settings.entra_agent_credential_map().get(agent_id)
        if not creds:
            return None
        import msal

        app = msal.ConfidentialClientApplication(
            client_id=creds["client_id"],
            authority=self._authority(),
            client_credential=creds["client_secret"],
        )
        self._apps[agent_id] = app
        return app

    def token_for(self, agent_id: str, role: str = "worker") -> str | None:
        app = self._app_for(agent_id)
        if app is None:
            _log.warning("entra.no_app_registration", agent_id=agent_id)
            return None
        scope = f"{self._settings.entra_agent_audience}/.default"
        try:
            result = app.acquire_token_for_client(scopes=[scope])
        except Exception as exc:  # network / config error - never crash the swarm
            _log.warning("entra.token_acquire_error", agent_id=agent_id, error=str(exc))
            return None
        token = result.get("access_token") if isinstance(result, dict) else None
        if not token:
            _log.warning(
                "entra.token_acquire_failed",
                agent_id=agent_id,
                error=str((result or {}).get("error_description", "unknown"))[:200],
            )
            return None
        return token


_GLOBAL: EntraAgentIdSensor | None = None
_ISSUER: EntraTokenIssuer | None = None


def get_entra_sensor() -> EntraAgentIdSensor:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = EntraAgentIdSensor()
    return _GLOBAL


def get_entra_token_issuer() -> EntraTokenIssuer:
    global _ISSUER
    if _ISSUER is None:
        _ISSUER = EntraTokenIssuer()
    return _ISSUER
