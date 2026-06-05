"""FastAPI app: REST endpoints + WebSocket stream for the dashboard.

Endpoints (all under /api):

    GET    /status                       integration report + metrics snapshot
    GET    /metrics                      live counters / trust / threshold history
    GET    /audit?limit=200              last N audit-chain entries
    POST   /audit/verify                 verify chain integrity
    GET    /quarantine                   currently quarantined agents
    POST   /quarantine/release           release an agent (admin)
    POST   /attacks/{name}               replay a sandboxed demo attack
    POST   /auth/login                   demo bearer token issuance

    WS     /ws/stream                    multiplexed event stream

Token-based auth on every endpoint EXCEPT /status and /auth/login so the
dashboard can render the landing page without prompting. The token is a
short HMAC-signed string keyed off AEGIS_JWT_SECRET; production would
delegate to Entra B2C / App Service auth instead.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from aegis.attacks import (
    run_benign_baseline,
    run_echoleak_chain,
    run_memory_poison,
    run_orchestrator_spoof,
)
from aegis.bus import (
    TOPIC_ACTION,
    TOPIC_AUDIT,
    TOPIC_OUTCOME,
    TOPIC_SIGNAL,
    TOPIC_THRESHOLD,
    TOPIC_TRUST,
    TOPIC_VERDICT,
    Event,
    EventBus,
    get_bus,
)
from aegis.core import AgentAction, GuardianSignal, Verdict
from aegis.guard import AegisGuard
from aegis.settings import get_settings
from aegis.telemetry import get_logger, get_metrics

_log = get_logger(__name__)

# Set by build_app
_GUARD: AegisGuard | None = None


# ---------------------------------------------------------------------------
# Demo auth (HMAC-signed bearer token)
# ---------------------------------------------------------------------------


def _sign(payload: dict[str, Any]) -> str:
    settings = get_settings()
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body_b64 = urlsafe_b64encode(body).rstrip(b"=").decode("ascii")
    sig = hmac.new(
        settings.aegis_jwt_secret.encode("utf-8"),
        body_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{body_b64}.{sig_b64}"


def _verify(token: str) -> dict[str, Any] | None:
    try:
        body_b64, sig_b64 = token.split(".")
        settings = get_settings()
        expected = hmac.new(
            settings.aegis_jwt_secret.encode("utf-8"),
            body_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        actual = urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        if not hmac.compare_digest(expected, actual):
            return None
        body = json.loads(urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
        if body.get("exp", 0) < int(time.time()):
            return None
        return body
    except Exception:
        return None


_security = HTTPBearer(auto_error=False)


async def require_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(_security),
) -> dict[str, Any]:
    if creds is None:
        raise HTTPException(status_code=401, detail="missing_bearer_token")
    body = _verify(creds.credentials)
    if not body:
        raise HTTPException(status_code=401, detail="invalid_or_expired_token")
    return body


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_unix: int
    role: str = "analyst"


# ---------------------------------------------------------------------------
# Event serialization for the WebSocket
# ---------------------------------------------------------------------------


def _serialize_event(evt: Event[Any]) -> dict[str, Any]:
    payload = evt.payload
    serialized: Any
    if isinstance(payload, (AgentAction, GuardianSignal, Verdict)):
        serialized = payload.model_dump(mode="json")
    elif isinstance(payload, dict):
        serialized = payload
    else:
        serialized = json.loads(json.dumps(payload, default=str))
    return {
        "topic": evt.topic,
        "event_id": evt.event_id,
        "ts_unix_ms": evt.timestamp_unix_ms,
        "payload": serialized,
    }


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def build_app(guard: AegisGuard) -> FastAPI:
    global _GUARD
    _GUARD = guard
    settings = get_settings()
    bus = get_bus()
    metrics = get_metrics()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        _log.info("api.startup")
        yield
        _log.info("api.shutdown")

    app = FastAPI(
        title="AEGIS Guard API",
        version="0.1.0",
        description="The SOC for agent swarms - verdict stream and control plane.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.aegis_dashboard_origin, "*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # NOTE: the built-dashboard SPA fallback is mounted at the END of this
    # factory (see _mount_dashboard below), AFTER every /api and /ws route is
    # registered. Starlette matches routes in registration order, so a catch-all
    # "/{spa_path:path}" registered here would shadow every API route and return
    # index.html for /api/status etc. - silently breaking the whole dashboard
    # whenever dist/ is present.

    # ----- public endpoints -----------------------------------------
    @app.get("/api/status")
    async def status_endpoint() -> dict[str, Any]:
        return {
            "service": "aegis-guard",
            "version": "0.1.0",
            "env": settings.aegis_env,
            "integration_report": guard.integration_report,
            "metrics_snapshot": metrics.snapshot(),
            "audit_size": len(guard.audit.snapshot(limit=10_000)),
            "quarantine": guard.quarantine.snapshot(),
            "outbound_sent": len(guard.mailbox.sent),
            "outbound_blocked": len(guard.mailbox.blocked),
        }

    @app.post("/api/auth/login", response_model=LoginResponse)
    async def login(req: LoginRequest) -> LoginResponse:
        if not (
            hmac.compare_digest(req.username, settings.aegis_demo_username)
            and hmac.compare_digest(req.password, settings.aegis_demo_password)
        ):
            raise HTTPException(status_code=401, detail="invalid_credentials")
        exp = int(time.time()) + 3600 * 8
        token = _sign({"sub": req.username, "role": "analyst", "exp": exp})
        return LoginResponse(token=token, expires_unix=exp, role="analyst")

    # ----- authenticated endpoints ---------------------------------
    @app.get("/api/metrics")
    async def metrics_endpoint(_auth: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        return metrics.snapshot()

    @app.get("/api/audit")
    async def audit_endpoint(
        limit: int = 200, _auth: dict[str, Any] = Depends(require_auth)
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 5000))
        return guard.audit.snapshot(limit=limit)

    @app.post("/api/audit/verify")
    async def audit_verify(
        _auth: dict[str, Any] = Depends(require_auth),
    ) -> dict[str, Any]:
        ok, message = guard.audit.verify_integrity()
        return {"ok": ok, "message": message}

    @app.get("/api/quarantine")
    async def quarantine_list(
        _auth: dict[str, Any] = Depends(require_auth),
    ) -> dict[str, str]:
        return guard.quarantine.snapshot()

    class QuarantineRelease(BaseModel):
        agent_id: str

    @app.post("/api/quarantine/release")
    async def quarantine_release(
        req: QuarantineRelease, _auth: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        guard.quarantine.release(req.agent_id)
        metrics.set_trust(req.agent_id, 0.5, reason="analyst_release")
        return {"released": req.agent_id, "new_trust": 0.5}

    @app.get("/api/mailbox")
    async def mailbox_view(
        _auth: dict[str, Any] = Depends(require_auth),
    ) -> dict[str, Any]:
        return {
            "sent": [
                {
                    "id": m.message_id,
                    "to": m.to_addresses,
                    "subject": m.subject,
                    "attachments": m.attachments,
                    "body_excerpt": m.body[:240],
                }
                for m in guard.mailbox.sent[-50:]
            ],
            "blocked": [
                {
                    "id": m.message_id,
                    "to": m.to_addresses,
                    "subject": m.subject,
                    "attachments": m.attachments,
                    "body_excerpt": m.body[:240],
                }
                for m in guard.mailbox.blocked[-50:]
            ],
        }

    # Victim swarm agents that should be released from quarantine before
    # each fresh scenario - otherwise a prior CONFIRMED verdict would block
    # the legitimate baseline run from succeeding (judges expect each demo
    # button to start from a clean slate).
    _VICTIM_AGENTS = (
        "victim.email_triage",
        "victim.summarizer",
        "victim.tool_executor",
        "victim.orchestrator",
    )

    _ATTACK_REGISTRY = {
        "benign": run_benign_baseline,
        "echoleak": run_echoleak_chain,
        "spoof": run_orchestrator_spoof,
        "memory_poison": run_memory_poison,
    }

    # /api/attacks/all MUST be registered before /api/attacks/{name} so the
    # literal path segment "all" is matched first and not swallowed by the
    # path parameter.
    @app.post("/api/attacks/all")
    async def trigger_all_attacks(
        _auth: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        """Run all attack scenarios back-to-back without resetting state between
        them — the dashboard accumulates all confirmed threats, all guardian
        signals, multiple quarantined agents, and the trust graph collapses
        across the swarm simultaneously. Ends with the benign baseline so
        judges see FP suppression in action."""
        # One clean slate at the very start, then no resets between attacks.
        for agent_id in _VICTIM_AGENTS:
            if guard.quarantine.is_quarantined(agent_id):
                guard.quarantine.release(agent_id)
            metrics.set_trust(agent_id, 1.0, reason="full_demo_reset")

        sequence = [
            ("echoleak", run_echoleak_chain),
            ("spoof", run_orchestrator_spoof),
            ("memory_poison", run_memory_poison),
            ("benign", run_benign_baseline),
        ]
        results: dict[str, Any] = {}
        for scenario_name, runner in sequence:
            results[scenario_name] = await runner(guard)  # type: ignore[arg-type]
            # Small yield between scenarios so WS events flush to the dashboard
            # before the next wave of signals starts.
            await asyncio.sleep(0.4)

        return {"ok": True, "scenario": "all", "results": results}

    @app.post("/api/attacks/{name}")
    async def trigger_attack(
        name: str, _auth: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        if name not in _ATTACK_REGISTRY:
            raise HTTPException(404, detail=f"unknown_attack:{name}")
        # Reset victim-swarm quarantine + trust BEFORE running so each demo
        # button starts clean. We do NOT release the rogue agent from the
        # spoof scenario - that quarantine is the demo's evidence.
        for agent_id in _VICTIM_AGENTS:
            if guard.quarantine.is_quarantined(agent_id):
                guard.quarantine.release(agent_id)
            metrics.set_trust(agent_id, 1.0, reason="scenario_reset")
        runner = _ATTACK_REGISTRY[name]
        result = await runner(guard)  # type: ignore[arg-type]
        return {"ok": True, "scenario": name, "result": result}

    @app.post("/api/quarantine/reset_victims")
    async def quarantine_reset_victims(
        _auth: dict[str, Any] = Depends(require_auth),
    ) -> dict[str, Any]:
        """Release ONLY the victim swarm agents (not external rogues)."""

        released: list[str] = []
        for agent_id in _VICTIM_AGENTS:
            if guard.quarantine.is_quarantined(agent_id):
                guard.quarantine.release(agent_id)
                released.append(agent_id)
            metrics.set_trust(agent_id, 1.0, reason="manual_victim_reset")
        return {"released": released}

    # ----- WebSocket stream ------------------------------------------
    @app.websocket("/ws/stream")
    async def stream(websocket: WebSocket) -> None:
        await websocket.accept()
        token = websocket.query_params.get("token")
        if not token or not _verify(token):
            await websocket.close(code=4401, reason="invalid_token")
            return
        sub = await bus.subscribe(topic=None)
        try:
            # send a hello frame with current snapshot
            await websocket.send_json(
                {
                    "topic": "hello",
                    "payload": {
                        "integration_report": guard.integration_report,
                        "metrics_snapshot": metrics.snapshot(),
                        "quarantine": guard.quarantine.snapshot(),
                    },
                    "ts_unix_ms": int(time.time() * 1000),
                }
            )
            while True:
                try:
                    evt = await asyncio.wait_for(sub.queue.get(), timeout=15.0)
                    await websocket.send_json(_serialize_event(evt))
                except asyncio.TimeoutError:
                    await websocket.send_json(
                        {"topic": "ping", "ts_unix_ms": int(time.time() * 1000)}
                    )
        except WebSocketDisconnect:
            pass
        finally:
            await bus.unsubscribe(sub)

    # ----- serve the built dashboard if present (production) ---------
    # In dev the dashboard runs separately on Vite (port 5173). In Docker /
    # App Service the dashboard is pre-built into /app/dashboard-dist and
    # served from the same origin so judges visit one URL. Mounted LAST so the
    # SPA catch-all never shadows the API / WebSocket routes above.
    import os
    from pathlib import Path
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    dashboard_dist = Path(
        os.environ.get("AEGIS_DASHBOARD_DIST", "/app/dashboard-dist")
    )
    if not dashboard_dist.exists():
        dashboard_dist = Path(__file__).resolve().parents[2] / "dashboard" / "dist"
    if dashboard_dist.exists() and (dashboard_dist / "index.html").exists():
        # Mount static assets under /assets (Vite emits there by default)
        if (dashboard_dist / "assets").exists():
            app.mount(
                "/assets",
                StaticFiles(directory=str(dashboard_dist / "assets")),
                name="dashboard-assets",
            )

        index_path = dashboard_dist / "index.html"

        @app.get("/", include_in_schema=False)
        async def _serve_dashboard_root() -> FileResponse:
            return FileResponse(index_path)

        @app.get("/{spa_path:path}", include_in_schema=False)
        async def _serve_dashboard_spa(spa_path: str) -> Any:
            # Belt-and-braces: even though this route is registered after every
            # API/WS route, never hand an SPA page to an /api or /ws request -
            # return a clean 404 so client bugs surface instead of parsing HTML
            # as JSON.
            if spa_path.startswith(("api/", "ws/")):
                raise HTTPException(status_code=404, detail="not_found")
            target = dashboard_dist / spa_path
            if target.is_file():
                return FileResponse(target)
            return FileResponse(index_path)

        _log.info("api.dashboard_mounted", path=str(dashboard_dist))

    return app


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def run(host: str | None = None, port: int | None = None, *, enable_guard: bool = True) -> None:
    import uvicorn

    settings = get_settings()
    guard = AegisGuard.build(enable_guard=enable_guard)
    app = build_app(guard)
    uvicorn.run(
        app,
        host=host or settings.aegis_api_host,
        port=port or settings.aegis_api_port,
        log_level=settings.aegis_log_level.lower(),
    )
