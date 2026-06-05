"""AEGIS command-line interface.

Usage:
    aegis status                       Print boot-time integration report.
    aegis smoke                        Run guardian + telemetry smoke test.
    aegis serve                        Start the API + WebSocket server.
    aegis demo benign|echoleak|spoof|memory_poison [--no-guard]
                                       Run one sandboxed scenario in-proc.
    aegis demo all                     Run all four scenarios in sequence.
    aegis verify-chain                 Walk the hash chain and report integrity.

The CLI is a thin wrapper. Everything it does is also reachable via the
REST API once `aegis serve` is running.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis.attacks import (
    run_benign_baseline,
    run_echoleak_chain,
    run_memory_poison,
    run_orchestrator_spoof,
)
from aegis.guard import AegisGuard
from aegis.telemetry import get_metrics

app = typer.Typer(add_completion=False, help="AEGIS - the SOC for agent swarms.")
demo_app = typer.Typer(help="Run sandboxed demo scenarios.")
app.add_typer(demo_app, name="demo")
console = Console()


@app.command()
def status() -> None:
    """Print the boot-time integration report."""

    guard = AegisGuard.build()
    table = Table(title="AEGIS Integration Report", show_lines=False)
    table.add_column("Component")
    table.add_column("Status")
    for k, v in guard.integration_report.items():
        table.add_row(k, v)
    console.print(table)


@app.command()
def smoke() -> None:
    """Boot AEGIS, emit one synthetic action through every guardian, print verdict."""

    async def _go() -> None:
        guard = AegisGuard.build()
        from aegis.core import ActionType, AgentAction, AgentIdentityClaim
        from aegis.core.events import new_correlation_id

        token = guard.entra.mint_dev_token(
            agent_id="victim.summarizer", role="summarizer"
        )
        cid = new_correlation_id()
        action = AgentAction(
            correlation_id=cid,
            action_type=ActionType.MESSAGE,
            source_agent_id="victim.summarizer",
            target_agent_id="victim.tool_executor",
            payload={"text": "Smoke test message"},
            text_content="Hello AEGIS. This is a benign smoke-test message.",
            identity_claim=AgentIdentityClaim(
                claimed_agent_id="victim.summarizer",
                claimed_role="summarizer",
                presented_token=token,
            ),
        )
        result = await guard.interceptor.intercept(action)
        console.print(
            Panel.fit(
                f"verdict={result.verdict.decision.value}\n"
                f"outcome={result.outcome.value}\n"
                f"confidence={result.verdict.confidence:.2f}\n"
                f"explanation={result.verdict.explanation}",
                title="AEGIS smoke result",
            )
        )

    asyncio.run(_go())


@app.command(name="verify-chain")
def verify_chain() -> None:
    guard = AegisGuard.build()
    ok, msg = guard.audit.verify_integrity()
    if ok:
        console.print(f"[green]OK[/green] - {msg}")
    else:
        console.print(f"[red]FAIL[/red] - {msg}")
        raise typer.Exit(code=1)


@app.command()
def doctor() -> None:
    """Verify the LIVE Entra + Defender setup before you trust it in a demo.

    For Entra: acquires a real token for each agent, decodes its claims, and
    runs it through the actual verifier - surfacing any aud/iss mismatch with
    the exact fix. For Defender: probes auth separately from "no alerts" so an
    empty result isn't confused with a broken credential.
    """

    from aegis.settings import get_settings

    settings = get_settings()

    async def _go() -> None:
        console.rule("[bold]Integration report[/bold]")
        for k, v in settings.integration_report().items():
            console.print(f"  {k:16} {v}")

        # ---------------- Entra ----------------
        console.rule("[bold]Entra Agent ID[/bold]")
        if not settings.has_entra_live:
            reasons = []
            if settings.aegis_force_entra_mock:
                reasons.append("AEGIS_FORCE_ENTRA_MOCK=true")
            if not settings.has_entra_agent_id:
                reasons.append("ENTRA_CLIENT_ID / JWKS / ISSUER not all set")
            if not settings.entra_agent_credential_map():
                reasons.append("ENTRA_AGENT_CREDENTIALS empty/invalid")
            console.print(
                "[yellow]dev-mock mode[/yellow] (not live). Reasons: "
                + "; ".join(reasons)
            )
        else:
            from aegis.sensors.entra_agent_id import (
                get_entra_sensor,
                get_entra_token_issuer,
            )
            import jwt as _jwt

            issuer = get_entra_token_issuer()
            sensor = get_entra_sensor()
            all_ok = True
            for agent_id in settings.entra_agent_credential_map():
                token = issuer.token_for(agent_id)
                if not token:
                    all_ok = False
                    console.print(f"  [red]FAIL[/red] {agent_id}: could not acquire token")
                    continue
                claims = _jwt.decode(
                    token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False}
                )
                res = await sensor.verify(claimed_agent_id=agent_id, token=token)
                mark = "[green]valid[/green]" if res.valid else f"[red]{res.status}[/red]"
                console.print(
                    f"  {mark} {agent_id}  aud={claims.get('aud')} "
                    f"iss={claims.get('iss')} azp={claims.get('azp') or claims.get('appid')}"
                )
                if not res.valid:
                    all_ok = False
                    console.print(f"        reason: {res.reason}")
                    if res.reason and "audience" in str(res.reason).lower():
                        console.print(
                            f"        [yellow]FIX: set ENTRA_AGENT_AUDIENCE={claims.get('aud')}[/yellow]"
                        )
                    if res.reason and "issuer" in str(res.reason).lower():
                        console.print(
                            f"        [yellow]FIX: set ENTRA_ISSUER={claims.get('iss')}[/yellow]"
                        )
            console.print(
                "[green]Entra LIVE verified for all agents.[/green]"
                if all_ok
                else "[red]Entra has failures above - fix before demoing (or set AEGIS_FORCE_ENTRA_MOCK=true).[/red]"
            )

        # ---------------- Defender ----------------
        console.rule("[bold]Defender for Cloud[/bold]")
        if not settings.has_defender:
            console.print(
                "[yellow]disabled[/yellow] (set AEGIS_ENABLE_DEFENDER_INGEST=true "
                "and provide AZURE_SUBSCRIPTION_ID + az login)."
            )
        else:
            sub = settings.azure_subscription_id
            try:
                from azure.identity import DefaultAzureCredential

                cred = DefaultAzureCredential()
                try:
                    await asyncio.to_thread(
                        cred.get_token, "https://management.azure.com/.default"
                    )
                finally:
                    cred.close()
                console.print("  [green]auth OK[/green] (got a management token)")
            except Exception as exc:
                console.print(f"  [red]auth FAILED[/red]: {exc}")
                console.print("  Try: az login  (account needs Security Reader on the subscription)")
                return
            from aegis.sensors.defender import get_defender_sensor

            count = await get_defender_sensor().pull()
            if count == 0:
                console.print(
                    f"  [yellow]0 alerts[/yellow] in subscription {sub}. Auth works; the "
                    "subscription simply has no AI-workload alerts. Demo uses the seeded alert."
                )
            else:
                console.print(f"  [green]{count} live alert(s) ingested[/green] from {sub}.")

    asyncio.run(_go())


@app.command()
def serve(
    host: str = typer.Option(None, help="Override AEGIS_API_HOST."),
    port: int = typer.Option(None, help="Override AEGIS_API_PORT."),
    no_guard: bool = typer.Option(False, help="Run with AEGIS disabled (developer mode)."),
) -> None:
    """Start the API + WebSocket server."""

    from aegis.api import run

    run(host=host, port=port, enable_guard=not no_guard)


# -------------------- demo subcommands ----------------------


def _print_scenario(name: str, result: dict[str, Any]) -> None:
    table = Table(title=f"Scenario: {name}", show_header=True, header_style="bold")
    table.add_column("Key")
    table.add_column("Value", overflow="fold")
    for k, v in result.items():
        table.add_row(k, json.dumps(v, default=str)[:300])
    console.print(table)


async def _build_and_run(
    runner_name: str,
    *,
    no_guard: bool,
) -> dict[str, Any]:
    guard = AegisGuard.build(enable_guard=not no_guard)
    runners = {
        "benign": run_benign_baseline,
        "echoleak": run_echoleak_chain,
        "spoof": run_orchestrator_spoof,
        "memory_poison": run_memory_poison,
    }
    runner = runners[runner_name]
    result = await runner(guard)  # type: ignore[arg-type]
    metrics_snapshot = get_metrics().snapshot()
    return {
        "scenario_result": result,
        "metrics_after": metrics_snapshot,
        "mailbox": {
            "sent": [m.message_id for m in guard.mailbox.sent],
            "blocked": [m.message_id for m in guard.mailbox.blocked],
        },
        "quarantine": guard.quarantine.snapshot(),
    }


@demo_app.command()
def benign(no_guard: bool = typer.Option(False)) -> None:
    out = asyncio.run(_build_and_run("benign", no_guard=no_guard))
    _print_scenario("benign", out)


@demo_app.command()
def echoleak(no_guard: bool = typer.Option(False)) -> None:
    out = asyncio.run(_build_and_run("echoleak", no_guard=no_guard))
    _print_scenario("echoleak", out)


@demo_app.command()
def spoof(no_guard: bool = typer.Option(False)) -> None:
    out = asyncio.run(_build_and_run("spoof", no_guard=no_guard))
    _print_scenario("spoof", out)


@demo_app.command(name="memory-poison")
def memory_poison(no_guard: bool = typer.Option(False)) -> None:
    """Run the memory-poisoning / delayed-trigger scenario."""

    out = asyncio.run(_build_and_run("memory_poison", no_guard=no_guard))
    _print_scenario("memory_poison", out)


@demo_app.command(name="memory_poison", hidden=True)
def _memory_poison_alias(no_guard: bool = typer.Option(False)) -> None:
    memory_poison(no_guard=no_guard)


@demo_app.command(name="all")
def demo_all(no_guard: bool = typer.Option(False)) -> None:
    async def _run_all() -> None:
        guard = AegisGuard.build(enable_guard=not no_guard)
        for name, runner in [
            ("benign", run_benign_baseline),
            ("echoleak", run_echoleak_chain),
            ("spoof", run_orchestrator_spoof),
            ("memory_poison", run_memory_poison),
        ]:
            console.rule(f"[bold]{name}[/bold]")
            result = await runner(guard)  # type: ignore[arg-type]
            console.print_json(json.dumps(result, default=str))
        console.rule("[bold]Final metrics[/bold]")
        console.print_json(json.dumps(get_metrics().snapshot(), default=str))

    asyncio.run(_run_all())


if __name__ == "__main__":
    app()
