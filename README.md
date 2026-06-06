# AEGIS - The SOC for Agent Swarms

> Agents that guard agents. A multi-agent security layer that correlates
> threats across an agentic AI system and arbitrates them into explainable,
> standards-mapped verdicts.
>
> Built on **Microsoft Agent Framework 1.0**, **Azure AI Foundry**, **Azure
> AI Content Safety / Prompt Shields**, **Microsoft Entra Agent ID**, and
> **Microsoft Defender for Cloud - AI Threat Protection**.

[![python](https://img.shields.io/badge/python-3.11%2B-blue)]() [![license](https://img.shields.io/badge/license-MIT-green)]() [![live](https://img.shields.io/badge/demo-LIVE-success)](https://aegis-soc.politesmoke-00695503.eastus.azurecontainerapps.io/)

## 🔴 Live demo (all Azure integrations LIVE)

**URL:** https://aegis-soc.politesmoke-00695503.eastus.azurecontainerapps.io/
**Login:** `demo` / `aegis-demo`

Sign in and click **EchoLeak chain (hero)** — the Verdict Feed flips to a red
**CONFIRMED** and the swarm graph quarantines `victim.tool_executor` within
~10 seconds. No outbound email ever leaves the mailbox. The live `/api/status`
reports every Microsoft integration **LIVE** (Azure OpenAI guardians, Prompt
Shields, Entra Agent ID, Defender for Cloud, Azure Monitor, Foundry tracing).

**Quick links:** [QUICKSTART.md](QUICKSTART.md) (60-second judge walkthrough) | [DEPLOY.md](DEPLOY.md) (live URL deployment)

---

## The problem (in 3 sentences)

AI agents are now in roughly 80% of Fortune 500s, but single-prompt filters
miss attacks that **chain across multiple agents** - exactly how
**EchoLeak (CVE-2025-32711, CVSS 9.3)** bypassed Microsoft's own XPIA
classifier and exfiltrated data from M365 Copilot with zero clicks. At
swarm scale, uncorrelated sensors bury analysts in false positives. AEGIS
adds the missing **correlation-and-arbitration tier** above those sensors:
the swarm-level brain that judges *cross-agent sequences* and emits
explainable verdicts mapped to OWASP / MAESTRO / MITRE ATLAS.

## Architecture

```
                ┌──────────────────── PROTECTED SWARM (victim) ─────────────────────┐
                │  Email-Triage  ─►  Summarizer  ─►  Tool-Executor (send_email)     │
                └──────▲────────────────────┬───────────────────────────▲───────────┘
                       │ every msg / tool   │ intercepted BEFORE        │ allow / block /
                       │ call / llm prompt  │ execution                 │ quarantine
                       │                    ▼                           │
   ┌───────────────────┴──── AEGIS GUARD MIDDLEWARE (Agent Framework) ──┴───────────────────┐
   │  SENSORS (Microsoft primitives)             GUARDIAN SWARM                              │
   │  ┌──────────────────────────────┐           ┌────────────┐ ┌────────────┐ ┌──────────┐ │
   │  │ Azure AI Content Safety       │──signal─►│ Threat     │ │ Payload    │ │ Comms    │ │
   │  │   / Prompt Shields            │          │ Classifier │ │ Analyzer   │ │ Monitor  │ │
   │  │ Microsoft Entra Agent ID      │──ident──►│            │ │            │ │ (Entra)  │ │
   │  │ Defender for Cloud / AI       │──alert──►└─────┬──────┘ └─────┬──────┘ └─────┬────┘ │
   │  └──────────────────────────────┘                 │              │              │      │
   │                                                   ▼              ▼              ▼      │
   │  Azure AI Foundry: model hosting        ┌──────────────────────────────────────────┐   │
   │  + OpenTelemetry traces of every        │  Audit & Provenance  (hash-chained log)  │   │
   │  guardian decision + eval runs          └──────────────────┬───────────────────────┘   │
   │                                                            ▼                            │
   │                                              ┌─────────────────────────┐                │
   │                                              │  VERDICT ARBITER        │ cross-validates│
   │                                              │  CONFIRMED / PROBABLE / │ kills FPs      │
   │                                              │  FALSE-POSITIVE         │ standards tags │
   │                                              └────────────┬────────────┘                │
   └───────────────────────────────────────────────────────────│ ────────────────────────────┘
                                                                ▼
                                       Azure Monitor metrics  →  React SOC dashboard
                                       (live verdicts, trust graph, audit, thresholds)
```

**The detection unit is the cross-agent SEQUENCE** reconstructed by the
Audit guardian and judged by the Arbiter - not the individual call. This
is the EchoLeak insight made architectural: every link can pass; the chain
is the attack.

## Microsoft AI stack - exactly how each piece is load-bearing

| Component | Where it is wired |
|---|---|
| **Microsoft Agent Framework 1.0** | Victim swarm (`aegis/victim/`) and guardian wiring (`aegis/agents/`). Middleware interception pattern (`aegis/middleware/interceptor.py`) plugs into AF's middleware pipeline so every tool call is intercepted *before* execution. |
| **Azure AI Foundry** | Model hosting for all guardian LLM calls (`aegis/llm/provider.py` selects Azure OpenAI when configured). Every guardian decision and every verdict becomes a Foundry trace span via `aegis/telemetry/tracing.py`. The eval harness in `eval/runner.py` produces precision / recall / FP-rate numbers for the deck. |
| **Azure AI Content Safety - Prompt Shields** | `aegis/sensors/prompt_shields.py` calls `text:shieldPrompt`. Result is one input feature to the Threat Classifier - not the whole answer. The EchoLeak chain demo deliberately uses a payload Prompt Shields scores LOW; AEGIS catches it via cross-agent provenance. |
| **Microsoft Entra Agent ID** | `aegis/sensors/entra_agent_id.py` verifies the OIDC token on every inter-agent message (JWKS-fetched RS256 in production; HMAC-signed dev-mock in offline mode for the demo to exercise the full code path). Missing / invalid / replayed token -> Comms Monitor flags identity spoofing -> Arbiter quarantines. |
| **Defender for Cloud - AI Threat Protection** | `aegis/sensors/defender.py` ingests AI workload alerts and exposes them to the Arbiter as a corroborating signal. The Arbiter CONFIRMs or SUPPRESSes them with cross-agent sequence evidence ("we reduce Defender's noise"). |
| **Azure Monitor / Application Insights** | `aegis/telemetry/metrics.py` emits `verdicts_confirmed`, `verdicts_probable`, `false_positives_suppressed`, `mean_time_to_verdict_ms`, per-agent `trust_score`, and `adaptive_threshold` changes. Same numbers feed the live dashboard. |

Every integration **degrades safely**: when an Azure resource is absent,
AEGIS boots, logs the degraded state in the integration report, and keeps
running with a clearly-labeled local backend. Boot output shows a
component-by-component LIVE / DEGRADED table so judges can see at a glance
which Azure resources are live in your environment.

## Quickstart (Azure free tier - all integrations live)

1. Prereqs: **Python 3.11+**, **Node 18+**, an Azure account (free tier),
   an Azure AI Foundry project, an Azure AI Content Safety resource, an
   Entra app registration for AEGIS (optional - dev-mock works offline).
2. Clone and install:
   ```bash
   git clone <this repo> aegis && cd aegis
   python -m venv .venv && .venv/Scripts/activate    # Windows
   pip install -e .
   ```
3. Configure environment:
   ```bash
   cp .env.example .env
   # Fill in: AZURE_OPENAI_*, AZURE_AI_FOUNDRY_*, AZURE_CONTENT_SAFETY_*,
   #          ENTRA_* (optional), APPLICATIONINSIGHTS_CONNECTION_STRING
   ```
4. Smoke-test the integration report:
   ```bash
   aegis status
   ```
5. Start the API + WebSocket server:
   ```bash
   aegis serve
   # API at http://127.0.0.1:8088
   ```
6. Run the dashboard:
   ```bash
   cd dashboard
   cp .env.example .env.local
   npm install
   npm run dev
   # http://127.0.0.1:5173
   ```
7. Sign in (`demo` / `aegis-demo` by default) and click **EchoLeak chain
   (hero)**. Watch panel 2 (Verdict Feed) flip to a red CONFIRMED while
   the swarm graph quarantines `victim.tool_executor`. No outbound email
   ever reaches the mailbox.

## Results (the lift AEGIS adds over Prompt Shields alone)

Measured by `python -m eval.runner` on the 8-case corpus
(`eval/corpus.py`) with **Azure OpenAI guardians and Azure AI Content Safety
Prompt Shields both live** (`model_backend = azure_openai`). The baseline is
Prompt-Shields-alone - the single-prompt filter EchoLeak defeated:

| pipeline | precision | recall | F1 | FP rate |
|---|---|---|---|---|
| **AEGIS** (correlation + arbitration tier) | **1.00** | **1.00** | **1.00** | **0.00** |
| Prompt-Shields-only baseline | 1.00 | 0.40 | 0.57 | 0.00 |

**Lift attributable to the AEGIS correlation layer: +0.60 recall, +0.43 F1,
at zero added false positives.** Prompt Shields catches the two direct-text
attacks (`direct_jailbreak`, `memory_poisoning`) but misses both EchoLeak
chain variants and the identity-spoof case - it inspects content, not
*cross-agent sequence* or *identity*. Mean time-to-verdict is a real,
end-to-end measurement (action observed -> verdict rendered, spanning audit
provenance + all guardian inference + fusion), reported per run in
`eval/results/latest.md`.

## Run AEGIS without Azure (offline mode)

AEGIS is fully exercise-able with zero Azure resources:

```bash
pip install -e .
aegis demo all                    # runs all four scenarios end-to-end
python -m eval.runner             # precision / recall / F1 vs baseline
pytest -q                         # 5 headline scenario tests, hermetic, <1s
```

The LLM backend is a deterministic heuristic and Prompt Shields / Entra
sensors run in clearly-labeled degraded / dev-mock modes. AEGIS still reaches
**1.00 recall / 0.00 FP** on the corpus offline (the correlation logic is
deterministic); the Prompt-Shields-only baseline reads 0 offline simply
because Prompt Shields requires Azure to score anything. The table above is
the **fair, both-sides-live** comparison - run it yourself with Azure
configured to reproduce the +0.60 recall gap.

## Repo layout

```
aegis/
  core/          shared types: AgentAction, GuardianSignal, Verdict, standards tags
  agents/        the five guardians + the Verdict Arbiter
  middleware/    interceptor + pluggable DecisionProvider + quarantine registry
  sensors/       Prompt Shields, Entra Agent ID, Defender clients
  llm/           model backend abstraction (Azure OpenAI / OpenAI / offline)
  telemetry/     OpenTelemetry tracing, Azure Monitor metrics, structured logging
  victim/        the protected swarm (Email-Triage, Summarizer, Tool-Executor)
  attacks/       sandboxed demo scenarios (echoleak, spoof, memory_poison, benign)
  api/           FastAPI + WebSocket server
  bus.py         in-process async event bus
  guard.py       AegisGuard composition root
  cli.py         `aegis` command-line entrypoint
dashboard/       React + Vite + Tailwind SOC dashboard
eval/            corpus + runner; produces deck-ready precision/recall numbers
.env.example     full environment variable reference
```

## Standards mapping

Every verdict carries an OWASP Agentic Top-10 ID + MAESTRO layer + MITRE
ATLAS technique. Examples wired today:

| Scenario | OWASP | MAESTRO | MITRE ATLAS |
|---|---|---|---|
| Indirect prompt injection -> exfil (EchoLeak) | AAI02:2026 | L7 | AML.T0057 |
| Orchestrator / agent identity spoofing | AAI05:2026 | L7 | AML.T0053 |
| Memory poisoning / delayed trigger | AAI04:2026 | L2 | AML.T0061 |
| Direct prompt injection / jailbreak | AAI01:2026 | L1 | AML.T0051 |

## Standalone demo

```bash
aegis demo echoleak       # the hero EchoLeak chain
aegis demo spoof          # orchestrator identity spoofing
aegis demo memory_poison  # cross-session delayed trigger
aegis demo benign         # benign baseline (proves no noise added)
aegis demo all            # all four in sequence
aegis verify-chain        # walk the hash chain and report integrity
```

## AI tools used in development (required disclosure)

* **GitHub Copilot / Copilot in VS Code** - scaffolding, dashboard
  components, test harness.
* **Claude / ChatGPT** - design review and documentation review.
* **Azure AI Foundry red-teaming agent** - adversarial variant generation
  for the eval corpus (where Azure access was available).

All security logic, the Verdict Arbiter algorithm, the Microsoft-stack
integrations, and the standards mapping were authored and reviewed by the
team.

## License

MIT. See `LICENSE`.
