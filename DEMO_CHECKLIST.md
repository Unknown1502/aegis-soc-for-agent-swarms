# AEGIS — Presenter Checklist & Dry-Run Report

_Last verified: 2026-06-03 against live Azure (Azure OpenAI + Prompt Shields +
Azure Monitor + Foundry tracing all LIVE)._

## TL;DR — the project is demo-ready

Full judge path verified working end-to-end against live Azure:
status → login → trigger all 4 scenarios → metrics → audit chain → mailbox.
Offline test suite is green and hermetic (`pytest -q` → 5 passed in <1s).

---

## Pre-demo boot sequence (run in this order)

```powershell
# 1. Backend (one terminal) — boots clean, prints LIVE/DEGRADED table
.venv\Scripts\python.exe -m aegis.cli serve        # API on http://127.0.0.1:8088

# 2. Confirm integrations are LIVE before judges arrive
.venv\Scripts\python.exe -m aegis.cli status
#    Expect: model_backend=azure_openai, prompt_shields=LIVE,
#            azure_monitor=LIVE, foundry_tracing=LIVE

# 3. Dashboard (second terminal) — OR rely on the bundled dist the API serves
cd dashboard
npm run build            # rebuild AFTER any source change, then API serves it at :8088
npm run dev              # OR live-reload dev server on http://127.0.0.1:5173
```

Login: **demo / aegis-demo**.

> If you change ANY dashboard source, re-run `npm run build` AND restart
> `aegis serve` so the bundled `dist/` the API serves is fresh.

## The hero moment (Beat 2)

Click **EchoLeak chain (hero)**. Watch:
- Verdict Feed flips a red **CONFIRMED** at chain link 9 (`send_email`).
- Swarm graph quarantines `victim.tool_executor`.
- Mailbox shows the outbound email **blocked** — it never sent.
- Talking point: *"Eight individual actions each scored benign — Prompt
  Shields passed the payload. The chain is the attack. AEGIS judges the
  cross-agent sequence, not the call."*

## Numbers to quote (real, reproducible)

From `python -m eval.runner` → `eval/results/latest.md`, both layers live:

| pipeline | precision | recall | F1 | FP rate |
|---|---|---|---|---|
| **AEGIS** | 1.00 | 1.00 | 1.00 | 0.00 |
| Prompt-Shields-only | 1.00 | 0.40 | 0.57 | 0.00 |

**+0.60 recall, +0.43 F1, zero added false positives.** Mean time-to-verdict
~3–7 s end-to-end (real live-Azure guardian inference, not a mock).

---

## Fixes applied in this dry-run (what changed and why)

1. **`mean_time_to_verdict_ms` was always `0`** → now a real end-to-end
   measurement (action observed → verdict rendered). A "0 ms" metric reads as
   broken to a judge. `aegis/agents/verdict_arbiter.py`.
2. **Azure SDK log flood** drowned the CLI verdict output → noisy third-party
   loggers pinned to WARNING. `aegis/telemetry/logging.py`, `tracing.py`.
   (Set `AEGIS_LOG_LEVEL=DEBUG` to restore the firehose.)
3. **Tests hit live Azure (~5 min, network-dependent)** → `tests/conftest.py`
   forces the deterministic offline backend; suite now runs in <1 s.
4. **README results table** showed a misleading offline baseline (0.00) →
   replaced with the fair both-sides-live comparison (+0.60 recall lift).
5. **CRITICAL routing bug**: the SPA catch-all route was registered *before*
   the API routes, so with `dashboard/dist/` present every `/api/*` call
   returned `index.html` — the dashboard was fully broken against a bundled
   build (Docker / single-URL judge deploy). Moved the SPA mount to the end of
   the app factory + added an `/api`,`/ws` guard. `aegis/api/server.py`.
6. **Dashboard showed "FP rate 88.9%"** — on a SOC panel that reads as a
   catastrophe. It was actually the clean-pass rate. Relabeled to **"allow
   rate"**, derived honestly from outcome counters.
   `dashboard/src/components/MetricsPanel.tsx`.

## Open judgment calls (your decision)

- **TTV of ~3–7 s** is honest live-LLM latency. If you want a snappier number
  for inline-blocking framing, point the guardians at a faster deployment
  (e.g. a Haiku/`gpt-4o-mini`-class model) to cut it to ~1–2 s. Trade-off:
  speed vs. the "real model reasoning" story. Current setting is defensible —
  just be ready to explain it in Q&A.
- **Entra Agent ID is DEGRADED (mock)** and **Defender is disabled**. The
  spoof demo still exercises the full identity code path via the dev-mock
  signer, but if a judge asks "is Entra live?" answer honestly: the code path
  is real and JWKS-ready; per-agent app registrations weren't provisioned for
  the demo tenant.

## Failure-mode safety net

- Have a **recorded screen capture** of the full demo in case venue
  wifi/Azure quota hiccups mid-pitch.
- `pytest -q` and `aegis demo all` both run fully offline — a reliable
  fallback that needs no network if Azure is unreachable at the venue.
