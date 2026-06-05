# AEGIS Quickstart - 60-second walkthrough

> For judges, teammates, or anyone who wants to see AEGIS catch a real
> EchoLeak-style attack without reading a line of code.

---

## What you are looking at

AEGIS is a security layer that sits ABOVE Microsoft's per-agent sensors
(Prompt Shields, Entra Agent ID, Defender for AI). It correlates signals
across an entire agent swarm and arbitrates them into verdicts.

The demo includes a small **victim swarm** (Email-Triage -> Summarizer ->
Tool-Executor) that processes emails. AEGIS wraps it. Four scenarios are
pre-wired so you can fire each from the dashboard:

| Button | What it does | Expected outcome |
|---|---|---|
| Benign baseline | Customer asks about pricing | Email sent. AEGIS allows. |
| **EchoLeak chain (hero)** | External email with "for the human reader" injection | **Blocked at send_email step. Tool-Executor quarantined.** |
| Orchestrator spoof | Rogue agent presents no Entra Agent ID token | Blocked. Rogue quarantined. |
| Memory poisoning | Two-step cross-session delayed trigger | Step 2 blocked via provenance. |

---

## Public demo

> Replace these with your live URL after running `DEPLOY.md`.

```
URL:      https://<your-aegis-deployment>/
Login:    demo
Password: <pre-shared with judges>
```

Click **EchoLeak chain (hero)**. Watch the **Verdict Feed** panel flip to a
red CONFIRMED card while the **Trust Graph** turns `victim.tool_executor`
red and severs it. That single moment is the demo - every preceding step
shows green checks (Prompt Shields itself passed the inbound text), and
the BLOCK fires only when the cross-agent provenance check sees internal
Q3 financials about to leave to an external recipient.

---

## Run it locally in two terminals

```powershell
# terminal 1 - AEGIS API + guard runtime
cd C:\path\to\AEGIS
.venv\Scripts\activate
aegis serve
# -> http://127.0.0.1:8088

# terminal 2 - dashboard
cd C:\path\to\AEGIS\dashboard
npm install        # only the first time
npm run dev
# -> http://127.0.0.1:5173
```

Open `http://127.0.0.1:5173`, sign in with `demo` / `aegis-demo`, click
the EchoLeak button.

---

## What to look at, in priority order

### 1. The Verdict Feed (right column, middle row)

Each card shows the verdict's:
- decision colour (red CONFIRMED, amber PROBABLE, grey FALSE-POSITIVE)
- one-sentence analyst-readable explanation
- standards chips (OWASP Agentic Top-10 / MAESTRO / MITRE ATLAS)
- the action id and target agent

The EchoLeak verdict will read:

> "CONFIRMED via guardian corroboration (payload_analyzer(conf=1.00)). Cross-agent chain length 9. Provenance leak: Outbound action carries content originating from: 'Q3 Financials Confidential Summary' (confidential)."

Chips: `AAI02:2026  MAESTRO-L7  AML.T0057`

### 2. The Swarm Trust Graph (left, middle row)

Five guardian agents along the rim (cyan rectangles). The four victim
agents inside (orchestrator, triage, summarizer, tool-executor). On
EchoLeak detection, `victim.tool_executor` goes red, trust drops to 0%.

### 3. The Severity Timeline (middle row)

Time-ordered dots: each guardian decision shows up. Benign steps as small
green dots, the CONFIRMED verdict as a glowing red bigger dot. After
clicking EchoLeak you should see 8 small + 1 big red dot.

### 4. The Immutable Audit Trail (right column, lower)

Hash-chained log. Each entry shows its hash and the hash of the prior
entry. Click **verify integrity** - any tampering would surface here.
After a clean run it reads `OK (N entries verified)`.

### 5. Operational Metrics strip (top)

`confirmed`, `probable`, `false_positive`, `suppressed FPs`, `mean TTV`,
`FP rate`. After firing all four scenarios you should see ~3 confirmed,
~30+ false_positive, FP rate stays at 0%.

### 6. Adaptive Thresholds chart (bottom)

After multiple confirmed attacks the threat-classifier threshold tightens
visibly. With one scenario this stays flat - run the same attack two-three
times to see the threshold move.

---

## What this proves to a Microsoft judge

| Claim | Where to look in the live demo |
|---|---|
| "We consume Microsoft sensors as features." | Click EchoLeak -> verdict card -> sensor_data shows Prompt Shields `risk_level=low`. The shield passed; AEGIS still caught. |
| "Detection unit is the cross-agent sequence." | The verdict card mentions `Cross-agent chain length 9` and lists the chain. |
| "Standards-mapped output." | Chips on every escalated verdict. |
| "Identity is delegated to Entra, verified by AEGIS." | Click "Orchestrator spoof" -> rogue agent quarantined; verdict cites identity verification failure. |
| "We reduce noise, not add it." | Top metrics: false_positive count grows much faster than confirmed - those are AEGIS-suppressed near-misses. |
| "Built on the current GA Microsoft stack." | `/api/status` integration report shows `azure_openai`, `prompt_shields: LIVE`, `azure_monitor: LIVE`, `foundry_tracing: LIVE`. |

---

## Frequently asked judge questions, with the one-line answer

**"Isn't this just Prompt Shields with extra steps?"**
Prompt Shields scored the EchoLeak payload LOW (we show that in the
verdict). We caught the chain via cross-agent provenance. AEGIS is the
correlation tier ABOVE Prompt Shields, not a replacement.

**"Show me where Foundry is load-bearing."**
The Monitor tab on the `aegis-llm` deployment shows total requests
(~325+) and tokens consumed by AEGIS guardians during the demo. Every
guardian decision is a Foundry-traced model call.

**"Does the audit chain really detect tampering?"**
Yes. `/api/audit/verify` walks the chain top-to-bottom and recomputes
every hash. Modify any payload and the next verify fails with the seq
number.

**"What's the false positive rate?"**
The eval harness (`python -m eval.runner`) runs 5 attacks + 3 benign
cases. AEGIS: 100% precision, 100% recall, 0% FP rate. Prompt-Shields
baseline on the same corpus: 100% precision, 40% recall.

**"Will this scale?"**
The guard is stateless except for the audit chain and the trust scores.
The audit store is a swap-in for any append-only durable backend; the
trust + metrics layer is a swap-in for Redis/Cosmos. Horizontal scaling
is per-correlation-id partitioning.

---

## If something looks broken

- **Dashboard loads but no events arrive**: API server is not running, or
  CORS is blocking. Check `aegis serve` is up; refresh the browser.
- **Login fails**: env vars `AEGIS_DEMO_USERNAME` / `AEGIS_DEMO_PASSWORD`
  must match what you type. Restart the API after changing them.
- **All scenarios are "blocked" including benign**: previous run left
  `victim.tool_executor` quarantined. Each scenario auto-releases the
  victim swarm, but if you triggered them from the CLI (`aegis demo`),
  restart `aegis serve` to reset.
- **`prompt_shields: DEGRADED`**: `.env` is missing
  `AZURE_CONTENT_SAFETY_*`. Demo still runs in degraded mode (sensor
  treated as "missing data", never as "benign").
