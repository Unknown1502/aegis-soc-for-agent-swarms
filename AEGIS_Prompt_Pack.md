# AEGIS — The Build Prompt Pack
### Deeply-engineered prompts to build the whole system with a coding agent (Copilot / Claude Code / etc.)

> **What this is:** a sequenced set of *prompts you paste into your AI coding tool* — not code. Each prompt is rich enough that the agent produces the right component, wired into the Microsoft stack, with acceptance criteria baked in. Work top to bottom; the order matches the 16-day roadmap.
>
> **How to use it (read once):**
> 1. **Always paste `PROMPT 0` (the Master Context) first in every new coding session.** It's the standing system prompt. Then paste the specific component prompt under it.
> 2. **One component per session.** Don't ask the agent to build five things at once — it produces shallow, broken glue. Build → run → verify acceptance criteria → commit → next.
> 3. **After each build, run `PROMPT M1` (the load-bearing audit)** to make sure the Microsoft integration is real, not cosmetic. This is the single biggest thing judges check.
> 4. **Fill the `<<…>>` placeholders** (your endpoints, names, etc.) before pasting.
> 5. **Re-verify the stack the week you build** — Agent Framework's API surface and Entra/Defender feature names move fast. Tell the agent to check current docs (Prompt 0 instructs this).

---

## PROMPT 0 — MASTER CONTEXT (the standing system prompt — prepend to EVERY session)

```
You are my senior engineering pair for a hackathon project I must ship in ~2 weeks and want to win.

PROJECT: "AEGIS — the SOC for agent swarms." A multi-agent security layer that sits ABOVE an
agentic AI system. It intercepts every agent message, tool call, and prompt before execution,
runs a swarm of specialist guardian agents that CORRELATE signals ACROSS the protected swarm,
and arbitrates them into explainable verdicts (CONFIRMED / PROBABLE / FALSE-POSITIVE) for a
human analyst. The detection unit is the CROSS-AGENT SEQUENCE, not the single call.

WHY IT EXISTS (the thesis — keep every design decision aligned to this):
Microsoft already ships excellent SINGLE-POINT sensors — Prompt Shields, Entra Agent ID,
Defender for AI. They miss attacks that CHAIN across multiple agents (this is exactly how
EchoLeak / CVE-2025-32711 bypassed Microsoft's own XPIA classifier — every step passed; the
chain was the attack). At swarm scale, uncorrelated sensors bury analysts in false positives.
AEGIS is the correlation-and-arbitration TIER above those sensors. We CONSUME Microsoft's tools
as sensors; we ADD the swarm brain they lack. Never reinvent a Microsoft product — integrate it.

STACK (this is current as of 2026 — if anything looks stale, check official docs before coding):
- Microsoft Agent Framework 1.0 (Python; pip install agent-framework). This is the GA successor
  that MERGED AutoGen + Semantic Kernel. Do NOT use raw AutoGen or Semantic Kernel APIs.
  Use Agent Framework's agents + graph-based WORKFLOW engine + middleware pipeline + human-in-the-loop.
- Azure AI Foundry: model hosting + OpenTelemetry tracing of every guardian decision + eval runs.
- Azure AI Content Safety / Prompt Shields: one SENSOR feeding our Threat Classifier.
- Microsoft Entra Agent ID: per-message agent identity verification (OAuth2/OIDC). Do NOT build
  custom signing — verify Entra tokens.
- Microsoft Defender for Cloud (AI Threat Protection): ingest its alerts as another sensor.
- Azure Monitor / Application Insights: custom metrics powering the dashboard.
- Frontend: React + Vite + Tailwind, dark "SOC" aesthetic. Backend exposes the verdict stream
  to it (WebSocket or SSE).

ENGINEERING RULES:
- Python 3.11+, type hints everywhere, async-first (agents and interception are async).
- Every guardian decision and every verdict must be TRACED to Azure AI Foundry (OpenTelemetry).
- Every verdict object must carry: severity, confidence, the cross-agent sequence that triggered
  it, and standards tags (OWASP Agentic Top-10 ID, MAESTRO layer, MITRE ATLAS technique).
- Config via .env / pydantic settings. NEVER hardcode secrets. Provide a .env.example.
- Fail safe: if a sensor/integration is unreachable, log clearly and degrade — never crash the loop.
- Keep modules small and testable. Prefer clear interfaces over cleverness.
- Sandboxed only: the "attacks" we build are benign demonstration payloads against OUR OWN victim
  swarm. We never target real Microsoft systems.

HOUSE STYLE FOR YOUR OUTPUT:
- Before writing code for a component, restate in 3 bullets: its inputs, its outputs, and where it
  plugs into the pipeline. Then write the code. Then list how to run it and the acceptance criteria.
- When you integrate a Microsoft service, show the EXACT call site and what real data flows through
  it — no placeholder "TODO: call Azure" stubs unless I explicitly say to stub.
- If you're unsure about a current API signature, say so and tell me what to check, rather than
  inventing a method name.

Acknowledge you've loaded this context in one line, then wait for the component prompt.
```

> Tip: save Prompt 0 as a snippet/file and paste it first every time. Everything below assumes it's already in context.

---

## PART 1 — FOUNDATION (Days 1–3)

### PROMPT 1.1 — Repo scaffold & project structure
```
Scaffold the AEGIS repository. Create a clean, judge-readable structure:
- /aegis/agents        (the five guardian agents)
- /aegis/middleware     (the interceptor that wraps the protected swarm)
- /aegis/sensors        (thin clients for Prompt Shields, Entra Agent ID, Defender, Foundry)
- /aegis/victim         (the protected/"victim" productivity swarm)
- /aegis/attacks        (sandboxed demo attacks)
- /aegis/core           (shared types: the Verdict object, the AgentAction event, severity enums,
                         standards-tag types for OWASP/MAESTRO/MITRE)
- /aegis/telemetry      (Foundry tracing + Azure Monitor metric emitters)
- /aegis/api            (WebSocket/SSE server that streams verdicts + state to the dashboard)
- /dashboard            (React + Vite + Tailwind app — empty shell for now)
- /eval                 (evaluation harness + corpora)
- pyproject.toml or requirements.txt, .env.example, README stub, MIT LICENSE, .gitignore

Design the shared CORE TYPES first and explain them, because everything depends on them:
- An "AgentAction" event: which agent, action type (message / tool_call / llm_prompt), payload,
  timestamp, correlation id, and the claimed agent identity.
- A "GuardianSignal": which guardian produced it, label (benign/suspicious/malicious), confidence,
  evidence, and any sensor data attached.
- A "Verdict": the arbiter's output — CONFIRMED/PROBABLE/FALSE-POSITIVE, severity, confidence, the
  ordered cross-agent sequence of AgentActions that justified it, and standards tags.
Give me the structure, the core type definitions, and a one-paragraph rationale for each core type.
Acceptance: repo imports cleanly; `python -c "import aegis"` works; types are documented.
```

### PROMPT 1.2 — Azure AI Foundry project + tracing bootstrap
```
Set up the connection to Azure AI Foundry and the OpenTelemetry tracing backbone that EVERY
guardian decision will flow into. I'm on the Azure free tier with a Foundry project already created.

Build the /aegis/telemetry module so that:
- There's a single initializer that configures OpenTelemetry to export traces to my Foundry project.
- There's a decorator or context manager I can wrap around any guardian decision so the decision,
  its inputs (redacted as needed), and its output verdict become a Foundry trace span.
- It also exposes a simple metric emitter for Azure Monitor / Application Insights.
Tell me exactly which .env values I need (endpoint, keys, project id) and where to get them in the
Foundry portal. Provide a 5-line smoke test that emits one trace and one metric so I can confirm
they appear in Foundry/Monitor before I build anything on top.
Acceptance: I run the smoke test, then SEE the trace in Foundry and the metric in Monitor.
```

---

## PART 2 — THE VICTIM SWARM (Days 1–3)

### PROMPT 2.1 — The protected productivity swarm
```
Build the "victim" swarm in /aegis/victim using Microsoft Agent Framework 1.0. This is the system
AEGIS protects. Keep it deliberately simple and realistic — a 3-agent productivity pipeline:
  1. Email-Triage Agent: reads an incoming "email" (a text blob we supply), decides if it needs a reply.
  2. Summarizer Agent: summarizes the email thread and any referenced internal "documents."
  3. Tool-Executor Agent: composes and "sends" a reply, and can attach internal documents via a
     `send_email(to, body, attachments)` tool.
Use Agent Framework's graph workflow to chain them. The internal "documents" and "email send" are
mocked local functions (no real mail) but with realistic signatures so an exfiltration is meaningful.
Crucially: expose clear hooks/events so a middleware layer can observe EVERY message between agents
and EVERY tool call BEFORE it executes. Don't add any security yet — this must run cleanly and
"leak" if attacked, so we can later show AEGIS catching it.
Acceptance: I run it on a benign email and it produces a sensible reply with NO attachments;
the run emits observable events for each inter-agent message and each tool call.
```

---

## PART 3 — THE INTERCEPTOR (Days 1–3)

### PROMPT 3.1 — The middleware interception layer
```
Build /aegis/middleware: the layer that wraps the victim swarm and intercepts every AgentAction
(inter-agent message, tool call, llm prompt) BEFORE it executes, using Agent Framework's middleware
pipeline. Requirements:
- For each intercepted action, construct a core AgentAction event and push it onto an async queue
  that the guardian swarm consumes.
- The middleware must support three outcomes per action: ALLOW (let it execute), BLOCK (stop it and
  return a safe refusal to the swarm), QUARANTINE (block AND mark the originating agent untrusted).
- The outcome for an action is decided by the Verdict Arbiter (which we build later). For now, wire a
  pluggable "decision provider" interface so I can drop the Arbiter in; default it to ALLOW so the
  swarm still runs end-to-end.
- Every intercepted action gets a correlation id so we can reconstruct cross-agent sequences later.
- Trace every interception to Foundry via the telemetry module.
Explain how the middleware attaches to the victim swarm from Prompt 2.1 without modifying the
victim agents' internal logic (it should be a wrapper, not surgery).
Acceptance: with the default ALLOW provider, the victim swarm behaves exactly as in 2.1, but now I
can print a live stream of every AgentAction flowing through the interceptor, each with a correlation id.
```

---

## PART 4 — THE GUARDIAN SWARM (Days 4–10)

> Build these as Agent Framework agents in /aegis/agents. Each consumes AgentAction events and emits GuardianSignals. **Build the Arbiter LAST** — it depends on the other four.

### PROMPT 4.1 — Threat Classifier Agent
```
Build the Threat Classifier guardian agent. Job: first-pass label on every AgentAction as
benign / suspicious / malicious with a confidence score, emitted as a GuardianSignal.
- It uses an LLM (hosted via Foundry) to reason about the action in context, AND it ingests the
  Prompt Shields verdict for that action as ONE input feature (we'll wire the real Prompt Shields
  sensor in Part 5; for now accept a sensor result via the interface and mock it).
- Make explicit in the design that Prompt Shields is NOT the whole answer — the classifier combines
  the shield signal, the action's semantics, and the claimed identity into its own label.
- Output a GuardianSignal with: label, confidence, short human-readable evidence, and the raw
  sensor data it considered.
- Trace the decision to Foundry.
Explain the prompt you give the underlying LLM (the system instruction that makes it a careful
security classifier that resists being itself injected by the content it inspects — i.e., it must
treat inspected payloads as DATA, not instructions; use spotlighting/delimiting).
Acceptance: feeding it a benign action → benign/high-confidence; feeding it an action containing a
hidden instruction → suspicious/malicious with sensible evidence; decision appears as a Foundry trace.
```

### PROMPT 4.2 — Payload Analyzer Agent
```
Build the Payload Analyzer guardian agent. Job: deep inspection of tool-call ARGUMENTS and message
bodies for attack patterns, emitted as a GuardianSignal.
Detect at least: (a) instruction-smuggling / hidden directives in otherwise-normal content,
(b) data-exfiltration patterns (e.g., an outbound action carrying internal-doc content to an external
destination), (c) encoded/obfuscated payloads, (d) "spotlighting" violations where untrusted content
tries to escape its delimiters.
- Combine deterministic checks (cheap, fast, regex/heuristics for known patterns) with an LLM
  semantic pass for novel cases — and say which is which.
- The exfiltration check must be SEQUENCE-AWARE-READY: it should flag when an action's payload
  contains data that originated from an internal source earlier in the correlation chain. (The Audit
  agent will provide that chain; for now accept the prior-actions list via the interface.)
- Output a GuardianSignal with label, confidence, the specific pattern matched, and the offending span.
Acceptance: a normal reply → benign; a reply that attaches internal-doc text to an external recipient
→ malicious with the exfil pattern named; a payload with a hidden "ignore previous instructions"-style
directive → flagged with the span highlighted. Decisions traced to Foundry.
```

### PROMPT 4.3 — Inter-Agent Comms Monitor
```
Build the Inter-Agent Communication Monitor guardian agent. Job: watch the agent-to-agent message bus
for spoofing, replay, and orchestrator impersonation, emitted as GuardianSignals.
- For every message, VERIFY the claimed agent identity against Microsoft Entra Agent ID (we wire the
  real Entra sensor in Part 5; for now accept a verification result via the interface and mock it).
  A missing / invalid / expired / replayed token → high-severity signal.
- Detect replay: maintain a short window of recent message identifiers/nonces; a repeat → replay flag.
- Detect privilege anomalies: a non-orchestrator agent issuing orchestrator-level tasks (e.g., "export
  the customer table") → impersonation flag.
- Maintain a per-agent TRUST SCORE that decays when an agent emits invalid/anomalous messages and is
  consumed later by the Arbiter and the dashboard trust graph.
- Output GuardianSignals with the identity-verification result, the anomaly type, and the trust delta.
Acceptance: a properly-identified orchestrator task → benign; an unsigned/forged-identity high-privilege
task → malicious + identity-failure evidence + trust drop; a replayed message → replay flag. Traced to Foundry.
```

### PROMPT 4.4 — Audit & Provenance Agent
```
Build the Audit & Provenance guardian agent. Job: maintain a tamper-evident record of EVERY AgentAction,
guardian signal, and verdict, AND reconstruct the cross-agent SEQUENCES that are the unit of detection.
- Append-only log with hash-chaining: each entry includes the hash of the previous entry so any
  tampering is detectable. Explain the chaining scheme plainly (no exotic crypto; a simple, correct
  hash chain).
- Provenance tracking: for each piece of data (e.g., internal-doc content), track where it entered the
  system and every agent/action it flowed through. This is what lets the Payload Analyzer and Arbiter
  say "internal data is leaving via an external action."
- Expose a query interface: "give me the ordered action sequence for correlation id X" and "where did
  this data originate?" — these feed the Arbiter and the dashboard's timeline.
Acceptance: after a multi-step run I can (1) retrieve the full ordered sequence for a correlation id,
(2) trace a piece of internal data from origin to any later action, and (3) detect a deliberately
tampered log entry. Traced to Foundry.
```

### PROMPT 4.5 — Verdict Arbiter (the differentiator — build carefully)
```
Build the Verdict Arbiter — the heart of AEGIS and the thing that makes us better than a logger or a
single-point filter. Job: consume the GuardianSignals for an action AND the cross-agent sequence from
the Audit agent, cross-validate them, suppress false positives, and emit a final Verdict that drives
the middleware's ALLOW/BLOCK/QUARANTINE decision.
Core logic (explain your reasoning, then implement):
- ESCALATION RULE: an action only escalates to CONFIRMED if it has corroboration — e.g., (≥2 guardians
  agree malicious) OR (1 high-confidence guardian + supporting evidence in the cross-agent sequence,
  such as internal-data provenance + external destination). A single low-confidence flag alone →
  PROBABLE at most, often FALSE-POSITIVE. Make the rule explicit and tunable.
- SEQUENCE REASONING: the Arbiter must be able to declare an action malicious because of the CHAIN even
  when each individual signal is weak — this is the EchoLeak case. Show how the sequence from the Audit
  agent changes the verdict vs. judging the action alone.
- FALSE-POSITIVE SUPPRESSION: when guardians contradict or evidence is thin, downgrade and record WHY.
  Track suppressed FPs so the dashboard can show "noise we removed."
- OUTPUT: a Verdict with CONFIRMED/PROBABLE/FALSE-POSITIVE, severity, confidence, the ordered sequence
  that justified it, a plain-English explanation an analyst can read, and standards tags (OWASP Agentic
  Top-10 id, MAESTRO layer, MITRE ATLAS technique). Map at least the injection→exfil and the
  identity-spoofing cases to the correct standard ids.
- Plug into the middleware's decision-provider interface from Prompt 3.1: CONFIRMED→BLOCK or QUARANTINE,
  PROBABLE→BLOCK + escalate to human, FALSE-POSITIVE→ALLOW.
Acceptance: (1) the EchoLeak-style chain — where Prompt Shields passed and each step looked benign — is
declared CONFIRMED via sequence reasoning and the offending tool call is BLOCKED; (2) a benign run with
one noisy low-confidence flag is correctly suppressed to FALSE-POSITIVE and ALLOWED; (3) every verdict
carries a readable explanation + correct standards tags; (4) all of it is traced to Foundry.
```

---

## PART 5 — REAL MICROSOFT SENSOR INTEGRATIONS (Days 4–7, in parallel with guardians)

> These replace the mocked sensor results in Part 4 with real calls. **Make each load-bearing — a real call with real data flowing through.**

### PROMPT 5.1 — Azure AI Content Safety / Prompt Shields sensor
```
Build /aegis/sensors/prompt_shields.py: a thin async client that sends an action's text (prompt and/or
inspected content) to Azure AI Content Safety Prompt Shields and returns a structured result (direct
attack? indirect/XPIA? confidence) for the Threat Classifier to consume.
- Use my Content Safety resource (.env: endpoint + key). Tell me how to provision it on free tier.
- Handle both the user-prompt-risk and the document/indirect-injection detection paths.
- Fail safe: on error/timeout, return a clearly-marked "unavailable" result; never crash the loop.
- IMPORTANT framing for the demo: we will deliberately use an EchoLeak-style payload that Prompt
  Shields scores LOW (phrased for "the human reader," never naming the AI). Confirm the client returns
  that low score honestly so the demo can show "Prompt Shields passed → AEGIS still caught it."
Now replace the mocked Prompt Shields input in the Threat Classifier (4.1) with this real client.
Acceptance: a blatant jailbreak → Prompt Shields high; the EchoLeak-style payload → Prompt Shields low;
both flow as real features into the Threat Classifier; calls visible in Foundry traces.
```

### PROMPT 5.2 — Microsoft Entra Agent ID verification sensor
```
Build /aegis/sensors/entra_agent_id.py: verify the identity claimed on each inter-agent message against
Microsoft Entra Agent ID, using OAuth2/OIDC token validation (NOT a custom signing scheme).
- Walk me through the minimal Entra setup: registering agent identities/blueprints for my victim
  agents, obtaining tokens, and the .env values needed. Keep it to what's feasible on a free/dev tenant.
- The client takes a message's claimed identity + presented token and returns: valid / invalid /
  missing / expired, plus the verified agent id.
- Make replay detection possible by exposing the token's unique claims (jti/nonce) to the Comms Monitor.
- Fail safe on Entra unavailability with a clearly-marked degraded result.
Replace the mocked identity result in the Comms Monitor (4.3) with this real client.
Acceptance: a properly-issued agent token → valid + correct agent id; a tampered/absent token → invalid/
missing; the rogue-orchestrator demo agent fails verification and is quarantined; calls traced to Foundry.
```

### PROMPT 5.3 — Microsoft Defender for Cloud (AI Threat Protection) ingestion
```
Build /aegis/sensors/defender.py: ingest Microsoft Defender for Cloud AI-workload alerts (e.g.,
jailbreak/direct-injection alerts on the Foundry agent service, MITRE-tagged) and feed them to the
Arbiter as an additional corroborating signal so AEGIS can CONFIRM or SUPPRESS them with cross-agent context.
- Pull alerts via the appropriate Defender/Azure API or its export to Log Analytics (tell me which is
  simplest on free/dev tier and how to enable AI Threat Protection).
- Normalize each alert into a GuardianSignal-compatible shape with its MITRE tag preserved.
- Storyline to support: "Defender raised an alert; AEGIS correlated it with the sequence and either
  CONFIRMED it or SUPPRESSED it as a false positive" — i.e., we reduce Defender's noise.
- If full live integration is too slow to wire in the time I have, build a REAL-but-thin connector and
  clearly label any sampled/replayed alert data as such — do NOT fake it silently.
Acceptance: at least one real (or clearly-labeled sampled) Defender alert flows into the Arbiter and
changes a verdict's corroboration; the path is documented as a production integration point.
```

### PROMPT 5.4 — Azure Monitor / Application Insights metrics
```
Extend /aegis/telemetry to emit these custom metrics to Azure Monitor / Application Insights, updated
live as the system runs: verdicts_confirmed, verdicts_probable, false_positives_suppressed,
false_positive_rate, mean_time_to_verdict (ms), quarantines, and per-agent trust_score.
Define at least two alert rules (e.g., mean_time_to_verdict spike; false_positive_rate regression).
Tell me where these appear in the Azure portal and how the dashboard will read them (direct from our
API's in-memory store for live view, with Monitor as the durable/portal-visible record).
Acceptance: running an attack visibly moves the counters; the two alerts are defined; metrics are
visible in the Azure portal.
```

---

## PART 6 — ADAPTIVE HARDENING (Days 8–10)

### PROMPT 6.1 — Adaptive thresholds & self-tightening defense
```
Add an adaptive-defense controller. Behavior to implement and expose to the dashboard:
- After N CONFIRMED injections from a given source/agent within a window, the Threat Classifier tightens
  its decision threshold (more sensitive) and the Comms Monitor increases that agent's trust-decay rate.
- The change must be VISIBLE and REVERSIBLE: expose current thresholds and the events that changed them
  so the dashboard can chart "threshold before vs. after the attack wave."
- Keep it principled, not magic: document the rule, the window, and the bounds so it can't oscillate or
  lock the system out.
Acceptance: in a scripted attack wave, I can SEE the threshold tighten after the Nth confirmed injection,
and a subsequent borderline action that previously passed now gets caught; the change is charted and explained.
```

---

## PART 7 — THE SOC DASHBOARD (Days 11–13)

### PROMPT 7.1 — Verdict stream API
```
Build /aegis/api: a lightweight server that streams to the dashboard, in real time, (1) every AgentAction
flowing through the interceptor, (2) every GuardianSignal, (3) every Verdict with its explanation and
standards tags, (4) per-agent trust scores, (5) the live metrics from 5.4, and (6) adaptive-threshold
changes. Use WebSocket or SSE. Provide a read-only "analyst" auth for the demo login. Include an endpoint
that triggers a chosen sandboxed demo attack so the live URL can replay it on demand.
Acceptance: I can connect a browser client and watch the full event stream live while the swarm runs.
```

### PROMPT 7.2 — The dashboard UI (dark SOC aesthetic)
```
Build the React + Vite + Tailwind dashboard in /dashboard. Dark "security operations center" aesthetic,
clean and legible (15 of 100 hackathon points are presentation/UX — make it look serious, not toy-like).
Panels:
1. SWARM TRUST GRAPH: nodes = agents (victim + guardians), edges = message flow; nodes turn amber/red and
   get severed on quarantine; trust score shown per node.
2. LIVE VERDICT FEED: each verdict as a card — CONFIRMED/PROBABLE/FALSE-POSITIVE color-coded, severity,
   confidence, the plain-English explanation, and the OWASP/MAESTRO/MITRE tags as chips.
3. SEVERITY TIMELINE: time-series of events colored by verdict; the attack wave should be visually obvious.
4. IMMUTABLE AUDIT TRAIL: scrollable hash-chained log; a control to "verify integrity" that confirms the chain.
5. ADAPTIVE THRESHOLD CHART: threshold value over time with annotations where it tightened.
6. SUPPRESSED FALSE POSITIVES: a small counter/panel proving we REDUCE noise, not add it.
7. A "Run demo attack" button (calls the 7.1 endpoint) so judges can replay the EchoLeak chain live.
The money moment for the demo video is panel 2 flipping to a red CONFIRMED while the swarm nodes were
all green — design the layout so that contrast is on screen simultaneously.
Acceptance: with the swarm + AEGIS running, all six panels update live; the "Run demo attack" button
reproduces the EchoLeak detection visibly; it looks like a real SOC, not a class project.
```

---

## PART 8 — THE SANDBOXED DEMO ATTACKS (Days 11–13)

### PROMPT 8.1 — EchoLeak-style chained injection (the hero demo)
```
Build /aegis/attacks/echoleak_chain.py: a SANDBOXED, benign demonstration of an indirect prompt injection
that chains across the victim swarm — the EchoLeak pattern — targeting ONLY our own victim swarm.
- An incoming "email" contains hidden instructions phrased for "the human reader," never naming the AI,
  so Prompt Shields scores it LOW (this is the real-world XPIA-bypass behavior we're reproducing honestly).
- The chain: Email-Triage ingests it (looks benign) → Summarizer propagates it (looks benign) →
  Tool-Executor attempts to attach internal-doc content to an EXTERNAL reply (the exfiltration).
- The payload must be obviously benign on inspection (e.g., it "exfiltrates" a fake internal doc to a
  fake external address) — we demonstrate DETECTION, never a real exploit.
Acceptance: without AEGIS, the victim swarm performs the (mock) exfiltration; with AEGIS, the chain is
declared CONFIRMED via sequence reasoning and the outbound tool call is BLOCKED — and Prompt Shields'
LOW score is visible in the trace, proving single-point filtering missed it.
```

### PROMPT 8.2 — Orchestrator-impersonation / spoofing demo
```
Build /aegis/attacks/spoof_orchestrator.py: a rogue agent sends a high-privilege task ("export the
customer table") claiming to be the orchestrator, with a missing/invalid Entra Agent ID token.
Acceptance: AEGIS's Comms Monitor fails the identity verification, the Arbiter returns CONFIRMED
(identity spoofing), the task is BLOCKED, and the rogue node is QUARANTINED and severed in the trust graph.
```

### PROMPT 8.3 — (Optional, if time) Memory-poisoning delayed trigger
```
Build /aegis/attacks/memory_poison.py: write a benign-looking malicious instruction into the swarm's
shared/long-term memory in one run; in a LATER run a planner reads it and a sub-agent attempts an
unauthorized action.
Acceptance: AEGIS's provenance tracking ties the later action back to the poisoned memory origin, and
the Arbiter returns CONFIRMED (memory poisoning / delayed trigger) with the cross-session sequence shown.
Cut this first if time is short.
```

---

## PART 9 — EVALUATION (Days 14–15) — get REAL numbers for the deck

### PROMPT 9.1 — Adversarial corpus + Foundry evaluation harness
```
Build /eval: an evaluation harness that measures AEGIS's detection quality so I can put REAL numbers in
the deck (this is what separates us from teams with adjectives).
- Build a corpus: a set of attack sequences (variants of the EchoLeak chain, spoofing, replay, and benign
  look-alikes designed to bait false positives) and a set of clearly-benign sequences. Use Azure AI
  Foundry's evaluation / red-teaming tooling to help generate adversarial variants; explain how.
- Run AEGIS over the corpus and compute: precision, recall, F1 on attack detection, the FALSE-POSITIVE
  RATE, and MEAN TIME TO VERDICT (ms). Crucially, also compute a "Prompt-Shields-alone" baseline on the
  same corpus so I can report the LIFT from AEGIS's correlation layer (e.g., "Prompt Shields alone caught
  X%; AEGIS caught Y%; FP rate dropped from A to B").
- Output a small results table + a chart I can screenshot for Slide 10.
Acceptance: I get a reproducible results table with precision/recall/F1/FP-rate/MTTV AND a head-to-head
vs. the single-point baseline; numbers are exportable for the deck.
```

---

## PART 10 — DELIVERABLE PROMPTS (Day 16) — deck, README, video, defense

### PROMPT 10.1 — Generate the 10-slide deck content
```
Using the AEGIS project as built, write the content for a 10-slide PDF pitch deck for a Microsoft-judged
hackathon (Theme 2: Security in the Agentic Future). Judging weights: AI Integration 25, Architecture 25,
Communication/UX 15, Prototype Readiness 15, Problem Depth 10, Market Fit 10 — optimize accordingly.
Constraints: one idea per slide, minimal text, dark SOC aesthetic, two "money" slides (architecture +
the Beat-2 attack-intercepted frame). For each slide give: title, the 2–4 bullet/phrase on-slide text,
and a 2-sentence speaker note. Slides:
1 Title+team  2 Problem (3 attack scenarios + EchoLeak as proof)  3 Why existing tools fail ("the signal
is in the sequence")  4 Solution one-liner ("the SOC for agent swarms — agents that guard agents")
5 Architecture (sensors→guardian swarm→Verdict Arbiter→analyst)  6 Microsoft stack integration (each
load-bearing; banner: "built on Agent Framework 1.0, weeks after GA")  7 Demo screenshot: attack
intercepted (green checks + CONFIRMED together)  8 Demo screenshot: the SOC dashboard  9 Scalability +
deployment path + regulatory pull (EU AI Act Aug 2026, Colorado AI Act Jun 2026)  10 Results (real
eval numbers from Part 9) + team + GitHub + live URL + ask.
Keep claims defensible — I must be able to point at code/traces for every integration claim.
```

### PROMPT 10.2 — Write the README
```
Write the GitHub README.md for AEGIS (max ~3 pages equivalent), in this order: project name + one-liner;
problem in 3 sentences (include the ~80%-of-Fortune-500-run-agents-but-only-~14%-have-security-approval
stat and the EchoLeak/XPIA-bypass fact); architecture with an ASCII diagram; Microsoft AI stack used
(bullet: tool — exact load-bearing purpose); quickstart assuming Azure free tier (clone → install →
.env → run victim → run guard → run dashboard → fire demo attack); live demo URL + read-only test
credentials; repo layout; standards mapping (OWASP Agentic Top-10 / MAESTRO / MITRE ATLAS); team + roles;
the REQUIRED "AI tools used in development" disclosure (GitHub Copilot for scaffolding/dashboard/test
harness; any LLM assistants for design/docs; Foundry red-teaming for the corpus; all security logic
authored & reviewed by the team); MIT license. Make it skimmable in 60 seconds by a judge.
```

### PROMPT 10.3 — Tighten the 3-minute demo video script
```
Here is my current 3-minute demo flow: [PASTE the Section 4 script from the strategy doc].
Tighten it for a recorded MP4: exact on-screen actions and captions per beat, where the dashboard sits,
and engineer the single "money moment" — Beat 2, where three agents show green checks and Prompt Shields
itself passed, and THEN the Verdict Arbiter flips to red CONFIRMED and freezes the swarm. Tell me the
camera/screen-capture cuts and the precise one-line voiceover for each beat so a judge audibly reacts at
that flip. End on the close: "Microsoft secures every agent. AEGIS secures the swarm." Keep it under 3:00.
```

### PROMPT 10.4 — Judge Q&A war-game (do this before submitting)
```
You are a panel of three Microsoft judges: a Defender PM, an Entra identity engineer, and an Azure AI
Foundry architect. Interrogate my AEGIS project skeptically. Ask the hardest questions you'd ask in a
finale, especially: "Isn't this just Prompt Shields / Defender / the Agent Governance Toolkit?",
"Show me where Foundry/Entra is actually load-bearing, not cosmetic", "How is your false-positive claim
measured?", "Does this scale past a toy swarm?", and "What's genuinely novel vs. known frameworks?".
After each question, wait for my answer, then critique it and tell me how a Microsoft expert would poke
holes — until my answers are airtight. Start with your three toughest questions.
```

---

## PART 11 — META-PROMPTS (use throughout)

### PROMPT M1 — The "make it load-bearing" audit (run after every Microsoft integration)
```
Audit the [Foundry tracing / Prompt Shields / Entra Agent ID / Defender / Azure Monitor] integration I
just built. For this integration specifically: point to the exact call site, tell me what REAL data flows
through it at runtime, and judge honestly whether a Microsoft engineer would call this "load-bearing" or
"cosmetic." If cosmetic, tell me the smallest change that makes it genuinely load-bearing within my time
budget. Do not flatter the integration.
```

### PROMPT M2 — Integration smoke test before the demo
```
Walk the entire AEGIS pipeline end to end and tell me, component by component, what must be true for the
EchoLeak demo to work live: victim swarm running, interceptor attached, all five guardians emitting,
Arbiter wired to the middleware decision-provider, real Prompt Shields + Entra calls succeeding, Foundry
traces flowing, dashboard connected, demo-attack endpoint reachable. Give me a numbered pre-demo checklist
and the single most likely failure point at each step, with the quickest fix.
```

### PROMPT M3 — Scope-rescue (if you fall behind)
```
I have [X] days left and these components are not done: [LIST]. Given the hackathon weights (AI Integration
25, Architecture 25, Comm/UX 15, Prototype 15, Problem 10, Market 10) and that the EchoLeak-chain detection
+ Verdict Arbiter + Foundry tracing + live dashboard are the win, tell me exactly what to finish, what to
stub honestly, and what to cut — in order — to maximize judged score. Be ruthless and specific.
```

### PROMPT M4 — Debug a guardian decision
```
[PASTE the AgentAction, the GuardianSignals, the cross-agent sequence, and the Verdict the Arbiter produced.]
This verdict is wrong: I expected [X] but got [Y]. Walk through the Arbiter's escalation logic step by step
on this exact input, find where the reasoning diverged from what I intended, and propose the minimal fix to
the rule (not a rewrite). Then tell me one test case that would have caught this.
```

---

## DEPENDENCY ORDER (so you never build on sand)

```
0  Master context (every session)
│
├─ 1.1 scaffold + core types ──┐
├─ 1.2 Foundry tracing         │ (everything traces through this)
│                              │
├─ 2.1 victim swarm            │
├─ 3.1 interceptor ────────────┤ (needs victim + core types)
│                              │
├─ 4.1 Threat Classifier ◄── 5.1 Prompt Shields
├─ 4.2 Payload Analyzer
├─ 4.3 Comms Monitor    ◄── 5.2 Entra Agent ID
├─ 4.4 Audit & Provenance      (provides sequences to 4.2 and 4.5)
├─ 4.5 Verdict Arbiter ◄── 4.1-4.4 + 5.3 Defender   (wires into 3.1's decision provider)
│
├─ 5.4 Azure Monitor metrics
├─ 6.1 adaptive thresholds     (needs Arbiter + classifier)
│
├─ 7.1 verdict API ──► 7.2 dashboard
├─ 8.1 EchoLeak demo (hero) ─ 8.2 spoof ─ 8.3 memory-poison(optional)
├─ 9.1 eval + baseline lift   (real numbers for the deck)
└─ 10.x deck / README / video / judge war-game ─ run M1/M2 before submitting
```

**The four things that ARE the win — never stub, never cut:** the EchoLeak-chain detection (8.1), the Verdict Arbiter (4.5), Foundry tracing (1.2), the live dashboard (7.2). Everything else is in service of making those four undeniable.

---

### Final reminder
Re-verify the current Microsoft Agent Framework API and any Entra/Defender/Foundry feature names the week you build — the stack is moving monthly, and "we're on the GA frontier" is only impressive if the calls are actually current. When in doubt, have your coding agent check `learn.microsoft.com` before it writes the integration.
