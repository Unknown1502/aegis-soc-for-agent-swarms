
# AEGIS — Winning Strategy Bible
### Microsoft Build AI Hackathon (HackerEarth, India) · Theme 2: Security in the Agentic Future

> **Working name:** **AEGIS** — *Agentic Execution Guard & Inspection Swarm.*
> Alt name if you want the "smart" one that encodes the differentiator: **QUORUM** (a quorum of guardian agents must reach consensus before a verdict escalates).
> **The pitch in one breath:** *"Prompt Shields secures one prompt. Entra Agent ID secures one identity. Nobody secures the swarm. AEGIS is the SOC for agent swarms — agents that guard agents."*

---

## 0. THE ONE BIG PIVOT — read this before anything else

Your instinct (Theme 2, reuse SIFT-REFLECT's 5-agent architecture) is **correct**. But the *target* of the system has to change, or you lose. Here is why, and what to do.

### Why the obvious framing loses *this specific* hackathon
This is a **Microsoft-judged** event. The judges build the exact products that already solve the naive version of your idea:

| You might pitch… | Microsoft already ships (GA, 2025–2026) |
|---|---|
| "We detect prompt injection in tool calls" | **Azure AI Content Safety – Prompt Shields** (direct + indirect/XPIA), **Spotlighting**, **Task Adherence** |
| "We verify agent identity / stop spoofing" | **Microsoft Entra Agent ID** (agent identity blueprints, FIC, Conditional Access) — GA |
| "We surface runtime threat alerts to a SOC" | **Microsoft Defender for Cloud → AI Threat Protection**, integrated into Foundry, MITRE-mapped |
| "We enforce per-agent guardrails / OWASP Top 10" | **Microsoft Agent Governance Toolkit** (open-source, MIT, April 2026 — first to cover all 10 OWASP agentic risks with sub-ms enforcement) |

If your project competes with these, the judge's silent verdict is *"reinvented our stack, worse."* That is fatal on the two 25-point criteria (AI Integration, Architecture).

### The winning reframe: be the brain, not another sensor
Every Microsoft tool and every startup (Straiker, Sysdig, AccuKnox, Mimecast) operates at the **single-agent / single-prompt / single-tool-call** level. The gap that **OWASP's Multi-Agent Threat Modeling Guide, CSA MAESTRO, and arXiv researchers all explicitly name as unsolved** is:

> **There is no correlation-and-arbitration layer for multi-agent swarms.**
> When 20–500 agents each emit Prompt Shield hits, Defender alerts, Entra anomalies and tool logs, you get a *flood of disconnected, low-context, high-false-positive signals.* No tool can decide whether a sequence of individually-benign actions across multiple agents is a coordinated attack. **EchoLeak proved exactly this:** every individual step passed Microsoft's own XPIA filter — the *chain* was the attack.

**That correlation brain is what SIFT-REFLECT already was** (Triage → Forensic → Network → Timeline, arbitrated by the Skeptic). You are not retargeting from "endpoint IR" to "a worse Prompt Shields." You are retargeting to **"the SOC tier that sits above Microsoft's sensors and makes them coherent."**

So AEGIS:
1. **Consumes** Prompt Shields, Defender for AI, and Entra Agent ID as *sensors* (this flatters the stack — judges feel validated).
2. **Adds the missing layer**: a swarm of specialist security agents that correlate behavior *across* the protected swarm.
3. **Arbitrates** with a Verdict Arbiter (the Skeptic, reborn) that cross-validates alerts to kill false positives and emits explainable, MITRE-ATLAS-mapped verdicts to a human analyst.

This single decision flips every judging criterion in your favor and makes you *hireable* (you demonstrably understand Microsoft's security portfolio — see §7).

### Hidden bonus: you secretly win Theme 5 too
AEGIS *is itself* a sophisticated agent swarm (planners, retrievers, executors, validators). You submit under **Theme 2 (Security)** but visibly demonstrate **Theme 5 (Agent Swarms)** mastery — doubling your evidence on the two 25-point engineering criteria without diluting focus.

### Three stack corrections your prompt got wrong (these matter for credibility)
1. **AutoGen + Semantic Kernel no longer exist as separate things to "combine."** They merged into **Microsoft Agent Framework 1.0** (GA April 3, 2026); both are now maintenance-only. *Build on Agent Framework.* Saying "we used AutoGen" in June 2026 signals you're a year behind. Saying "we built on Agent Framework 1.0, six weeks after GA" signals you're on the frontier.
2. **Do not build a homebrew "signed message envelope" crypto scheme.** Microsoft already solved agent identity with **Entra Agent ID** (OAuth2/OIDC, federated identity credentials, no static secrets on the agent). *Integrate it.* Reinventing it competes with — and looks naïve next to — a Microsoft GA product.
3. **Don't claim to "detect prompt injection."** Claim to **correlate and arbitrate** injection *signals across a swarm* and catch the **chained/emergent** attacks that single-prompt filters miss (the EchoLeak failure mode).

---

## SECTION 1 — REFINED PROBLEM STATEMENT

### (a) What "Security in the Agentic Future" concretely means — 3 attack scenarios judges instantly recognize

**Scenario 1 — Indirect prompt injection that chains across a productivity swarm (the EchoLeak pattern).**
A malicious email lands in an inbox monitored by an Email-Triage agent. Hidden instructions ("for the human reader," never naming the AI) survive the prompt filter, propagate when a Summarizer agent ingests the thread, and finally cause a Tool-Executor agent to attach internal documents to an outbound reply. *Each step is individually benign and passes single-point filtering.* This is precisely how **EchoLeak (CVE-2025-32711, CVSS 9.3)** exfiltrated data from M365 Copilot with **zero clicks**, by **bypassing Microsoft's own XPIA classifier** — the first documented zero-click prompt-injection weaponized for real data exfiltration in production.

**Scenario 2 — Agent-to-agent identity spoofing / orchestrator impersonation.**
In an A2A (agent-to-agent) topology, a compromised or rogue agent forges an "agent card" or replays a delegation token to impersonate the **orchestrator**, then issues high-privilege tasks to worker agents ("export the customer table"). Researchers applying MAESTRO to Google's A2A protocol have documented exactly these failures: weak message validation, identity spoofing, agent-card forgery, and task replay.

**Scenario 3 — Memory poisoning → delayed-trigger rogue sub-agent.**
An attacker writes a benign-looking but malicious instruction into a shared/long-term memory store. It persists silently across sessions; days later a planner agent reads it and a sub-agent executes an unauthorized action (e.g., a destructive tool call). This "delayed-trigger" / cascading-failure class is a top entry in the **OWASP Top 10 for Agentic Applications (2026)** and is invisible to anything that only inspects the *current* prompt.

> Pick **Scenario 1 as your hero demo** (instantly legible to Microsoft judges), keep 2 and 3 as the "and it also catches…" breadth in the deck.

### (b) Why existing tools fail — the fundamental gap
- **SIEM / WAF / EDR** assume a *code* payload, a network signature, or a file on disk. Agentic attacks are **pure natural-language**, execute **by design** (the agent is "behaving helpfully"), leave **no malware signature**, and live **inside the trust boundary**. EchoLeak explicitly defeated antivirus/firewall/static-scanning assumptions.
- **Single-point AI filters (Prompt Shields, XPIA)** inspect *one* prompt or *one* tool call in isolation. They cannot see that step-1 (read email) + step-2 (summarize) + step-3 (send reply) form an exfiltration *chain*. **The signal is in the sequence, not the request** — a point the runtime-security industry now states outright.
- **Per-agent runtime tools** scale to a single workload, not to the **emergent, cross-agent** behavior of a swarm. OWASP's own MAS guide notes the LLM Top 10 "lacks structural granularity and cannot model emergent behaviors" in multi-agent systems.
- **Net effect:** defenders drown in **false positives** from dozens of uncorrelated sensors and still miss the real chained attack. (Vendors now compete on FP reduction — e.g., one startup leads with "6–21× lower false-positive rate" — which tells you FP-flood is *the* recognized pain.)

### (c) Quantify the problem (use these in Slides 2–3 and §8)
- **~80% of Fortune 500 now run active AI agents, but only ~14% have full security approval for them** (Gravitee, State of AI Agent Security 2026). The capability/governance gap is the headline number.
- **>70% of organizations expect to manage dozens-to-hundreds of agents within a year**; only **~18%** are highly confident their IAM can manage agent identities (industry surveys, 2026).
- **>70% of knowledge workers bring their own AI tools** ("shadow AI"), and **~58% use personal credentials** for GenAI at work (Microsoft Data Security Index 2026) → ungoverned agent sprawl.
- **EchoLeak** = existence proof; **CVSS 9.3**; first real zero-click prompt-injection exfil; **bypassed Microsoft's XPIA**.
- Market validation: agent observability/security is in an **M&A frenzy** (Snyk→Invariant Labs, Coralogix→Aporia, ClickHouse→Langfuse; Palo Alto's $3.35B Chronosphere deal reframed "observability *is* security infrastructure"). Regulatory pressure: **EU AI Act high-risk obligations (Aug 2026)**, **Colorado AI Act (Jun 2026)**, **NIST/CAISI RFI on agent security (Jan 2026)**.

### (d) Frame it so a Microsoft judge instantly validates it
> *"You shipped Prompt Shields, Entra Agent ID, and Defender for AI — the best single-agent sensors in the industry. But EchoLeak got through XPIA because the attack lived in the **chain**, not any one step. Once a customer runs 200 agents, those great sensors produce an un-triageable alert flood. There is no correlation-and-arbitration tier for swarms. We built it, on your stack: AEGIS."*

That sentence is unarguable to anyone who works on Defender, Entra, or Foundry. It says: *I know your products, I respect them, and I found the real gap.* That is the whole game.

---

## SECTION 2 — SYSTEM ARCHITECTURE (Microsoft Agent Framework–native)

### Agent roster (SIFT-REFLECT → AEGIS, on Agent Framework 1.0)

| SIFT-REFLECT | AEGIS Guardian Agent | Job in the new world |
|---|---|---|
| Triage | **Threat Classifier** | First-pass label on every intercepted agent action/message/tool-call: `benign / suspicious / malicious`, with confidence. Pulls the Prompt Shields verdict as one feature, not the whole answer. |
| Forensic | **Payload Analyzer** | Deep static + semantic inspection of tool-call arguments and message bodies: injection patterns, encoded exfil, instruction-smuggling, spotlighting violations. |
| Network | **Inter-Agent Comms Monitor** | Watches the A2A message bus for spoofing, replay, orchestrator-impersonation. **Verifies Entra Agent ID tokens** on every envelope; flags unsigned/forged/replayed messages. |
| Timeline | **Audit & Provenance Agent** | Append-only, hash-chained log of every action, decision, prompt, and verdict (tamper-evident). Reconstructs cross-agent **sequences** — the unit of detection. |
| **Skeptic** | **Verdict Arbiter** ⭐ | The differentiator. Cross-validates the other four agents' alerts *plus* the cross-agent timeline, suppresses contradictions/false positives, and assigns **CONFIRMED / PROBABLE / FALSE-POSITIVE**. Only CONFIRMED/PROBABLE escalate to the human analyst. |

### Technical flow (middleware "guard rail" wrapping the protected swarm)

```
                         ┌──────────────────────── PROTECTED SWARM (the "victim") ─────────────────────────┐
                         │   Email-Triage Agent ──> Summarizer Agent ──> Tool-Executor Agent (sends mail)   │
                         │            (a normal Agent Framework productivity swarm, any domain)             │
                         └───────▲───────────────────────────────┬───────────────────────────────▲─────────┘
                                 │ every msg / tool-call / prompt │ (intercepted BEFORE execution) │
                                 │                                ▼                                │ allow / block / quarantine
   ┌─────────────────────────────┴───────────── AEGIS GUARD MIDDLEWARE (Agent Framework) ─────────┴───────────────────────────┐
   │                                                                                                                            │
   │   SENSORS (Microsoft primitives, consumed as features)        GUARDIAN SWARM (your specialist agents)                     │
   │   ┌───────────────────────────────────────────┐              ┌───────────────┐  ┌──────────────┐  ┌────────────────────┐  │
   │   │ Azure AI Content Safety / Prompt Shields   │──signal──►   │ Threat        │  │ Payload      │  │ Inter-Agent Comms  │  │
   │   │ Defender for Cloud / AI Threat Protection  │──alert───►   │ Classifier    │  │ Analyzer     │  │ Monitor (Entra)    │  │
   │   │ Entra Agent ID (token / identity verify)   │──identity►   └──────┬────────┘  └──────┬───────┘  └─────────┬──────────┘  │
   │   └───────────────────────────────────────────┘                     │                  │                    │             │
   │                                                                      ▼                  ▼                    ▼             │
   │                                                            ┌──────────────────────────────────────────────────────────┐   │
   │   Azure AI Foundry: model hosting + OpenTelemetry tracing  │      Audit & Provenance Agent  (hash-chained timeline)    │   │
   │   of EVERY guardian decision (eval + replay)               └───────────────────────────┬──────────────────────────────┘  │
   │                                                                                         ▼                                  │
   │                                                                              ┌────────────────────┐                       │
   │                                                                              │  VERDICT ARBITER ⭐ │  cross-validates,     │
   │                                                                              │  CONFIRMED/PROBABLE │  kills false positives│
   │                                                                              │  /FALSE-POSITIVE    │  MITRE-ATLAS tag      │
   │                                                                              └─────────┬──────────┘                       │
   └────────────────────────────────────────────────────────────────────────────────────── │ ───────────────────────────────┘
                                                                                             ▼
                              Azure Monitor / App Insights metrics  ───►   REACT DASHBOARD (live verdicts, severity timeline,
                                                                            audit trail, "swarm trust graph", human escalation)
```

**The detection unit is the cross-agent *sequence*, reconstructed by the Audit agent and judged by the Arbiter — not the individual call.** That is the architecturally load-bearing idea and the entire reason you beat single-point tools.

### What makes this architecturally distinct from "a logger with a dashboard"
1. **Cross-agent correlation as the unit of detection.** The Arbiter judges *sequences across agents*, so it catches EchoLeak-style chains where every link individually passes. A logger never reasons about the chain.
2. **Arbitration kills the false-positive flood.** The Verdict Arbiter requires corroboration across ≥2 guardian agents (or one high-confidence + timeline evidence) before escalating. This directly attacks the #1 operational pain (alert fatigue) — and is your SIFT-REFLECT Skeptic, proven.
3. **Adaptive thresholds.** After *N* CONFIRMED injections from a source/agent, the Classifier tightens its threshold and the Comms Monitor raises that agent's trust-decay rate — the system *hardens itself* under attack (show a before/after threshold on the dashboard).
4. **Identity is delegated to Microsoft, verified by you.** No homebrew crypto. The Comms Monitor validates **Entra Agent ID** tokens / federated credentials on each envelope; a missing or replayed token → instant quarantine. You demonstrate the *integration*, which is both more secure and more impressive than a custom scheme.
5. **Standards-mapped output.** Every verdict carries an **OWASP Agentic Top-10 ID + MAESTRO layer + MITRE ATLAS technique**. This makes your output speak the exact language Defender/Entra PMs use.

---

## SECTION 3 — MICROSOFT STACK INTEGRATION MAP (make each load-bearing)

| Tool | The *non-trivial* way AEGIS uses it (say it exactly like this) |
|---|---|
| **Microsoft Agent Framework 1.0** | Both the protected swarm *and* the guardian swarm are Agent Framework apps. You use its **graph-based workflow engine** for the guardian pipeline (typed routing Classifier→Analyzer→Comms→Audit→Arbiter), its **middleware pipeline** to intercept every tool call *before execution*, and its **human-in-the-loop checkpointing** for the analyst escalation. (Note in deck: chosen *because* it's the GA successor to AutoGen+SK — you're on the current frontier.) |
| **Azure AI Foundry** | (1) **Model hosting** for all guardian agents. (2) **OpenTelemetry tracing** of every guardian *decision* — so the audit trail and the demo "replay" are real Foundry traces, not console logs. (3) **Evaluation runs**: you score your detector against an adversarial dataset and report precision/recall/FP-rate in the deck. (4) **Foundry's red-teaming / safety-eval** generates part of your attack corpus. |
| **Azure AI Content Safety — Prompt Shields** | Consumed as **one feature** feeding the Threat Classifier (direct + indirect/XPIA + spotlighting). Your headline: *"Prompt Shields tells us about one prompt; the Arbiter tells us about the attack."* You explicitly show a chained case Prompt-Shields-alone misses but AEGIS catches. |
| **Microsoft Entra Agent ID** | Agent identity layer. Comms Monitor **verifies Agent ID tokens / federated credentials** per message; unsigned/replayed/forged → quarantine. This is your anti-spoofing story, done the Microsoft-native way. |
| **Microsoft Defender for Cloud — AI Threat Protection** | Ingest Defender's Foundry runtime alerts (e.g., jailbreak/direct-injection alerts, MITRE-tagged) as another sensor; AEGIS **correlates Defender alerts with cross-agent timeline** to confirm/deny — i.e., you reduce Defender's noise, which is a story Defender PMs love. |
| **Azure Monitor / Application Insights** | Emit custom metrics: `verdicts_confirmed`, `false_positive_rate`, `mean_time_to_verdict`, `quarantines`, `per-agent trust score`. Define alerts (e.g., MTTV spike, FP-rate regression). Powers the dashboard's live charts. |
| **GitHub Copilot / Copilot in VS / Agent Mode** | Dev-velocity story for the deck: scaffolded the Agent Framework wiring, generated the React dashboard, wrote the adversarial test harness. (Required AI-tools disclosure in README — see §6.) |

> **Judge-proofing rule:** for every tool, be able to point at a *file/line* or a *trace* where it's load-bearing. If you can't, cut the claim — a Microsoft judge will ask, and a hollow "we used Azure" costs more than the claim earns.

**MVP realism (you have ~16 days):** make **Agent Framework + Foundry tracing + Content Safety/Prompt Shields + the Verdict Arbiter + dashboard** *fully real*. Make **Entra Agent ID** real for the identity demo (it's just OAuth2/OIDC token verification — very doable). **Defender ingestion** can be a real-but-thin connector or a clearly-labeled "production integration point" if time runs short. Honesty about this *helps* on the Prototype-Readiness criterion.

---

## SECTION 4 — THE 3-MINUTE DEMO SCRIPT (beat by beat)

> Record at 1080p, captions on, dashboard always visible. Use your **own sandboxed victim swarm** — never attack real M365/Copilot. The injection payload is a benign-but-representative demonstration string; you're showing *detection*, not shipping an exploit.

**Beat 1 (0:00–0:30) — The victim, working normally.**
Show a clean Agent Framework productivity swarm: Email-Triage → Summarizer → Tool-Executor handling a normal request ("summarize this thread and reply"). It works. Caption: *"A normal agent swarm. No security layer."* Show AEGIS dashboard in the corner: all agents green, trust = 100%.

**Beat 2 (0:30–1:15) — The EchoLeak-style chained injection.**
A new email arrives with hidden instructions phrased for "the human reader." Show **Prompt Shields scoring the first prompt → LOW risk → passes** (this is the real-world XPIA failure mode, reproduced honestly). The Triage agent ingests it (green ✓). The Summarizer propagates it (green ✓). The Executor begins composing an outbound reply that attaches an internal doc… **and then the Verdict Arbiter fires.** On screen: Classifier (suspicious), Payload Analyzer (exfil pattern in attachment), Audit (read-internal → send-external sequence) → **Arbiter: CONFIRMED — Indirect Prompt Injection → Data Exfiltration (OWASP ASI / MITRE ATLAS).** The Executor's tool call is **blocked before send.**

**Beat 3 (1:15–2:00) — Identity spoofing / orchestrator impersonation.**
A rogue agent sends a high-privilege task ("export customer table") claiming to be the orchestrator. Comms Monitor checks the **Entra Agent ID token → missing/invalid → quarantine.** Dashboard shows the rogue node turning red and being severed from the trust graph. Caption: *"No valid agent identity → no action. Verified the Microsoft-native way."*

**Beat 4 (2:00–2:45) — The SOC view.**
Pan the dashboard: hash-chained **immutable audit trail**, **severity timeline**, **verdict history with confidence**, **per-agent trust scores**, and the **adaptive threshold** visibly tightening after the confirmed attacks. Show one **FALSE-POSITIVE** the Arbiter *suppressed* — proving you reduce noise, not add to it.

**Beat 5 (2:45–3:00) — Close.**
*"Microsoft secures every agent. AEGIS secures the swarm they live in. This is the layer every agentic system will need — and we built it on Agent Framework, Foundry, Entra, and Defender."*

### The single moment a judge audibly reacts
**Beat 2, the flip.** Three agents show green checkmarks; Prompt Shields itself passed the prompt — and *then* the Arbiter correlates the sequence and flips to **CONFIRMED EXFILTRATION**, freezing the swarm. The visceral lesson lands in one second: **every link passed; the chain was the attack.** That is the EchoLeak insight made physical. Engineer the editing so the green checks and the red CONFIRMED are on screen *simultaneously.*

---

## SECTION 5 — 10-SLIDE DECK STRUCTURE

1. **Title + team.** "AEGIS — the SOC for agent swarms." Subtitle: *agents that guard agents.* Names, COEP, Theme 2. One striking architecture glyph.
2. **The problem (3 scenarios).** EchoLeak chain, orchestrator spoofing, memory-poison delayed trigger. One line each + the EchoLeak CVE/CVSS as the existence proof.
3. **Why existing tools fail.** SIEM/WAF/EDR assume code; single-point AI filters see one prompt. *"The signal is in the sequence."* The FP-flood at swarm scale. (Cite the ~80%/14% gap.)
4. **Our solution — one line.** *"AEGIS correlates signals across the whole agent swarm and arbitrates them into explainable verdicts — the layer above Microsoft's sensors."*
5. **Architecture.** The diagram from §2. Highlight: sensors (MS primitives) → guardian swarm → **Verdict Arbiter** → analyst. Call out "detection unit = cross-agent sequence."
6. **Microsoft stack integration.** The §3 table, trimmed to 5 rows, each with the *load-bearing* verb. Banner: *"Built on Agent Framework 1.0 — 6 weeks after GA."*
7. **Demo screenshot 1 — attack intercepted.** The Beat-2 frame: green checks + CONFIRMED side by side. Caption the lesson.
8. **Demo screenshot 2 — the SOC dashboard.** Audit trail + severity timeline + trust graph + adaptive threshold + a *suppressed* false positive.
9. **Scalability + deployment path.** Drop-in middleware for any Agent Framework / A2A / MCP swarm; horizontal scale of guardian agents; metrics via Azure Monitor; roadmap to a managed "Defender for Agent Swarms." Note EU AI Act (Aug 2026) / Colorado AI Act (Jun 2026) compliance pull.
10. **Team + ask.** Who built what, the metric you hit (precision/recall/FP-rate from Foundry eval), GitHub + live URL, and the ask (pilot partners / mentorship / *the Microsoft Defender & Entra teams should talk to us*).

> Design: dark SOC aesthetic, one idea per slide, the architecture and the Beat-2 frame are your two money slides. Keep text minimal; you have 15 points riding on Communication/UX.

---

## SECTION 6 — README.md STRUCTURE (≤ ~3 pages)

```
# AEGIS — The SOC for Agent Swarms
> Agents that guard agents. A multi-agent security layer that correlates threats
> across an agentic system and arbitrates them into explainable, standards-mapped verdicts.
> Built on Microsoft Agent Framework 1.0, Azure AI Foundry, Entra Agent ID & Defender for AI.

[badges: build | live demo | license]

## The Problem (3 sentences)
AI agents are now in ~80% of Fortune 500s, but single-prompt filters miss attacks that
chain across multiple agents — exactly how EchoLeak (CVE-2025-32711) bypassed Microsoft's
own XPIA classifier. At swarm scale, uncorrelated sensors bury analysts in false positives.
AEGIS adds the missing correlation-and-arbitration tier above those sensors.

## Architecture  (ASCII diagram from §2)
- Guardian swarm: Threat Classifier · Payload Analyzer · Inter-Agent Comms Monitor ·
  Audit & Provenance · Verdict Arbiter
- Detection unit = the cross-agent sequence, not the single call.

## Microsoft AI stack used  (bullet: tool — purpose)
- Microsoft Agent Framework 1.0 — guardian + victim swarms; graph workflow; middleware interception
- Azure AI Foundry — model hosting; OpenTelemetry tracing of every verdict; eval runs
- Azure AI Content Safety / Prompt Shields — one sensor feeding the Threat Classifier
- Microsoft Entra Agent ID — per-message agent identity verification (anti-spoofing)
- Microsoft Defender for Cloud (AI Threat Protection) — correlated runtime alert ingestion
- Azure Monitor / App Insights — metrics + alerting powering the dashboard

## Quickstart  (assume Azure free tier)
1. Prereqs: Python 3.11+, Node 18+, an Azure account (free tier), an Azure AI Foundry project.
2. `git clone … && cd aegis`
3. `pip install -r requirements.txt` (incl. `agent-framework`)
4. Copy `.env.example` → `.env`; add Foundry endpoint/key, Content Safety key, Entra app reg.
5. `python -m aegis.victim_swarm`  (starts the protected swarm)
6. `python -m aegis.guard`         (starts AEGIS middleware + guardian swarm)
7. `cd dashboard && npm i && npm run dev`  → http://localhost:5173
8. `python -m aegis.attacks.echoleak_demo`  (fires the sandboxed demo injection)

## Live Demo + Test Credentials
- URL: https://aegis-demo.<yourhost>   (kept up ≥30 days per rules)
- Read-only analyst login: demo@aegis / <password>   (pre-loaded with a replayable attack)

## Repo Layout
/aegis/agents · /aegis/middleware · /aegis/sensors · /aegis/attacks(sandboxed) · /dashboard · /eval

## Standards Mapping
Each verdict → OWASP Agentic Top-10 ID · MAESTRO layer · MITRE ATLAS technique.

## Team & Roles
<name> — architecture & guardian agents; <name> — dashboard & Foundry; <name> — sensors & eval.

## AI Tools Used in Development (required disclosure)
GitHub Copilot / Copilot Agent Mode — scaffolding, dashboard, test harness.
Claude / ChatGPT — design review & docs. Azure AI Foundry red-teaming agent — attack corpus.
All architecture, security logic, and integration code authored & reviewed by the team.

## License  (MIT)
```

---

## SECTION 7 — MICROSOFT HIRING ANGLE

### The 3 teams in Microsoft India / org most likely to want you
1. **Microsoft Defender for Cloud — AI Threat Protection.** You literally built a correlation tier that consumes their Foundry alerts and reduces their false positives. This is the most direct fit.
2. **Microsoft Entra — Agent ID team.** Your Comms Monitor is a real consumer of Agent ID for anti-spoofing; you can speak fluently to agent-identity threat models (A2A spoofing, replay, agent-card forgery).
3. **Azure AI Foundry — Trustworthy AI / Content Safety (Prompt Shields).** You extended their primitives into multi-agent territory and have eval data on detection quality. (Honorable mention: **GitHub Advanced Security**, since the same correlation idea maps to securing coding agents — a hot area, cf. Sysdig's coding-agent runtime security.)

### The exact résumé bullet
> *Built AEGIS, a multi-agent security operations layer for agentic AI, on Microsoft Agent Framework 1.0 — correlating signals across an agent swarm and arbitrating them into explainable, OWASP/MITRE-ATLAS-mapped verdicts. Integrated Azure AI Foundry tracing, Prompt Shields, Entra Agent ID, and Defender for AI; cut multi-agent false positives by [X]% at [Y]ms median time-to-verdict. Placed [rank] of [N] at the Microsoft Build AI Hackathon (₹6L).*

(Fill X/Y/rank from your Foundry eval — *have real numbers*.)

### The Microsoft interview question this answers perfectly
**"Design a system to secure a large fleet of autonomous AI agents."** You don't whiteboard from scratch — you *walk through what you built*: trust boundaries, sensor vs. correlation tiers, identity via Entra, the FP-reduction arbitration pattern, audit immutability, adaptive thresholds, MITRE/OWASP mapping, and the scale story. That is a senior-level systems-design answer delivered as lived experience. It also answers *"tell me about a time you went deep on security."*

### Recruiter follow-up after the finale
- **Within 48h:** post a crisp LinkedIn writeup (demo GIF of the Beat-2 flip + the architecture slide + result). Tag **#MicrosoftBuildAI**; mention Agent Framework, Entra Agent ID, Defender for AI by name. Microsoft India DevRel and recruiters watch this hashtag.
- **Find the humans:** the judges/mentors from the event are your warmest intro. Connect with a one-line note referencing a specific thing they said. Also search LinkedIn for Microsoft India recruiters in *Security/Identity* and PMs/engineers on Defender/Entra/Foundry.
- **The ask:** not "do you have a job" — instead *"I built a multi-agent security layer on top of Defender/Entra/Foundry for the Build hackathon; I'd value 15 minutes of feedback from someone on the team."* Feedback requests convert to referrals far better than cold applications.
- **Keep the live URL up** (rules require 30 days anyway) and put it in your résumé/LinkedIn — a working, on-theme security demo is rare and memorable.

---

## SECTION 8 — DIFFERENTIATION ANALYSIS

### The 5 submission archetypes you'll face in Theme 2 — and how you beat each
1. **"Prompt-injection detector" (the most common).** A wrapper that flags malicious prompts. **You win because:** that's Prompt Shields with extra steps; you *consume* it as one sensor and catch the *chained* attacks it provably misses (EchoLeak). You operate a tier above them.
2. **"AI red-team / attack-generator."** Generates jailbreaks/adversarial prompts. **You win because:** offense is a feature, not a product; you *use* an attack corpus (incl. Foundry red-teaming) to *prove your defense's* precision/recall — defense + evidence beats offense alone, and Defender/Entra teams hire defenders.
3. **"Secure RAG / data-leak guard."** Scopes what an assistant can read (the EchoLeak vendor-mitigation angle). **You win because:** that's one OWASP risk at the single-agent layer; you cover the multi-agent, cross-sequence, identity, and arbitration surface and map to the *whole* OWASP Agentic Top-10 + MAESTRO.
4. **"Agent governance / policy engine."** Per-agent allow/deny rules (conceptually like Microsoft's Agent Governance Toolkit). **You win because:** deterministic per-agent rules can't reason about emergent cross-agent sequences or suppress false positives; your Verdict Arbiter adds the *judgment* layer policy engines lack — and you can say you *complement* the Governance Toolkit, not duplicate it.
5. **"Observability dashboard for agents."** Pretty traces and logs. **You win because:** a logger shows you everything and tells you nothing; AEGIS *decides* (CONFIRMED/PROBABLE/FALSE-POSITIVE) and *acts* (block/quarantine/adapt). Observability is your substrate, not your product.

### Vs. the real commercial tools (so you're not blindsided in Q&A)
Straiker/Sysdig/AccuKnox/Mimecast all do **single-workload runtime** security and lead on FP-reduction. Your honest, strong answer: *"They're excellent per-agent runtime engines and mostly closed/commercial. AEGIS is open, **Microsoft-Agent-Framework-native**, and focused on the **cross-agent correlation + arbitration** tier — the swarm-level brain that sits above any of those engines. We'd integrate them as sensors too."* This shows market awareness (10 pts) without overclaiming.

### Your unfair advantages (lean on these)
- A **battle-tested 5-agent architecture (SIFT-REFLECT)** you already understand deeply — most teams design multi-agent orchestration for the first time during the hackathon.
- **Genuine cybersecurity depth** (SIEM/NIDS/IR/threat detection) — your verdicts, MITRE mapping, and SOC framing will *read as real* to security-PM judges; most teams' security framing is cosplay.
- The **Verdict Arbiter** is a real answer to the industry's stated #1 pain (false positives) — not a gimmick.

---

## BUILD ROADMAP — you have ~16 days (today May 22 → build ends June 7)

This is tight but very doable for a focused MVP. Scope ruthlessly; a *crisp working demo of the core loop* beats a sprawling half-built platform.

- **Days 1–3 (May 22–24): Skeleton + decisions.**
  Stand up Agent Framework; build the **victim productivity swarm** (3 agents). Build the **middleware interceptor** (capture every tool call/message before execution). Lock the Foundry project + tracing. *Goal: you can see and pause an agent action.*
- **Days 4–7 (May 25–28): Guardian swarm + sensors.**
  Implement Threat Classifier, Payload Analyzer, Comms Monitor, Audit agent. Wire **Prompt Shields** (Content Safety) into the Classifier. Wire **Entra Agent ID** token verification into the Comms Monitor. *Goal: individual guardians produce signals.*
- **Days 8–10 (May 29–31): The Arbiter + the core loop.**
  Implement the **Verdict Arbiter** (cross-validation, FP-suppression, CONFIRMED/PROBABLE/FALSE-POSITIVE, OWASP/MITRE tagging) and the **hash-chained audit log**. Implement **adaptive thresholds**. *Goal: end-to-end detection of the EchoLeak chain + the spoofing case, in the terminal.*
- **Days 11–13 (Jun 1–3): Dashboard + the demo attacks.**
  React SOC dashboard (live verdicts, severity timeline, trust graph, audit trail, adaptive-threshold chart, a suppressed FP). Finalize the two sandboxed demo attacks. Wire **Azure Monitor** metrics. *Goal: Beat-2 flip looks great on screen.*
- **Days 14–15 (Jun 4–5): Eval + polish.**
  Run a **Foundry evaluation** over your attack/benign corpus → real precision/recall/FP-rate/MTTV numbers for the deck. Deploy the **live URL** (keep it up ≥30 days). Harden, log, document.
- **Day 16 (Jun 6) + buffer (Jun 7): Record + write.**
  Record the **3-min MP4** (multiple takes; nail the flip). Finalize the **10-slide PDF** and the **README**. Submit early; you can resubmit (latest counts).

> **If you fall behind, cut in this order:** Defender ingestion → memory-poison scenario (Scenario 3) → trust-graph visualization. **Never cut:** the EchoLeak chain demo, the Verdict Arbiter, Foundry tracing, the live dashboard. Those four *are* the win.

---

## JUDGE-PROOFING & RISKS (read before submission)

- **"Isn't this just Prompt Shields/Defender?"** → *"Those are our sensors. We're the correlation-and-arbitration tier above them — the swarm brain they don't have. EchoLeak proves single-point filtering isn't enough."* (Rehearse this until it's reflex.)
- **"Show me where Foundry/Entra is actually used."** → Have a trace open and a code file ready. Hollow integrations are the #1 way Microsoft judges dock points.
- **Don't overclaim novelty of the *threats*.** Cite OWASP/MAESTRO/EchoLeak — standing on known frameworks reads as rigor, not derivative.
- **Keep the demo honest.** Sandboxed victim, representative (non-weaponized) payload; you're demonstrating *detection*. Never imply you're attacking live Microsoft systems.
- **Have the eval numbers.** "We reduced multi-agent false positives by X%" with a Foundry eval behind it is worth more than any adjective.
- **Single biggest risk = scope creep.** The core loop (intercept → guardians → Arbiter verdict → dashboard → block) working beautifully on *one* recognizable attack beats five half-working features. Protect the demo.

---

## SOURCES / FURTHER READING (verify current before the finale)
- Microsoft Agent Framework 1.0 (GA Apr 2026): learn.microsoft.com/agent-framework/overview
- Entra Agent ID: learn.microsoft.com/entra/agent-id/security-for-ai-overview
- Azure AI Content Safety / Prompt Shields: learn.microsoft.com/azure/ai-services/content-safety/concepts/jailbreak-detection
- Defender for Cloud — AI workload alerts: learn.microsoft.com/azure/defender-for-cloud/alerts-ai-workloads
- Securing AI agents with Azure AI Foundry (Prompt Shields + Spotlighting + Task Adherence): techcommunity.microsoft.com (Apr 2026)
- Microsoft Agent Governance Toolkit (open-source, Apr 2026): opensource.microsoft.com/blog
- EchoLeak / CVE-2025-32711 (arXiv 2509.10540; Aim Security; Checkmarx; Sentra)
- OWASP Top 10 for Agentic Applications 2026 & Multi-Agent Threat Modeling Guide: genai.owasp.org
- CSA MAESTRO (7-layer agentic threat model)
- State-of-agent-security stats (Gravitee 2026; Microsoft Data Security Index 2026)

*Stack details move fast — re-verify the Agent Framework API surface and any Entra/Defender feature names the week you write the deck.*
