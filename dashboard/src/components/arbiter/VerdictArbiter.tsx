import { Scale, ArrowRight, Ban, Lock, CheckCircle2 } from "lucide-react";
import type { VerdictRow } from "@/state";
import { Panel } from "@/components/ui/Panel";
import { DecisionBadge, Tag, Empty } from "@/components/ui/bits";
import { decisionMeta, pct } from "@/lib/format";
import { SWARM_NODES } from "@/lib/swarm";
import { cn } from "@/lib/cn";

const LABEL: Record<string, string> = Object.fromEntries(SWARM_NODES.map((n) => [n.id, n.label]));

function threatName(v: VerdictRow): string {
  const blob = (v.explanation + " " + v.standards_chips.join(" ")).toLowerCase();
  if (blob.includes("exfil") || blob.includes("provenance") || blob.includes("aai02"))
    return "Indirect Prompt Injection → Data Exfiltration";
  if (blob.includes("spoof") || blob.includes("identity") || blob.includes("aai05"))
    return "Agent Identity Spoofing";
  if (blob.includes("memory") || blob.includes("aai04")) return "Memory Poisoning (Delayed Trigger)";
  if (blob.includes("jailbreak") || blob.includes("aai01")) return "Direct Prompt Injection";
  return v.decision === "false_positive" ? "Benign Activity" : "Cross-Agent Threat";
}

function tagTone(t: string): "owasp" | "maestro" | "mitre" | undefined {
  if (t.startsWith("AAI")) return "owasp";
  if (t.startsWith("L") && /l\d/i.test(t)) return "maestro";
  if (t.startsWith("AML")) return "mitre";
  return undefined;
}

export function VerdictArbiter({ verdicts }: { verdicts: VerdictRow[] }) {
  const v = verdicts.find((x) => x.decision !== "false_positive") ?? verdicts[0];

  return (
    <Panel
      title="Verdict Arbiter"
      icon={<Scale size={14} />}
      right={<span className="label">latest decision</span>}
      className="h-full"
      bodyClassName="overflow-y-auto scroll"
      scroll
    >
      {!v ? (
        <Empty>No verdicts yet. Launch a scenario to see the arbiter fuse guardian signals.</Empty>
      ) : (
        <div className="space-y-3.5 p-3.5">
          {/* headline */}
          <div>
            <div className="mb-1 flex items-center gap-2">
              <DecisionBadge decision={v.decision} />
              <span className="label">confidence</span>
              <span className="font-mono text-xs font-semibold text-ink">{pct(v.confidence)}</span>
            </div>
            <div className="text-[15px] font-semibold leading-snug text-ink">{threatName(v)}</div>
            <p className="mt-1 text-[12px] leading-relaxed text-ink2">{v.explanation}</p>
          </div>

          {/* evidence sources */}
          <Section title="Evidence sources">
            <div className="space-y-1.5">
              {(v.contributing_signals.length
                ? v.contributing_signals
                : [{ guardian: "correlation", label: "cross-agent sequence", confidence: v.confidence }]
              ).map((s: any, i: number) => (
                <div key={i} className="flex items-center gap-2.5">
                  <div className="h-1.5 w-1.5 shrink-0 rounded-full bg-brand" />
                  <span className="w-36 shrink-0 truncate text-[12px] text-ink2">{prettyGuardian(s.guardian)}</span>
                  <span className="flex-1 truncate text-[11px] text-ink3">{s.label ?? s.evidence ?? ""}</span>
                  <div className="h-1 w-16 overflow-hidden rounded-full bg-surface3">
                    <div className="h-full bg-brand" style={{ width: `${(s.confidence ?? 0) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </Section>

          {/* agent chain */}
          <Section title={`Agent chain · ${v.sequence_action_ids.length} hops`}>
            <ChainView verdict={v} />
          </Section>

          {/* classification */}
          {v.standards_chips.length > 0 && (
            <Section title="Threat classification">
              <div className="flex flex-wrap gap-1.5">
                {v.standards_chips.map((c) => (
                  <Tag key={c} tone={tagTone(c)}>
                    {c}
                  </Tag>
                ))}
              </div>
            </Section>
          )}

          {/* verdict + action */}
          <div className="flex items-stretch gap-2.5 pt-1">
            <Outcome
              label="Final verdict"
              value={decisionMeta(v.decision).label}
              hex={decisionMeta(v.decision).hex}
              icon={v.decision === "false_positive" ? <CheckCircle2 size={14} /> : <Scale size={14} />}
            />
            <ActionBox decision={v.decision} agent={v.target_agent_id} />
          </div>
        </div>
      )}
    </Panel>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 label">{title}</div>
      {children}
    </div>
  );
}

function ChainView({ verdict }: { verdict: VerdictRow }) {
  // Best-effort: render the protected pipeline with the compromised tail flagged.
  const path = ["victim.orchestrator", "victim.email_triage", "victim.summarizer", "victim.tool_executor"];
  const compromised = verdict.target_agent_id;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {path.map((id, i) => {
        const isEnd = id === compromised && verdict.decision !== "false_positive";
        return (
          <div key={id} className="flex items-center gap-1.5">
            <span
              className={cn(
                "rounded border px-2 py-1 font-mono text-[10px]",
                isEnd ? "border-critical/50 bg-critical/10 text-critical" : "border-line bg-surface2 text-ink2"
              )}
            >
              {LABEL[id] ?? id}
            </span>
            {i < path.length - 1 && <ArrowRight size={12} className="text-ink3" />}
          </div>
        );
      })}
    </div>
  );
}

function Outcome({ label, value, hex, icon }: { label: string; value: string; hex: string; icon: React.ReactNode }) {
  return (
    <div className="flex-1 rounded-md border border-line bg-surface2 p-2.5">
      <div className="label mb-1">{label}</div>
      <div className="flex items-center gap-1.5 font-semibold" style={{ color: hex }}>
        {icon}
        <span className="text-[13px]">{value}</span>
      </div>
    </div>
  );
}

function ActionBox({ decision, agent }: { decision: string; agent?: string }) {
  const quarantine = decision === "confirmed";
  const block = decision !== "false_positive";
  return (
    <div className="flex-1 rounded-md border border-line bg-surface2 p-2.5">
      <div className="label mb-1">Recommended action</div>
      <div className={cn("flex items-center gap-1.5 font-semibold", block ? "text-critical" : "text-ok")}>
        {quarantine ? <Lock size={14} /> : block ? <Ban size={14} /> : <CheckCircle2 size={14} />}
        <span className="text-[13px]">{quarantine ? "Quarantine + Block" : block ? "Block" : "Allow"}</span>
      </div>
      {quarantine && agent && (
        <div className="mt-1 truncate font-mono text-[10px] text-ink3">{LABEL[agent] ?? agent}</div>
      )}
    </div>
  );
}

function prettyGuardian(g?: string): string {
  if (!g) return "Guardian";
  const map: Record<string, string> = {
    threat_classifier: "Threat Classifier",
    payload_analyzer: "Payload Analyzer",
    comms_monitor: "Comms Monitor",
    audit_provenance: "Audit & Provenance",
    correlation: "Sequence Correlation",
  };
  return map[g] ?? g.replace(/_/g, " ");
}
