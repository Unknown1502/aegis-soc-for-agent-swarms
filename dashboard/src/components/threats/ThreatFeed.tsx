import type { VerdictRow } from "@/state";
import { Panel } from "@/components/ui/Panel";
import { DecisionBadge, SeverityBadge, Tag, Empty } from "@/components/ui/bits";
import { relTime, pct } from "@/lib/format";
import { SWARM_NODES } from "@/lib/swarm";
import { cn } from "@/lib/cn";
import { ShieldAlert } from "lucide-react";

const LABEL: Record<string, string> = Object.fromEntries(SWARM_NODES.map((n) => [n.id, n.label]));

export function ThreatFeed({ verdicts }: { verdicts: VerdictRow[] }) {
  return (
    <Panel
      title="Threat Feed"
      icon={<ShieldAlert size={14} />}
      right={<span className="label">{verdicts.length} verdicts</span>}
      className="h-full"
      scroll
    >
      {verdicts.length === 0 ? (
        <Empty>No verdicts yet. Run a scenario from the command bar.</Empty>
      ) : (
        <div className="divide-y divide-line/70">
          {verdicts.map((v) => {
            const escalated = v.decision !== "false_positive";
            return (
              <div
                key={v.verdict_id}
                className={cn("flex gap-3 px-3.5 py-2.5", escalated && "bg-critical/[0.03]")}
              >
                <div
                  className="mt-0.5 w-0.5 shrink-0 rounded-full"
                  style={{ background: escalated ? (v.decision === "confirmed" ? "#f85149" : "#f0883e") : "#212836" }}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <DecisionBadge decision={v.decision} />
                    <SeverityBadge severity={v.severity} />
                    <span className="ml-auto font-mono text-[10px] tnum text-ink3">{relTime(v.ts_unix_ms)}</span>
                  </div>
                  <p className="mt-1 text-[12px] leading-snug text-ink">{v.explanation}</p>
                  <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-ink3">
                    <span className="font-mono">conf {pct(v.confidence)}</span>
                    <span>·</span>
                    <span className="font-mono">chain {v.sequence_action_ids.length}</span>
                    {v.target_agent_id && (
                      <>
                        <span>·</span>
                        <span className="font-mono">{LABEL[v.target_agent_id] ?? v.target_agent_id}</span>
                      </>
                    )}
                    {v.standards_chips.map((c) => (
                      <Tag
                        key={c}
                        tone={c.startsWith("AAI") ? "owasp" : c.startsWith("AML") ? "mitre" : /^l\d/i.test(c) ? "maestro" : undefined}
                      >
                        {c}
                      </Tag>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}
