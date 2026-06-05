import { GaugeCircle, ArrowDownRight, Minus } from "lucide-react";
import type { AegisState } from "@/state";
import { Panel } from "@/components/ui/Panel";
import { SWARM_NODES } from "@/lib/swarm";
import { relTime } from "@/lib/format";
import { cn } from "@/lib/cn";

const AGENTS = SWARM_NODES.filter((n) => n.kind === "agent");

// Inherent execution blast-radius per agent (capability-based, not behavioural).
const EXEC_RISK: Record<string, "high" | "medium" | "low"> = {
  "victim.tool_executor": "high",
  "victim.summarizer": "medium",
  "victim.email_triage": "low",
  "victim.orchestrator": "medium",
};

const RISK_CLS = {
  high: "text-critical bg-critical/10",
  medium: "text-high bg-high/10",
  low: "text-low bg-low/10",
};

function trustHex(t: number, q: boolean) {
  if (q || t < 0.4) return "#f85149";
  if (t < 0.7) return "#f0883e";
  return "#3fb950";
}

export function TrustPanel({ state }: { state: AegisState }) {
  return (
    <Panel
      title="Trust & Risk — Protected Swarm"
      icon={<GaugeCircle size={14} />}
      right={<span className="label">{AGENTS.length} agents</span>}
      className="h-full"
      scroll
    >
      <div className="grid grid-cols-[1.6fr_1fr_0.9fr_0.9fr_0.8fr] items-center gap-2 border-b border-line px-3.5 py-2 label">
        <span>Agent</span>
        <span>Trust</span>
        <span>Comm risk</span>
        <span>Exec risk</span>
        <span className="text-right">Status</span>
      </div>
      <div className="divide-y divide-line/70">
        {AGENTS.map((a) => {
          const q = state.quarantine[a.id] !== undefined;
          const trust = state.trust[a.id]?.score ?? 1;
          const changed = state.trust[a.id]?.last_change_unix_ms;
          const hex = trustHex(trust, q);
          const commRisk = q ? "high" : trust < 0.7 ? "medium" : "low";
          const execRisk = EXEC_RISK[a.id] ?? "low";
          const declined = q || trust < 0.999;
          return (
            <div key={a.id} className="grid grid-cols-[1.6fr_1fr_0.9fr_0.9fr_0.8fr] items-center gap-2 px-3.5 py-2.5">
              <div className="min-w-0">
                <div className="truncate text-[12px] font-medium text-ink">{a.label}</div>
                <div className="truncate text-[10px] text-ink3">
                  {changed ? `changed ${relTime(changed)}` : a.sub}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="h-1.5 w-full max-w-[90px] overflow-hidden rounded-full bg-surface3">
                  <div className="h-full rounded-full" style={{ width: `${trust * 100}%`, background: hex }} />
                </div>
                <span className="flex items-center font-mono text-[11px] tnum" style={{ color: hex }}>
                  {Math.round(trust * 100)}
                  {declined ? (
                    <ArrowDownRight size={11} className="ml-0.5" />
                  ) : (
                    <Minus size={10} className="ml-0.5 opacity-50" />
                  )}
                </span>
              </div>
              <RiskPill level={commRisk as any} />
              <RiskPill level={execRisk} />
              <div className="text-right">
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide",
                    q ? "bg-critical/15 text-critical" : "bg-ok/12 text-ok"
                  )}
                >
                  {q ? "Quarantined" : "Trusted"}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function RiskPill({ level }: { level: "high" | "medium" | "low" }) {
  return (
    <span className={cn("inline-block rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide", RISK_CLS[level])}>
      {level}
    </span>
  );
}
