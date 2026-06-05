import type { ReactNode } from "react";
import {
  ShieldX,
  ShieldAlert,
  Lock,
  Gauge,
  Filter,
  Timer,
} from "lucide-react";
import type { AegisState } from "@/state";
import { cn } from "@/lib/cn";
import { VICTIM_IDS } from "@/lib/swarm";

interface Tile {
  label: string;
  value: string;
  hint: string;
  icon: ReactNode;
  tone: "critical" | "high" | "brand" | "ok" | "neutral";
  emphasis?: boolean;
}

const TONE: Record<Tile["tone"], { v: string; ic: string; bar: string }> = {
  critical: { v: "text-critical", ic: "text-critical bg-critical/12", bar: "bg-critical" },
  high: { v: "text-high", ic: "text-high bg-high/12", bar: "bg-high" },
  brand: { v: "text-brand", ic: "text-brand bg-brand/12", bar: "bg-brand" },
  ok: { v: "text-ok", ic: "text-ok bg-ok/12", bar: "bg-ok" },
  neutral: { v: "text-ink", ic: "text-ink2 bg-surface3", bar: "bg-line2" },
};

export function CommandCenter({ state }: { state: AegisState }) {
  const c = state.metrics.counters ?? {};
  const confirmed = c.verdicts_confirmed ?? 0;
  const probable = c.verdicts_probable ?? 0;
  const quarantined = Object.keys(state.quarantine).length;
  const suppressed = (c.false_positives_suppressed ?? 0) + state.suppressedTotal;
  const ttv = state.metrics.mean_time_to_verdict_ms ?? 0;

  // Trust index = mean trust across the protected swarm (default 100%).
  const trustVals = VICTIM_IDS.map((id) => state.trust[id]?.score ?? 1);
  const trustIdx = trustVals.reduce((a, b) => a + b, 0) / (trustVals.length || 1);

  const tiles: Tile[] = [
    {
      label: "Confirmed Threats",
      value: String(confirmed),
      hint: confirmed ? "cross-agent chains blocked" : "no confirmed activity",
      icon: <ShieldX size={16} />,
      tone: confirmed ? "critical" : "neutral",
      emphasis: confirmed > 0,
    },
    {
      label: "Probable Threats",
      value: String(probable),
      hint: "awaiting corroboration",
      icon: <ShieldAlert size={16} />,
      tone: probable ? "high" : "neutral",
    },
    {
      label: "Quarantined Agents",
      value: String(quarantined),
      hint: quarantined ? "isolated from swarm" : "swarm fully trusted",
      icon: <Lock size={16} />,
      tone: quarantined ? "critical" : "neutral",
    },
    {
      label: "Trust Index",
      value: `${Math.round(trustIdx * 100)}%`,
      hint: "mean swarm trust",
      icon: <Gauge size={16} />,
      tone: trustIdx > 0.8 ? "ok" : trustIdx > 0.5 ? "high" : "critical",
    },
    {
      label: "False Positives Prevented",
      value: String(suppressed),
      hint: "noise the arbiter suppressed",
      icon: <Filter size={16} />,
      tone: "brand",
    },
    {
      label: "Mean Time to Verdict",
      value: ttv >= 1000 ? `${(ttv / 1000).toFixed(1)}s` : `${ttv}ms`,
      hint: "observe → verdict, end-to-end",
      icon: <Timer size={16} />,
      tone: "neutral",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-6">
      {tiles.map((t) => {
        const tone = TONE[t.tone];
        return (
          <div
            key={t.label}
            className={cn(
              "panel relative overflow-hidden p-3.5",
              t.emphasis && "ring-1 ring-critical/40"
            )}
          >
            <div className={cn("absolute left-0 top-0 h-full w-0.5", tone.bar)} />
            <div className="mb-2 flex items-center justify-between">
              <span className="label">{t.label}</span>
              <span className={cn("grid h-7 w-7 place-items-center rounded-md", tone.ic)}>{t.icon}</span>
            </div>
            <div className={cn("font-mono text-[26px] font-semibold leading-none tnum", tone.v)}>{t.value}</div>
            <div className="mt-1.5 text-[11px] text-ink3">{t.hint}</div>
          </div>
        );
      })}
    </div>
  );
}
