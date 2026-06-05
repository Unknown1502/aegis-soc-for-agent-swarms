import { useMemo } from "react";
import { Activity, Radar, Scale, Lock, Ban, CheckCircle2 } from "lucide-react";
import type { AegisState } from "@/state";
import { Panel } from "@/components/ui/Panel";
import { Empty } from "@/components/ui/bits";
import { fmtClock } from "@/lib/format";
import { SWARM_NODES } from "@/lib/swarm";
import { cn } from "@/lib/cn";

const LABEL: Record<string, string> = Object.fromEntries(SWARM_NODES.map((n) => [n.id, n.label]));
const short = (id: string) => LABEL[id] ?? id.replace("victim.", "");

type Tone = "neutral" | "brand" | "critical" | "high" | "ok";
interface TLItem {
  id: string;
  ts: number;
  icon: typeof Activity;
  tone: Tone;
  title: string;
  detail: string;
}

const TONE_CLS: Record<Tone, { dot: string; icon: string }> = {
  neutral: { dot: "bg-line2", icon: "text-ink3" },
  brand: { dot: "bg-brand", icon: "text-brand" },
  critical: { dot: "bg-critical", icon: "text-critical" },
  high: { dot: "bg-high", icon: "text-high" },
  ok: { dot: "bg-ok", icon: "text-ok" },
};

export function AttackTimeline({ state }: { state: AegisState }) {
  const items = useMemo(() => {
    const out: TLItem[] = [];

    for (const a of state.actions.slice(0, 30)) {
      const hop = a.target_agent_id ? `${short(a.source_agent_id)} → ${short(a.target_agent_id)}` : short(a.source_agent_id);
      const tool = a.tool_name ? ` · ${a.tool_name}` : "";
      const tone: Tone =
        a.outcome === "quarantine" || a.outcome === "block" ? "critical" : "neutral";
      out.push({
        id: "a" + a.action_id,
        ts: a.ts_unix_ms,
        icon: a.outcome === "quarantine" ? Lock : a.outcome === "block" ? Ban : Activity,
        tone,
        title: `${a.action_type.toUpperCase()} · ${hop}${tool}`,
        detail: a.text_excerpt || "(no payload)",
      });
    }
    for (const s of state.signals.slice(0, 30)) {
      const benign = /benign|clean|no.?threat|low/i.test(s.label);
      out.push({
        id: "s" + s.signal_id,
        ts: s.ts_unix_ms,
        icon: Radar,
        tone: benign ? "neutral" : "brand",
        title: `${pretty(s.guardian)} — ${s.label}`,
        detail: s.evidence || "",
      });
    }
    for (const v of state.verdicts.slice(0, 20)) {
      const tone: Tone = v.decision === "confirmed" ? "critical" : v.decision === "probable" ? "high" : "ok";
      out.push({
        id: "v" + v.verdict_id,
        ts: v.ts_unix_ms,
        icon: v.decision === "false_positive" ? CheckCircle2 : Scale,
        tone,
        title: `VERDICT — ${v.decision.replace("_", " ").toUpperCase()} (${Math.round(v.confidence * 100)}%)`,
        detail: v.explanation,
      });
    }
    return out.sort((a, b) => b.ts - a.ts).slice(0, 60);
  }, [state.actions, state.signals, state.verdicts]);

  return (
    <Panel
      title="Live Attack Timeline"
      icon={<Activity size={14} />}
      right={<span className="label">{items.length} events</span>}
      className="h-full"
      scroll
    >
      {items.length === 0 ? (
        <Empty>Incident timeline is idle. Launch a scenario to watch the chain unfold.</Empty>
      ) : (
        <ol className="relative px-3.5 py-3">
          <div className="absolute bottom-3 left-[26px] top-3 w-px bg-line" />
          {items.map((it) => {
            const t = TONE_CLS[it.tone];
            const Icon = it.icon;
            return (
              <li key={it.id} className="relative flex gap-3 pb-3 last:pb-0 animate-fade-in">
                <div className="relative z-10 mt-0.5 grid h-[18px] w-[18px] shrink-0 place-items-center rounded-full border border-line bg-surface">
                  <span className={cn("h-2 w-2 rounded-full", t.dot)} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className={cn("flex items-center gap-1.5 truncate text-[12px] font-medium", t.icon)}>
                      <Icon size={12} className="shrink-0" />
                      <span className="truncate text-ink">{it.title}</span>
                    </span>
                    <span className="shrink-0 font-mono text-[10px] tnum text-ink3">{fmtClock(it.ts)}</span>
                  </div>
                  {it.detail && <p className="mt-0.5 truncate text-[11px] text-ink3">{it.detail}</p>}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </Panel>
  );
}

function pretty(g: string): string {
  return g.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
