import { useEffect, useRef, useState } from "react";
import { Play, ChevronDown, ShieldCheck, LogOut, Radio, Loader2, Zap } from "lucide-react";
import { triggerAttack, triggerFullDemo, verifyChain } from "@/api";
import type { AegisState } from "@/state";
import type { View } from "./NavRail";
import { cn } from "@/lib/cn";
import { fmtClock } from "@/lib/format";
import { StatusDot } from "@/components/ui/bits";

type AttackId = "benign" | "echoleak" | "spoof" | "memory_poison";

const SCENARIOS: { id: AttackId; label: string; desc: string; hero?: boolean }[] = [
  { id: "echoleak", label: "EchoLeak chain", desc: "Indirect injection → cross-agent exfil", hero: true },
  { id: "spoof", label: "Orchestrator spoof", desc: "Agent identity impersonation" },
  { id: "memory_poison", label: "Memory poisoning", desc: "Delayed cross-session trigger" },
  { id: "benign", label: "Benign baseline", desc: "Legitimate traffic (no noise)" },
];

const TITLES: Record<View, { title: string; sub: string }> = {
  overview: { title: "Operations Center", sub: "Live cross-agent threat correlation" },
  topology: { title: "Agent Swarm Topology", sub: "Protected swarm & guardian tier" },
  threats: { title: "Threat Feed", sub: "Verdicts, classifications & standards mapping" },
  trust: { title: "Trust & Risk", sub: "Per-agent behavioural scoring" },
  audit: { title: "Audit & Provenance", sub: "Hash-chained decision ledger" },
  settings: { title: "Integrations", sub: "Microsoft security stack status" },
};

export function CommandBar({
  view,
  token,
  state,
  onLogout,
}: {
  view: View;
  token: string;
  state: AegisState;
  onLogout: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [demoStep, setDemoStep] = useState<string | null>(null);
  const [menu, setMenu] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [chain, setChain] = useState<{ ok: boolean; message: string } | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenu(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  async function fire(id: AttackId) {
    setMenu(false);
    setBusy(id);
    try {
      await triggerAttack(token, id);
    } finally {
      setBusy(null);
    }
  }

  async function fireAll() {
    setMenu(false);
    setBusy("all");
    const steps = ["EchoLeak", "Spoof", "Memory Poison", "Benign"];
    let i = 0;
    setDemoStep(steps[0]);
    const tick = setInterval(() => {
      i += 1;
      if (i < steps.length) setDemoStep(steps[i]);
    }, 4500);
    try {
      await triggerFullDemo(token);
    } finally {
      clearInterval(tick);
      setBusy(null);
      setDemoStep(null);
    }
  }
  async function check() {
    setBusy("verify");
    setChain(null);
    try {
      setChain(await verifyChain(token));
      setTimeout(() => setChain(null), 6000);
    } finally {
      setBusy(null);
    }
  }

  const t = TITLES[view];
  const liveCount = Object.values(state.integrationReport).filter(
    (v) => v === "LIVE" || v.startsWith("azure") || v.startsWith("openai")
  ).length;
  const total = Object.keys(state.integrationReport).length || 6;

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-line bg-surface px-4">
      <div className="min-w-0">
        <h1 className="truncate text-[15px] font-semibold leading-tight text-ink">{t.title}</h1>
        <p className="truncate text-[11px] text-ink3">{t.sub}</p>
      </div>

      <div className="flex items-center gap-3">
        {/* environment */}
        <div className="hidden items-center gap-2 rounded-md border border-line bg-surface2 px-2.5 py-1.5 lg:flex">
          <StatusDot ok={liveCount === total} pulse />
          <span className="text-[11px] text-ink2">
            Azure <span className="font-semibold text-ink">{liveCount}/{total}</span> live
          </span>
        </div>

        {/* connection + clock */}
        <div className="hidden items-center gap-2 text-[11px] text-ink3 md:flex">
          <Radio size={13} className={state.connected ? "text-ok" : "text-critical"} />
          <span className="font-mono tnum text-ink2">{fmtClock(now)}</span>
          <span className="text-ink3">UTC</span>
        </div>

        <div className="h-6 w-px bg-line" />

        {chain && (
          <span className={cn("text-[11px] font-medium", chain.ok ? "text-ok" : "text-critical")}>
            {chain.ok ? "✓ chain intact" : "✗ chain broken"}
          </span>
        )}
        <button onClick={check} disabled={busy !== null} className="btn-icon" title="Verify audit chain">
          <ShieldCheck size={15} />
        </button>

        {/* scenario launcher */}
        <div className="relative" ref={menuRef}>
          <div className="flex gap-2">
            {/* Full Demo hero button */}
            <button
              onClick={fireAll}
              disabled={busy !== null}
              className="flex items-center gap-2 rounded-md border border-brand/60 bg-brand/12 px-3 py-1.5 text-[12px] font-semibold text-brand transition-colors hover:bg-brand/22 disabled:opacity-60"
              title="Run all 4 scenarios in sequence — accumulates all threats, quarantines, and guardian signals"
            >
              {busy === "all" ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  {demoStep ?? "Running…"}
                </>
              ) : (
                <>
                  <Zap size={13} />
                  Full Demo
                </>
              )}
            </button>

            <div className="flex">
              <button
                onClick={() => fire("echoleak")}
                disabled={busy !== null}
                className="flex items-center gap-2 rounded-l-md border border-critical/50 bg-critical/12 px-3 py-1.5 text-[12px] font-semibold text-critical transition-colors hover:bg-critical/20 disabled:opacity-60"
              >
                {busy === "echoleak" ? <Loader2 size={14} className="animate-spin" /> : <Play size={13} />}
                Run EchoLeak
              </button>
              <button
                onClick={() => setMenu((m) => !m)}
                disabled={busy !== null}
                className="rounded-r-md border border-l-0 border-critical/50 bg-critical/12 px-1.5 text-critical hover:bg-critical/20 disabled:opacity-60"
              >
                <ChevronDown size={14} />
              </button>
            </div>
          </div>
          {menu && (
            <div className="absolute right-0 top-full z-30 mt-1.5 w-72 overflow-hidden rounded-lg border border-line2 bg-surface2 shadow-pop">
              <div className="border-b border-line px-3 py-2 text-2xs uppercase tracking-wider text-ink3">
                Run sandboxed scenario
              </div>
              {SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => fire(s.id)}
                  className="flex w-full items-start gap-2 px-3 py-2 text-left transition-colors hover:bg-surface3"
                >
                  <Play size={12} className={cn("mt-1 shrink-0", s.hero ? "text-critical" : "text-ink3")} />
                  <div>
                    <div className={cn("text-[12px] font-medium", s.hero ? "text-critical" : "text-ink")}>{s.label}</div>
                    <div className="text-[11px] text-ink3">{s.desc}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        <button onClick={onLogout} className="btn-icon" title="Sign out">
          <LogOut size={15} />
        </button>
      </div>
    </header>
  );
}
