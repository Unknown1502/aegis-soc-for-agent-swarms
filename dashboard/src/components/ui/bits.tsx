import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { decisionMeta, SEVERITY_HEX } from "@/lib/format";

/** Small status dot with optional live pulse. */
export function StatusDot({ ok, pulse, className }: { ok: boolean; pulse?: boolean; className?: string }) {
  return (
    <span
      className={cn(
        "inline-block h-2 w-2 rounded-full",
        ok ? "bg-ok" : "bg-critical",
        ok && pulse && "animate-pulse-dot",
        className
      )}
    />
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const hex = SEVERITY_HEX[severity] ?? SEVERITY_HEX.info;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide"
      style={{ color: hex, background: `${hex}1a` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: hex }} />
      {severity}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: string }) {
  const m = decisionMeta(decision);
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-2xs font-bold uppercase tracking-wider"
      style={{ color: m.hex, background: `${m.hex}1a` }}
    >
      {m.label}
    </span>
  );
}

/** A labelled standards chip (OWASP / MAESTRO / MITRE). */
export function Tag({ children, tone }: { children: ReactNode; tone?: "owasp" | "maestro" | "mitre" }) {
  const color =
    tone === "owasp" ? "#58a6ff" : tone === "mitre" ? "#bc8cff" : tone === "maestro" ? "#3fb950" : "#aab3c2";
  return (
    <span
      className="rounded border px-1.5 py-0.5 font-mono text-2xs"
      style={{ color, borderColor: `${color}40`, background: `${color}12` }}
    >
      {children}
    </span>
  );
}

export function KeyVal({ k, v, mono }: { k: string; v: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="label">{k}</span>
      <span className={cn("text-xs text-ink2 text-right", mono && "font-mono")}>{v}</span>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="flex h-full items-center justify-center p-6 text-center text-xs text-ink3">{children}</div>;
}
