/** Formatting helpers shared across the console. */

export function fmtClock(ms: number): string {
  return new Date(ms).toISOString().slice(11, 19);
}

export function fmtClockMs(ms: number): string {
  return new Date(ms).toISOString().slice(11, 23);
}

export function relTime(ms: number, now = Date.now()): string {
  const d = Math.max(0, now - ms);
  const s = Math.floor(d / 1000);
  if (s < 1) return "now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

export function pct(n: number, digits = 0): string {
  return `${(n * 100).toFixed(digits)}%`;
}

export function shortHash(h: string | undefined, n = 10): string {
  if (!h) return "—";
  return h.length > n ? `${h.slice(0, n)}…` : h;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Decision = "confirmed" | "probable" | "false_positive";

export const SEVERITY_HEX: Record<string, string> = {
  critical: "#f85149",
  high: "#f0883e",
  medium: "#d29922",
  low: "#3fb950",
  info: "#58a6ff",
};

export const DECISION_META: Record<
  string,
  { label: string; hex: string; text: string; bg: string; ring: string }
> = {
  confirmed: {
    label: "Confirmed",
    hex: "#f85149",
    text: "text-critical",
    bg: "bg-critical/10",
    ring: "ring-critical/40",
  },
  probable: {
    label: "Probable",
    hex: "#f0883e",
    text: "text-high",
    bg: "bg-high/10",
    ring: "ring-high/40",
  },
  false_positive: {
    label: "Cleared",
    hex: "#3fb950",
    text: "text-low",
    bg: "bg-low/5",
    ring: "ring-low/30",
  },
};

export function decisionMeta(d: string) {
  return DECISION_META[d] ?? DECISION_META.false_positive;
}
