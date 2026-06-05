import { useMemo } from "react";
import { Flame } from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Cell, Tooltip } from "recharts";
import type { VerdictRow } from "@/state";
import { Panel } from "@/components/ui/Panel";

const CATEGORIES = [
  "Prompt Injection",
  "Identity Spoofing",
  "Memory Poisoning",
  "Tool Abuse",
  "Data Exfiltration",
  "Agent Impersonation",
];

function categorize(v: VerdictRow): string[] {
  const b = (v.explanation + " " + v.standards_chips.join(" ")).toLowerCase();
  const out: string[] = [];
  if (b.includes("inject") || b.includes("aai01") || b.includes("aai02") || b.includes("jailbreak"))
    out.push("Prompt Injection");
  if (b.includes("spoof") || b.includes("aai05")) out.push("Identity Spoofing", "Agent Impersonation");
  if (b.includes("memory") || b.includes("aai04")) out.push("Memory Poisoning");
  if (b.includes("tool") || b.includes("send_email") || b.includes("execut")) out.push("Tool Abuse");
  if (b.includes("exfil") || b.includes("provenance") || b.includes("leak")) out.push("Data Exfiltration");
  return out.length ? out : [];
}

function barColor(n: number): string {
  if (n >= 4) return "#f85149";
  if (n >= 2) return "#f0883e";
  if (n >= 1) return "#d29922";
  return "#212836";
}

export function ThreatHeatmap({ verdicts }: { verdicts: VerdictRow[] }) {
  const data = useMemo(() => {
    const counts: Record<string, number> = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
    verdicts
      .filter((v) => v.decision !== "false_positive")
      .forEach((v) => categorize(v).forEach((c) => (counts[c] += 1)));
    return CATEGORIES.map((name) => ({ name, value: counts[name] }));
  }, [verdicts]);

  const total = data.reduce((a, b) => a + b.value, 0);

  return (
    <Panel
      title="Threat Heatmap"
      icon={<Flame size={14} />}
      right={<span className="label">{total} detections</span>}
    >
      <div className="h-[230px] w-full min-w-0 overflow-hidden p-3">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 8 }} barCategoryGap={6}>
            <XAxis type="number" hide domain={[0, "dataMax"]} allowDecimals={false} />
            <YAxis
              type="category"
              dataKey="name"
              width={118}
              tick={{ fill: "#aab3c2", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: "rgba(255,255,255,0.03)" }}
              contentStyle={{
                background: "#141923",
                border: "1px solid #2b3445",
                borderRadius: 8,
                fontSize: 12,
              }}
              labelStyle={{ color: "#e6e9ef" }}
              itemStyle={{ color: "#aab3c2" }}
            />
            <Bar dataKey="value" radius={[0, 3, 3, 0]} barSize={16} background={{ fill: "#11151d" }}>
              {data.map((d) => (
                <Cell key={d.name} fill={barColor(d.value)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="border-t border-line px-3 py-2 text-[11px] text-ink3">
        Concentration across the agentic attack surface. Bars weight by confirmed/probable verdicts.
      </div>
    </Panel>
  );
}
