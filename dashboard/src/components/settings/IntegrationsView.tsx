import { CheckCircle2, AlertTriangle, Mail, Ban } from "lucide-react";
import type { AegisState } from "@/state";
import { useMailbox } from "@/hooks/useApiData";
import { Panel } from "@/components/ui/Panel";
import { Empty } from "@/components/ui/bits";
import { cn } from "@/lib/cn";

const META: Record<string, { label: string; desc: string }> = {
  model_backend: { label: "Azure AI Foundry / OpenAI", desc: "Guardian model inference + trace spans" },
  prompt_shields: { label: "Azure AI Content Safety", desc: "Prompt Shields — one input feature, not the verdict" },
  entra_agent_id: { label: "Microsoft Entra Agent ID", desc: "Per-message OIDC identity verification" },
  defender: { label: "Defender for Cloud (AI)", desc: "AI threat alerts as corroborating signal" },
  azure_monitor: { label: "Azure Monitor", desc: "Operational metrics + verdict telemetry" },
  foundry_tracing: { label: "Foundry Tracing", desc: "OpenTelemetry spans per guardian decision" },
};

function isLive(v: string) {
  return v === "LIVE" || v.startsWith("azure") || v.startsWith("openai");
}

export function IntegrationsView({ state, token }: { state: AegisState; token: string }) {
  const report = Object.entries(state.integrationReport);
  const { data: mailbox } = useMailbox(token);

  return (
    <div className="grid h-full grid-cols-1 gap-3 lg:grid-cols-[1.3fr_1fr]">
      <Panel title="Microsoft Security Stack" className="h-full" right={<span className="label">{report.filter(([, v]) => isLive(v)).length}/{report.length} live</span>} scroll>
        <div className="divide-y divide-line/70">
          {report.length === 0 && <Empty>Awaiting status from the API…</Empty>}
          {report.map(([k, v]) => {
            const live = isLive(v);
            const m = META[k] ?? { label: k, desc: "" };
            return (
              <div key={k} className="flex items-center gap-3 px-3.5 py-3">
                <span
                  className={cn(
                    "grid h-8 w-8 shrink-0 place-items-center rounded-md",
                    live ? "bg-ok/12 text-ok" : "bg-high/12 text-high"
                  )}
                >
                  {live ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium text-ink">{m.label}</div>
                  <div className="truncate text-[11px] text-ink3">{m.desc}</div>
                </div>
                <span
                  className={cn(
                    "shrink-0 rounded px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide",
                    live ? "bg-ok/12 text-ok" : "bg-high/12 text-high"
                  )}
                >
                  {v}
                </span>
              </div>
            );
          })}
        </div>
        <div className="border-t border-line px-3.5 py-2.5 text-[11px] text-ink3">
          Every integration degrades safely — absent resources drop to a clearly-labeled local backend without
          stopping the guard.
        </div>
      </Panel>

      <Panel title="Protected Mailbox" icon={<Mail size={14} />} className="h-full" scroll>
        <div className="grid grid-cols-2 gap-2 border-b border-line p-3">
          <div className="rounded-md border border-line bg-surface2 p-2.5 text-center">
            <div className="font-mono text-2xl font-semibold text-ok tnum">{mailbox?.sent.length ?? 0}</div>
            <div className="label mt-1">Sent (allowed)</div>
          </div>
          <div className="rounded-md border border-line bg-surface2 p-2.5 text-center">
            <div className="font-mono text-2xl font-semibold text-critical tnum">{mailbox?.blocked.length ?? 0}</div>
            <div className="label mt-1">Blocked</div>
          </div>
        </div>
        <div className="divide-y divide-line/70">
          {(mailbox?.blocked ?? []).map((m) => (
            <div key={m.id} className="flex items-start gap-2 px-3.5 py-2.5">
              <Ban size={13} className="mt-0.5 shrink-0 text-critical" />
              <div className="min-w-0">
                <div className="truncate text-[12px] text-ink">{m.subject || "(no subject)"}</div>
                <div className="truncate text-[10px] text-ink3">→ {m.to.join(", ")}</div>
              </div>
            </div>
          ))}
          {(mailbox?.blocked.length ?? 0) === 0 && (
            <div className="px-3.5 py-3 text-[11px] text-ink3">No exfiltration attempts blocked yet.</div>
          )}
        </div>
      </Panel>
    </div>
  );
}
