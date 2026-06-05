import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Bot, Mail, FileText, Send, Lock, ShieldCheck, Scale, Inbox } from "lucide-react";
import { cn } from "@/lib/cn";

export interface AgentNodeData {
  label: string;
  sub: string;
  trust: number;
  quarantined: boolean;
  active: boolean;
  [key: string]: unknown;
}

export interface GuardianNodeData {
  label: string;
  sub: string;
  firing: boolean;
  status?: "idle" | "benign" | "flagged";
  lastLabel?: string;
  [key: string]: unknown;
}

const AGENT_ICON: Record<string, typeof Bot> = {
  Orchestrator: Bot,
  "Email Triage": Mail,
  Summarizer: FileText,
  "Tool Executor": Send,
};

function trustHex(t: number, q: boolean): string {
  if (q) return "#f85149";
  if (t < 0.4) return "#f85149";
  if (t < 0.7) return "#f0883e";
  return "#3fb950";
}

const Anchors = () => (
  <>
    <Handle type="target" position={Position.Left} id="left" />
    <Handle type="source" position={Position.Right} id="right" />
    <Handle type="target" position={Position.Top} id="t" />
    <Handle type="source" position={Position.Bottom} id="b" />
    {/* bottom-as-target: lets the arbiter's enforcement link enter a node from
        below without colliding with the top-down pipeline flow */}
    <Handle type="target" position={Position.Bottom} id="bt" />
  </>
);

export function AgentNode({ data }: NodeProps) {
  const d = data as AgentNodeData;
  const hex = trustHex(d.trust, d.quarantined);
  const Icon = AGENT_ICON[d.label] ?? Bot;
  return (
    <div
      className={cn(
        "w-[176px] rounded-lg border bg-surface2 px-3 py-2.5 shadow-card transition-colors",
        d.quarantined ? "border-critical" : d.active ? "border-brand/70" : "border-line2"
      )}
      style={d.quarantined ? { boxShadow: "0 0 0 1px #f85149, 0 0 22px -8px #f85149" } : undefined}
    >
      <Anchors />
      <div className="flex items-center gap-2">
        <span className="grid h-7 w-7 place-items-center rounded-md" style={{ background: `${hex}1f`, color: hex }}>
          {d.quarantined ? <Lock size={14} /> : <Icon size={14} />}
        </span>
        <div className="min-w-0">
          <div className="truncate text-[12px] font-semibold text-ink">{d.label}</div>
          <div className="truncate text-[10px] text-ink3">{d.sub}</div>
        </div>
      </div>
      <div className="mt-2 flex items-center gap-2">
        <div className="h-1 flex-1 overflow-hidden rounded-full bg-surface3">
          <div className="h-full rounded-full transition-all" style={{ width: `${d.trust * 100}%`, background: hex }} />
        </div>
        <span className="font-mono text-[10px] tnum" style={{ color: hex }}>
          {Math.round(d.trust * 100)}
        </span>
      </div>
      {d.quarantined && (
        <div className="mt-1.5 text-center text-[9px] font-bold uppercase tracking-wider text-critical">
          ◉ Quarantined
        </div>
      )}
    </div>
  );
}

export function GuardianNode({ data }: NodeProps) {
  const d = data as GuardianNodeData;
  const status = d.status ?? "idle";
  const dot = status === "flagged" ? "#f85149" : status === "benign" ? "#3fb950" : "#3a4760";
  const statusText = status === "flagged" ? "SIGNAL" : status === "benign" ? "clear" : "monitoring";
  return (
    <div
      className={cn(
        "w-[168px] rounded-lg border bg-surface px-3 py-2 transition-colors",
        d.firing ? "border-brand/70 bg-brand/5" : "border-line"
      )}
    >
      <Anchors />
      <div className="flex items-center gap-2">
        <ShieldCheck size={13} className={d.firing ? "text-brand" : "text-ink3"} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[11px] font-semibold text-ink2">{d.label}</div>
          <div className="truncate text-[9px] uppercase tracking-wide text-ink3">{d.sub}</div>
        </div>
        <span
          className={cn("h-1.5 w-1.5 shrink-0 rounded-full", d.firing && status === "flagged" && "animate-pulse-dot")}
          style={{ background: dot }}
          title={statusText}
        />
      </div>
      <div className="mt-1.5 flex items-center justify-between border-t border-line/70 pt-1.5">
        <span className="text-[8px] uppercase tracking-wider" style={{ color: dot }}>
          {statusText}
        </span>
        <span className="truncate pl-1 text-[8px] text-ink3" title={d.lastLabel}>
          {d.lastLabel ? d.lastLabel.slice(0, 18) : "—"}
        </span>
      </div>
    </div>
  );
}

export function ArbiterNode({ data }: NodeProps) {
  const d = data as GuardianNodeData;
  return (
    <div
      className={cn(
        "w-[164px] rounded-lg border px-3 py-2.5 transition-colors",
        d.firing ? "border-brand bg-brand/10" : "border-brand/40 bg-brand/5"
      )}
    >
      <Anchors />
      <div className="flex items-center gap-2">
        <span className="grid h-7 w-7 place-items-center rounded-md bg-brand/15 text-brand">
          <Scale size={15} />
        </span>
        <div>
          <div className="text-[12px] font-bold text-ink">{d.label}</div>
          <div className="text-[9px] uppercase tracking-wide text-ink3">{d.sub}</div>
        </div>
      </div>
    </div>
  );
}

export function IngressNode({ data }: NodeProps) {
  const d = data as { label: string; sub: string };
  return (
    <div className="w-[130px] rounded-lg border border-dashed border-line2 bg-surface px-3 py-2.5">
      <Anchors />
      <div className="flex items-center gap-2">
        <Inbox size={14} className="text-ink3" />
        <div>
          <div className="text-[11px] font-semibold text-ink2">{d.label}</div>
          <div className="text-[9px] uppercase tracking-wide text-ink3">{d.sub}</div>
        </div>
      </div>
    </div>
  );
}

export const nodeTypes = {
  agent: AgentNode,
  guardian: GuardianNode,
  arbiter: ArbiterNode,
  ingress: IngressNode,
};
