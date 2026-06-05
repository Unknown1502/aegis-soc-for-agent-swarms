import { useState } from "react";
import { ScrollText, ShieldCheck, Link2, Loader2 } from "lucide-react";
import { verifyChain } from "@/api";
import { useAudit, type AuditEntry } from "@/hooks/useApiData";
import { Panel } from "@/components/ui/Panel";
import { Empty } from "@/components/ui/bits";
import { fmtClockMs, shortHash } from "@/lib/format";
import { cn } from "@/lib/cn";

const KIND_HEX: Record<string, string> = {
  action: "#58a6ff",
  signal: "#bc8cff",
  verdict: "#f0883e",
  provenance: "#3fb950",
};

export function ProvenanceExplorer({ token }: { token: string }) {
  const { data: entries = [], isLoading } = useAudit(token, 200);
  const [sel, setSel] = useState<AuditEntry | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  const ordered = [...entries].reverse(); // newest first
  const selected = sel ?? ordered[0];

  async function verify() {
    setVerifying(true);
    setResult(null);
    try {
      setResult(await verifyChain(token));
    } catch {
      setResult({ ok: false, message: "request failed" });
    } finally {
      setVerifying(false);
    }
  }

  return (
    <Panel
      title="Provenance Explorer"
      icon={<ScrollText size={14} />}
      className="h-full"
      right={
        <div className="flex items-center gap-2">
          {result && (
            <span className={cn("text-[11px] font-medium", result.ok ? "text-ok" : "text-critical")}>
              {result.ok ? `✓ ${result.message}` : `✗ ${result.message}`}
            </span>
          )}
          <button
            onClick={verify}
            disabled={verifying}
            className="flex items-center gap-1.5 rounded-md border border-brand/40 px-2 py-1 text-[11px] font-medium text-brand transition-colors hover:bg-brand/10"
          >
            {verifying ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
            Verify integrity
          </button>
        </div>
      }
    >
      {isLoading && entries.length === 0 ? (
        <Empty>Loading hash-chained ledger…</Empty>
      ) : ordered.length === 0 ? (
        <Empty>Chain is empty. Launch a scenario to populate the ledger.</Empty>
      ) : (
        <div className="grid h-full grid-cols-[1fr_300px]">
          {/* ledger list */}
          <div className="overflow-y-auto scroll border-r border-line">
            <div className="grid grid-cols-[44px_1fr_120px] gap-2 border-b border-line px-3 py-1.5 label">
              <span>#</span>
              <span>Entry</span>
              <span>Hash</span>
            </div>
            {ordered.map((e) => {
              const hex = KIND_HEX[e.kind] ?? "#aab3c2";
              const active = selected?.entry_hash === e.entry_hash;
              return (
                <button
                  key={e.seq + e.entry_hash.slice(0, 6)}
                  onClick={() => setSel(e)}
                  className={cn(
                    "grid w-full grid-cols-[44px_1fr_120px] items-center gap-2 border-b border-line/60 px-3 py-2 text-left transition-colors",
                    active ? "bg-brand/8" : "hover:bg-surface2"
                  )}
                >
                  <span className="font-mono text-[11px] tnum text-ink3">{e.seq}</span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-1.5">
                      <span
                        className="rounded px-1 py-0.5 text-[9px] font-semibold uppercase"
                        style={{ color: hex, background: `${hex}1a` }}
                      >
                        {e.kind}
                      </span>
                      <span className="truncate text-[11px] text-ink2">{summarise(e.payload)}</span>
                    </span>
                  </span>
                  <span className="truncate font-mono text-[10px] text-ink3">{shortHash(e.entry_hash, 12)}</span>
                </button>
              );
            })}
          </div>

          {/* detail */}
          <div className="overflow-y-auto scroll p-3.5">
            {selected && (
              <div className="space-y-3 animate-fade-in">
                <div>
                  <div className="label mb-1">Ledger entry</div>
                  <div className="font-mono text-[13px] font-semibold text-ink">#{selected.seq} · {selected.kind}</div>
                  <div className="text-[11px] text-ink3">{fmtClockMs(selected.timestamp_unix_ms)} UTC</div>
                </div>
                <HashRow icon label="entry hash" value={selected.entry_hash} hex="#3fb950" />
                <div className="flex justify-center text-ink3">
                  <Link2 size={13} />
                </div>
                <HashRow label="prev hash" value={selected.prev_hash} hex="#58a6ff" />
                <div>
                  <div className="label mb-1">Payload</div>
                  <pre className="max-h-48 overflow-auto scroll rounded-md border border-line bg-bg p-2 font-mono text-[10px] leading-relaxed text-ink2">
                    {JSON.stringify(selected.payload, null, 2)}
                  </pre>
                </div>
                <div className="flex items-center gap-1.5 rounded-md border border-line bg-surface2 px-2.5 py-2 text-[11px] text-ink3">
                  <ShieldCheck size={13} className="text-ok" />
                  Each entry's hash includes the previous hash — tampering breaks the chain.
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}

function HashRow({ label, value, hex, icon }: { label: string; value: string; hex: string; icon?: boolean }) {
  return (
    <div className="rounded-md border border-line bg-surface2 p-2.5">
      <div className="mb-1 flex items-center gap-1.5">
        {icon && <span className="h-1.5 w-1.5 rounded-full" style={{ background: hex }} />}
        <span className="label">{label}</span>
      </div>
      <div className="break-all font-mono text-[10px] leading-relaxed" style={{ color: hex }}>
        {value}
      </div>
    </div>
  );
}

function summarise(p: Record<string, any>): string {
  if (p.action_id) return `${p.source ?? ""}${p.target ? "→" + p.target : ""}${p.tool ? " · " + p.tool : ""}`;
  if (p.signal_id) return `${p.guardian} · ${p.label}`;
  if (p.verdict_id) return `${p.decision}/${p.severity} → ${p.outcome}`;
  if (p.data_id) return `provenance ${p.data_id} (${p.sensitivity})`;
  return JSON.stringify(p).slice(0, 80);
}
