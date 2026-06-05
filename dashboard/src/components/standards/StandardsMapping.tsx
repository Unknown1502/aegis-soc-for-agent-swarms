import { useMemo } from "react";
import { Library } from "lucide-react";
import type { VerdictRow } from "@/state";
import { Panel } from "@/components/ui/Panel";
import { Empty, Tag } from "@/components/ui/bits";

const FRAMEWORKS = [
  { key: "owasp", label: "OWASP Agentic Top 10", prefix: "AAI", tone: "owasp" as const },
  { key: "maestro", label: "MAESTRO", test: (t: string) => /^l\d/i.test(t), tone: "maestro" as const },
  { key: "mitre", label: "MITRE ATLAS", prefix: "AML", tone: "mitre" as const },
];

export function StandardsMapping({ verdicts }: { verdicts: VerdictRow[] }) {
  const escalations = verdicts.filter((v) => v.decision !== "false_positive");

  const coverage = useMemo(() => {
    const sets: Record<string, Set<string>> = { owasp: new Set(), maestro: new Set(), mitre: new Set() };
    escalations.forEach((v) =>
      v.standards_chips.forEach((c) => {
        if (c.startsWith("AAI")) sets.owasp.add(c);
        else if (/^l\d/i.test(c)) sets.maestro.add(c);
        else if (c.startsWith("AML")) sets.mitre.add(c);
      })
    );
    return sets;
  }, [verdicts]);

  return (
    <Panel title="Standards Mapping" icon={<Library size={14} />} right={<span className="label">auto-mapped</span>} scroll>
      {/* coverage summary */}
      <div className="grid grid-cols-3 gap-2 border-b border-line p-3">
        {FRAMEWORKS.map((f) => {
          const tags = [...(coverage[f.key] ?? [])];
          return (
            <div key={f.key} className="rounded-md border border-line bg-surface2 p-2.5">
              <div className="label mb-1.5">{f.label}</div>
              {tags.length ? (
                <div className="flex flex-wrap gap-1">
                  {tags.map((t) => (
                    <Tag key={t} tone={f.tone}>
                      {t}
                    </Tag>
                  ))}
                </div>
              ) : (
                <span className="text-[11px] text-ink3">no mappings yet</span>
              )}
            </div>
          );
        })}
      </div>

      {/* per-incident mapping */}
      {escalations.length === 0 ? (
        <Empty>Confirmed incidents will be auto-mapped to OWASP / MAESTRO / MITRE here.</Empty>
      ) : (
        <div className="divide-y divide-line/70">
          {escalations.slice(0, 20).map((v) => (
            <div key={v.verdict_id} className="flex items-center justify-between gap-3 px-3.5 py-2.5">
              <div className="min-w-0">
                <div className="truncate text-[12px] text-ink2">{v.explanation}</div>
                <div className="text-[10px] uppercase tracking-wide text-ink3">{v.decision}</div>
              </div>
              <div className="flex shrink-0 flex-wrap justify-end gap-1">
                {v.standards_chips.map((c) => (
                  <Tag
                    key={c}
                    tone={c.startsWith("AAI") ? "owasp" : c.startsWith("AML") ? "mitre" : /^l\d/i.test(c) ? "maestro" : undefined}
                  >
                    {c}
                  </Tag>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
