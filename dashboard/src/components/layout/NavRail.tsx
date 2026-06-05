import {
  LayoutGrid,
  Network,
  ShieldAlert,
  GaugeCircle,
  ScrollText,
  SlidersHorizontal,
  ShieldHalf,
  CircleUser,
} from "lucide-react";
import { cn } from "@/lib/cn";

export type View = "overview" | "topology" | "threats" | "trust" | "audit" | "settings";

const NAV: { id: View; label: string; icon: typeof LayoutGrid; group: string }[] = [
  { id: "overview", label: "Operations", icon: LayoutGrid, group: "Monitor" },
  { id: "topology", label: "Swarm Topology", icon: Network, group: "Monitor" },
  { id: "threats", label: "Threat Feed", icon: ShieldAlert, group: "Investigate" },
  { id: "trust", label: "Trust & Risk", icon: GaugeCircle, group: "Investigate" },
  { id: "audit", label: "Audit & Provenance", icon: ScrollText, group: "Investigate" },
  { id: "settings", label: "Integrations", icon: SlidersHorizontal, group: "Admin" },
];

export function NavRail({ view, setView }: { view: View; setView: (v: View) => void }) {
  const groups = Array.from(new Set(NAV.map((n) => n.group)));
  return (
    <nav className="flex w-[220px] shrink-0 flex-col border-r border-line bg-surface">
      {/* brand */}
      <div className="flex h-14 items-center gap-2.5 border-b border-line px-4">
        <div className="grid h-7 w-7 place-items-center rounded-md bg-brand/15 ring-1 ring-brand/30">
          <ShieldHalf size={16} className="text-brand" />
        </div>
        <div className="leading-tight">
          <div className="text-[13px] font-bold tracking-wide text-ink">AEGIS</div>
          <div className="text-[9px] uppercase tracking-[0.18em] text-ink3">SOC for Agent Swarms</div>
        </div>
      </div>

      {/* nav groups */}
      <div className="flex-1 overflow-y-auto scroll px-2.5 py-3">
        {groups.map((g) => (
          <div key={g} className="mb-4">
            <div className="px-2 pb-1.5 text-[9px] font-semibold uppercase tracking-[0.16em] text-ink3">{g}</div>
            <div className="space-y-0.5">
              {NAV.filter((n) => n.group === g).map((n) => {
                const active = view === n.id;
                const Icon = n.icon;
                return (
                  <button
                    key={n.id}
                    onClick={() => setView(n.id)}
                    className={cn(
                      "group flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] transition-colors",
                      active
                        ? "bg-brand/12 text-ink"
                        : "text-ink2 hover:bg-surface2 hover:text-ink"
                    )}
                  >
                    <span
                      className={cn(
                        "absolute left-0 h-5 w-0.5 rounded-r bg-brand transition-opacity",
                        active ? "opacity-100" : "opacity-0"
                      )}
                      style={{ marginLeft: "-10px" }}
                    />
                    <Icon size={16} className={active ? "text-brand" : "text-ink3 group-hover:text-ink2"} />
                    <span className="font-medium">{n.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* user */}
      <div className="flex items-center gap-2.5 border-t border-line px-3 py-3">
        <div className="grid h-7 w-7 place-items-center rounded-full bg-surface3 ring-1 ring-line2">
          <CircleUser size={16} className="text-ink2" />
        </div>
        <div className="leading-tight">
          <div className="text-[12px] font-medium text-ink">analyst</div>
          <div className="text-[10px] text-ink3">Tier-2 · read/respond</div>
        </div>
      </div>
    </nav>
  );
}
