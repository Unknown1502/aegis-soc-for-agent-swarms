import { useState } from "react";
import { Login } from "@/components/Login";
import { NavRail, type View } from "@/components/layout/NavRail";
import { CommandBar } from "@/components/layout/CommandBar";
import { CommandCenter } from "@/components/command-center/CommandCenter";
import { SwarmTopology } from "@/components/topology/SwarmTopology";
import { VerdictArbiter } from "@/components/arbiter/VerdictArbiter";
import { AttackTimeline } from "@/components/timeline/AttackTimeline";
import { ThreatFeed } from "@/components/threats/ThreatFeed";
import { ThreatHeatmap } from "@/components/heatmap/ThreatHeatmap";
import { StandardsMapping } from "@/components/standards/StandardsMapping";
import { TrustPanel } from "@/components/trust/TrustPanel";
import { ProvenanceExplorer } from "@/components/provenance/ProvenanceExplorer";
import { IntegrationsView } from "@/components/settings/IntegrationsView";
import { Panel } from "@/components/ui/Panel";
import { ErrorBoundary } from "@/components/ui/ErrorBoundary";
import { useAegisStream } from "@/hooks/useAegisStream";
import { Network } from "lucide-react";

/** Parse a one-shot deep link (#token=…&view=…) for demos/screenshots, stash
 *  the token into sessionStorage, and strip the hash from the URL immediately. */
let bootView: View = "overview";
function initialToken(): string | null {
  let token = sessionStorage.getItem("aegis_token");
  if (typeof location !== "undefined" && location.hash.length > 1) {
    const p = new URLSearchParams(location.hash.slice(1));
    const t = p.get("token");
    const v = p.get("view");
    if (v) bootView = v as View;
    if (t) {
      sessionStorage.setItem("aegis_token", t);
      token = t;
    }
    if (t || v) history.replaceState(null, "", location.pathname);
  }
  return token;
}

export function App() {
  const [token, setToken] = useState<string | null>(initialToken);
  const [view, setView] = useState<View>(bootView);
  const state = useAegisStream(token);

  if (!token) return <Login onAuthenticated={setToken} />;

  function logout() {
    sessionStorage.removeItem("aegis_token");
    setToken(null);
  }

  return (
    <div className="flex h-screen overflow-hidden bg-bg text-ink">
      <NavRail view={view} setView={setView} />
      <div className="flex min-w-0 flex-1 flex-col">
        <CommandBar view={view} token={token!} state={state} onLogout={logout} />
        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto overflow-x-hidden scroll p-3">
          {view === "overview" && (
            <div className="flex flex-col gap-3">
              <CommandCenter state={state} />
              <div className="grid min-w-0 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
                <div className="flex min-w-0 flex-col gap-3">
                  <Panel
                    title="Agent Swarm Topology"
                    icon={<Network size={14} />}
                    right={<TopoLegend />}
                    className="h-[440px]"
                    bodyClassName="relative"
                  >
                    <ErrorBoundary name="Swarm Topology">
                      <SwarmTopology state={state} />
                    </ErrorBoundary>
                  </Panel>
                  <div className="h-[340px]">
                    <AttackTimeline state={state} />
                  </div>
                </div>
                <div className="flex min-w-0 flex-col gap-3">
                  <div className="h-[440px]">
                    <VerdictArbiter verdicts={state.verdicts} />
                  </div>
                  <ThreatHeatmap verdicts={state.verdicts} />
                </div>
              </div>
            </div>
          )}

          {view === "topology" && (
            <Panel
              title="Agent Swarm Topology"
              icon={<Network size={14} />}
              right={<TopoLegend />}
              className="h-[calc(100vh-104px)]"
              bodyClassName="relative"
            >
              <ErrorBoundary name="Swarm Topology">
                <SwarmTopology state={state} />
              </ErrorBoundary>
            </Panel>
          )}

          {view === "threats" && (
            <div className="grid min-w-0 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
              <div className="h-[calc(100vh-104px)] min-w-0">
                <ThreatFeed verdicts={state.verdicts} />
              </div>
              <div className="flex min-w-0 flex-col gap-3">
                <ThreatHeatmap verdicts={state.verdicts} />
                <div className="min-h-[300px] flex-1">
                  <StandardsMapping verdicts={state.verdicts} />
                </div>
              </div>
            </div>
          )}

          {view === "trust" && (
            <div className="grid min-w-0 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <div className="h-[calc(100vh-104px)] min-w-0">
                <TrustPanel state={state} />
              </div>
              <Panel title="Swarm Topology" icon={<Network size={14} />} right={<TopoLegend />} bodyClassName="relative">
                <ErrorBoundary name="Swarm Topology">
                  <SwarmTopology state={state} />
                </ErrorBoundary>
              </Panel>
            </div>
          )}

          {view === "audit" && (
            <div className="h-[calc(100vh-104px)]">
              <ProvenanceExplorer token={token!} />
            </div>
          )}

          {view === "settings" && (
            <div className="h-[calc(100vh-104px)]">
              <IntegrationsView state={state} token={token!} />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function TopoLegend() {
  const items = [
    { c: "#3fb950", l: "trusted" },
    { c: "#f0883e", l: "degraded" },
    { c: "#f85149", l: "quarantined" },
    { c: "#3b9eff", l: "active flow" },
  ];
  return (
    <div className="hidden items-center gap-3 md:flex">
      {items.map((i) => (
        <span key={i.l} className="flex items-center gap-1 text-[10px] text-ink3">
          <span className="h-2 w-2 rounded-full" style={{ background: i.c }} />
          {i.l}
        </span>
      ))}
    </div>
  );
}
