import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  type Node,
  type Edge,
  type CoordinateExtent,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { AegisState } from "@/state";
import { SWARM_NODES, SWARM_EDGES, guardianNodeId } from "@/lib/swarm";
import { nodeTypes } from "./nodes";

const C_LINE = "#2b3445";
const C_IDLE = "#3a4760";
const C_BRAND = "#3b9eff";
const C_CRIT = "#f85149";
const C_ENFORCE = "#f0883e";

// Bounds the pannable area to the swarm's footprint so the fixed viewport can
// never drift off the nodes. Generous margin around the node coordinate span.
const DEFAULT_EXTENT: CoordinateExtent = [
  [-200, -200],
  [1400, 900],
];

const benignLabel = (l: string) => /benign|clean|none|no.?threat|low|valid|negative/i.test(l);

export function SwarmTopology({ state }: { state: AegisState }) {
  const { nodes, edges } = useMemo(() => {
    const recentActions = state.actions.slice(0, 16);
    const hopSet = new Set(
      recentActions.filter((a) => a.target_agent_id).map((a) => `${a.source_agent_id}->${a.target_agent_id}`)
    );
    const touched = new Set<string>();
    recentActions.forEach((a) => {
      touched.add(a.source_agent_id);
      if (a.target_agent_id) touched.add(a.target_agent_id);
    });
    const anyRecent = recentActions.length > 0;
    const lastVerdict = state.verdicts[0];
    const verdictFresh = Boolean(lastVerdict && Date.now() - lastVerdict.ts_unix_ms < 20000);

    // Latest signal per guardian node → drives the node's live status.
    const guardianSig: Record<string, { label: string; flagged: boolean }> = {};
    for (const s of state.signals) {
      const nid = guardianNodeId(s.guardian);
      if (nid && !(nid in guardianSig)) {
        guardianSig[nid] = { label: s.label, flagged: !benignLabel(s.label) };
      }
    }

    const nodes: Node[] = SWARM_NODES.map((n) => {
      const quarantined = state.quarantine[n.id] !== undefined;
      const trust = state.trust[n.id]?.score ?? 1;
      if (n.kind === "agent") {
        return {
          id: n.id,
          type: "agent",
          position: { x: n.x, y: n.y },
          data: { label: n.label, sub: n.sub, trust, quarantined, active: touched.has(n.id) },
          draggable: true,
        };
      }
      if (n.kind === "arbiter") {
        return {
          id: n.id,
          type: "arbiter",
          position: { x: n.x, y: n.y },
          data: { label: n.label, sub: n.sub, firing: verdictFresh },
          draggable: true,
        };
      }
      if (n.kind === "guardian") {
        const sig = guardianSig[n.id];
        const status = sig ? (sig.flagged ? "flagged" : "benign") : "idle";
        return {
          id: n.id,
          type: "guardian",
          position: { x: n.x, y: n.y },
          data: { label: n.label, sub: n.sub, firing: verdictFresh, status, lastLabel: sig?.label },
          draggable: true,
        };
      }
      return {
        id: n.id,
        type: "ingress",
        position: { x: n.x, y: n.y },
        data: { label: n.label, sub: n.sub },
        draggable: true,
      };
    });

    const edges: Edge[] = SWARM_EDGES.map((e) => {
      const isFeeder = e.target === "guardian.arbiter";

      if (e.enforce) {
        // Arbiter → pipeline control link. The verdict gates the outbound
        // action; lights red + animated when the executor is quarantined
        // (the arbiter actively enforcing a block), amber otherwise.
        const blocking = state.quarantine[e.target] !== undefined;
        const stroke = blocking ? C_CRIT : C_ENFORCE;
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "smoothstep",
          sourceHandle: "right",
          targetHandle: "bt",
          label: "GATES",
          labelStyle: { fill: stroke, fontSize: 9, fontWeight: 700, letterSpacing: 0.5 },
          labelBgStyle: { fill: "#0d1117", fillOpacity: 0.85 },
          labelBgPadding: [4, 2] as [number, number],
          animated: blocking,
          style: {
            stroke,
            strokeWidth: blocking ? 2 : 1.4,
            strokeDasharray: "2 3",
            opacity: blocking ? 1 : 0.7,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
        };
      }

      if (e.pipeline && !isFeeder) {
        const hop = `${e.source}->${e.target}`;
        const isIngress = e.source === "ingress";
        const live = hopSet.has(hop) || (isIngress && anyRecent);
        const targetQ = state.quarantine[e.target] !== undefined;
        const stroke = targetQ ? C_CRIT : live ? C_BRAND : C_LINE;
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          sourceHandle: "right",
          targetHandle: "left",
          animated: live,
          style: { stroke, strokeWidth: live || targetQ ? 2 : 1.4 },
          markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 16, height: 16 },
        };
      }

      // Guardian feeder links — straight diagonal from each guardian's bottom
      // handle to the arbiter's top handle. "straight" type draws a direct line
      // with no horizontal routing, so left-side guardians never cross right-side
      // guardians' edges.
      const sourceQ = state.quarantine[e.source] !== undefined;
      const active = verdictFresh;
      const stroke = sourceQ ? C_CRIT : active ? C_BRAND : C_IDLE;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: "straight",
        sourceHandle: "b",
        targetHandle: "t",
        animated: active,
        style: {
          stroke,
          strokeWidth: active ? 1.8 : 1.2,
          strokeDasharray: active ? undefined : "5 4",
          opacity: active ? 1 : 0.55,
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 13, height: 13 },
      };
    });

    return { nodes, edges };
  }, [state.actions, state.trust, state.quarantine, state.verdicts, state.signals]);

  return (
    <div className="h-full w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        proOptions={{ hideAttribution: true }}
        // Fixed viewport — NO fitView. fitView re-fits whenever the nodes/edges
        // arrays change identity (every streamed verdict/signal), and at the
        // moment a verdict lands that re-fit can resolve to a bad transform that
        // hides the graph. A hardcoded defaultViewport (computed from the known
        // node coordinates) renders the graph at a stable position immediately
        // and never recomputes, so it can't vanish on a verdict.
        defaultViewport={{ x: 24, y: 28, zoom: 0.5 }}
        minZoom={0.5}
        maxZoom={0.5}
        translateExtent={DEFAULT_EXTENT}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        zoomOnScroll={false}
        zoomOnPinch={false}
        zoomOnDoubleClick={false}
        panOnScroll={false}
        panOnDrag={false}
        preventScrolling={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#1b2230" />
      </ReactFlow>
    </div>
  );
}
