/**
 * Canonical AEGIS swarm model. Agent IDs match the live backend exactly
 * (aegis/victim + aegis/agents), so topology, trust, and quarantine state all
 * key off real telemetry — nothing here is mock.
 */

export type NodeKind = "ingress" | "agent" | "guardian" | "arbiter";

export interface SwarmNodeDef {
  id: string;
  label: string;
  sub: string;
  kind: NodeKind;
  /** layout position on the React Flow canvas */
  x: number;
  y: number;
}

export interface SwarmEdgeDef {
  id: string;
  source: string;
  target: string;
  /** part of the protected data pipeline (vs. a guardian observation link) */
  pipeline?: boolean;
  /** arbiter → pipeline control link: the verdict gates the outbound action */
  enforce?: boolean;
}

/**
 * Layout: the protected swarm runs left→right across the top pipeline row; the
 * guardian tier sits in a row beneath it; the Verdict Arbiter is a collector
 * centered BELOW the guardians. Each guardian drops straight down into the
 * arbiter, so the feeder edges fan through empty space and converge — none
 * crosses a node.
 */
export const SWARM_NODES: SwarmNodeDef[] = [
  { id: "ingress", label: "Inbound Email", sub: "external", kind: "ingress", x: 40, y: 150 },
  { id: "victim.orchestrator", label: "Orchestrator", sub: "planner", kind: "agent", x: 300, y: 150 },
  { id: "victim.email_triage", label: "Email Triage", sub: "agent", kind: "agent", x: 560, y: 40 },
  { id: "victim.summarizer", label: "Summarizer", sub: "agent", kind: "agent", x: 560, y: 260 },
  { id: "victim.tool_executor", label: "Tool Executor", sub: "send_email", kind: "agent", x: 840, y: 150 },

  // guardian tier (middle row) — observes the pipeline
  { id: "guardian.classifier", label: "Threat Classifier", sub: "Prompt Shields", kind: "guardian", x: 120, y: 420 },
  { id: "guardian.payload", label: "Payload Analyzer", sub: "provenance", kind: "guardian", x: 410, y: 420 },
  { id: "guardian.comms", label: "Comms Monitor", sub: "Entra Agent ID", kind: "guardian", x: 700, y: 420 },
  { id: "guardian.audit", label: "Audit Chain", sub: "hash-chained", kind: "guardian", x: 990, y: 420 },

  // collector — centered below the guardian row
  { id: "guardian.arbiter", label: "Verdict Arbiter", sub: "correlation", kind: "arbiter", x: 545, y: 610 },
];

export const SWARM_EDGES: SwarmEdgeDef[] = [
  { id: "e0", source: "ingress", target: "victim.orchestrator", pipeline: true },
  { id: "e1", source: "victim.orchestrator", target: "victim.email_triage", pipeline: true },
  { id: "e2", source: "victim.email_triage", target: "victim.summarizer", pipeline: true },
  { id: "e3", source: "victim.summarizer", target: "victim.tool_executor", pipeline: true },
  { id: "e4", source: "victim.orchestrator", target: "victim.tool_executor", pipeline: true },
  // guardian observation links feed the arbiter (drawn bottom→top, fan-in)
  { id: "g1", source: "guardian.classifier", target: "guardian.arbiter" },
  { id: "g2", source: "guardian.payload", target: "guardian.arbiter" },
  { id: "g3", source: "guardian.comms", target: "guardian.arbiter" },
  { id: "g4", source: "guardian.audit", target: "guardian.arbiter" },
  // enforcement: the arbiter's verdict gates the outbound action (Tool Executor)
  { id: "enf1", source: "guardian.arbiter", target: "victim.tool_executor", enforce: true },
];

export const VICTIM_IDS = SWARM_NODES.filter((n) => n.kind === "agent").map((n) => n.id);

export function isVictim(id: string): boolean {
  return VICTIM_IDS.includes(id);
}

/** Map a guardian display name (from a signal) to its node id. */
export function guardianNodeId(guardian: string): string | undefined {
  const g = guardian.toLowerCase();
  if (g.includes("threat") || g.includes("classif")) return "guardian.classifier";
  if (g.includes("payload")) return "guardian.payload";
  if (g.includes("comm")) return "guardian.comms";
  if (g.includes("audit") || g.includes("proven")) return "guardian.audit";
  if (g.includes("arbiter")) return "guardian.arbiter";
  return undefined;
}
