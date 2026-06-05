/**
 * In-browser event store for the AEGIS dashboard.
 *
 * Holds the rolling windows the panels render:
 *   - verdicts (newest first)
 *   - signals  (newest first)
 *   - actions  (newest first)
 *   - outcomes (action_id -> outcome)
 *   - trust    (agent_id -> score)
 *   - threshold history
 *   - metrics snapshot from the latest 'hello' / 'status' poll
 *
 * Backed by a tiny pub/sub so React components subscribe and rerender
 * without an external store dependency.
 */

import type { MetricsSnapshot, StreamEvent } from "./api";

export interface VerdictRow {
  verdict_id: string;
  decision: "confirmed" | "probable" | "false_positive";
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  explanation: string;
  target_action_id: string;
  target_agent_id?: string;
  correlation_id: string;
  sequence_action_ids: string[];
  standards_chips: string[];
  ts_unix_ms: number;
  contributing_signals: any[];
}

export interface ActionRow {
  action_id: string;
  correlation_id: string;
  source_agent_id: string;
  target_agent_id?: string | null;
  action_type: string;
  tool_name?: string | null;
  text_excerpt: string;
  ts_unix_ms: number;
  outcome?: string;
}

export interface SignalRow {
  signal_id: string;
  guardian: string;
  action_id: string;
  label: string;
  confidence: number;
  evidence: string;
  ts_unix_ms: number;
}

export interface TrustRow {
  agent_id: string;
  score: number;
  last_change_unix_ms: number;
}

export interface ThresholdRow {
  when_unix_ms: number;
  name: string;
  old: number;
  new: number;
  reason: string;
}

export interface AegisState {
  connected: boolean;
  verdicts: VerdictRow[];
  signals: SignalRow[];
  actions: ActionRow[];
  trust: Record<string, TrustRow>;
  thresholds: ThresholdRow[];
  quarantine: Record<string, string>;
  metrics: MetricsSnapshot;
  integrationReport: Record<string, string>;
  suppressedTotal: number;
}

const MAX = 200;

const defaultMetrics: MetricsSnapshot = {
  counters: {},
  fp_rate: 0,
  mean_time_to_verdict_ms: 0,
  trust_scores: [],
  threshold_history: [],
};

let _state: AegisState = {
  connected: false,
  verdicts: [],
  signals: [],
  actions: [],
  trust: {},
  thresholds: [],
  quarantine: {},
  metrics: defaultMetrics,
  integrationReport: {},
  suppressedTotal: 0,
};

type Listener = (s: AegisState) => void;
const listeners = new Set<Listener>();

function emit() {
  for (const l of listeners) l(_state);
}

export function subscribe(l: Listener): () => void {
  listeners.add(l);
  l(_state);
  return () => listeners.delete(l);
}

export function getState(): AegisState {
  return _state;
}

export function setConnected(c: boolean) {
  _state = { ..._state, connected: c };
  emit();
}

export function applyHello(payload: any) {
  _state = {
    ..._state,
    integrationReport: payload.integration_report ?? {},
    metrics: payload.metrics_snapshot ?? defaultMetrics,
    quarantine: payload.quarantine ?? {},
    trust: Object.fromEntries(
      (payload.metrics_snapshot?.trust_scores ?? []).map((t: TrustRow) => [
        t.agent_id,
        t,
      ])
    ),
    thresholds: payload.metrics_snapshot?.threshold_history ?? [],
  };
  emit();
}

export function applyStatus(s: { metrics_snapshot: MetricsSnapshot; quarantine: Record<string, string>; integration_report: Record<string, string> }) {
  _state = {
    ..._state,
    metrics: s.metrics_snapshot,
    quarantine: s.quarantine,
    integrationReport: s.integration_report,
    trust: Object.fromEntries(
      (s.metrics_snapshot.trust_scores ?? []).map((t) => [t.agent_id, t])
    ),
    thresholds: s.metrics_snapshot.threshold_history ?? [],
  };
  emit();
}

export function handleEvent(evt: StreamEvent) {
  switch (evt.topic) {
    case "hello":
      applyHello(evt.payload);
      return;
    case "aegis.action": {
      const a = evt.payload;
      const row: ActionRow = {
        action_id: a.action_id,
        correlation_id: a.correlation_id,
        source_agent_id: a.source_agent_id,
        target_agent_id: a.target_agent_id ?? null,
        action_type: a.action_type,
        tool_name: a.tool_name ?? null,
        text_excerpt: (a.text_content ?? "").slice(0, 160),
        ts_unix_ms: evt.ts_unix_ms,
      };
      _state = {
        ..._state,
        actions: [row, ..._state.actions].slice(0, MAX),
      };
      emit();
      return;
    }
    case "aegis.signal": {
      const s = evt.payload;
      const row: SignalRow = {
        signal_id: s.signal_id,
        guardian: s.guardian,
        action_id: s.action_id,
        label: s.label,
        confidence: s.confidence,
        evidence: s.evidence,
        ts_unix_ms: evt.ts_unix_ms,
      };
      _state = { ..._state, signals: [row, ..._state.signals].slice(0, MAX) };
      emit();
      return;
    }
    case "aegis.verdict": {
      const v = evt.payload;
      const chips: string[] = [];
      for (const tag of v.standards_tags ?? []) {
        if (tag.owasp) chips.push(tag.owasp);
        if (tag.maestro) chips.push(tag.maestro);
        if (tag.mitre_atlas) chips.push(tag.mitre_atlas);
      }
      const row: VerdictRow = {
        verdict_id: v.verdict_id,
        decision: v.decision,
        severity: v.severity,
        confidence: v.confidence,
        explanation: v.explanation,
        target_action_id: v.target_action_id,
        target_agent_id: v.target_agent_id,
        correlation_id: v.correlation_id,
        sequence_action_ids: v.sequence_action_ids ?? [],
        standards_chips: chips,
        ts_unix_ms: evt.ts_unix_ms,
        contributing_signals: v.contributing_signals ?? [],
      };
      const suppressed = (v.suppressed_signal_ids ?? []).length;
      _state = {
        ..._state,
        verdicts: [row, ..._state.verdicts].slice(0, MAX),
        suppressedTotal: _state.suppressedTotal + suppressed,
      };
      emit();
      return;
    }
    case "aegis.outcome": {
      const o = evt.payload;
      _state = {
        ..._state,
        actions: _state.actions.map((a) =>
          a.action_id === o.action_id ? { ...a, outcome: o.outcome } : a
        ),
      };
      emit();
      return;
    }
    case "aegis.trust": {
      const t = evt.payload;
      _state = {
        ..._state,
        trust: {
          ..._state.trust,
          [t.agent_id]: {
            agent_id: t.agent_id,
            score: t.score,
            last_change_unix_ms: evt.ts_unix_ms,
          },
        },
      };
      emit();
      return;
    }
    case "aegis.threshold": {
      const t = evt.payload;
      _state = {
        ..._state,
        thresholds: [..._state.thresholds, { ...t, when_unix_ms: evt.ts_unix_ms }],
      };
      emit();
      return;
    }
    case "ping":
      return;
  }
}
