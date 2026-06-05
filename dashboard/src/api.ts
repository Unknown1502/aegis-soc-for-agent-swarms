/**
 * Thin wrapper around the AEGIS API + WebSocket stream.
 */

const API_BASE: string =
  (import.meta as any).env?.VITE_AEGIS_API ?? "http://127.0.0.1:8088";

export interface LoginResponse {
  token: string;
  expires_unix: number;
  role: string;
}

export interface StreamEvent {
  topic: string;
  event_id?: string;
  ts_unix_ms: number;
  payload?: any;
}

export interface StatusResponse {
  service: string;
  version: string;
  env: string;
  integration_report: Record<string, string>;
  metrics_snapshot: MetricsSnapshot;
  audit_size: number;
  quarantine: Record<string, string>;
  outbound_sent: number;
  outbound_blocked: number;
}

export interface MetricsSnapshot {
  counters: Record<string, number>;
  fp_rate: number;
  mean_time_to_verdict_ms: number;
  trust_scores: { agent_id: string; score: number; last_change_unix_ms: number }[];
  threshold_history: {
    when_unix_ms: number;
    name: string;
    old: number;
    new: number;
    reason: string;
  }[];
}

export async function login(
  username: string,
  password: string
): Promise<LoginResponse> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error(`login_failed_${res.status}`);
  return res.json();
}

export async function getStatus(): Promise<StatusResponse> {
  const res = await fetch(`${API_BASE}/api/status`);
  if (!res.ok) throw new Error("status_failed");
  return res.json();
}

export async function getAudit(token: string, limit = 200): Promise<any[]> {
  const res = await fetch(`${API_BASE}/api/audit?limit=${limit}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("audit_failed");
  return res.json();
}

export async function verifyChain(
  token: string
): Promise<{ ok: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/api/audit/verify`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("verify_failed");
  return res.json();
}

export async function triggerAttack(
  token: string,
  name: "benign" | "echoleak" | "spoof" | "memory_poison"
): Promise<any> {
  const res = await fetch(`${API_BASE}/api/attacks/${name}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`attack_failed_${res.status}`);
  return res.json();
}

export async function triggerFullDemo(token: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/attacks/all`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`full_demo_failed_${res.status}`);
  return res.json();
}

export async function getMailbox(token: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/mailbox`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("mailbox_failed");
  return res.json();
}

export function openStream(
  token: string,
  onEvent: (e: StreamEvent) => void,
  onOpen?: () => void,
  onClose?: () => void
): WebSocket {
  const wsBase = API_BASE.replace(/^http/, "ws");
  const ws = new WebSocket(`${wsBase}/ws/stream?token=${encodeURIComponent(token)}`);
  ws.onopen = () => onOpen?.();
  ws.onclose = () => onClose?.();
  ws.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data));
    } catch {
      // ignore
    }
  };
  return ws;
}
