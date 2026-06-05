import { useQuery } from "@tanstack/react-query";
import { getAudit, getMailbox } from "@/api";

export interface AuditEntry {
  seq: number;
  kind: string;
  correlation_id: string;
  payload: Record<string, any>;
  prev_hash: string;
  entry_hash: string;
  timestamp_unix_ms: number;
}

/** Hash-chained audit log, polled on a short interval (server-state via Query). */
export function useAudit(token: string, limit = 120) {
  return useQuery({
    queryKey: ["audit", limit],
    queryFn: () => getAudit(token, limit) as Promise<AuditEntry[]>,
    refetchInterval: 4000,
    enabled: !!token,
  });
}

export interface MailboxView {
  sent: { id: string; to: string[]; subject: string; attachments: string[]; body_excerpt: string }[];
  blocked: { id: string; to: string[]; subject: string; attachments: string[]; body_excerpt: string }[];
}

export function useMailbox(token: string) {
  return useQuery({
    queryKey: ["mailbox"],
    queryFn: () => getMailbox(token) as Promise<MailboxView>,
    refetchInterval: 4000,
    enabled: !!token,
  });
}
