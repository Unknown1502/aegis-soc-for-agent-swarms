import { useEffect, useState } from "react";
import { openStream } from "@/api";
import {
  type AegisState,
  getState,
  handleEvent,
  setConnected,
  subscribe,
} from "@/state";

/**
 * Subscribes to the in-browser AEGIS store and keeps a live WebSocket open for
 * the session token. Returns the current snapshot; components re-render on each
 * pushed event (verdict / signal / action / trust / threshold).
 */
export function useAegisStream(token: string | null): AegisState {
  const [state, setState] = useState<AegisState>(getState());

  useEffect(() => subscribe(setState), []);

  useEffect(() => {
    if (!token) return;
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let closed = false; // set on unmount so we stop reconnecting

    const connect = () => {
      if (closed) return;
      ws = openStream(
        token,
        handleEvent,
        () => setConnected(true),
        () => {
          setConnected(false);
          // Auto-reconnect (e.g. after a server restart) so the dashboard
          // recovers without a manual page refresh.
          if (!closed && !retry) {
            retry = setTimeout(() => {
              retry = null;
              connect();
            }, 1500);
          }
        }
      );
    };

    connect();

    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      ws?.close();
    };
  }, [token]);

  return state;
}
