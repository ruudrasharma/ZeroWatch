"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { detectionRunStreamUrl } from "@/lib/api-client";
import type { WsAlertEvent, WsFlowEvent, WsRunCompletedEvent } from "@/lib/api-types";

const MAX_FLOWS = 60;
const MAX_ALERTS = 100;

export type ConnectionState = "idle" | "connecting" | "open" | "closed" | "error";

export function useDetectionStream(runId: number | null) {
  const [connectionState, setConnectionState] = useState<ConnectionState>("idle");
  const [flows, setFlows] = useState<WsFlowEvent[]>([]);
  const [alerts, setAlerts] = useState<WsAlertEvent[]>([]);
  const [summary, setSummary] = useState<WsRunCompletedEvent | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (runId == null) return;

    setFlows([]);
    setAlerts([]);
    setSummary(null);
    setErrorMessage(null);
    setConnectionState("connecting");

    const ws = new WebSocket(detectionRunStreamUrl(runId));
    wsRef.current = ws;

    ws.onopen = () => setConnectionState("open");

    ws.onmessage = (event) => {
      let data: Record<string, unknown>;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }

      if (data.error) {
        const err = data.error as { message?: string };
        setErrorMessage(err.message ?? "Unknown error");
        return;
      }

      switch (data.type) {
        case "flow":
          setFlows((prev) => {
            const next = [data as unknown as WsFlowEvent, ...prev];
            return next.length > MAX_FLOWS ? next.slice(0, MAX_FLOWS) : next;
          });
          break;
        case "alert":
          setAlerts((prev) => {
            const next = [data as unknown as WsAlertEvent, ...prev];
            return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
          });
          break;
        case "run_completed":
          setSummary(data as unknown as WsRunCompletedEvent);
          break;
      }
    };

    ws.onerror = () => setConnectionState("error");
    ws.onclose = () => setConnectionState((s) => (s === "error" ? s : "closed"));

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [runId]);

  const setThreshold = useCallback((value: number) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "set_threshold", value }));
    }
  }, []);

  // Stopping early closes the socket client-side — the backend has no explicit
  // "stop" message, and USER_FLOWS.md's edge case ("partial run saved, no
  // summary metrics computed") is exactly what a disconnect already produces:
  // the run row never gets completed_at/precision/recall filled in.
  const stop = useCallback(() => {
    wsRef.current?.close();
  }, []);

  return { connectionState, flows, alerts, summary, errorMessage, setThreshold, stop };
}
