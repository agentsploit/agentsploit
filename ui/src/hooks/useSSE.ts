import { useEffect, useRef, useState } from "react";

import { eventsUrl, type BrokerEvent } from "@/api/client";

export interface UseSSEResult {
  events: BrokerEvent[];
  connected: boolean;
  error: string | null;
}

/**
 * Subscribe to /api/events. Keeps the most recent N events in state.
 *
 * The hook is intentionally simple: no auto-reconnect, no offline buffer.
 * Pages that care about "live findings" should also re-fetch the
 * findings list when the connection drops.
 */
export function useSSE(limit = 200): UseSSEResult {
  const [events, setEvents] = useState<BrokerEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource(eventsUrl());
    ref.current = es;

    es.onopen = () => {
      setConnected(true);
      setError(null);
    };
    es.onerror = () => {
      setConnected(false);
      setError("event stream disconnected");
    };

    const handle = (e: MessageEvent) => {
      try {
        const evt: BrokerEvent = JSON.parse(e.data);
        setEvents((prev) => {
          const next = prev.concat(evt);
          return next.length > limit ? next.slice(next.length - limit) : next;
        });
      } catch {
        // ignore malformed frames
      }
    };

    // Named events get routed to listeners with the same name; default
    // EventSource.onmessage only fires for events without a `event:` line.
    const types: BrokerEvent["type"][] = [
      "job.queued",
      "job.started",
      "job.finding",
      "job.finished",
      "job.failed",
      "job.cancelled",
    ];
    types.forEach((t) => es.addEventListener(t, handle as EventListener));

    return () => {
      types.forEach((t) => es.removeEventListener(t, handle as EventListener));
      es.close();
      ref.current = null;
    };
  }, [limit]);

  return { events, connected, error };
}
