// API client for the AgentSploit backend.
// All requests go through the relative `/api` prefix; in dev mode Vite
// proxies that to the FastAPI server on :8800.

export interface Health {
  status: string;
  version: string;
  engagement_dir: string;
}

export interface SessionSummary {
  session_id: string;
  engagement_id: string;
  started_at: string | null;
  finished_at: string | null;
  finding_count: number;
  has_graph: boolean;
  has_traces: boolean;
}

export interface Finding {
  id: string;
  detected_at: string;
  module: string;
  check: string;
  target: string;
  severity: number;
  severity_label: string;
  title: string;
  description: string;
  remediation: string;
  references: string[];
  tags: string[];
  evidence: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  server_uri: string;
  name: string;
  description: string;
  classification: "source" | "pivot" | "sink" | "unknown";
  privilege: number;
  classification_reasons: string[];
}

export interface GraphEdge {
  src: string;
  dst: string;
  weight: number;
  reasons: string[];
}

export interface PermissionGraph {
  nodes: Record<string, GraphNode>;
  edges: GraphEdge[];
  targets: string[];
  built_at: string;
}

async function getJson<T>(path: string): Promise<T> {
  const resp = await fetch(path, { headers: { Accept: "application/json" } });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      if (body && typeof body.detail === "string") detail = body.detail;
    } catch {
      // swallow
    }
    throw new Error(`${resp.status}: ${detail}`);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  health: () => getJson<Health>("/api/health"),
  sessions: () => getJson<SessionSummary[]>("/api/sessions"),
  session: (id: string) => getJson<SessionSummary>(`/api/sessions/${id}`),
  findings: (id: string) => getJson<Finding[]>(`/api/sessions/${id}/findings`),
  graph: (id: string) => getJson<PermissionGraph>(`/api/sessions/${id}/graph`),
  traces: (id: string) =>
    getJson<{ traces: { filename: string; size_bytes: string; modified_at: string }[] }>(
      `/api/sessions/${id}/traces`
    ),
};
