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

export interface PathSummary {
  id: string;
  source_name: string;
  source_server_uri: string;
  sink_name: string;
  sink_server_uri: string;
  sink_privilege: number;
  sink_privilege_label: string;
  length: number;
  total_weight: number;
  severity_score: number;
  render: string;
}

export type JobStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface Job {
  id: string;
  kind: "scan" | "verify" | string;
  label: string;
  request: Record<string, unknown>;
  status: JobStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  session_id: string | null;
  finding_count: number;
  error: string | null;
}

export interface ScanRequest {
  target_uri: string;
  checks?: string[] | null;
  headers?: string[] | null;
  bearer_token?: string | null;
  bearer_env?: string | null;
  insecure?: boolean;
  timeout?: number;
}

export interface VerifyRequest {
  source_session_id: string;
  path_id: string;
  agent_config_path?: string | null;
  sink_arg?: string | null;
}

export interface JobAccepted {
  job_id: string;
  status: JobStatus;
  session_id: string;
}

// ----------------------------------------------------------- auth

const TOKEN_KEY = "agentsploit.token";

export const tokenStore = {
  get: (): string | null => {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set: (t: string) => {
    try {
      localStorage.setItem(TOKEN_KEY, t);
    } catch {
      // ignore
    }
  },
  clear: () => {
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      // ignore
    }
  },
};

class AuthError extends Error {
  readonly status: number;
  constructor(status: number, msg: string) {
    super(msg);
    this.status = status;
  }
}

function authHeaders(): HeadersInit {
  const t = tokenStore.get();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function request<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const headers: HeadersInit = {
    Accept: "application/json",
    ...(init?.headers ?? {}),
    ...authHeaders(),
  };
  if (init?.body && !(headers as Record<string, string>)["Content-Type"]) {
    (headers as Record<string, string>)["Content-Type"] = "application/json";
  }
  const resp = await fetch(path, { ...init, headers });
  if (resp.status === 401 || resp.status === 403) {
    throw new AuthError(resp.status, `auth required (${resp.status})`);
  }
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

export { AuthError };

export const api = {
  health: () => request<Health>("/api/health"),
  sessions: () => request<SessionSummary[]>("/api/sessions"),
  session: (id: string) => request<SessionSummary>(`/api/sessions/${id}`),
  findings: (id: string) => request<Finding[]>(`/api/sessions/${id}/findings`),
  graph: (id: string) => request<PermissionGraph>(`/api/sessions/${id}/graph`),
  paths: (id: string) => request<PathSummary[]>(`/api/sessions/${id}/paths`),
  traces: (id: string) =>
    request<{ traces: { filename: string; size_bytes: string; modified_at: string }[] }>(
      `/api/sessions/${id}/traces`
    ),
  jobs: () => request<Job[]>("/api/jobs"),
  job: (id: string) => request<Job>(`/api/jobs/${id}`),
  submitScan: (body: ScanRequest) =>
    request<JobAccepted>("/api/jobs/scan", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  submitVerify: (body: VerifyRequest) =>
    request<JobAccepted>("/api/jobs/verify", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  cancelJob: (id: string) =>
    request<{ job_id: string; status: string }>(`/api/jobs/${id}/cancel`, {
      method: "POST",
    }),
};

// SSE: the EventSource browser API can't set headers, so we pass the
// token as a query param. The server accepts both.
export function eventsUrl(): string {
  const t = tokenStore.get();
  return t ? `/api/events?token=${encodeURIComponent(t)}` : "/api/events";
}

export interface BrokerEvent {
  type:
    | "job.queued"
    | "job.started"
    | "job.finding"
    | "job.finished"
    | "job.failed"
    | "job.cancelled";
  timestamp: number;
  job_id: string | null;
  session_id: string | null;
  payload: Record<string, unknown>;
}
