import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, type Job } from "@/api/client";
import { useSSE } from "@/hooks/useSSE";

const STATUS_COLOURS: Record<string, string> = {
  queued: "bg-slate-200 text-slate-700",
  running: "bg-blue-100 text-blue-700",
  succeeded: "bg-emerald-100 text-emerald-700",
  failed: "bg-red-100 text-red-700",
  cancelled: "bg-yellow-100 text-yellow-700",
};

export default function JobsPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["jobs"], queryFn: api.jobs });
  const { events } = useSSE();
  const [showScanForm, setShowScanForm] = useState(false);

  // Re-fetch on any job lifecycle event.
  useEffect(() => {
    if (events.length === 0) return;
    const last = events[events.length - 1];
    if (last.type.startsWith("job.")) qc.invalidateQueries({ queryKey: ["jobs"] });
  }, [events, qc]);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Jobs</h1>
          <p className="text-sm text-slate-500">
            Background scan / verify runs. Findings stream into their own
            sessions as they're discovered.
          </p>
        </div>
        <button
          onClick={() => setShowScanForm((v) => !v)}
          className="bg-slate-900 text-white text-sm rounded px-3 py-1.5"
        >
          {showScanForm ? "Cancel" : "Run scan"}
        </button>
      </div>

      {showScanForm && (
        <ScanForm
          onSubmitted={() => {
            setShowScanForm(false);
            qc.invalidateQueries({ queryKey: ["jobs"] });
          }}
        />
      )}

      {isLoading ? (
        <div className="text-slate-500 text-sm">Loading...</div>
      ) : !data?.length ? (
        <div className="text-slate-500 text-sm">No jobs yet.</div>
      ) : (
        <table className="w-full text-sm border border-slate-200 rounded bg-white">
          <thead className="text-left text-xs uppercase tracking-wide text-slate-500 bg-slate-50">
            <tr>
              <th className="px-3 py-2 font-medium">Job</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Started</th>
              <th className="px-3 py-2 font-medium">Findings</th>
              <th className="px-3 py-2 font-medium">Session</th>
            </tr>
          </thead>
          <tbody>
            {data.map((j) => (
              <JobRow key={j.id} job={j} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function JobRow({ job }: { job: Job }) {
  return (
    <tr className="border-t">
      <td className="px-3 py-2">
        <div className="font-mono text-xs text-slate-500">{job.id}</div>
        <div>{job.label}</div>
      </td>
      <td className="px-3 py-2">
        <span
          className={
            "inline-block text-xs font-semibold uppercase tracking-wide rounded px-1.5 py-0.5 " +
            (STATUS_COLOURS[job.status] ?? "bg-slate-100 text-slate-700")
          }
        >
          {job.status}
        </span>
        {job.error && (
          <div className="text-xs text-red-600 mt-1 font-mono break-all">{job.error}</div>
        )}
      </td>
      <td className="px-3 py-2 text-xs text-slate-500 font-mono">
        {job.started_at ? new Date(job.started_at).toLocaleTimeString() : "-"}
      </td>
      <td className="px-3 py-2">{job.finding_count}</td>
      <td className="px-3 py-2">
        {job.session_id ? (
          <Link
            to={`/sessions/${job.session_id}`}
            className="text-blue-600 hover:underline font-mono text-xs"
          >
            {job.session_id}
          </Link>
        ) : (
          <span className="text-slate-300">-</span>
        )}
      </td>
    </tr>
  );
}

function ScanForm({ onSubmitted }: { onSubmitted: () => void }) {
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setError(null);
    if (!target.trim()) {
      setError("Target URI required (e.g. stdio://./vuln-mcp or http://host:port).");
      return;
    }
    setBusy(true);
    try {
      await api.submitScan({ target_uri: target.trim() });
      setTarget("");
      onSubmitted();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="bg-white border rounded p-4 space-y-3">
      <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        Run MCP scan
      </div>
      <label className="block">
        <span className="text-xs text-slate-600">Target URI</span>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="stdio://./vuln-mcp or http://host:port"
          className="mt-1 w-full font-mono text-xs border rounded px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-200"
        />
      </label>
      {error && (
        <div className="text-xs text-red-600 bg-red-50 border border-red-100 rounded px-2 py-1.5 break-words">
          {error}
        </div>
      )}
      <div className="flex gap-2">
        <button
          onClick={submit}
          disabled={busy}
          className="bg-slate-900 text-white text-sm rounded px-3 py-1.5 disabled:opacity-50"
        >
          {busy ? "Submitting..." : "Submit"}
        </button>
        <div className="text-xs text-slate-500 self-center">
          The target must be allowed by the active engagement authorization.
        </div>
      </div>
    </div>
  );
}
