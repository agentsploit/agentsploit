import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api, type PathSummary } from "@/api/client";

const PRIV_COLOURS: Record<string, string> = {
  execution: "bg-red-100 text-red-700",
  mutation: "bg-orange-100 text-orange-700",
  egress: "bg-amber-100 text-amber-700",
  internal_action: "bg-slate-100 text-slate-700",
  read: "bg-emerald-100 text-emerald-700",
};

interface Props {
  sessionId: string;
}

export default function PathsTable({ sessionId }: Props) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["paths", sessionId],
    queryFn: () => api.paths(sessionId),
  });
  const [verifying, setVerifying] = useState<string | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  if (isLoading) return <div className="p-6 text-slate-500">Loading...</div>;
  if (error)
    return <div className="p-6 text-red-600">Error: {(error as Error).message}</div>;
  if (!data || data.length === 0)
    return (
      <div className="p-6 text-slate-500 space-y-2">
        <div>No paths.json artifact in this session.</div>
        <div className="text-xs text-slate-400">
          Run <code className="font-mono bg-slate-100 px-1 rounded">agentsploit map build</code>{" "}
          (v1.6+) to produce this file. Sessions written by older versions don't
          have it.
        </div>
      </div>
    );

  async function onVerify(path: PathSummary) {
    setVerifyError(null);
    setVerifying(path.id);
    try {
      await api.submitVerify({ source_session_id: sessionId, path_id: path.id });
    } catch (e) {
      setVerifyError(`${path.id}: ${(e as Error).message}`);
    } finally {
      setVerifying(null);
    }
  }

  return (
    <div className="p-6 space-y-3">
      <div className="text-sm text-slate-500">
        {data.length} path{data.length === 1 ? "" : "s"} sorted by severity score.
      </div>
      {verifyError && (
        <div className="text-xs text-red-600 bg-red-50 border border-red-100 rounded px-3 py-2">
          {verifyError}
        </div>
      )}
      <table className="w-full text-sm border border-slate-200 rounded bg-white">
        <thead className="text-left text-xs uppercase tracking-wide text-slate-500 bg-slate-50">
          <tr>
            <th className="px-3 py-2 font-medium">Path</th>
            <th className="px-3 py-2 font-medium">Sink privilege</th>
            <th className="px-3 py-2 font-medium">Hops</th>
            <th className="px-3 py-2 font-medium">Score</th>
            <th className="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          {data.map((p) => (
            <tr key={p.id} className="border-t">
              <td className="px-3 py-2 font-mono text-xs break-all">{p.render}</td>
              <td className="px-3 py-2">
                <span
                  className={
                    "inline-block text-xs font-semibold uppercase tracking-wide rounded px-1.5 py-0.5 " +
                    (PRIV_COLOURS[p.sink_privilege_label] ?? "bg-slate-100 text-slate-700")
                  }
                >
                  {p.sink_privilege_label}
                </span>
              </td>
              <td className="px-3 py-2">{p.length}</td>
              <td className="px-3 py-2">{p.severity_score}</td>
              <td className="px-3 py-2 text-right">
                <button
                  onClick={() => onVerify(p)}
                  disabled={verifying === p.id}
                  className="text-xs bg-slate-900 text-white rounded px-2 py-1 disabled:opacity-50"
                  title="Queue a verify job for this path"
                >
                  {verifying === p.id ? "Queueing..." : "Verify"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
