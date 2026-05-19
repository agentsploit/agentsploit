import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export default function SessionsList() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["sessions"],
    queryFn: api.sessions,
  });

  if (isLoading) {
    return <div className="p-6 text-slate-500">Loading sessions...</div>;
  }
  if (error) {
    return <div className="p-6 text-red-600">Error: {(error as Error).message}</div>;
  }

  const sessions = data ?? [];

  if (sessions.length === 0) {
    return (
      <div className="p-6">
        <div className="bg-amber-50 border border-amber-200 rounded p-4 max-w-2xl">
          <h2 className="font-semibold text-amber-900">No sessions yet</h2>
          <p className="text-sm text-amber-800 mt-1">
            Run any AgentSploit command from this directory and refresh. Examples:
          </p>
          <pre className="text-xs bg-white border rounded mt-3 p-3 overflow-x-auto">
{`agentsploit scan mcp "stdio://./tests/fixtures/vulnerable_mcp/server.py" --training
agentsploit map build --targets ./examples/map-targets.yaml --training
agentsploit poison verify --sink-tool send_email --sink-arg body --sink-privilege egress --training`}
          </pre>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-5xl">
      <h1 className="text-xl font-semibold mb-4">Sessions ({sessions.length})</h1>
      <div className="bg-white rounded border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-100 text-slate-600">
            <tr>
              <th className="text-left px-4 py-2">Session</th>
              <th className="text-left px-4 py-2">Engagement</th>
              <th className="text-left px-4 py-2">Started</th>
              <th className="text-right px-4 py-2">Findings</th>
              <th className="text-left px-4 py-2">Artifacts</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.session_id} className="border-t hover:bg-slate-50">
                <td className="px-4 py-2 font-mono text-xs">
                  <Link to={`/sessions/${s.session_id}`} className="text-blue-600 hover:underline">
                    {s.session_id}
                  </Link>
                </td>
                <td className="px-4 py-2 font-mono text-xs">{s.engagement_id}</td>
                <td className="px-4 py-2 text-xs text-slate-600">
                  {s.started_at ? new Date(s.started_at).toLocaleString() : "-"}
                </td>
                <td className="px-4 py-2 text-right">{s.finding_count}</td>
                <td className="px-4 py-2 text-xs">
                  <div className="flex gap-2">
                    {s.has_graph && (
                      <span className="px-1.5 py-0.5 bg-emerald-100 text-emerald-700 rounded">
                        graph
                      </span>
                    )}
                    {s.has_traces && (
                      <span className="px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded">
                        traces
                      </span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
