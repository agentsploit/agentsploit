import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import FindingsTable from "@/components/FindingsTable";
import GraphView from "@/components/GraphView";

type Tab = "findings" | "graph";

export default function SessionDetail() {
  const { sessionId = "" } = useParams<{ sessionId: string }>();
  const [tab, setTab] = useState<Tab>("findings");

  const { data: session } = useQuery({
    queryKey: ["session", sessionId],
    queryFn: () => api.session(sessionId),
  });

  if (!session) {
    return <div className="p-6 text-slate-500">Loading session...</div>;
  }

  return (
    <div className="flex flex-col h-full">
      <div className="border-b bg-white px-6 py-3">
        <div className="text-xs text-slate-500">
          <Link to="/" className="hover:underline">
            Sessions
          </Link>{" "}
          /
        </div>
        <div className="flex items-baseline gap-3 mt-1">
          <h1 className="text-lg font-semibold font-mono">{session.session_id}</h1>
          <span className="text-sm text-slate-600 font-mono">{session.engagement_id}</span>
          <span className="ml-auto text-xs text-slate-500">
            {session.finding_count} finding{session.finding_count === 1 ? "" : "s"}
          </span>
        </div>
        <div className="mt-3 flex gap-1 border-b -mb-3">
          <TabButton current={tab} target="findings" onClick={setTab}>
            Findings ({session.finding_count})
          </TabButton>
          {session.has_graph && (
            <TabButton current={tab} target="graph" onClick={setTab}>
              Permission graph
            </TabButton>
          )}
        </div>
      </div>
      <div className="flex-1 overflow-auto">
        {tab === "findings" && <FindingsTable sessionId={sessionId} />}
        {tab === "graph" && session.has_graph && <GraphView sessionId={sessionId} />}
      </div>
    </div>
  );
}

function TabButton({
  current,
  target,
  onClick,
  children,
}: {
  current: Tab;
  target: Tab;
  onClick: (t: Tab) => void;
  children: React.ReactNode;
}) {
  const active = current === target;
  return (
    <button
      onClick={() => onClick(target)}
      className={`px-3 py-1.5 text-sm border-b-2 transition-colors ${
        active
          ? "border-slate-900 text-slate-900 font-medium"
          : "border-transparent text-slate-500 hover:text-slate-700"
      }`}
    >
      {children}
    </button>
  );
}
