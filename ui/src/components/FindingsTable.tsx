import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type Finding } from "@/api/client";
import SeverityBadge from "./SeverityBadge";

interface Props {
  sessionId: string;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export default function FindingsTable({ sessionId }: Props) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["findings", sessionId],
    queryFn: () => api.findings(sessionId),
  });
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [selected, setSelected] = useState<Finding | null>(null);

  const findings = useMemo(() => {
    if (!data) return [];
    if (!severityFilter) return data;
    return data.filter((f) => f.severity_label === severityFilter);
  }, [data, severityFilter]);

  if (isLoading) return <div className="p-6 text-slate-500">Loading findings...</div>;
  if (error) return <div className="p-6 text-red-600">Error: {(error as Error).message}</div>;
  if (!data || data.length === 0) return <div className="p-6 text-slate-500">No findings.</div>;

  return (
    <div className="flex h-full">
      <div className="flex-1 overflow-auto p-6">
        <div className="flex items-center gap-3 mb-3 text-sm">
          <span className="text-slate-500">Filter severity:</span>
          <button
            onClick={() => setSeverityFilter("")}
            className={`px-2 py-0.5 rounded text-xs ${
              !severityFilter
                ? "bg-slate-800 text-white"
                : "bg-slate-200 text-slate-700 hover:bg-slate-300"
            }`}
          >
            all ({data.length})
          </button>
          {SEVERITY_ORDER.map((sev) => {
            const count = data.filter((f) => f.severity_label === sev).length;
            if (count === 0) return null;
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded text-xs ${
                  severityFilter === sev
                    ? "bg-slate-800 text-white"
                    : "bg-slate-200 text-slate-700 hover:bg-slate-300"
                }`}
              >
                {sev} ({count})
              </button>
            );
          })}
        </div>
        <div className="bg-white rounded border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-100 text-slate-600 text-xs">
              <tr>
                <th className="text-left px-3 py-2 w-20">Severity</th>
                <th className="text-left px-3 py-2">Check</th>
                <th className="text-left px-3 py-2">Title</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelected(f)}
                  className={`border-t cursor-pointer hover:bg-slate-50 ${
                    selected?.id === f.id ? "bg-blue-50" : ""
                  }`}
                >
                  <td className="px-3 py-2">
                    <SeverityBadge label={f.severity_label} />
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{f.check}</td>
                  <td className="px-3 py-2">{f.title}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {selected && (
        <aside className="w-1/3 min-w-[24rem] max-w-2xl border-l bg-white overflow-auto">
          <FindingDetail finding={selected} onClose={() => setSelected(null)} />
        </aside>
      )}
    </div>
  );
}

function FindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div className="p-6">
      <div className="flex items-start gap-3 mb-3">
        <SeverityBadge label={finding.severity_label} />
        <button
          onClick={onClose}
          className="ml-auto text-slate-400 hover:text-slate-700 text-xl leading-none"
          aria-label="Close"
        >
          x
        </button>
      </div>
      <h2 className="text-lg font-semibold leading-tight">{finding.title}</h2>
      <div className="mt-2 text-xs font-mono text-slate-500">
        {finding.module} / {finding.check}
      </div>
      <div className="mt-2 text-xs font-mono text-slate-500 break-all">{finding.target}</div>

      <Section title="Description">{finding.description}</Section>
      <Section title="Remediation">{finding.remediation}</Section>

      {finding.tags.length > 0 && (
        <Section title="Tags">
          <div className="flex flex-wrap gap-1">
            {finding.tags.map((t) => (
              <span
                key={t}
                className="px-1.5 py-0.5 bg-slate-100 text-slate-700 rounded text-xs font-mono"
              >
                {t}
              </span>
            ))}
          </div>
        </Section>
      )}

      {finding.references.length > 0 && (
        <Section title="References">
          <ul className="list-disc list-inside text-sm text-blue-600 break-words">
            {finding.references.map((r) => (
              <li key={r}>
                <a href={r} target="_blank" rel="noreferrer" className="hover:underline">
                  {r}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section title="Evidence">
        <pre className="text-xs bg-slate-50 border rounded p-3 overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(finding.evidence, null, 2)}
        </pre>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-4">
      <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1">
        {title}
      </div>
      <div className="text-sm text-slate-800 whitespace-pre-wrap">{children}</div>
    </div>
  );
}
