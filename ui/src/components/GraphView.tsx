import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import CytoscapeComponent from "react-cytoscapejs";
import type cytoscape from "cytoscape";
import { api, type GraphNode, type PermissionGraph } from "@/api/client";

interface Props {
  sessionId: string;
}

const CLASS_COLORS: Record<string, string> = {
  source: "#86efac",
  pivot: "#e5e7eb",
  sink: "#fca5a5",
  unknown: "#fde68a",
};

const PRIVILEGE_LABELS = ["READ", "ACT", "EGRESS", "MUTATE", "EXEC"];

export default function GraphView({ sessionId }: Props) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["graph", sessionId],
    queryFn: () => api.graph(sessionId),
  });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const elements = useMemo(() => buildElements(data), [data]);

  if (isLoading) return <div className="p-6 text-slate-500">Loading graph...</div>;
  if (error) return <div className="p-6 text-red-600">Error: {(error as Error).message}</div>;
  if (!data) return <div className="p-6 text-slate-500">No graph data.</div>;

  return (
    <div className="flex h-full">
      <div className="flex-1 relative bg-white">
        <CytoscapeComponent
          elements={elements}
          style={{ width: "100%", height: "100%" }}
          layout={{ name: "breadthfirst", directed: true, padding: 30, spacingFactor: 1.4 }}
          stylesheet={STYLE}
          cy={(cy: cytoscape.Core) => {
            cy.on("tap", "node", (e) => {
              const node = e.target.data();
              setSelectedNode(node as GraphNode);
            });
            cy.on("tap", (e) => {
              if (e.target === cy) setSelectedNode(null);
            });
          }}
        />
        <Legend totals={data} />
      </div>
      {selectedNode && (
        <aside className="w-1/3 min-w-[20rem] max-w-xl border-l bg-white overflow-auto">
          <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
        </aside>
      )}
    </div>
  );
}

function buildElements(graph: PermissionGraph | undefined) {
  if (!graph) return [];
  const nodes = Object.values(graph.nodes).map((n) => ({
    data: {
      ...n,
      label: `${n.name}\n[${PRIVILEGE_LABELS[n.privilege] ?? n.privilege}]`,
      colour: CLASS_COLORS[n.classification] ?? "#fff",
    },
  }));
  const edges = graph.edges.map((e, i) => ({
    data: {
      id: `e${i}`,
      source: e.src,
      target: e.dst,
      label: e.weight.toFixed(1),
      reasons: e.reasons,
    },
  }));
  return [...nodes, ...edges];
}

const STYLE: cytoscape.StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      "background-color": "data(colour)",
      label: "data(label)",
      "text-wrap": "wrap",
      "text-valign": "center",
      "text-halign": "center",
      "font-size": 11,
      "font-family": "ui-monospace, SFMono-Regular, Menlo, monospace",
      shape: "round-rectangle",
      width: 180,
      height: 50,
      "border-width": 1,
      "border-color": "#475569",
    },
  },
  {
    selector: "edge",
    style: {
      width: 1.5,
      "line-color": "#94a3b8",
      "target-arrow-color": "#94a3b8",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      label: "data(label)",
      "font-size": 9,
      "text-background-color": "#fff",
      "text-background-opacity": 1,
      "text-background-padding": "2px",
    },
  },
];

function Legend({ totals }: { totals: PermissionGraph }) {
  const counts = Object.values(totals.nodes).reduce<Record<string, number>>((acc, n) => {
    acc[n.classification] = (acc[n.classification] ?? 0) + 1;
    return acc;
  }, {});
  return (
    <div className="absolute bottom-3 left-3 bg-white border rounded shadow-sm p-2 text-xs space-y-1">
      <div className="font-semibold">
        {Object.values(totals.nodes).length} nodes / {totals.edges.length} edges
      </div>
      {(["source", "pivot", "sink", "unknown"] as const).map((cls) =>
        counts[cls] ? (
          <div key={cls} className="flex items-center gap-1.5">
            <span
              className="inline-block w-3 h-3 rounded"
              style={{ background: CLASS_COLORS[cls] }}
            />
            <span>
              {cls} ({counts[cls]})
            </span>
          </div>
        ) : null
      )}
    </div>
  );
}

function NodeDetail({ node, onClose }: { node: GraphNode; onClose: () => void }) {
  return (
    <div className="p-6">
      <div className="flex items-start gap-3 mb-3">
        <span
          className="px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide"
          style={{ background: CLASS_COLORS[node.classification] }}
        >
          {node.classification} - {PRIVILEGE_LABELS[node.privilege] ?? node.privilege}
        </span>
        <button
          onClick={onClose}
          className="ml-auto text-slate-400 hover:text-slate-700 text-xl leading-none"
          aria-label="Close"
        >
          x
        </button>
      </div>
      <h2 className="font-mono text-base">{node.name}</h2>
      <div className="mt-1 text-xs font-mono text-slate-500 break-all">{node.server_uri}</div>

      <div className="mt-4">
        <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1">
          Description
        </div>
        <div className="text-sm whitespace-pre-wrap">{node.description || "(none)"}</div>
      </div>

      {node.classification_reasons.length > 0 && (
        <div className="mt-4">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1">
            Classification reasons
          </div>
          <ul className="list-disc list-inside text-sm text-slate-700">
            {node.classification_reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
