import { useMemo } from "react";
import ReactFlow, { Background, Controls, MarkerType } from "reactflow";
import "reactflow/dist/style.css";
import type { GraphData, AttackPath } from "../../types";
export function TopologyCanvas({
  graph,
  targets,
  path,
  selected,
  onSelect,
}: {
  graph: GraphData;
  targets: string[];
  path?: AttackPath;
  selected: string;
  onSelect: (id: string) => void;
}) {
  const pathEdges = new Set(
    path?.traverses.map((t) => t.edge_id.replace(/#rev$/, "")) ?? [],
  );
  const pathNodes = new Set(path?.traverses.map((t) => t.asset_id) ?? []);
  const threat = graph.threat_points.find(
    (t) => t.threatpoint_id === path?.entry_point_id,
  );
  if (threat) pathNodes.add(threat.related_asset_id);
  const nodes = useMemo(() => {
    const counts: Record<string, number> = {};
    return graph.asset_nodes.map((a) => {
      const domain = a.security_domain ?? "Shared";
      const row = counts[domain] ?? 0;
      counts[domain] = row + 1;
      return {
        id: a.asset_id,
        position: {
          x: ["External", "DMZ", "Shared", "Internal"].indexOf(domain) * 240,
          y: row * 100,
        },
        data: {
          label: (
            <div>
              <strong>{a.asset_name}</strong>
              <small className="workbench-node-label">
                {domain} {targets.includes(a.asset_id) ? "◎ 目标" : ""}
              </small>
            </div>
          ),
        },
        className: `workbench-node ${selected === a.asset_id ? "workbench-selected" : ""} ${pathNodes.has(a.asset_id) ? "workbench-path-node" : ""}`,
      };
    });
  }, [graph, selected, path, targets]);
  const edges = graph.asset_edges.map((e) => ({
    id: e.edge_id,
    source: e.source_asset_id,
    target: e.target_asset_id,
    animated: pathEdges.has(e.edge_id),
    className: pathEdges.has(e.edge_id) ? "workbench-path-edge" : "",
    markerEnd: { type: MarkerType.ArrowClosed },
    markerStart:
      e.direction === "Bidirectional"
        ? { type: MarkerType.ArrowClosed }
        : undefined,
  }));
  return (
    <div className="workbench-canvas">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        minZoom={0.1}
        nodesDraggable={false}
        onNodeClick={(_, node) => onSelect(node.id)}
      >
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
