import { useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  applyEdgeChanges,
  applyNodeChanges,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange
} from "reactflow";
import "reactflow/dist/style.css";
import { commitChangeSet, getGraph, persistPaths, runAnalysis, seedSampleData, validateChangeSet } from "./api";
import type { AssetNode, AttackPath, GraphChangeSet, GraphData } from "./types";

const emptyChangeSet = (version: string): GraphChangeSet => ({
  graphVersion: version,
  assets: { add: [], update: [], delete: [] },
  edges: { add: [], update: [], delete: [] },
  threats: { add: [], update: [], delete: [] }
});

const domainOrder = ["Internet", "Gateway", "Application", "Data", "Identity", "Operations", "Other"];

function inferDomain(asset: AssetNode): string {
  const words = `${asset.assetType} ${(asset.tags ?? []).join(" ")} ${asset.name}`.toLowerCase();
  if (/internet|public|edge|external|dmz/.test(words)) {
    return "Internet";
  }
  if (/waf|gateway|proxy|loadbalancer/.test(words)) {
    return "Gateway";
  }
  if (/application|app|service|business/.test(words)) {
    return "Application";
  }
  if (/data|db|database|redis|cache|mq|queue|storage/.test(words)) {
    return "Data";
  }
  if (/iam|identity|auth|ad/.test(words)) {
    return "Identity";
  }
  if (/ops|operation|management|jump|bastion/.test(words)) {
    return "Operations";
  }
  return "Other";
}

function buildLanePosition(assets: AssetNode[]): Record<string, { x: number; y: number }> {
  const xGap = 220;
  const yGap = 130;
  const laneCounts = new Map<string, number>();
  const positions: Record<string, { x: number; y: number }> = {};

  for (const lane of domainOrder) {
    laneCounts.set(lane, 0);
  }

  for (const asset of assets) {
    const lane = inferDomain(asset);
    const laneIndex = domainOrder.indexOf(lane);
    const row = laneCounts.get(lane) ?? 0;
    laneCounts.set(lane, row + 1);
    positions[asset.assetId] = {
      x: laneIndex * xGap,
      y: row * yGap
    };
  }

  return positions;
}

function edgeIdSetFromPath(path: AttackPath | null): Set<string> {
  return new Set((path?.traverses ?? []).map((t) => (t.edgeId.endsWith("#rev") ? t.edgeId.replace("#rev", "") : t.edgeId)));
}

export function App() {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [message, setMessage] = useState("点击“加载图数据”开始");
  const [busy, setBusy] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [layoutVersion, setLayoutVersion] = useState(0);

  const draft = useMemo(() => (graph ? emptyChangeSet(graph.version) : null), [graph]);

  const selectedPath = useMemo(
    () => (selectedPathId ? paths.find((item) => item.pathId === selectedPathId) ?? null : null),
    [paths, selectedPathId]
  );

  const laneStats = useMemo(() => {
    const stats = new Map<string, number>();
    for (const lane of domainOrder) {
      stats.set(lane, 0);
    }
    for (const asset of graph?.assets ?? []) {
      const lane = inferDomain(asset);
      stats.set(lane, (stats.get(lane) ?? 0) + 1);
    }
    return Array.from(stats.entries()).filter(([, count]) => count > 0);
  }, [graph]);

  useEffect(() => {
    if (!graph) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const pathEdgeIds = edgeIdSetFromPath(selectedPath);
    const lanePosition = buildLanePosition(graph.assets);

    const threatCountByAsset = new Map<string, number>();
    for (const threat of graph.threats) {
      threatCountByAsset.set(threat.assetId, (threatCountByAsset.get(threat.assetId) ?? 0) + 1);
    }

    const createdNodes: Node[] = graph.assets.map((asset, index) => {
      const threatCount = threatCountByAsset.get(asset.assetId) ?? 0;
      const position = lanePosition[asset.assetId] ?? { x: index * 180, y: 0 };
      return {
        id: asset.assetId,
        position,
        data: {
          label: (
            <div className="topo-node">
              <strong>{asset.name}</strong>
              <span>{asset.assetType}</span>
              <small>{inferDomain(asset)}</small>
              {threatCount > 0 ? <em>Threat × {threatCount}</em> : null}
            </div>
          )
        },
        style: {
          border: "1px solid #435279",
          borderRadius: "10px",
          background: "#131c34",
          color: "#dbe5ff",
          width: 170,
          padding: 2
        }
      };
    });

    const createdEdges: Edge[] = graph.edges.map((edge) => {
      const highlighted = pathEdgeIds.has(edge.edgeId);
      return {
        id: edge.edgeId,
        source: edge.sourceAssetId,
        target: edge.targetAssetId,
        label: edge.relationType,
        animated: highlighted,
        style: {
          stroke: highlighted ? "#7aa2ff" : "#3e4a70",
          strokeWidth: highlighted ? 2.8 : 1.4
        },
        labelStyle: { fill: highlighted ? "#bcd0ff" : "#90a0c8", fontSize: 11 }
      };
    });

    setNodes(createdNodes);
    setEdges(createdEdges);
  }, [graph, selectedPath, layoutVersion]);

  useEffect(() => {
    if (!graph) {
      return;
    }
    const pathEdgeIds = edgeIdSetFromPath(selectedPath);
    setEdges(
      graph.edges.map((edge) => {
        const highlighted = pathEdgeIds.has(edge.edgeId);
        return {
          id: edge.edgeId,
          source: edge.sourceAssetId,
          target: edge.targetAssetId,
          label: edge.relationType,
          animated: highlighted,
          style: {
            stroke: highlighted ? "#7aa2ff" : "#3e4a70",
            strokeWidth: highlighted ? 2.8 : 1.4
          },
          labelStyle: { fill: highlighted ? "#bcd0ff" : "#90a0c8", fontSize: 11 }
        } as Edge;
      })
    );
  }, [selectedPath, graph]);

  async function handleLoadGraph() {
    try {
      setBusy(true);
      const data = await getGraph();
      setGraph(data);
      setMessage(`已加载图数据，版本 ${data.version}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "加载失败");
    } finally {
      setBusy(false);
    }
  }

  async function handleValidate() {
    if (!draft) {
      return;
    }
    const result = await validateChangeSet(draft);
    setMessage(result.valid ? "Draft 校验通过" : `Draft 校验失败：${result.errors.join("; ")}`);
  }

  async function handleCommit() {
    if (!draft) {
      return;
    }
    const result = await commitChangeSet(draft);
    if (result.committed) {
      setMessage(`提交成功，commitId=${result.commitId}，新版本=${result.newVersion}`);
      await handleLoadGraph();
    } else {
      setMessage(`提交失败：${(result.errors ?? []).join("; ")}`);
    }
  }

  async function handleRunAnalysis() {
    try {
      setBusy(true);
      const result = await runAnalysis();
      setPaths(result.paths);
      setSelectedPathId(result.paths[0]?.pathId ?? null);
      setMessage(`分析完成，生成 ${result.count} 条路径`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "分析失败");
    } finally {
      setBusy(false);
    }
  }

  async function handlePersistPaths() {
    if (paths.length === 0) {
      setMessage("没有可持久化的路径");
      return;
    }
    const result = await persistPaths(paths);
    setMessage(`已持久化 ${result.persisted} 条路径`);
  }

  async function handleSeedSample() {
    try {
      setBusy(true);
      const result = await seedSampleData();
      setMessage(
        `示例数据初始化完成：assets=${result.counts.assets}, edges=${result.counts.edges}, threats=${result.counts.threats}`
      );
      await handleLoadGraph();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "示例数据初始化失败");
    } finally {
      setBusy(false);
    }
  }

  const kpi = {
    assets: graph?.assets.length ?? 0,
    threats: graph?.threats.length ?? 0,
    paths: paths.length,
    version: graph?.version ?? "-"
  };

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>Attackgraph 审查工作台</h1>
          <p>建模 → 推演 → 评分 → 评审</p>
        </div>
        <div className="header-actions">
          <button className="button primary" onClick={handleSeedSample} disabled={busy}>
            一键初始化示例数据
          </button>
          <button className="button" onClick={handleLoadGraph} disabled={busy}>
            刷新图数据
          </button>
        </div>
      </header>

      <section className="kpi-grid">
        <article className="kpi-card">
          <span>AssetNode</span>
          <strong>{kpi.assets}</strong>
        </article>
        <article className="kpi-card">
          <span>ThreatPoint</span>
          <strong>{kpi.threats}</strong>
        </article>
        <article className="kpi-card">
          <span>AttackPath</span>
          <strong>{kpi.paths}</strong>
        </article>
        <article className="kpi-card">
          <span>Graph Version</span>
          <strong>{kpi.version}</strong>
        </article>
      </section>

      <div className="layout">
        <aside className="panel left">
          <h3>对象导航与过滤</h3>
          <p>按资产类型快速浏览当前拓扑对象</p>
          <div className="list compact">
            {(graph?.assets ?? []).slice(0, 10).map((asset) => (
              <div key={asset.assetId} className="item vertical">
                <strong>{asset.name}</strong>
                <span>{asset.assetType}</span>
              </div>
            ))}
          </div>
        </aside>

        <main className="panel center">
          <h3>主图画布（资产拓扑）</h3>
          <div className="toolbar">
            <button className="button" onClick={handleRunAnalysis} disabled={busy}>
              运行路径推演
            </button>
            <button className="button" onClick={handlePersistPaths} disabled={busy || paths.length === 0}>
              持久化路径
            </button>
            <button className="button" onClick={() => setLayoutVersion((v) => v + 1)} disabled={busy || !graph}>
              按域重排布局
            </button>
          </div>
          <div className="lane-row">
            {laneStats.map(([lane, count]) => (
              <span key={lane} className="lane-pill">
                {lane} · {count}
              </span>
            ))}
          </div>
          <div className="topology-canvas">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              onNodesChange={(changes: NodeChange[]) => setNodes((current) => applyNodeChanges(changes, current))}
              onEdgesChange={(changes: EdgeChange[]) => setEdges((current) => applyEdgeChanges(changes, current))}
            >
              <MiniMap pannable zoomable />
              <Controls />
              <Background gap={16} color="#243353" />
            </ReactFlow>
          </div>
        </main>

        <aside className="panel right">
          <h3>审查详情面板</h3>
          <p className="status">{message}</p>
          <div className="list">
            {paths.slice(0, 8).map((path) => (
              <div
                key={path.pathId}
                className={`item vertical clickable ${selectedPathId === path.pathId ? "active" : ""}`}
                onClick={() => setSelectedPathId(path.pathId)}
              >
                <strong>
                  {path.priority} | Score {path.score}
                </strong>
                <span>hop={path.hopCount}</span>
                <span>{path.explanations[0]}</span>
              </div>
            ))}
          </div>
        </aside>

        <footer className="panel bottom">
          <h3>变更与提交面板（Draft ChangeSet）</h3>
          <div className="toolbar">
            <button className="button" onClick={handleValidate} disabled={!draft || busy}>
              校验 Draft
            </button>
            <button className="button primary" onClick={handleCommit} disabled={!draft || busy}>
              显式保存提交
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
}
