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
import {
  commitChangeSet,
  createOrUpdateDo326aLink,
  getDo326aLinks,
  getGraph,
  persistPaths,
  reviewDo326aLink,
  runAnalysis,
  seedSampleData,
  validateChangeSet
} from "./api";
import type { AssetNode, AttackPath, DO326ALink, GraphChangeSet, GraphData, ReviewStatus } from "./types";

const emptyChangeSet = (graphVersion: string): GraphChangeSet => ({
  graph_version: graphVersion,
  asset_nodes: { add: [], update: [], delete: [] },
  asset_edges: { add: [], update: [], delete: [] },
  threat_points: { add: [], update: [], delete: [] },
  do326a_links: { add: [], update: [], delete: [] }
});

const domainOrder = ["Internal", "Shared", "DMZ", "External"];

function inferDomain(asset: AssetNode): string {
  return asset.security_domain ?? "Shared";
}

function buildLanePosition(assets: AssetNode[]): Record<string, { x: number; y: number }> {
  const xGap = 240;
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
    positions[asset.asset_id] = {
      x: Math.max(0, laneIndex) * xGap,
      y: row * yGap
    };
  }
  return positions;
}

function edgeIdSetFromPath(path: AttackPath | null): Set<string> {
  return new Set((path?.traverses ?? []).map((item) => (item.edge_id.endsWith("#rev") ? item.edge_id.replace("#rev", "") : item.edge_id)));
}

function getNextLinkId(links: DO326ALink[]): string {
  const max = links.reduce((acc, link) => {
    const value = Number.parseInt(link.link_id.replace("DL-", ""), 10);
    return Number.isFinite(value) ? Math.max(acc, value) : acc;
  }, 0);
  return `DL-${String(max + 1).padStart(3, "0")}`;
}

export function App() {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [links, setLinks] = useState<DO326ALink[]>([]);
  const [message, setMessage] = useState("Load graph data to start");
  const [busy, setBusy] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [layoutVersion, setLayoutVersion] = useState(0);
  const [linkDraft, setLinkDraft] = useState<DO326ALink>({
    link_id: "DL-001",
    standard_id: "DO-326A-3.2.1",
    clause_title: "Security Risk Assessment",
    semantic_element_id: [],
    linkage_type: "Requirement",
    review_status: "Draft"
  });
  const [reviewForm, setReviewForm] = useState<{ link_id: string; review_status: ReviewStatus; reviewer: string }>({
    link_id: "",
    review_status: "Reviewed",
    reviewer: "frontend-reviewer/10001"
  });

  const selectedPath = useMemo(
    () => (selectedPathId ? paths.find((item) => item.path_id === selectedPathId) ?? null : null),
    [paths, selectedPathId]
  );
  const draft = useMemo(() => (graph ? emptyChangeSet(graph.graph_version) : null), [graph]);

  const laneStats = useMemo(() => {
    const stats = new Map<string, number>();
    for (const lane of domainOrder) {
      stats.set(lane, 0);
    }
    for (const asset of graph?.asset_nodes ?? []) {
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
    const lanePosition = buildLanePosition(graph.asset_nodes);
    const threatCountByAsset = new Map<string, number>();
    for (const threat of graph.threat_points) {
      threatCountByAsset.set(threat.related_asset_id, (threatCountByAsset.get(threat.related_asset_id) ?? 0) + 1);
    }

    const createdNodes: Node[] = graph.asset_nodes.map((asset, index) => {
      const threatCount = threatCountByAsset.get(asset.asset_id) ?? 0;
      const position = lanePosition[asset.asset_id] ?? { x: index * 180, y: 0 };
      return {
        id: asset.asset_id,
        position,
        data: {
          label: (
            <div className="topo-node">
              <strong>{asset.asset_name}</strong>
              <span>{asset.asset_type}</span>
              <small>{inferDomain(asset)}</small>
              {threatCount > 0 ? <em>Threat x {threatCount}</em> : null}
            </div>
          )
        },
        style: {
          border: "1px solid #435279",
          borderRadius: "10px",
          background: "#131c34",
          color: "#dbe5ff",
          width: 180,
          padding: 2
        }
      };
    });

    const createdEdges: Edge[] = graph.asset_edges.map((assetEdge) => {
      const highlighted = pathEdgeIds.has(assetEdge.edge_id);
      return {
        id: assetEdge.edge_id,
        source: assetEdge.source_asset_id,
        target: assetEdge.target_asset_id,
        label: `${assetEdge.link_type}${assetEdge.trust_level ? `/${assetEdge.trust_level}` : ""}`,
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
    if (!links.length) {
      setLinkDraft((current) => ({ ...current, link_id: "DL-001" }));
      return;
    }
    setLinkDraft((current) => ({ ...current, link_id: getNextLinkId(links) }));
    if (!reviewForm.link_id) {
      setReviewForm((current) => ({ ...current, link_id: links[0].link_id }));
    }
  }, [links, reviewForm.link_id]);

  async function handleLoadGraph() {
    try {
      setBusy(true);
      const data = await getGraph();
      setGraph(data);
      setLinks(data.do326a_links);
      setMessage(`Graph loaded: version ${data.graph_version}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to load graph");
    } finally {
      setBusy(false);
    }
  }

  async function handleRefreshLinks() {
    try {
      const result = await getDo326aLinks();
      setLinks(result.links);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to load links");
    }
  }

  async function handleValidate() {
    if (!draft) {
      return;
    }
    const result = await validateChangeSet(draft);
    setMessage(result.valid ? "Draft validation passed" : `Draft validation failed: ${result.errors.join("; ")}`);
  }

  async function handleCommit() {
    if (!draft) {
      return;
    }
    const result = await commitChangeSet(draft);
    if (result.committed) {
      setMessage(`Commit succeeded: ${result.commit_id}, version ${result.new_version}`);
      await handleLoadGraph();
    } else {
      setMessage(`Commit failed: ${(result.errors ?? []).join("; ")}`);
    }
  }

  async function handleRunAnalysis() {
    try {
      setBusy(true);
      const result = await runAnalysis();
      setPaths(result.paths);
      setSelectedPathId(result.paths[0]?.path_id ?? null);
      setMessage(`Analysis done: ${result.count} paths`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Analysis failed");
    } finally {
      setBusy(false);
    }
  }

  async function handlePersistPaths() {
    if (paths.length === 0) {
      setMessage("No paths to persist");
      return;
    }
    const result = await persistPaths(paths);
    setMessage(`Persisted ${result.persisted} paths`);
  }

  async function handleSeedSample() {
    try {
      setBusy(true);
      const result = await seedSampleData();
      setMessage(
        `Seed complete: assets=${result.counts.asset_nodes}, edges=${result.counts.asset_edges}, threats=${result.counts.threat_points}, links=${result.counts.do326a_links}`
      );
      await handleLoadGraph();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Seed failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveLink() {
    try {
      const normalizedIds = linkDraft.semantic_element_id
        .map((item) => item.trim())
        .filter((item) => item.length > 0);
      const payload: DO326ALink = {
        ...linkDraft,
        semantic_element_id: normalizedIds
      };
      await createOrUpdateDo326aLink(payload);
      setMessage(`Saved ${payload.link_id}`);
      await handleRefreshLinks();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to save link");
    }
  }

  async function handleReviewLink() {
    try {
      if (!reviewForm.link_id) {
        setMessage("Please select link_id");
        return;
      }
      const reviewer = reviewForm.reviewer.trim();
      await reviewDo326aLink(reviewForm.link_id, reviewForm.review_status, reviewer || undefined);
      setMessage(`Updated review status for ${reviewForm.link_id}`);
      await handleRefreshLinks();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to update review");
    }
  }

  const kpi = {
    assets: graph?.asset_nodes.length ?? 0,
    threats: graph?.threat_points.length ?? 0,
    paths: paths.length,
    links: links.length,
    version: graph?.graph_version ?? "-"
  };

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>Attackgraph Review Console</h1>
          <p>Design-native schema + DPS heuristic scoring + DO326A mapping</p>
        </div>
        <div className="header-actions">
          <button className="button primary" onClick={handleSeedSample} disabled={busy}>
            Seed Sample
          </button>
          <button className="button" onClick={handleLoadGraph} disabled={busy}>
            Refresh Graph
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
          <span>DO326A Link</span>
          <strong>{kpi.links}</strong>
        </article>
      </section>

      <div className="layout">
        <aside className="panel left">
          <h3>Domain View</h3>
          <p>Assets grouped by security domain</p>
          <div className="lane-row">
            {laneStats.map(([lane, count]) => (
              <span key={lane} className="lane-pill">
                {lane} / {count}
              </span>
            ))}
          </div>
          <div className="list compact">
            {(graph?.asset_nodes ?? []).map((asset) => (
              <div key={asset.asset_id} className="item vertical">
                <strong>{asset.asset_name}</strong>
                <span>{asset.asset_id}</span>
                <span>
                  {asset.asset_type} / {asset.criticality}
                </span>
              </div>
            ))}
          </div>
        </aside>

        <main className="panel center">
          <h3>Topology Canvas</h3>
          <div className="toolbar">
            <button className="button" onClick={handleRunAnalysis} disabled={busy}>
              Run DPS Analysis
            </button>
            <button className="button" onClick={handlePersistPaths} disabled={busy || paths.length === 0}>
              Persist Paths
            </button>
            <button className="button" onClick={() => setLayoutVersion((v) => v + 1)} disabled={busy || !graph}>
              Re-layout
            </button>
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
          <h3>Review Panel</h3>
          <p className="status">{message}</p>

          <h3>Path Ranking</h3>
          <div className="list">
            {paths.slice(0, 8).map((path) => (
              <div
                key={path.path_id}
                className={`item vertical clickable ${selectedPathId === path.path_id ? "active" : ""}`}
                onClick={() => setSelectedPathId(path.path_id)}
              >
                <strong>
                  {path.priority_label} / {path.path_id}
                </strong>
                <span>{path.hop_sequence}</span>
                <span>normalized={path.normalized_score.toFixed(3)}</span>
                <span>{path.is_low_priority ? "low priority" : "mitigation queue"}</span>
              </div>
            ))}
          </div>
        </aside>

        <footer className="panel bottom">
          <h3>ChangeSet + DO326A Mapping</h3>
          <div className="toolbar">
            <button className="button" onClick={handleValidate} disabled={!draft || busy}>
              Validate Draft
            </button>
            <button className="button primary" onClick={handleCommit} disabled={!draft || busy}>
              Commit Draft
            </button>
            <button className="button" onClick={handleRefreshLinks} disabled={busy}>
              Refresh Links
            </button>
          </div>

          <div className="toolbar">
            <input
              className="button"
              style={{ width: 120, cursor: "text" }}
              value={linkDraft.link_id}
              onChange={(event) => setLinkDraft((current) => ({ ...current, link_id: event.target.value }))}
              placeholder="DL-001"
            />
            <input
              className="button"
              style={{ width: 180, cursor: "text" }}
              value={linkDraft.standard_id}
              onChange={(event) => setLinkDraft((current) => ({ ...current, standard_id: event.target.value }))}
              placeholder="DO-326A-3.2.1"
            />
            <input
              className="button"
              style={{ width: 220, cursor: "text" }}
              value={linkDraft.clause_title}
              onChange={(event) => setLinkDraft((current) => ({ ...current, clause_title: event.target.value }))}
              placeholder="clause_title"
            />
            <input
              className="button"
              style={{ width: 280, cursor: "text" }}
              value={linkDraft.semantic_element_id.join(",")}
              onChange={(event) =>
                setLinkDraft((current) => ({
                  ...current,
                  semantic_element_id: event.target.value.split(",")
                }))
              }
              placeholder="semantic ids: SYS-CIS,TP-EXT-WIFI-01"
            />
            <button className="button" onClick={handleSaveLink}>
              Save Link
            </button>
          </div>

          <div className="toolbar">
            <select
              className="button"
              style={{ width: 130 }}
              value={reviewForm.link_id}
              onChange={(event) => setReviewForm((current) => ({ ...current, link_id: event.target.value }))}
            >
              <option value="">select link</option>
              {links.map((link) => (
                <option key={link.link_id} value={link.link_id}>
                  {link.link_id}
                </option>
              ))}
            </select>
            <select
              className="button"
              style={{ width: 120 }}
              value={reviewForm.review_status}
              onChange={(event) =>
                setReviewForm((current) => ({ ...current, review_status: event.target.value as ReviewStatus }))
              }
            >
              <option value="Draft">Draft</option>
              <option value="Reviewed">Reviewed</option>
              <option value="Approved">Approved</option>
            </select>
            <input
              className="button"
              style={{ width: 200, cursor: "text" }}
              value={reviewForm.reviewer}
              onChange={(event) => setReviewForm((current) => ({ ...current, reviewer: event.target.value }))}
              placeholder="reviewer"
            />
            <button className="button" onClick={handleReviewLink}>
              Update Review
            </button>
          </div>

          <div className="list" style={{ maxHeight: 180 }}>
            {links.map((link) => (
              <div key={link.link_id} className="item vertical">
                <strong>
                  {link.link_id} / {link.review_status}
                </strong>
                <span>{link.standard_id}</span>
                <span>{link.clause_title}</span>
                <span>{link.semantic_element_id.join(", ")}</span>
              </div>
            ))}
          </div>
        </footer>
      </div>
    </div>
  );
}
