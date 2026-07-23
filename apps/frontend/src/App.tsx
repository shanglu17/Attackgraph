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
  commitF353203,
  exportModelingResult,
  getBoundaryDataFlowReport,
  getFunctionPropagationReport,
  getF3532Report03,
  getGraph,
  getInternalDataFlowReport,
  getTrustBoundaryReport,
  persistPaths,
  runAnalysis,
  runF3532Generate03,
  runFunctionPropagationAnalysis,
  type FpGroupBy,
  seedGenericData,
  seedSampleData
} from "./api";
import { CxfImportPanel } from "./CxfImportPanel";
import { F3532ImportPanel } from "./F3532ImportPanel";
import { F353204Panel } from "./F353204Panel";
import { AppWorkspaceNav, type AppWorkspace } from "./app/AppWorkspaceNav";
import { ChangeSetStudio } from "./features/changes/ChangeSetStudio";
import type {
  AssetNode,
  AttackPath,
  BoundaryDataFlowReportRow,
  F353203BoundaryFlowRow,
  F353203PathRow,
  F3532Report03Data,
  FunctionPropagationReportRow,
  InternalDataFlowReportRow,
  GraphData,
  TrustBoundaryReportRow
} from "./types";

type ImportWorkspace = "f3532" | "cxf" | "f353204";
const IMPORT_WORKSPACES: Array<{ id: ImportWorkspace; label: string; description: string }> = [
  { id: "f3532", label: "F3532 01/02", description: "导入 01、02，准备生成 03" },
  { id: "cxf", label: "CXF 多 Sheet", description: "导入资产/接口/数据流清单" },
  { id: "f353204", label: "F3532 04 / FHA", description: "导入 FHA 并生成 04 草稿" }
];
const domainOrder = ["Internal", "Shared", "DMZ", "External"];

function inferDomain(asset: AssetNode): string {
  return asset.security_domain ?? "Shared";
}

function buildLanePosition(assets: AssetNode[]): Record<string, { x: number; y: number }> {
  const laneCounts = new Map<string, number>();
  const positions: Record<string, { x: number; y: number }> = {};
  const laneGroups = new Map<string, AssetNode[]>();
  for (const lane of domainOrder) {
    laneCounts.set(lane, 0);
    laneGroups.set(lane, []);
  }

  for (const asset of assets) {
    const lane = inferDomain(asset);
    const list = laneGroups.get(lane) ?? laneGroups.get("Shared") ?? [];
    list.push(asset);
    laneGroups.set(lane, list);
  }

  const maxLaneDepth = Math.max(...Array.from(laneGroups.values(), (items) => items.length), 1);
  const xGap = maxLaneDepth >= 5 ? 210 : 225;
  const yGap = maxLaneDepth >= 5 ? 104 : 118;

  for (const lane of domainOrder) {
    const laneIndex = domainOrder.indexOf(lane);
    for (const asset of laneGroups.get(lane) ?? []) {
      const row = laneCounts.get(lane) ?? 0;
      laneCounts.set(lane, row + 1);
      positions[asset.asset_id] = {
        x: Math.max(0, laneIndex) * xGap,
        y: row * yGap
      };
    }
  }
  return positions;
}

function edgeIdSetFromPath(path: AttackPath | null): Set<string> {
  return new Set((path?.traverses ?? []).map((item) => (item.edge_id.endsWith("#rev") ? item.edge_id.replace("#rev", "") : item.edge_id)));
}

function createExportFileName(analysisBatchId?: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const batchPart = analysisBatchId ? `-${analysisBatchId.replace(/[^a-zA-Z0-9-_]+/g, "_")}` : "";
  return `astra-aviation-threat-modeling-result${batchPart}-${timestamp}.json`;
}

function downloadJson(payload: unknown, fileName: string): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  window.URL.revokeObjectURL(url);
}

async function exportChapter4Workbook(
  boundaryRows: TrustBoundaryReportRow[],
  dataFlowRows: BoundaryDataFlowReportRow[],
  propagationRows: FunctionPropagationReportRow[],
  internalRows: InternalDataFlowReportRow[]
): Promise<void> {
  const xlsx = await import("xlsx");
  const wb = xlsx.utils.book_new();

  const sheet42 = [
    ["信任边界", "边界名称", "边界说明", "对应接口(BI)", "相关威胁主体(TA)"],
    ...boundaryRows.map((row) => [
      row.boundary_id,
      row.name,
      row.description ?? "",
      row.interfaces.join("、"),
      row.threat_actors.join("、")
    ])
  ];
  xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(sheet42), "4.2 信任边界汇总");

  const sheet43 = [
    ["信任边界", "数据流类型", "典型接口(BI)", "关联BDF", "关联功能(F)", "是否进入内部传播"],
    ...dataFlowRows.map((row) => [
      row.boundary_id,
      row.data_flow_type,
      row.interfaces.join("、"),
      row.bdf_ids.join("、"),
      row.function_ids.join("、"),
      row.enters_internal_propagation ? "是" : "否"
    ])
  ];
  xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(sheet43), "4.3 边界数据流分析");

  const sheet44 = [
    ["SDF编号", "产生者", "用户", "数据流类型", "内容", "影响功能", "起点归类", "是否边界可达"],
    ...internalRows.map((row) => [
      row.sdf_id,
      row.producer,
      row.consumer,
      row.data_flow_type,
      row.content ?? "",
      row.function_ids.join("、"),
      row.origin_class,
      row.boundary_reachable ? "是" : "否（纯内部）"
    ])
  ];
  xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(sheet44), "4.4 内部数据流分析");

  const sheet45 = [
    ["FP编号", "数据类型", "入口BI", "关联BDF", "关联SDF", "系统传播路径", "影响功能"],
    ...propagationRows.map((row) => [
      row.fp_id,
      row.data_type,
      row.entry_bis.join("、"),
      row.bdf_ids.join("、"),
      row.sdf_ids.length > 0 ? row.sdf_ids.join("、") : row.sdf_note ?? "",
      row.system_path,
      row.function_ids.join("、")
    ])
  ];
  xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(sheet45), "4.5 功能传播路径");

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  xlsx.writeFile(wb, `vol3-chapter4-report-${timestamp}.xlsx`);
}

async function exportF353203Workbook(
  dataFlowRows: F353203BoundaryFlowRow[],
  propagationRows: F353203PathRow[]
): Promise<void> {
  const xlsx = await import("xlsx");
  const wb = xlsx.utils.book_new();

  const bdfBoundarySheet = [
    ["信任边界", "数据流类型", "边界接口(BI)", "关联BDF", "关联功能"],
    ...dataFlowRows.map((row) => [
      row.security_boundary,
      row.data_flow_type,
      row.boundary_interface_ids.join("、"),
      row.bdf_display,
      row.function_display
    ])
  ];
  xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(bdfBoundarySheet), "边界数据流-安保边界对照表");

  const pathSheet = [
    ["路径编号", "路径名称", "数据流类型", "入口/起源边界", "关联外部BI", "关联SDF", "关联内部SI", "关联BDF", "关联功能", "路径简述"],
    ...propagationRows.map((row) => [
      row.path_id,
      row.path_name,
      row.data_flow_types.join("/"),
      row.origin,
      row.boundary_interface_ids.join("、"),
      row.sdf_ids.join("、"),
      row.system_interface_ids.join("、"),
      row.bdf_ids.join("、"),
      row.function_ids.join("、"),
      row.path_description
    ])
  ];
  xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet(pathSheet), "关键数据流传播路径表");

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  xlsx.writeFile(wb, `f3532-03-report-${timestamp}.xlsx`);
}

export function App() {
  const [activeWorkspace, setActiveWorkspace] = useState<AppWorkspace>("analysis");
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [message, setMessage] = useState("Load graph data to start");
  const [busy, setBusy] = useState(false);
  const [exportBatchId, setExportBatchId] = useState("");
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [layoutVersion, setLayoutVersion] = useState(0);
  const [importWorkspace, setImportWorkspace] = useState<ImportWorkspace>("f3532");
  const [boundaryReport, setBoundaryReport] = useState<TrustBoundaryReportRow[]>([]);
  const [dataFlowReport, setDataFlowReport] = useState<BoundaryDataFlowReportRow[]>([]);
  const [propagationReport, setPropagationReport] = useState<FunctionPropagationReportRow[]>([]);
  const [internalFlowReport, setInternalFlowReport] = useState<InternalDataFlowReportRow[]>([]);
  const [f353203Report, setF353203Report] = useState<F3532Report03Data | null>(null);
  const [fpGroupBy, setFpGroupBy] = useState<FpGroupBy>("boundary");
  const [reportLoaded, setReportLoaded] = useState(false);

  const selectedPath = useMemo(
    () => (selectedPathId ? paths.find((item) => item.path_id === selectedPathId) ?? null : null),
    [paths, selectedPathId]
  );
  const links = graph?.do326a_links ?? [];

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
          border: "1px solid #8ea7d1",
          borderRadius: "10px",
          background: "#f8fbff",
          color: "#243453",
          width: 168,
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
          stroke: highlighted ? "#4f7dff" : "#7f96bf",
          strokeWidth: highlighted ? 2.8 : 1.4
        },
        labelStyle: { fill: highlighted ? "#3d62c9" : "#667da6", fontSize: 11 }
      };
    });

    setNodes(createdNodes);
    setEdges(createdEdges);
  }, [graph, selectedPath, layoutVersion]);

  async function handleLoadGraph() {
    try {
      setBusy(true);
      const data = await getGraph();
      setGraph(data);
      setMessage(`Graph loaded: version ${data.graph_version}.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to load graph");
    } finally {
      setBusy(false);
    }
  }

  async function handleRunAnalysis() {
    try {
      setBusy(true);
      const result = await runAnalysis();
      setPaths(result.paths);
      setSelectedPathId(result.paths[0]?.path_id ?? null);
      setExportBatchId(result.paths[0]?.analysis_batch_id ?? "");
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
    try {
      setBusy(true);
      const result = await persistPaths(paths);
      setMessage(`Persisted ${result.persisted} paths`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Persist failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleSeedSample() {
    try {
      setBusy(true);
      const result = await seedSampleData();
      setMessage(
        `DO-356A seed complete: assets=${result.counts.asset_nodes}, edges=${result.counts.asset_edges}, threats=${result.counts.threat_points}, links=${result.counts.do326a_links}`
      );
      await handleLoadGraph();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Seed failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleSeedGeneric() {
    try {
      setBusy(true);
      const result = await seedGenericData();
      setMessage(
        `Generic seed complete: assets=${result.counts.asset_nodes}, edges=${result.counts.asset_edges}, threats=${result.counts.threat_points}, links=${result.counts.do326a_links}`
      );
      await handleLoadGraph();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Seed failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleWorkbookImportCommit(result: { commit_id?: string; new_version?: string }) {
    try {
      setBusy(true);
      const data = await getGraph();
      setGraph(data);
      setMessage(`Workbook import committed: ${result.commit_id ?? "-"}, version ${result.new_version ?? data.graph_version}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to refresh graph after import");
    } finally {
      setBusy(false);
    }
  }

  async function handleExportResult() {
    try {
      setBusy(true);
      const analysisBatchId = exportBatchId.trim() || undefined;
      const payload = await exportModelingResult(analysisBatchId);
      downloadJson(payload, createExportFileName(analysisBatchId));
      setMessage(
        analysisBatchId
          ? `Exported modeling result for analysis batch ${analysisBatchId}`
          : "Exported modeling result for the full dataset"
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to export modeling result");
    } finally {
      setBusy(false);
    }
  }

  async function handleLoadChapter4Report() {
    try {
      setBusy(true);
      const [tb, bdf, fp, idf] = await Promise.all([
        getTrustBoundaryReport(),
        getBoundaryDataFlowReport(),
        getFunctionPropagationReport(),
        getInternalDataFlowReport()
      ]);
      setBoundaryReport(tb.rows);
      setDataFlowReport(bdf.rows);
      setPropagationReport(fp.rows);
      setInternalFlowReport(idf.rows);
      setF353203Report(null);
      setReportLoaded(true);
      const pureInternal = idf.rows.filter((row) => !row.boundary_reachable).length;
      setMessage(
        `第四章报告已加载：信任边界 ${tb.rows.length} 行，边界数据流 ${bdf.rows.length} 行，功能传播路径 ${fp.rows.length} 行，内部数据流 ${idf.rows.length} 行（纯内部 ${pureInternal} 条）`
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to load chapter 4 report");
    } finally {
      setBusy(false);
    }
  }

  async function handleRunFpAnalysis() {
    try {
      setBusy(true);
      const result = await runFunctionPropagationAnalysis({ groupBy: fpGroupBy });
      setPropagationReport(result.rows);
      setReportLoaded(true);
      setMessage(`FP 分析完成（按 ${fpGroupBy} 归并）：由 BDF+SDF 归并出 ${result.fp_count} 条功能传播路径`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to run FP analysis");
    } finally {
      setBusy(false);
    }
  }

  async function handleGenerateF353203() {
    try {
      setBusy(true);
      const result = await runF3532Generate03();
      setF353203Report(result);
      setReportLoaded(true);
      setMessage(
        `F3532 03 只读预览：逐 BDF ${result.boundary_data_flows.count} 行，路径 ${result.propagation_paths.count} 条（确认 ${result.metadata.confirmed_count} / 待审核 ${result.metadata.needs_review_count} / 未匹配 ${result.metadata.unmatched_count}）`
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to generate F3532 03");
    } finally {
      setBusy(false);
    }
  }

  async function handleCommitF353203() {
    if (!f353203Report) {
      setMessage("请先生成 F3532 03 只读预览，再基于预览 GraphVersion 显式提交");
      return;
    }
    try {
      setBusy(true);
      const result = await commitF353203({ expectedGraphVersion: f353203Report.metadata.graph_version });
      setF353203Report(result);
      setMessage(`F3532 03 已提交 ${result.committed_path_count ?? result.propagation_paths.count} 条路径；人工/Approved 路径未被覆盖`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to commit F3532 03");
    } finally {
      setBusy(false);
    }
  }

  async function handleLoadF353203() {
    try {
      setBusy(true);
      const result = await getF3532Report03();
      setF353203Report(result);
      setReportLoaded(true);
      setMessage(
        `F3532 03 已按当前 GraphVersion 只读重算：逐 BDF ${result.boundary_data_flows.count} 行，路径 ${result.propagation_paths.count} 条`
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to load F3532 03");
    } finally {
      setBusy(false);
    }
  }

  async function handleExportF353203() {
    try {
      setBusy(true);
      const report = f353203Report ?? await getF3532Report03();
      await exportF353203Workbook(report.boundary_data_flows.rows, report.propagation_paths.rows);
      setMessage("F3532 03 已导出为 Excel 文件");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to export F3532 03");
    } finally {
      setBusy(false);
    }
  }

  async function handleExportChapter4() {
    try {
      setBusy(true);
      const [tb, bdf, fp, idf] = reportLoaded
        ? [{ rows: boundaryReport }, { rows: dataFlowReport }, { rows: propagationReport }, { rows: internalFlowReport }]
        : await Promise.all([
            getTrustBoundaryReport(),
            getBoundaryDataFlowReport(),
            getFunctionPropagationReport(),
            getInternalDataFlowReport()
          ]);
      await exportChapter4Workbook(tb.rows, bdf.rows, fp.rows, idf.rows);
      setMessage("第四章报告已导出为 Excel 文件");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to export chapter 4 report");
    } finally {
      setBusy(false);
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
        <div className="brand-block">
          <h1>ASTRA 航空威胁建模语义分析系统</h1>
          <p>Aviation Semantic Threat Reasoning & Analysis System</p>
        </div>
        <div className="header-actions">
          <button className="button primary" onClick={handleSeedSample} disabled={busy}>
            载入 DO-356A 示例
          </button>
          <button className="button" onClick={handleSeedGeneric} disabled={busy}>
            载入通用示例
          </button>
          <button className="button" onClick={handleLoadGraph} disabled={busy}>
            刷新图谱
          </button>
        </div>
      </header>

      <AppWorkspaceNav activeWorkspace={activeWorkspace} status={message} onChange={setActiveWorkspace} />

      <main className="workspace-content">
      <section className={activeWorkspace === "analysis" ? "kpi-grid" : "hidden"} aria-label="图谱指标">
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

      <section className={activeWorkspace === "imports" ? "import-workspace" : "hidden"} aria-label="数据导入工作台">
        <div className="import-switcher-header">
          <div>
            <h2 className="section-title">数据导入工作台</h2>
            <p>{IMPORT_WORKSPACES.find((item) => item.id === importWorkspace)?.description}</p>
          </div>
          <div className="mode-toggle import-tabs" role="tablist" aria-label="Upload type">
            {IMPORT_WORKSPACES.map((workspace) => (
              <button
                key={workspace.id}
                type="button"
                role="tab"
                aria-selected={importWorkspace === workspace.id}
                className={`mode-toggle-button ${importWorkspace === workspace.id ? "active" : ""}`}
                onClick={() => setImportWorkspace(workspace.id)}
              >
                {workspace.label}
              </button>
            ))}
          </div>
        </div>

        <div className={importWorkspace === "f3532" ? "import-tab-panel" : "import-tab-panel hidden"} role="tabpanel">
          <F3532ImportPanel disabled={busy} onStatusChange={setMessage} onCommitSuccess={handleWorkbookImportCommit} />
        </div>
        <div className={importWorkspace === "cxf" ? "import-tab-panel" : "import-tab-panel hidden"} role="tabpanel">
          <CxfImportPanel disabled={busy} onStatusChange={setMessage} onCommitSuccess={handleWorkbookImportCommit} />
        </div>
        <div className={importWorkspace === "f353204" ? "import-tab-panel" : "import-tab-panel hidden"} role="tabpanel">
          <F353204Panel disabled={busy} onStatusChange={setMessage} />
        </div>
      </section>

      <div className={`layout workspace-${activeWorkspace}`}>
        <aside className={activeWorkspace === "analysis" ? "panel left" : "hidden"}>
          <h3>Domain View</h3>
          <p>Assets grouped by security domain</p>
          <div className="lane-row">
            {laneStats.map(([lane, count]) => (
              <span key={lane} className="lane-pill">
                {lane} / {count}
              </span>
            ))}
          </div>
          <div className="scroll-panel domain-scroll-panel">
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
          </div>
        </aside>

        <section className={activeWorkspace === "analysis" ? "panel center" : "hidden"}>
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
              fitViewOptions={{ padding: 0.08 }}
              minZoom={0.2}
              maxZoom={1.5}
              onNodesChange={(changes: NodeChange[]) => setNodes((current) => applyNodeChanges(changes, current))}
              onEdgesChange={(changes: EdgeChange[]) => setEdges((current) => applyEdgeChanges(changes, current))}
            >
              <MiniMap pannable zoomable style={{ width: 136, height: 88 }} />
              <Controls />
              <Background gap={16} color="#a9bcdd" />
            </ReactFlow>
          </div>
        </section>

        <aside className={activeWorkspace === "analysis" || activeWorkspace === "reports" ? "panel right review-panel" : "hidden"}>
          <div className={activeWorkspace === "analysis" ? "review-section" : "hidden"}>
          <div className="section-heading">
            <div>
              <h2 className="section-title">攻击路径审查</h2>
              <p>按优先级检查分析结果，选择路径后会在拓扑中高亮。</p>
            </div>
          </div>
          <div className="toolbar wrap">
            <input
              className="input-field"
              value={exportBatchId}
              onChange={(event) => setExportBatchId(event.target.value)}
              placeholder="analysis_batch_id (optional)"
            />
            <button className="button" onClick={handleExportResult} disabled={busy}>
              Export Modeling JSON
            </button>
          </div>

          <h3>Path Ranking</h3>
          <div className="scroll-panel path-scroll-panel">
            <div className="list path-list">
              {paths.map((path) => (
                <button
                  key={path.path_id}
                  type="button"
                  className={`item vertical clickable ${selectedPathId === path.path_id ? "active" : ""}`}
                  onClick={() => setSelectedPathId(path.path_id)}
                >
                  <strong>
                    {path.priority_label} / {path.path_id}
                  </strong>
                  <span>{path.hop_sequence}</span>
                  <span>normalized={path.normalized_score.toFixed(3)}</span>
                  <span>{path.is_low_priority ? "low priority" : "mitigation queue"}</span>
                </button>
              ))}
              {paths.length === 0 ? <div className="item vertical">Run analysis to populate attack paths.</div> : null}
            </div>
          </div>
          </div>

          <div className={activeWorkspace === "reports" ? "review-section report-section" : "hidden"}>
          <div className="section-heading">
            <div>
              <h2 className="section-title">报告中心</h2>
              <p>生成、检查并导出 F3532 03 与第四章分析结果。</p>
            </div>
          </div>
          <div className="toolbar wrap">
            <button className="button primary" onClick={handleGenerateF353203} disabled={busy}>
              预览 F3532 03
            </button>
            <button className="button" onClick={handleCommitF353203} disabled={busy || !f353203Report}>
              提交 F3532 03
            </button>
            <button className="button" onClick={handleLoadF353203} disabled={busy}>
              加载 F3532 03
            </button>
            <button className="button" onClick={handleExportF353203} disabled={busy}>
              导出 03 Excel
            </button>
            <button className="button" onClick={handleLoadChapter4Report} disabled={busy}>
              加载 vol3 报告
            </button>
            <select
              className="input-field"
              value={fpGroupBy}
              onChange={(event) => setFpGroupBy(event.target.value as FpGroupBy)}
              disabled={busy}
              title="FP 归并粒度"
            >
              <option value="boundary">按信任边界(SB)</option>
              <option value="function">按影响功能集合</option>
              <option value="type">按数据类型</option>
            </select>
            <button className="button" onClick={handleRunFpAnalysis} disabled={busy}>
              分析生成FP
            </button>
            <button className="button" onClick={handleExportChapter4} disabled={busy}>
              导出 vol3 Excel
            </button>
          </div>
          {f353203Report ? (
            <div className="scroll-panel">
              <p>
                GraphVersion {f353203Report.metadata.graph_version}；确认 {f353203Report.metadata.confirmed_count} / 待审核 {f353203Report.metadata.needs_review_count} / 未匹配 {f353203Report.metadata.unmatched_count}
              </p>
              <h4>边界数据流—安保边界对照表（逐 BDF）</h4>
              <table className="report-table">
                <thead><tr><th>安保边界</th><th>数据流类型</th><th>边界接口</th><th>关联BDF</th><th>关联功能</th><th>方向/状态</th></tr></thead>
                <tbody>
                  {f353203Report.boundary_data_flows.rows.map((row) => (
                    <tr key={row.bdf_id}>
                      <td>{row.security_boundary || "—"}</td><td>{row.data_flow_type}</td>
                      <td>{row.boundary_interface_ids.join("、") || "—"}</td><td>{row.bdf_display}</td>
                      <td>{row.function_display || "—"}</td><td>{row.direction}{row.warnings.length ? " / 待核" : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <h4>关键数据流传播路径表</h4>
              <table className="report-table">
                <thead><tr><th>编号</th><th>名称</th><th>起源</th><th>外部BI</th><th>内部SI</th><th>BDF</th><th>SDF</th><th>功能</th><th>系统路径</th><th>简述/状态</th></tr></thead>
                <tbody>
                  {f353203Report.propagation_paths.rows.map((row) => (
                    <tr key={row.path_id}>
                      <td>{row.path_id}</td><td>{row.path_name}</td><td>{row.origin}</td>
                      <td>{row.boundary_interface_ids.join("、") || "—"}</td><td>{row.system_interface_ids.join("、") || "—"}</td>
                      <td>{row.bdf_ids.join("、") || "—"}</td><td>{row.sdf_ids.join("、") || "—"}</td>
                      <td>{row.function_ids.join("、") || "—"}</td><td>{row.system_path || "—"}</td>
                      <td>{row.path_description}<br />[{row.status}]</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          {reportLoaded && !f353203Report ? (
            <div className="scroll-panel">
              <h4>4.2 信任边界汇总</h4>
              <table className="report-table">
                <thead>
                  <tr>
                    <th>信任边界</th>
                    <th>对应接口(BI)</th>
                    <th>相关威胁主体(TA)</th>
                  </tr>
                </thead>
                <tbody>
                  {boundaryReport.map((row) => (
                    <tr key={row.boundary_id}>
                      <td>{row.boundary_id} {row.name}</td>
                      <td>{row.interfaces.join("、") || "—"}</td>
                      <td>{row.threat_actors.join("、") || "—"}</td>
                    </tr>
                  ))}
                  {boundaryReport.length === 0 ? (
                    <tr>
                      <td colSpan={3}>无信任边界数据（导入含信任边界表的模板后可见）。</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>

              <h4>4.3 边界数据流分析</h4>
              <table className="report-table">
                <thead>
                  <tr>
                    <th>边界</th>
                    <th>数据流类型</th>
                    <th>典型接口(BI)</th>
                    <th>关联BDF</th>
                    <th>关联功能(F)</th>
                    <th>内部传播</th>
                  </tr>
                </thead>
                <tbody>
                  {dataFlowReport.map((row) => (
                    <tr key={`${row.boundary_id}-${row.data_flow_type}`}>
                      <td>{row.boundary_id}</td>
                      <td>{row.data_flow_type}</td>
                      <td>{row.interfaces.join("、") || "—"}</td>
                      <td>{row.bdf_ids.join("、") || "—"}</td>
                      <td>{row.function_ids.join("、") || "—"}</td>
                      <td>{row.enters_internal_propagation ? "是" : "否"}</td>
                    </tr>
                  ))}
                  {dataFlowReport.length === 0 ? (
                    <tr>
                      <td colSpan={6}>无边界数据流数据。</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>

              <h4>4.5 功能传播路径 (FP)</h4>
              <table className="report-table">
                <thead>
                  <tr>
                    <th>FP编号</th>
                    <th>数据类型</th>
                    <th>入口BI</th>
                    <th>关联BDF</th>
                    <th>关联SDF</th>
                    <th>系统传播路径</th>
                    <th>影响功能</th>
                  </tr>
                </thead>
                <tbody>
                  {propagationReport.map((row) => (
                    <tr key={row.fp_id}>
                      <td>{row.fp_id}</td>
                      <td>{row.data_type || "—"}</td>
                      <td>{row.entry_bis.join("、") || "—"}</td>
                      <td>{row.bdf_ids.join("、") || "—"}</td>
                      <td>{row.sdf_ids.length > 0 ? row.sdf_ids.join("、") : row.sdf_note || "—"}</td>
                      <td>{row.system_path || "—"}</td>
                      <td>{row.function_ids.join("、") || "—"}</td>
                    </tr>
                  ))}
                  {propagationReport.length === 0 ? (
                    <tr>
                      <td colSpan={7}>无功能传播路径数据（导入含系统数据流表/功能传播路径表的模板后可见）。</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          ) : null}
          </div>
        </aside>

        {activeWorkspace === "changes" ? (
          <ChangeSetStudio
            graph={graph}
            busy={busy}
            onBusyChange={setBusy}
            onMessageChange={setMessage}
            onReloadGraph={handleLoadGraph}
          />
        ) : null}
      </div>
      </main>
    </div>
  );
}
