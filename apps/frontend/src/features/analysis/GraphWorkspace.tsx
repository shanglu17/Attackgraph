import { RunLoadStatus } from "../../shared/components/RunLoadStatus";
import { useMemo } from "react";
import { useWorkbench } from "../../app/WorkspaceProvider";
import { workbenchApi } from "../../api";
import {
  currentRun,
  graphData,
  runMetadata,
  runPaths,
} from "../../shared/model/workbench";
import { TopologyCanvas } from "./TopologyCanvas";
import { PathRanking } from "./PathRanking";
export default function GraphWorkspace() {
  const { state, patch, perform, envelope, refresh, navigate } = useWorkbench();
  const snapshot = state.snapshot;
  const run =
    state.runs.find((r) => r.id === state.selectedRun) ??
    state.runs.slice(-1)[0];
  const metadata = runMetadata(run);
  const paths = useMemo(() => runPaths(run), [run]);
  const graph = useMemo(
    () => (snapshot ? graphData(snapshot) : null),
    [snapshot],
  );
  if (!snapshot || !graph?.asset_nodes.length)
    return (
      <section className="panel">
        <h2>图谱分析</h2>
        <p>当前修订尚无模型，请先导入清单。</p>
        <button className="button primary" onClick={() => navigate("imports")}>
          准备数据
        </button>
      </section>
    );
  const current = currentRun(run, snapshot, state.parameters);
  const selected =
    paths.find((p) => p.path_id === state.selectedPath) ?? paths[0];
  const asset = graph.asset_nodes.find(
    (a) => a.asset_id === state.selectedAsset,
  );
  return (
    <section>
      <RunLoadStatus/>
      <div className="panel">
        <span className="tag">02 / 检查模型与分析</span>
        <h2>从入口追踪到关键资产</h2>
        <p>
          {graph.asset_nodes.length} 个资产 · {graph.asset_edges.length} 条连接
          · {graph.threat_points.length} 个威胁候选
        </p>
        <p>
          本次实际分析目标：
          {snapshot.target_ids
            .map(
              (id) =>
                graph.asset_nodes.find((a) => a.asset_id === id)?.asset_name ??
                id,
            )
            .join("、") || "未识别到目标"}
        </p>
        <div className="toolbar wrap">
          <label className="field-stack">
            最大跳数
            <input
              className="input-field"
              type="number"
              min={1}
              max={8}
              value={state.parameters.max_hops}
              disabled={state.busy}
              onChange={(e) =>
                patch({
                  parameters: {
                    ...state.parameters,
                    max_hops: Number(e.target.value),
                  },
                })
              }
            />
          </label>
          <label className="field-stack">
            每跳衰减
            <input
              className="input-field"
              type="number"
              min={0.8}
              max={1}
              step={0.01}
              value={state.parameters.dps_hop_decay}
              disabled={state.busy}
              onChange={(e) =>
                patch({
                  parameters: {
                    ...state.parameters,
                    dps_hop_decay: Number(e.target.value),
                  },
                })
              }
            />
          </label>
          <button
            className="button primary"
            disabled={
              state.busy ||
              !!state.draft ||
              snapshot.status !== "Draft" ||
              state.parameters.max_hops < 1 ||
              state.parameters.max_hops > 8 ||
              state.parameters.dps_hop_decay < 0.8 ||
              state.parameters.dps_hop_decay > 1
            }
            onClick={() =>
              void perform(async () => {
                const result = await workbenchApi.run({
                  ...envelope("analysis", state.parameters),
                  contract_version: "saved-model-analysis.v1",
                  parameters: state.parameters,
                });
                await refresh();
                patch({
                  selectedRun: result.run_id,
                  selectedPath: "",
                  message:
                    result.status === "Failed"
                      ? "分析失败，已保存诊断记录。"
                      : "分析完成。点击排名查看路径高亮与评分解释。",
                  error:
                    result.status === "Failed"
                      ? (result.error ?? "分析失败，请查看诊断后重试")
                      : "",
                });
              })
            }
          >
            {state.busy ? "处理中…" : "运行 DPS 分析"}
          </button>
        </div>
        {state.draft && (
          <p className="workbench-warning">
            存在未保存草稿，请先在变更管理保存或放弃。正式分析只读取服务端模型。
          </p>
        )}
        {run && !current && (
          <p className="workbench-warning">
            以下为历史或已过期结果；重新分析后才能导出为当前成果。
          </p>
        )}
        {metadata && (
          <p>
            输入模型 v{run.input_revision_version} · 映射{" "}
            {metadata.mapping_version} · 计算 {metadata.calculation_ms} ms
          </p>
        )}
      </div>
      <div className="workbench-analysis-grid">
        <aside className="panel">
          <h3>模型检查</h3>
          <div className="workbench-asset-list scroll-panel">
            {graph.asset_nodes.map((a) => (
              <button
                className={`button ${asset?.asset_id === a.asset_id ? "active" : ""}`}
                key={a.asset_id}
                onClick={() => patch({ selectedAsset: a.asset_id })}
              >
                {a.asset_name}
                {snapshot.target_ids.includes(a.asset_id) ? " ◎" : ""}
              </button>
            ))}
          </div>
          {asset ? (
            <div className="preview-card">
              <h4>{asset.asset_name}</h4>
              <p>
                {asset.asset_id} · {asset.asset_type} · {asset.security_domain}{" "}
                · {asset.criticality}
              </p>
              <p>{asset.description}</p>
              <p>
                来源：{asset.source_sheet ?? "核心模型 / 人工编辑"} · Excel{" "}
                {asset.source_row ?? "—"} 行
              </p>
              <h4>关联候选威胁（自动威胁未经人工确认）</h4>
              {graph.threat_points
                .filter((t) => t.related_asset_id === asset.asset_id)
                .map((t) => (
                  <p key={t.threatpoint_id}>
                    {t.name} · 入口 {t.entry_likelihood_level} / 复杂度{" "}
                    {t.attack_complexity_level}
                  </p>
                ))}
            </div>
          ) : (
            <p>点击资产或拓扑节点查看属性与来源。</p>
          )}
          <button className="button" onClick={() => navigate("changes")}>
            编辑模型与威胁
          </button>
        </aside>
        <div className="panel">
          <h3>安全域拓扑</h3>
          <p>◎ 为推断目标。点击节点查看属性；点击路径高亮节点与连接。</p>
          <TopologyCanvas
            graph={graph}
            targets={snapshot.target_ids}
            selected={state.selectedAsset}
            path={current ? selected : undefined}
            onSelect={(id) => patch({ selectedAsset: id })}
          />
          <details>
            <summary>连接与推导来源（{graph.asset_edges.length} 条）</summary>
            <div className="scroll-panel">
              {graph.asset_edges.map((e) => (
                <p key={e.edge_id}>
                  {e.source_asset_id} → {e.target_asset_id} · {e.direction} ·{" "}
                  {e.trust_level}
                  <br />
                  {e.description ?? "未声明来源说明"}
                </p>
              ))}
            </div>
          </details>
        </div>
        <PathRanking
          paths={paths}
          graph={graph}
          selected={state.selectedPath}
          onSelect={(id) => patch({ selectedPath: id })}
          decay={metadata?.parameters.dps_hop_decay ?? 0.95}
          current={current}
          ran={!!run}
          failure={
            run?.status === "Failed"
              ? (metadata?.error ?? "分析失败，请查看运行诊断")
              : undefined
          }
        />
      </div>
      <button className="button" onClick={() => navigate("reports")}>
        查看报告与导出 →
      </button>
    </section>
  );
}
