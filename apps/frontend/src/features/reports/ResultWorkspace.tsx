import { lazy, Suspense, useState } from "react";
import { useWorkbench } from "../../app/WorkspaceProvider";
import { workbenchApi } from "../../api";
import {
  currentRun,
  runMetadata,
  disclaimer,
} from "../../shared/model/workbench";
import { exportResult } from "./resultExport";
const Advanced = lazy(() => import("../advanced/AdvancedTools"));
export default function ResultWorkspace() {
  const { state, patch, perform, navigate } = useWorkbench();
  const [advanced, setAdvanced] = useState(false);
  const run =
    state.runs.find((r) => r.id === state.selectedRun) ??
    state.runs.slice(-1)[0];
  const metadata = runMetadata(run);
  const current = currentRun(run, state.snapshot, state.parameters);
  async function download(format: "json" | "xlsx") {
    if (!run || !state.snapshot) return;
    const { snapshot, run: verified } = await workbenchApi.export({
      project_id: run.project_id,
      revision_id: run.revision_id,
      run_id: run.id,
      parameters: state.parameters,
    });
    patch({ snapshot });
    await exportResult(format, snapshot, verified);
  }
  return (
    <section className="panel">
      <span className="tag">04 / 解释与导出</span>
      <h2>报告中心</h2>
      <p>
        当前模型事务版本：{state.snapshot?.model.revision_version ?? "未加载"} ·
        分析状态：
        {!run
          ? "尚未分析"
          : run.status === "Failed"
            ? "分析失败 / 已保存诊断"
            : current
              ? "当前结果"
              : "历史 / 已过期"}
      </p>
      {run && (
        <>
          <p>
            输入修订版本 v{run.input_revision_version} · 完成时间{" "}
            {run.completed_at} · 计算 {metadata?.calculation_ms ?? "未知"} ms
          </p>
          <p>
            映射 {metadata?.mapping_version ?? "兼容运行"} · 搜索状态：
            {run.status === "Failed"
              ? (metadata?.error ?? "搜索失败，不能判断无路径")
              : metadata
                ? "配置跳数范围内已完成；完整性 partial"
                : "请查看历史运行诊断"}
          </p>
        </>
      )}
      <p>{disclaimer}</p>
      <div className="toolbar wrap">
        <button
          className="button primary"
          disabled={state.busy || !current}
          onClick={() => void perform(() => download("json"))}
        >
          导出 JSON
        </button>
        <button
          className="button"
          disabled={state.busy || !current}
          onClick={() => void perform(() => download("xlsx"))}
        >
          导出 Excel
        </button>
        <button className="button" onClick={() => navigate("analysis")}>
          检查并重新分析
        </button>
      </div>
      {!current && (
        <p className="workbench-warning">
          只有匹配当前模型、分析配置和参数的结果才能导出为当前成果。
        </p>
      )}
      {state.runs.length > 0 && (
        <>
          <h3>分析历史</h3>
          <label className="field-stack">
            查看运行
            <select
              className="input-field"
              value={run?.id ?? ""}
              onChange={(e) =>
                patch({ selectedRun: e.target.value, selectedPath: "" })
              }
            >
              {[...state.runs].reverse().map((r) => (
                <option key={r.id} value={r.id}>
                  {r.completed_at} · 输入 v{r.input_revision_version} ·{" "}
                  {currentRun(r, state.snapshot, state.parameters)
                    ? "当前"
                    : "历史 / 已过期"}
                </option>
              ))}
            </select>
          </label>
          <details>
            <summary>查看此运行的输入快照、评分和诊断（历史保留）</summary>
            <pre className="scroll-panel">{JSON.stringify(run, null, 2)}</pre>
          </details>
        </>
      )}
      <button
        className="button"
        aria-expanded={advanced}
        onClick={() => setAdvanced(!advanced)}
      >
        高级：工程审查与研究工具
      </button>
      {advanced && (
        <Suspense fallback={<p>加载高级工具…</p>}>
          <Advanced />
        </Suspense>
      )}
    </section>
  );
}
