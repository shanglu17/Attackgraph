import { lazy, Suspense, useState } from "react";
import { useWorkbench } from "../../app/WorkspaceProvider";
import { useWorkspaceContext } from "../../app/WorkspaceContext";
const Assurance = lazy(() =>
  import("../reports/AssuranceReviewWorkspace").then((m) => ({
    default: m.AssuranceReviewWorkspace,
  })),
);
const Analysis = lazy(() =>
  import("../analysis/AnalysisRunWorkbench").then((m) => ({
    default: m.AnalysisRunWorkbench,
  })),
);
const Rules = lazy(() =>
  import("../featureRules/FeatureRulesPanel").then((m) => ({
    default: m.FeatureRulesPanel,
  })),
);
const Document=lazy(()=>import("./DocumentPreviewTool"));
export default function AdvancedTools() {
  const [tab, setTab] = useState("assurance");
  const context=useWorkspaceContext();
  const { patch, state } = useWorkbench();
  return (
    <section className="panel">
      <h3>高级工具</h3>
      <p>
        工程审查和研究能力沿用现有修订管理；不属于首次导入与分析的前置步骤。
      </p>
      <label className="field-stack">受控审查 API Key（仅在内存中使用）<input className="input-field" type="password" autoComplete="off" value={context.apiKey} onChange={e=>context.update({apiKey:e.target.value})}/></label>
      <div className="toolbar wrap" role="tablist" aria-label="高级工具">
        {[
          ["assurance", "工程与受控审查"],
          ["analysis", "研究分析方法"],
          ["rules", "特征规则研究"],
          ["document", "文档解析"],
        ].map(([key, label]) => (
          <button
            key={key}
            className="button"
            role="tab"
            aria-selected={tab === key}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </div>
      <Suspense fallback={<p>加载工具…</p>}>
        {tab === "assurance" && (
          <Assurance
            disabled={state.busy}
            onStatusChange={(message) => patch({ message })}
          />
        )}
        {tab === "analysis" && (
          <Analysis onStatusChange={(message) => patch({ message })} />
        )}
        {tab === "rules" && <Rules disabled={state.busy} />}
        {tab === "document" && <Document/>}
      </Suspense>
    </section>
  );
}
