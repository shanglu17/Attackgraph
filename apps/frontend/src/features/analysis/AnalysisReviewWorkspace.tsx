import { lazy, Suspense, useState, type ReactNode } from "react";
const AnalysisRunWorkbench = lazy(() => import("./AnalysisRunWorkbench").then(m => ({ default: m.AnalysisRunWorkbench })));

interface Props {
  children: ReactNode;
  onStatusChange: (message: string) => void;
}

export function AnalysisReviewWorkspace({ children, onStatusChange }: Props) {
  const [tab, setTab] = useState<"legacy" | "governed">("legacy");
  const [opened, setOpened] = useState(false);
  return (
    <div className="analysis-review-workspace">
      <div className="mode-toggle" role="tablist" aria-label="分析审查模式">
        <button type="button" role="tab" aria-selected={tab === "legacy"} className={tab === "legacy" ? "active" : ""} onClick={() => setTab("legacy")}>即时路径</button>
        <button type="button" role="tab" aria-selected={tab === "governed"} className={tab === "governed" ? "active" : ""} onClick={() => { setOpened(true); setTab("governed"); }}>高级：受控分析运行</button>
      </div>
      <div role="tabpanel" className={tab === "legacy" ? "review-section" : "hidden"}>{children}</div>
      <div role="tabpanel" className={tab === "governed" ? "review-section" : "hidden"}>
        {opened && <Suspense fallback={<p>加载受控分析…</p>}><AnalysisRunWorkbench onStatusChange={onStatusChange} /></Suspense>}
      </div>
    </div>
  );
}
