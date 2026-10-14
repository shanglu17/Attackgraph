import { useState, type ReactNode } from "react";
import { AnalysisRunWorkbench } from "./AnalysisRunWorkbench";

interface Props {
  children: ReactNode;
  onStatusChange: (message: string) => void;
}

export function AnalysisReviewWorkspace({ children, onStatusChange }: Props) {
  const [tab, setTab] = useState<"legacy" | "governed">("legacy");
  return (
    <div className="analysis-review-workspace">
      <div className="mode-toggle" role="tablist" aria-label="分析审查模式">
        <button type="button" role="tab" aria-selected={tab === "legacy"} className={tab === "legacy" ? "active" : ""} onClick={() => setTab("legacy")}>即时路径</button>
        <button type="button" role="tab" aria-selected={tab === "governed"} className={tab === "governed" ? "active" : ""} onClick={() => setTab("governed")}>受控分析运行</button>
      </div>
      <div role="tabpanel" className={tab === "legacy" ? "review-section" : "hidden"}>{children}</div>
      <div role="tabpanel" className={tab === "governed" ? "review-section" : "hidden"}>
        <AnalysisRunWorkbench onStatusChange={onStatusChange} />
      </div>
    </div>
  );
}
