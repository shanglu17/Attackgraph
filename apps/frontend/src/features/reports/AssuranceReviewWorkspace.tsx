import { lazy, Suspense, useState } from "react";
const EngineeringCasePanel = lazy(() => import("./EngineeringCasePanel").then(m => ({ default: m.EngineeringCasePanel })));
const Vg1TraceabilityPanel = lazy(() => import("./Vg1TraceabilityPanel").then(m => ({ default: m.Vg1TraceabilityPanel })));
const ImpactWorkProductPanel = lazy(() => import("./ImpactWorkProductPanel").then(m => ({ default: m.ImpactWorkProductPanel })));
const ReviewWorkbenchPanel = lazy(() => import("./ReviewWorkbenchPanel").then(m => ({ default: m.ReviewWorkbenchPanel })));

interface Props {
  disabled?: boolean;
  onStatusChange: (message: string) => void;
}

export function AssuranceReviewWorkspace(props: Props) {
  const [tab, setTab] = useState<"traceability" | "engineering" | "impact" | "review">("traceability");
  const [visited, setVisited] = useState(new Set(["traceability"]));
  function select(value: typeof tab) { setVisited(v => new Set([...v, value])); setTab(value); }
  return <Suspense fallback={<p>加载审查工具…</p>}>
    <div className="mode-toggle report-tabs" role="tablist" aria-label="保证与评审">
      <button type="button" className={`mode-toggle-button ${tab === "traceability" ? "active" : ""}`} onClick={() => select("traceability")} role="tab" aria-selected={tab === "traceability"}>追踪与基线</button>
      <button type="button" className={`mode-toggle-button ${tab === "engineering" ? "active" : ""}`} onClick={() => select("engineering")} role="tab" aria-selected={tab === "engineering"}>工程闭环</button>
      <button type="button" className={`mode-toggle-button ${tab === "impact" ? "active" : ""}`} onClick={() => select("impact")} role="tab" aria-selected={tab === "impact"}>影响与工作产品</button>
      <button type="button" className={`mode-toggle-button ${tab === "review" ? "active" : ""}`} onClick={() => select("review")} role="tab" aria-selected={tab === "review"}>受控评审</button>
    </div>
    <div className={tab === "traceability" ? "" : "hidden"}>{visited.has("traceability") && <Vg1TraceabilityPanel {...props} />}</div>
    <div className={tab === "engineering" ? "" : "hidden"}>{visited.has("engineering") && <EngineeringCasePanel {...props} />}</div>
    <div className={tab === "impact" ? "" : "hidden"}>{visited.has("impact") && <ImpactWorkProductPanel {...props} />}</div>
    <div className={tab === "review" ? "" : "hidden"}>{visited.has("review") && <ReviewWorkbenchPanel {...props} />}</div>
  </Suspense>;
}
