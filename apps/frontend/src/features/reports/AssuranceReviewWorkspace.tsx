import { useState } from "react";
import { EngineeringCasePanel } from "./EngineeringCasePanel";
import { Vg1TraceabilityPanel } from "./Vg1TraceabilityPanel";

interface Props {
  disabled?: boolean;
  onStatusChange: (message: string) => void;
}

export function AssuranceReviewWorkspace(props: Props) {
  const [tab, setTab] = useState<"traceability" | "engineering">("traceability");
  return <>
    <div className="mode-toggle report-tabs" role="tablist" aria-label="保证与评审">
      <button type="button" className={tab === "traceability" ? "active" : ""} onClick={() => setTab("traceability")} role="tab" aria-selected={tab === "traceability"}>追踪与基线</button>
      <button type="button" className={tab === "engineering" ? "active" : ""} onClick={() => setTab("engineering")} role="tab" aria-selected={tab === "engineering"}>工程闭环</button>
    </div>
    <div className={tab === "traceability" ? "" : "hidden"}><Vg1TraceabilityPanel {...props} /></div>
    <div className={tab === "engineering" ? "" : "hidden"}><EngineeringCasePanel {...props} /></div>
  </>;
}
