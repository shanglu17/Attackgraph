import { useState } from "react";
import { CxfImportPanel } from "../../CxfImportPanel";
import { F353204Panel } from "../../F353204Panel";
import { F3532ImportPanel } from "./F3532ImportPanel";
import { FeatureRulesPanel } from "../featureRules/FeatureRulesPanel";

const modes = [
  { id: "f3532", label: "F3532 01/02", description: "导入 01、02，准备生成 03" },
  { id: "cxf", label: "CXF 多 Sheet", description: "导入资产/接口/数据流清单" },
  { id: "f353204", label: "F3532 04 / FHA", description: "导入 FHA 并生成 04 草稿" },
  { id: "features", label: "特征规则分析", description: "导入研究数据包，预览判定并追溯证据" }
];
interface Props { active: boolean; disabled: boolean; onStatusChange: (message: string) => void;
  onCommitSuccess: (result: { commit_id?: string; new_version?: string }) => void | Promise<void> }
export function ImportWorkspace({ active, disabled, onStatusChange, onCommitSuccess }: Props) {
  const [mode, setMode] = useState("f3532");
  return <section className={active ? "import-workspace" : "hidden"} aria-label="数据导入工作台">
    <div className="import-switcher-header"><div><h2 className="section-title">数据导入工作台</h2>
      <p>{modes.find(item => item.id === mode)?.description}</p></div>
      <div className="mode-toggle import-tabs" role="tablist" aria-label="导入与研究分析">
        {modes.map(item => <button key={item.id} type="button" role="tab" id={`import-tab-${item.id}`}
          aria-controls={`import-panel-${item.id}`} aria-selected={mode === item.id}
          className={`mode-toggle-button ${mode === item.id ? "active" : ""}`} onClick={() => setMode(item.id)}>{item.label}</button>)}
      </div>
    </div>
    {modes.map(item => <div key={item.id} id={`import-panel-${item.id}`} role="tabpanel" aria-labelledby={`import-tab-${item.id}`}
      className={mode === item.id ? "import-tab-panel" : "import-tab-panel hidden"}>
      {item.id === "f3532" && <F3532ImportPanel disabled={disabled} onStatusChange={onStatusChange} onCommitSuccess={onCommitSuccess} />}
      {item.id === "cxf" && <CxfImportPanel disabled={disabled} onStatusChange={onStatusChange} onCommitSuccess={onCommitSuccess} />}
      {item.id === "f353204" && <F353204Panel disabled={disabled} onStatusChange={onStatusChange} />}
      {item.id === "features" && <FeatureRulesPanel disabled={disabled} />}
    </div>)}
  </section>;
}
