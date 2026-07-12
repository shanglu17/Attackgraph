import { useState, type ChangeEvent } from "react";
import {
  commitF353204,
  commitFhaImport,
  generateF353204,
  previewFhaImport
} from "./api";
import { parseFhaDocument, type ParsedFhaDocument } from "./fhaDocument";
import type { F353204GenerationResult, FhaSeverity, ThreatCondition, ThreatScenario } from "./types";

interface F353204PanelProps {
  disabled?: boolean;
  onStatusChange?: (message: string) => void;
}

const severityOptions: FhaSeverity[] = [
  "Catastrophic",
  "Hazardous",
  "Major",
  "Minor",
  "NoSafetyEffect",
  "Unknown"
];

const severityLabels: Record<FhaSeverity, string> = {
  Catastrophic: "灾难性",
  Hazardous: "危险",
  Major: "重大",
  Minor: "轻微",
  NoSafetyEffect: "无安全影响",
  Unknown: "待确认"
};

const ciaLabels = { C: "机密性丧失", I: "完整性丧失", A: "可用性丧失" } as const;

async function exportF353204Workbook(
  threatConditions: ThreatCondition[],
  threatScenarios: ThreatScenario[]
): Promise<void> {
  const xlsx = await import("xlsx");
  const workbook = xlsx.utils.book_new();
  const tcRows = [
    ["编号", "资产", "受影响功能", "安保属性丧失", "威胁状况描述", "发生阶段", "对飞机影响", "对系统影响", "对机组影响", "对乘员影响", "严重程度", "关联失效状况", "关联安保边界/路径", "备注"],
    ...threatConditions.map((row) => [
      row.tc_id,
      (row.affected_assets ?? []).join("、"),
      row.function_id ?? "",
      row.cia_attributes.map((item) => ciaLabels[item]).join("/"),
      row.description ?? "",
      (row.flight_phases ?? []).join("、"),
      row.aircraft_effect ?? "",
      row.system_effect ?? "",
      row.crew_effect ?? "",
      row.occupant_effect ?? "",
      severityLabels[row.severity],
      row.failure_condition_ids.join("、"),
      row.path_ids.join("、"),
      row.coverage_status === "linked" ? "由01/02、FHA及关键路径自动关联" : "未找到可达路径，需人工复核"
    ])
  ];
  const tcSheet = xlsx.utils.aoa_to_sheet(tcRows);
  tcSheet["!autofilter"] = { ref: `A1:N${tcRows.length}` };
  tcSheet["!cols"] = [12, 28, 16, 20, 42, 20, 30, 30, 30, 30, 14, 26, 24, 34].map((wch) => ({ wch }));
  xlsx.utils.book_append_sheet(workbook, tcSheet, "威胁状况Threat Condition");

  const tsRows = [
    ["编号", "威胁来源(关联TA)", "攻击向量(对应数据流/接口)", "攻击路径", "攻击路径上现有安全措施", "触发的威胁状况(TC编号)", "备注"],
    ...threatScenarios.map((row) => [
      row.ts_id,
      row.threat_actor_id ?? "",
      row.attack_vector ?? "",
      row.attack_path,
      row.existing_security_measures ?? "",
      row.tc_ids.join("、"),
      row.review_status
    ])
  ];
  const tsSheet = xlsx.utils.aoa_to_sheet(tsRows);
  tsSheet["!autofilter"] = { ref: `A1:G${tsRows.length}` };
  tsSheet["!cols"] = [12, 28, 28, 58, 42, 26, 18].map((wch) => ({ wch }));
  xlsx.utils.book_append_sheet(workbook, tsSheet, "威胁场景Threat Scenario");

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  xlsx.writeFile(workbook, `f3532-04-report-${timestamp}.xlsx`);
}

export function F353204Panel({ disabled = false, onStatusChange }: F353204PanelProps) {
  const [file, setFile] = useState<File | null>(null);
  const [parsed, setParsed] = useState<ParsedFhaDocument | null>(null);
  const [previewOk, setPreviewOk] = useState(false);
  const [fhaMessage, setFhaMessage] = useState("Select the AFHA/FHA DOCX file.");
  const [ciaMode, setCiaMode] = useState<"single" | "all_non_empty">("single");
  const [generation, setGeneration] = useState<F353204GenerationResult | null>(null);
  const [threatConditions, setThreatConditions] = useState<ThreatCondition[]>([]);
  const [threatScenarios, setThreatScenarios] = useState<ThreatScenario[]>([]);
  const [busy, setBusy] = useState(false);

  function updateStatus(message: string): void {
    onStatusChange?.(message);
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>): void {
    setFile(event.target.files?.[0] ?? null);
    setParsed(null);
    setPreviewOk(false);
    setFhaMessage("Parse the selected FHA document.");
  }

  async function handleParse(): Promise<void> {
    if (!file) {
      setFhaMessage("Choose an FHA DOCX file first.");
      return;
    }
    try {
      setBusy(true);
      const result = await parseFhaDocument(file);
      setParsed(result);
      setPreviewOk(false);
      setFhaMessage(`Parsed ${result.payload.failure_conditions.length} failure conditions.`);
      updateStatus(`FHA parsed: ${result.payload.failure_conditions.length} failure conditions`);
    } catch (error) {
      setParsed(null);
      setPreviewOk(false);
      setFhaMessage(error instanceof Error ? error.message : "Failed to parse FHA document");
    } finally {
      setBusy(false);
    }
  }

  async function handlePreview(): Promise<void> {
    if (!parsed) {
      await handleParse();
      return;
    }
    try {
      setBusy(true);
      const result = await previewFhaImport(parsed.payload);
      setPreviewOk(result.ok);
      setFhaMessage(result.ok ? `FHA preview passed: ${result.count} rows.` : (result.errors ?? []).join("; "));
    } finally {
      setBusy(false);
    }
  }

  async function handleCommitFha(): Promise<void> {
    if (!parsed || !previewOk) {
      setFhaMessage("Run a successful FHA preview before commit.");
      return;
    }
    try {
      setBusy(true);
      const result = await commitFhaImport(parsed.payload);
      if (!result.committed) {
        setFhaMessage(`FHA commit failed: ${(result.errors ?? []).join("; ")}`);
        return;
      }
      setFhaMessage(
        `FHA committed: ${result.imported} FC, linked BDF ${result.linked_bdf_count ?? 0}, linked SDF ${result.linked_sdf_count ?? 0}, unlinked FC ${(result.unlinked_failure_condition_ids ?? []).length}.`
      );
      updateStatus("FHA imported and linked to BoundaryDataFlow/SystemDataFlow nodes.");
    } finally {
      setBusy(false);
    }
  }

  async function handleGenerate04(): Promise<void> {
    try {
      setBusy(true);
      const result = await generateF353204({ cia_mode: ciaMode, include_unlinked_failure_conditions: true });
      setGeneration(result);
      setThreatConditions(result.threat_conditions);
      setThreatScenarios(result.threat_scenarios);
      updateStatus(
        `F3532 04 defaults generated: TC ${result.coverage.generated_tc_count}, TS ${result.coverage.generated_ts_count}, unlinked FC ${result.coverage.unlinked_failure_condition_ids.length}`
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleCommit04(): Promise<void> {
    try {
      setBusy(true);
      const result = await commitF353204(threatConditions, threatScenarios);
      updateStatus(
        result.committed
          ? `F3532 04 committed: TC ${result.threat_condition_count}, TS ${result.threat_scenario_count}`
          : `F3532 04 commit failed: ${(result.errors ?? []).join("; ")}`
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleExport04(): Promise<void> {
    try {
      setBusy(true);
      await exportF353204Workbook(threatConditions, threatScenarios);
      updateStatus(`F3532 04 已导出：TC ${threatConditions.length} 行，TS ${threatScenarios.length} 行`);
    } finally {
      setBusy(false);
    }
  }

  function updateTc(index: number, patch: Partial<ThreatCondition>): void {
    setThreatConditions((current) => current.map((row, rowIndex) => (rowIndex === index ? { ...row, ...patch } : row)));
  }

  function updateTs(index: number, patch: Partial<ThreatScenario>): void {
    setThreatScenarios((current) => current.map((row, rowIndex) => (rowIndex === index ? { ...row, ...patch } : row)));
  }

  const importDisabled = disabled || busy;
  const defaults = generation?.defaults;

  return (
    <section className="panel import-panel">
      <div className="import-panel-header">
        <div>
          <h3>FHA Import & F3532 04 Workbench</h3>
          <p>Import failure conditions first, then generate editable TC/TS defaults from FHA, CIA, threat actors and key paths.</p>
        </div>
        <p className="status import-status">{fhaMessage}</p>
      </div>

      <div className="import-toolbar">
        <label className="field-stack import-field">
          <span className="field-label">AFHA/FHA DOCX</span>
          <input className="input-field file-input" type="file" accept=".docx" onChange={handleFileChange} disabled={importDisabled} />
        </label>
        <div className="import-actions">
          <button className="button" type="button" onClick={() => void handleParse()} disabled={importDisabled || !file}>Parse FHA</button>
          <button className="button" type="button" onClick={() => void handlePreview()} disabled={importDisabled || !parsed}>Preview FHA</button>
          <button className="button primary" type="button" onClick={() => void handleCommitFha()} disabled={importDisabled || !previewOk}>Commit FHA</button>
        </div>
      </div>

      {parsed ? (
        <div className="import-kpi-grid">
          <span className="pill">FC {parsed.payload.failure_conditions.length}</span>
          <span className="pill">Catastrophic {parsed.counts.Catastrophic}</span>
          <span className="pill">Hazardous {parsed.counts.Hazardous}</span>
          <span className="pill">Major {parsed.counts.Major}</span>
        </div>
      ) : null}

      <div className="toolbar wrap f3532-04-toolbar">
        <select className="input-field" value={ciaMode} onChange={(event) => setCiaMode(event.target.value as typeof ciaMode)} disabled={importDisabled}>
          <option value="single">CIA 单属性（C / I / A）</option>
          <option value="all_non_empty">CIA 全排列（7 种）</option>
        </select>
        <button className="button primary" type="button" onClick={() => void handleGenerate04()} disabled={importDisabled}>Generate 04 Defaults</button>
        <button className="button" type="button" onClick={() => void handleCommit04()} disabled={importDisabled || threatConditions.length === 0}>Commit Edited 04</button>
        <button className="button" type="button" onClick={() => void handleExport04()} disabled={importDisabled || threatConditions.length === 0}>导出 04 Excel</button>
      </div>

      {generation ? (
        <>
          <div className="import-kpi-grid">
            <span className="pill">FHA {generation.coverage.total_failure_conditions}</span>
            <span className="pill">Linked {generation.coverage.linked_failure_conditions}</span>
            <span className="pill">Unlinked {generation.coverage.unlinked_failure_condition_ids.length}</span>
            <span className="pill">TC {threatConditions.length}</span>
            <span className="pill">TS {threatScenarios.length}</span>
          </div>
          {generation.coverage.unlinked_failure_condition_ids.length > 0 ? (
            <div className="import-warning-list">
              <div className="import-warning-item">
                Unlinked FHA rows: {generation.coverage.unlinked_failure_condition_ids.join("、")}
              </div>
            </div>
          ) : null}

          {defaults ? (
            <div className="import-warning-list">
              {defaults.reference_notes.map((note) => <div key={note} className="import-warning-item">{note}</div>)}
            </div>
          ) : null}

          <div className="scroll-panel f3532-04-editor">
            <h4>Threat Condition Defaults</h4>
            <table className="report-table">
              <thead>
                <tr>
                  <th>TC</th><th>FHA</th><th>Asset</th><th>Function</th><th>CIA</th><th>Flight Phase</th><th>Description</th><th>Aircraft Effect</th><th>System Effect</th><th>Crew Effect</th><th>Occupant Effect</th><th>Severity</th><th>Paths</th>
                </tr>
              </thead>
              <tbody>
                {threatConditions.map((row, index) => (
                  <tr key={row.tc_id}>
                    <td>{row.tc_id}</td>
                    <td>{row.failure_condition_ids.join("、")}</td>
                    <td>{(row.affected_assets ?? []).join("、") || "待复核"}</td>
                    <td>{row.function_id ?? "待关联"}</td>
                    <td>{row.cia_attributes.join("+")}</td>
                    <td>{(row.flight_phases ?? []).join("、") || "待确认"}</td>
                    <td><input className="input-field" value={row.description ?? ""} onChange={(event) => updateTc(index, { description: event.target.value || undefined })} placeholder="可留空，参考 04 范例填写" /></td>
                    <td><input className="input-field" list="f3532-aircraft-effects" value={row.aircraft_effect ?? ""} onChange={(event) => updateTc(index, { aircraft_effect: event.target.value || undefined })} /></td>
                    <td><input className="input-field" list="f3532-system-effects" value={row.system_effect ?? ""} onChange={(event) => updateTc(index, { system_effect: event.target.value || undefined })} /></td>
                    <td><input className="input-field" list="f3532-crew-effects" value={row.crew_effect ?? ""} onChange={(event) => updateTc(index, { crew_effect: event.target.value || undefined })} /></td>
                    <td><input className="input-field" list="f3532-occupant-effects" value={row.occupant_effect ?? ""} onChange={(event) => updateTc(index, { occupant_effect: event.target.value || undefined })} /></td>
                    <td>
                      <select className="input-field" value={row.severity} onChange={(event) => updateTc(index, { severity: event.target.value as FhaSeverity, severity_source: "manual" })}>
                        {severityOptions.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
                      </select>
                    </td>
                    <td>{row.path_ids.join("、") || "待关联"}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <h4>Threat Scenario Defaults</h4>
            <table className="report-table">
              <thead>
                <tr><th>TS</th><th>Threat Actor</th><th>Vector</th><th>Attack Path</th><th>Existing Security Measures</th><th>TC</th></tr>
              </thead>
              <tbody>
                {threatScenarios.map((row, index) => (
                  <tr key={row.ts_id}>
                    <td>{row.ts_id}</td>
                    <td>{row.threat_actor_id ?? "待关联"}</td>
                    <td>
                      <select className="input-field" value={row.attack_vector ?? ""} onChange={(event) => updateTs(index, { attack_vector: (event.target.value || undefined) as ThreatScenario["attack_vector"] })}>
                        <option value="">待选择</option>
                        <option value="Network">Network</option>
                        <option value="Wireless">Wireless</option>
                        <option value="Physical">Physical</option>
                        <option value="Maintenance">Maintenance</option>
                        <option value="SupplyChain">SupplyChain</option>
                      </select>
                    </td>
                    <td><input className="input-field" value={row.attack_path} onChange={(event) => updateTs(index, { attack_path: event.target.value })} /></td>
                    <td><input className="input-field" value={row.existing_security_measures ?? ""} onChange={(event) => updateTs(index, { existing_security_measures: event.target.value || undefined })} placeholder="用户输入，可留空" /></td>
                    <td>{row.tc_ids.join("、")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <datalist id="f3532-aircraft-effects">{defaults?.aircraft_effect_options.map((value) => <option key={value} value={value} />)}</datalist>
          <datalist id="f3532-system-effects">{defaults?.system_effect_options.map((value) => <option key={value} value={value} />)}</datalist>
          <datalist id="f3532-crew-effects">{defaults?.crew_effect_options.map((value) => <option key={value} value={value} />)}</datalist>
          <datalist id="f3532-occupant-effects">{defaults?.occupant_effect_options.map((value) => <option key={value} value={value} />)}</datalist>
        </>
      ) : null}
    </section>
  );
}
