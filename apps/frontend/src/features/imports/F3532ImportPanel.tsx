import { useState, type ChangeEvent } from "react";
import { commitF3532InputImport, previewF3532InputImport } from "../../api";
import {
  parseF3532Workbooks,
  type F3532WorkbookParseError,
  type ParsedF3532Workbook
} from "../../f3532Workbook";
import type {
  F3532InputImportCommitResult,
  F3532InputImportErrorDetail,
  F3532InputImportPreviewResult
} from "../../types";

interface F3532ImportPanelProps {
  disabled?: boolean;
  onCommitSuccess?: (result: F3532InputImportCommitResult) => Promise<void> | void;
  onStatusChange?: (message: string) => void;
}

function formatErrorDetail(detail: F3532InputImportErrorDetail): string {
  const prefix: string[] = [detail.type];
  if (detail.sheet) {
    prefix.push(detail.sheet);
  }
  if (detail.row) {
    prefix.push(`row ${detail.row}`);
  }
  if (detail.field) {
    prefix.push(detail.field);
  }
  return `${prefix.join(" / ")}: ${detail.message}`;
}

function formatFileError(error: F3532WorkbookParseError): string {
  const prefix: string[] = [error.kind];
  if (error.sheet) {
    prefix.push(error.sheet);
  }
  if (error.row) {
    prefix.push(`row ${error.row}`);
  }
  if (error.field) {
    prefix.push(error.field);
  }
  return `${prefix.join(" / ")}: ${error.message}`;
}

export function F3532ImportPanel({ disabled = false, onCommitSuccess, onStatusChange }: F3532ImportPanelProps) {
  const [aircraftModel, setAircraftModel] = useState("F3532-ASTRA");
  const [file01, setFile01] = useState<File | null>(null);
  const [file02, setFile02] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<"parse" | "preview" | "commit" | null>(null);
  const [parsedWorkbook, setParsedWorkbook] = useState<ParsedF3532Workbook | null>(null);
  const [preview, setPreview] = useState<F3532InputImportPreviewResult | F3532InputImportCommitResult | null>(null);
  const [fileError, setFileError] = useState<F3532WorkbookParseError | null>(null);
  const [localMessage, setLocalMessage] = useState("先选择下方两份 Excel，再点击“解析并预览”。");

  function updateMessage(message: string): void {
    setLocalMessage(message);
    onStatusChange?.(message);
  }

  function handleFile01Change(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0] ?? null;
    setFile01(file);
    resetParseState();
    updateMessage(file ? `已选择 01 资产与数据流清单： ${file.name}` : "先选择下方两份 Excel，再点击“解析并预览”。");
  }

  function handleFile02Change(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0] ?? null;
    setFile02(file);
    resetParseState();
    updateMessage(file ? `已选择 02 安保边界与威胁主体： ${file.name}` : "先选择下方两份 Excel，再点击“解析并预览”。");
  }

  function resetParseState(): void {
    setParsedWorkbook(null);
    setPreview(null);
    setFileError(null);
  }

  async function handlePreviewImport(): Promise<void> {
    if (!file01 || !file02) {
      updateMessage("请分别选择 01 资产与数据流清单、02 安保边界与威胁主体。");
      return;
    }
    const started = performance.now();
    try {
      setBusy(true);
      setPhase("parse");
      setFileError(null);
      setPreview(null);
      updateMessage("正在读取并解析两份 Excel…");
      const parsed = await parseF3532Workbooks(file01, file02, aircraftModel);
      setParsedWorkbook(parsed);
      setPhase("preview");
      updateMessage("解析完成，正在校验数据及关联关系…");
      const result = await previewF3532InputImport(parsed.payload);
      setPreview(result);
      updateMessage(result.ok
        ? `校验通过，用时 ${((performance.now() - started) / 1000).toFixed(2)} 秒。请检查下方预览，再确认导入。`
        : `发现 ${result.error_details.length} 个问题，请修正文件后重新预览。`);
    } catch (error) {
      setParsedWorkbook(null);
      const normalized = typeof error === "object" && error && "kind" in error
        ? error as F3532WorkbookParseError
        : { kind: "file" as const, message: error instanceof Error ? error.message : "解析或预览失败，请重试。" };
      setFileError(normalized);
      updateMessage(formatFileError(normalized));
    } finally {
      setBusy(false);
      setPhase(null);
    }
  }

  async function handleCommitImport(): Promise<void> {
    if (!parsedWorkbook) {
      updateMessage("请先解析并预览两份工作簿。");
      return;
    }
    if (!preview || !preview.ok) {
      updateMessage("请先通过导入预览校验。");
      return;
    }

    const started = performance.now();
    try {
      setBusy(true);
      setPhase("commit");
      updateMessage("正在写入图谱，请稍候…");
      const result = await commitF3532InputImport(parsedWorkbook.payload);
      setPreview(result);
      if (result.committed) {
        updateMessage(`导入成功，用时 ${((performance.now() - started) / 1000).toFixed(2)} 秒。`);
        await onCommitSuccess?.(result);
      } else {
        updateMessage(`导入失败： ${result.errors.join("; ")}`);
      }
    } catch (error) {
      updateMessage(error instanceof Error ? error.message : "导入失败，请重试。");
    } finally {
      setBusy(false);
      setPhase(null);
    }
  }

  const sheetCounts = parsedWorkbook?.sheet_counts ?? {
    boundary_interfaces: 0,
    boundary_data_flows: 0,
    system_interfaces: 0,
    system_data_flows: 0,
    threat_actors: 0,
    trust_boundaries: 0
  };
  const importDisabled = disabled || busy;
  const committed = !!(preview && "committed" in preview && preview.committed);

  return (
    <section className="panel import-panel">
      <div className="import-panel-header">
        <div>
          <h3>F3532 资产与安保边界导入</h3>
          <p>选择文件 → 解析并预览 → 确认导入。预览不会修改图谱。支持 .xlsx / .xls。</p>
        </div>
        <p className="status import-status" role="status" aria-live="polite">{localMessage}</p>
      </div>

      <div className="f3532-file-grid">
        <label className="field-stack import-field">
          <span className="field-label">飞机 / 系统型号</span>
          <input
            className="input-field"
            value={aircraftModel}
            onChange={(event) => { setAircraftModel(event.target.value); resetParseState(); }}
            disabled={importDisabled}
          />
        </label>

        <label className="preview-card field-stack import-field">
          <span className="pill">文件 01 · 必选</span>
          <span className="field-label">网络安保资产、接口与数据流清单</span>
          <span className="muted">包含：边界接口、边界数据流、系统间接口、系统间数据流</span>
          <input
            className="input-field file-input"
            type="file"
            accept=".xlsx,.xls"
            aria-label="选择 01 资产与数据流 Excel"
            onChange={handleFile01Change}
            disabled={importDisabled}
          />
        </label>

        <label className="preview-card field-stack import-field">
          <span className="pill">文件 02 · 必选</span>
          <span className="field-label">安保边界及威胁主体</span>
          <span className="muted">包含：安保边界、威胁主体及其关联关系</span>
          <input
            className="input-field file-input"
            type="file"
            accept=".xlsx,.xls"
            aria-label="选择 02 安保边界与威胁主体 Excel"
            onChange={handleFile02Change}
            disabled={importDisabled}
          />
        </label>

      </div>

        <div className="import-actions">
          <button className={`button${preview?.ok ? "" : " primary"}`} type="button" onClick={() => void handlePreviewImport()} disabled={importDisabled || !file01 || !file02}>
            {phase === "parse" ? "正在解析…" : phase === "preview" ? "正在校验…" : "1. 解析并预览"}
          </button>
          <button
            className={`button${preview?.ok && !committed ? " primary" : ""}`}
            type="button"
            onClick={() => void handleCommitImport()}
            disabled={importDisabled || !parsedWorkbook || !preview?.ok || committed}
          >
            {phase === "commit" ? "正在导入…" : committed ? "已导入" : "2. 确认导入图谱"}
          </button>
        </div>

      <div className="import-grid">
        <article className="preview-card">
          <strong>文件与解析结果</strong>
          <div className="import-kpi-grid">
            <span className="pill">BI {sheetCounts.boundary_interfaces}</span>
            <span className="pill">BDF {sheetCounts.boundary_data_flows}</span>
            <span className="pill">SI {sheetCounts.system_interfaces}</span>
            <span className="pill">SDF {sheetCounts.system_data_flows}</span>
            <span className="pill">TA {sheetCounts.threat_actors}</span>
            <span className="pill">SB {sheetCounts.trust_boundaries}</span>
          </div>
          <p className="muted">{file01 ? `01: ${file01.name}` : "尚未选择 01 资产与数据流清单。"}</p>
          <p className="muted">{file02 ? `02: ${file02.name}` : "尚未选择 02 安保边界与威胁主体。"}</p>
          {fileError ? (
            <div className="import-error-list">
              <div className="import-error-item">{formatFileError(fileError)}</div>
            </div>
          ) : (
            <p className="muted">{parsedWorkbook ? `系统型号：${parsedWorkbook.payload.source.aircraft_model}` : "选择两份文件后，点击“解析并预览”查看结果。"}</p>
          )}
        </article>

        <article className="preview-card">
          <strong>导入预览</strong>
          {preview ? (
            <>
              <div className="import-kpi-grid">
                <span className="pill">资产 +{preview.summary.asset_nodes_to_add}</span>
                <span className="pill">连线 +{preview.summary.asset_edges_to_add}</span>
                <span className="pill">BI +{preview.summary.boundary_interfaces_to_add}</span>
                <span className="pill">SB +{preview.summary.trust_boundaries_to_add}</span>
                <span className="pill">TA +{preview.summary.threat_actors_to_add}</span>
                <span className="pill">SDF +{preview.summary.system_data_flows_to_add}</span>
                <span className="pill">功能 +{preview.summary.function_nodes_to_add}</span>
              </div>
              <div className="import-kpi-grid">
                <span className="pill">安保边界 {preview.accepted.trust_boundaries}</span>
                <span className="pill">边界接口 {preview.accepted.boundary_interfaces}</span>
                <span className="pill">边界数据流 {preview.accepted.boundary_data_flows}</span>
                <span className="pill">系统数据流 {preview.accepted.system_data_flows}</span>
                <span className="pill">威胁主体 {preview.accepted.threat_actors}</span>
              </div>
              {preview.summary.warnings.length > 0 ? (
                <div className="import-warning-list">
                  {preview.summary.warnings.map((warning) => (
                    <div key={warning} className="import-warning-item">
                      {warning}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted">没有导入警告。</p>
              )}
              {"committed" in preview && preview.committed ? (
                <p className="muted">
                  commit_id={preview.commit_id} / version={preview.new_version}
                </p>
              ) : null}
            </>
          ) : (
            <p className="muted">预览后会显示导入数量和需处理的问题。</p>
          )}
        </article>

        <article className="preview-card">
          <strong>生成 03 的数据准备</strong>
          {preview ? (
            <div className="import-threat-list">
              <div className="item vertical">
                <strong>{"SB -> BI -> BDF"}</strong>
                <span>
                  {preview.accepted.trust_boundaries} 个边界， {preview.accepted.boundary_interfaces} 个接口，{" "}
                  {preview.accepted.boundary_data_flows} 条边界数据流。
                </span>
              </div>
              <div className="item vertical">
                <strong>{"TA -> SB"}</strong>
                <span>{preview.accepted.threat_actors} 个威胁主体按边界关联。</span>
              </div>
              <div className="item vertical">
                <strong>{"SDF -> Function"}</strong>
                <span>
                  {preview.accepted.system_data_flows} 条系统数据流， {preview.summary.function_links_to_add} 条功能关联。
                </span>
              </div>
            </div>
          ) : (
            <p className="muted">预览后检查边界、接口、数据流与功能的关联。</p>
          )}
        </article>

        <article className="preview-card">
          <strong>校验问题</strong>
          {preview && preview.error_details.length > 0 ? (
            <div className="import-error-list">
              {preview.error_details.map((detail, index) => (
                <div key={`${detail.message}-${index}`} className="import-error-item">
                  {formatErrorDetail(detail)}
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">暂无校验问题。</p>
          )}
        </article>
      </div>
    </section>
  );
}
