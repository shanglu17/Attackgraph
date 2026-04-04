import { useState, type ChangeEvent } from "react";
import { commitCxfImport, previewCxfImport } from "./api";
import { parseCxfWorkbook, type CxfWorkbookParseError, type ParsedCxfWorkbook } from "./cxfWorkbook";
import type { CxfImportCommitResult, CxfImportErrorDetail, CxfImportPreviewResult } from "./types";

interface CxfImportPanelProps {
  disabled?: boolean;
  onCommitSuccess?: (result: CxfImportCommitResult) => Promise<void> | void;
  onStatusChange?: (message: string) => void;
}

function formatErrorDetail(detail: CxfImportErrorDetail): string {
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

function formatFileError(error: CxfWorkbookParseError): string {
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

export function CxfImportPanel({ disabled = false, onCommitSuccess, onStatusChange }: CxfImportPanelProps) {
  const [aircraftModel, setAircraftModel] = useState("DO356A-AMS");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [parsedWorkbook, setParsedWorkbook] = useState<ParsedCxfWorkbook | null>(null);
  const [preview, setPreview] = useState<CxfImportPreviewResult | CxfImportCommitResult | null>(null);
  const [fileError, setFileError] = useState<CxfWorkbookParseError | null>(null);
  const [localMessage, setLocalMessage] = useState("Select a DO-356A multi-sheet workbook to start.");

  function updateMessage(message: string): void {
    setLocalMessage(message);
    onStatusChange?.(message);
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
    setParsedWorkbook(null);
    setPreview(null);
    setFileError(null);
    if (file) {
      updateMessage(`Selected workbook: ${file.name}`);
    } else {
      updateMessage("Select a DO-356A multi-sheet workbook to start.");
    }
  }

  async function handleParseWorkbook(): Promise<void> {
    if (!selectedFile) {
      updateMessage("Choose an Excel workbook before parsing.");
      return;
    }

    try {
      setBusy(true);
      setFileError(null);
      const parsed = await parseCxfWorkbook(selectedFile, aircraftModel);
      setParsedWorkbook(parsed);
      setPreview(null);
      updateMessage(
        `Workbook parsed: 功能 ${parsed.sheet_counts.functional_assets}, 接口 ${parsed.sheet_counts.interface_assets}, 支持 ${parsed.sheet_counts.support_assets}, 数据 ${parsed.sheet_counts.data_assets}`
      );
    } catch (error) {
      const normalized =
        typeof error === "object" && error && "kind" in error
          ? (error as CxfWorkbookParseError)
          : ({
              kind: "file",
              message: error instanceof Error ? error.message : "Failed to parse workbook"
            } satisfies CxfWorkbookParseError);
      setParsedWorkbook(null);
      setPreview(null);
      setFileError(normalized);
      updateMessage(formatFileError(normalized));
    } finally {
      setBusy(false);
    }
  }

  async function handlePreviewImport(): Promise<void> {
    if (!parsedWorkbook) {
      await handleParseWorkbook();
      return;
    }

    try {
      setBusy(true);
      const result = await previewCxfImport(parsedWorkbook.payload);
      setPreview(result);
      updateMessage(
        result.ok
          ? `Preview ready: assets=${result.summary.asset_nodes_to_add}, edges=${result.summary.asset_edges_to_add}, threats=${result.summary.threat_points_to_add}`
          : `Preview found ${result.error_details.length} issues`
      );
    } catch (error) {
      updateMessage(error instanceof Error ? error.message : "Failed to preview import");
    } finally {
      setBusy(false);
    }
  }

  async function handleCommitImport(): Promise<void> {
    if (!parsedWorkbook) {
      updateMessage("Parse the workbook before commit.");
      return;
    }

    if (!preview || !preview.ok) {
      updateMessage("Run a successful preview before commit.");
      return;
    }

    try {
      setBusy(true);
      const result = await commitCxfImport(parsedWorkbook.payload);
      setPreview(result);
      if (result.committed) {
        updateMessage(`Multi-sheet import committed: ${result.commit_id}, version ${result.new_version}`);
        await onCommitSuccess?.(result);
      } else {
        updateMessage(`Commit failed: ${result.errors.join("; ")}`);
      }
    } catch (error) {
      updateMessage(error instanceof Error ? error.message : "Failed to commit import");
    } finally {
      setBusy(false);
    }
  }

  const sheetCounts = parsedWorkbook?.sheet_counts ?? {
    functional_assets: 0,
    interface_assets: 0,
    support_assets: 0,
    data_assets: 0
  };
  const importDisabled = disabled || busy;

  return (
    <section className="panel import-panel">
      <div className="import-panel-header">
        <div>
          <h3>Multi-Sheet Excel Import</h3>
          <p>Upload the DO-356A workbook, parse it locally, preview generated graph changes, then commit atomically.</p>
        </div>
        <p className="status import-status">{localMessage}</p>
      </div>

      <div className="import-toolbar">
        <label className="field-stack import-field">
          <span className="field-label">Aircraft Model</span>
          <input
            className="input-field"
            value={aircraftModel}
            onChange={(event) => setAircraftModel(event.target.value)}
            disabled={importDisabled}
          />
        </label>

        <label className="field-stack import-field">
          <span className="field-label">Workbook</span>
          <input
            className="input-field file-input"
            type="file"
            accept=".xlsx,.xls"
            onChange={handleFileChange}
            disabled={importDisabled}
          />
        </label>

        <div className="import-actions">
          <button className="button" type="button" onClick={() => void handleParseWorkbook()} disabled={importDisabled}>
            Parse Workbook
          </button>
          <button className="button" type="button" onClick={() => void handlePreviewImport()} disabled={importDisabled || !selectedFile}>
            Preview Import
          </button>
          <button
            className="button primary"
            type="button"
            onClick={() => void handleCommitImport()}
            disabled={importDisabled || !parsedWorkbook || !preview?.ok}
          >
            Commit Import
          </button>
        </div>
      </div>

      <div className="import-grid">
        <article className="preview-card">
          <strong>Workbook Parse</strong>
          <div className="import-kpi-grid">
            <span className="pill">功能 {sheetCounts.functional_assets}</span>
            <span className="pill">接口 {sheetCounts.interface_assets}</span>
            <span className="pill">支持 {sheetCounts.support_assets}</span>
            <span className="pill">数据 {sheetCounts.data_assets}</span>
          </div>
          {selectedFile ? <p className="muted">{selectedFile.name}</p> : <p className="muted">No workbook selected.</p>}
          {fileError ? (
            <div className="import-error-list">
              <div className="import-error-item">{formatFileError(fileError)}</div>
            </div>
          ) : (
            <pre>{parsedWorkbook ? JSON.stringify(parsedWorkbook.payload.source, null, 2) : "Parse a workbook to inspect source metadata."}</pre>
          )}
        </article>

        <article className="preview-card">
          <strong>Preview Summary</strong>
          {preview ? (
            <>
              <div className="import-kpi-grid">
                <span className="pill">Asset +{preview.summary.asset_nodes_to_add}</span>
                <span className="pill">Edge +{preview.summary.asset_edges_to_add}</span>
                <span className="pill">Threat +{preview.summary.threat_points_to_add}</span>
                <span className="pill">Placeholder +{preview.summary.auto_placeholder_assets_to_add}</span>
              </div>
              <div className="import-kpi-grid">
                <span className="pill">Accepted 功能 {preview.accepted.functional_assets}</span>
                <span className="pill">Accepted 接口 {preview.accepted.interface_assets}</span>
                <span className="pill">Accepted 支持 {preview.accepted.support_assets}</span>
                <span className="pill">Accepted 数据 {preview.accepted.data_assets}</span>
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
                <p className="muted">No import warnings.</p>
              )}
              {"committed" in preview && preview.committed ? (
                <p className="muted">
                  commit_id={preview.commit_id} / version={preview.new_version}
                </p>
              ) : null}
            </>
          ) : (
            <p className="muted">Run preview to inspect generated graph counts and warnings.</p>
          )}
        </article>

        <article className="preview-card">
          <strong>Auto Threats</strong>
          {preview && preview.summary.auto_generated_threats.length > 0 ? (
            <div className="import-threat-list">
              {preview.summary.auto_generated_threats.slice(0, 12).map((item) => (
                <div key={item.threatpoint_id} className="item vertical">
                  <strong>{item.threatpoint_id}</strong>
                  <span>{item.asset_name}</span>
                  <span>
                    {item.threat_kind} / {item.attack_vector} / {item.stride_category}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">Preview to inspect generated baseline threat points.</p>
          )}
        </article>

        <article className="preview-card">
          <strong>Errors</strong>
          {preview && preview.error_details.length > 0 ? (
            <div className="import-error-list">
              {preview.error_details.map((detail, index) => (
                <div key={`${detail.message}-${index}`} className="import-error-item">
                  {formatErrorDetail(detail)}
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">No backend validation errors.</p>
          )}
        </article>
      </div>
    </section>
  );
}
