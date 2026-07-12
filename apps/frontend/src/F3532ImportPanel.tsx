import { useState, type ChangeEvent } from "react";
import { commitF3532InputImport, previewF3532InputImport } from "./api";
import {
  parseF3532Workbooks,
  type F3532WorkbookParseError,
  type ParsedF3532Workbook
} from "./f3532Workbook";
import type {
  F3532InputImportCommitResult,
  F3532InputImportErrorDetail,
  F3532InputImportPreviewResult
} from "./types";

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
  const [parsedWorkbook, setParsedWorkbook] = useState<ParsedF3532Workbook | null>(null);
  const [preview, setPreview] = useState<F3532InputImportPreviewResult | F3532InputImportCommitResult | null>(null);
  const [fileError, setFileError] = useState<F3532WorkbookParseError | null>(null);
  const [localMessage, setLocalMessage] = useState("Select F3532 01 and 02 workbooks to start.");

  function updateMessage(message: string): void {
    setLocalMessage(message);
    onStatusChange?.(message);
  }

  function handleFile01Change(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0] ?? null;
    setFile01(file);
    resetParseState();
    updateMessage(file ? `Selected 01 workbook: ${file.name}` : "Select F3532 01 and 02 workbooks to start.");
  }

  function handleFile02Change(event: ChangeEvent<HTMLInputElement>): void {
    const file = event.target.files?.[0] ?? null;
    setFile02(file);
    resetParseState();
    updateMessage(file ? `Selected 02 workbook: ${file.name}` : "Select F3532 01 and 02 workbooks to start.");
  }

  function resetParseState(): void {
    setParsedWorkbook(null);
    setPreview(null);
    setFileError(null);
  }

  async function handleParseWorkbook(): Promise<void> {
    if (!file01 || !file02) {
      updateMessage("Choose both F3532 01 and 02 workbooks before parsing.");
      return;
    }

    try {
      setBusy(true);
      setFileError(null);
      const parsed = await parseF3532Workbooks(file01, file02, aircraftModel);
      setParsedWorkbook(parsed);
      setPreview(null);
      updateMessage(
        `F3532 workbooks parsed: BI ${parsed.sheet_counts.boundary_interfaces}, BDF ${parsed.sheet_counts.boundary_data_flows}, SI ${parsed.sheet_counts.system_interfaces}, SDF ${parsed.sheet_counts.system_data_flows}, TA ${parsed.sheet_counts.threat_actors}, SB ${parsed.sheet_counts.trust_boundaries}`
      );
    } catch (error) {
      const normalized =
        typeof error === "object" && error && "kind" in error
          ? (error as F3532WorkbookParseError)
          : ({
              kind: "file",
              message: error instanceof Error ? error.message : "Failed to parse F3532 workbooks"
            } satisfies F3532WorkbookParseError);
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
      const result = await previewF3532InputImport(parsedWorkbook.payload);
      setPreview(result);
      updateMessage(
        result.ok
          ? `F3532 preview ready: SB=${result.accepted.trust_boundaries}, BI=${result.accepted.boundary_interfaces}, BDF=${result.accepted.boundary_data_flows}, SDF=${result.accepted.system_data_flows}, TA=${result.accepted.threat_actors}`
          : `F3532 preview found ${result.error_details.length} issues`
      );
    } catch (error) {
      updateMessage(error instanceof Error ? error.message : "Failed to preview F3532 import");
    } finally {
      setBusy(false);
    }
  }

  async function handleCommitImport(): Promise<void> {
    if (!parsedWorkbook) {
      updateMessage("Parse the F3532 workbooks before commit.");
      return;
    }
    if (!preview || !preview.ok) {
      updateMessage("Run a successful F3532 preview before commit.");
      return;
    }

    try {
      setBusy(true);
      const result = await commitF3532InputImport(parsedWorkbook.payload);
      setPreview(result);
      if (result.committed) {
        updateMessage(`F3532 input import committed: ${result.commit_id}, version ${result.new_version}`);
        await onCommitSuccess?.(result);
      } else {
        updateMessage(`F3532 commit failed: ${result.errors.join("; ")}`);
      }
    } catch (error) {
      updateMessage(error instanceof Error ? error.message : "Failed to commit F3532 import");
    } finally {
      setBusy(false);
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

  return (
    <section className="panel import-panel">
      <div className="import-panel-header">
        <div>
          <h3>F3532 Input Import</h3>
          <p>Upload 01 and 02 workbooks, preview SB/BI/BDF/SDF/TA graph facts, then commit through the same ChangeSet path.</p>
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
          <span className="field-label">01 Workbook</span>
          <input
            className="input-field file-input"
            type="file"
            accept=".xlsx,.xls"
            onChange={handleFile01Change}
            disabled={importDisabled}
          />
        </label>

        <label className="field-stack import-field">
          <span className="field-label">02 Workbook</span>
          <input
            className="input-field file-input"
            type="file"
            accept=".xlsx,.xls"
            onChange={handleFile02Change}
            disabled={importDisabled}
          />
        </label>

        <div className="import-actions">
          <button className="button" type="button" onClick={() => void handleParseWorkbook()} disabled={importDisabled}>
            Parse 01/02
          </button>
          <button className="button" type="button" onClick={() => void handlePreviewImport()} disabled={importDisabled || !file01 || !file02}>
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
            <span className="pill">BI {sheetCounts.boundary_interfaces}</span>
            <span className="pill">BDF {sheetCounts.boundary_data_flows}</span>
            <span className="pill">SI {sheetCounts.system_interfaces}</span>
            <span className="pill">SDF {sheetCounts.system_data_flows}</span>
            <span className="pill">TA {sheetCounts.threat_actors}</span>
            <span className="pill">SB {sheetCounts.trust_boundaries}</span>
          </div>
          <p className="muted">{file01 ? `01: ${file01.name}` : "01 workbook not selected."}</p>
          <p className="muted">{file02 ? `02: ${file02.name}` : "02 workbook not selected."}</p>
          {fileError ? (
            <div className="import-error-list">
              <div className="import-error-item">{formatFileError(fileError)}</div>
            </div>
          ) : (
            <pre>{parsedWorkbook ? JSON.stringify(parsedWorkbook.payload.source, null, 2) : "Parse 01/02 to inspect source metadata."}</pre>
          )}
        </article>

        <article className="preview-card">
          <strong>Preview Summary</strong>
          {preview ? (
            <>
              <div className="import-kpi-grid">
                <span className="pill">Asset +{preview.summary.asset_nodes_to_add}</span>
                <span className="pill">Edge +{preview.summary.asset_edges_to_add}</span>
                <span className="pill">BI +{preview.summary.boundary_interfaces_to_add}</span>
                <span className="pill">SB +{preview.summary.trust_boundaries_to_add}</span>
                <span className="pill">TA +{preview.summary.threat_actors_to_add}</span>
                <span className="pill">SDF +{preview.summary.system_data_flows_to_add}</span>
                <span className="pill">Function +{preview.summary.function_nodes_to_add}</span>
              </div>
              <div className="import-kpi-grid">
                <span className="pill">Accepted SB {preview.accepted.trust_boundaries}</span>
                <span className="pill">Accepted BI {preview.accepted.boundary_interfaces}</span>
                <span className="pill">Accepted BDF {preview.accepted.boundary_data_flows}</span>
                <span className="pill">Accepted SDF {preview.accepted.system_data_flows}</span>
                <span className="pill">Accepted TA {preview.accepted.threat_actors}</span>
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
            <p className="muted">Run preview to inspect generated F3532 graph facts and warnings.</p>
          )}
        </article>

        <article className="preview-card">
          <strong>Stage-3 Readiness</strong>
          {preview ? (
            <div className="import-threat-list">
              <div className="item vertical">
                <strong>{"SB -> BI -> BDF"}</strong>
                <span>
                  {preview.accepted.trust_boundaries} boundaries, {preview.accepted.boundary_interfaces} interfaces,{" "}
                  {preview.accepted.boundary_data_flows} boundary data flows.
                </span>
              </div>
              <div className="item vertical">
                <strong>{"TA -> SB"}</strong>
                <span>{preview.accepted.threat_actors} threat actors linked by boundary references.</span>
              </div>
              <div className="item vertical">
                <strong>{"SDF -> Function"}</strong>
                <span>
                  {preview.accepted.system_data_flows} SDF rows, {preview.summary.function_links_to_add} SUPPORTS_FUNCTION links.
                </span>
              </div>
            </div>
          ) : (
            <p className="muted">Preview to confirm the data needed for generating 03 is present.</p>
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
