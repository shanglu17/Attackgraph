import { useState } from "react";
import { exportTraceabilityReport, freezeRevision, getTraceabilityReport } from "../../api";
import type { TraceabilityReport, TraceabilityReportQuery } from "../../types";

interface Vg1TraceabilityPanelProps {
  disabled?: boolean;
  onStatusChange: (message: string) => void;
}

export function Vg1TraceabilityPanel({ disabled = false, onStatusChange }: Vg1TraceabilityPanelProps) {
  const [projectId, setProjectId] = useState("");
  const [revisionId, setRevisionId] = useState("");
  const [baselineId, setBaselineId] = useState("");
  const [actor, setActor] = useState("frontend-reviewer");
  const [baselineBusinessId, setBaselineBusinessId] = useState("VG1-BASELINE-001");
  const [report, setReport] = useState<TraceabilityReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function query(): TraceabilityReportQuery {
    const project_id = projectId.trim();
    const baseline_id = baselineId.trim();
    const revision_id = revisionId.trim();
    if (!project_id) throw new Error("请输入 Project UUID");
    if ((baseline_id ? 1 : 0) + (revision_id ? 1 : 0) !== 1) {
      throw new Error("Revision UUID 与 Baseline UUID 必须且只能填写一个");
    }
    return baseline_id ? { project_id, baseline_id } : { project_id, revision_id };
  }

  async function loadReport(nextQuery?: TraceabilityReportQuery) {
    try {
      setBusy(true);
      setError("");
      const loaded = await getTraceabilityReport(nextQuery ?? query(), actor.trim() || "frontend-reviewer");
      setReport(loaded);
      onStatusChange(`已加载 ${loaded.context.baseline ? "Baseline" : "Revision"} 追踪报告：${loaded.chains.length} 条链路`);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "加载追踪报告失败";
      setError(message);
      onStatusChange(message);
    } finally {
      setBusy(false);
    }
  }

  async function freezeLoadedRevision() {
    if (!report || report.context.baseline || report.context.revision.status !== "Draft") return;
    try {
      setBusy(true);
      setError("");
      const result = await freezeRevision({
        actor: actor.trim() || "frontend-reviewer",
        command_id: crypto.randomUUID(),
        project_id: report.context.project.id,
        revision_id: report.context.revision.id,
        expected_revision_version: report.context.revision.version,
        baseline: { business_id: baselineBusinessId.trim(), content_hash: report.metadata.content_hash }
      });
      setBaselineId(result.value.id);
      setRevisionId("");
      await loadReport({ project_id: report.context.project.id, baseline_id: result.value.id });
      onStatusChange(`Revision 已冻结为 ${result.value.business_id}，内容摘要校验通过`);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "冻结 Revision 失败";
      setError(message);
      onStatusChange(message);
    } finally {
      setBusy(false);
    }
  }

  async function exportReport() {
    try {
      setBusy(true);
      setError("");
      await exportTraceabilityReport(query(), actor.trim() || "frontend-reviewer");
      onStatusChange("通用追踪报告已导出为 JSON");
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "导出追踪报告失败";
      setError(message);
      onStatusChange(message);
    } finally {
      setBusy(false);
    }
  }

  const unavailable = disabled || busy;
  return (
    <section className="preview-card vg1-traceability-panel" aria-labelledby="vg1-traceability-title">
      <div className="section-heading"><div>
        <h3 id="vg1-traceability-title">VG-1 通用追踪链</h3>
        <p>打开一个 Project 的 Revision 或 Baseline，核查 DO-356A 引用、来源、Draft 威胁和审计信息。</p>
      </div></div>
      <div className="toolbar wrap">
        <label className="field-stack"><span className="field-label">Project UUID</span><input className="input-field" value={projectId} onChange={(event) => setProjectId(event.target.value)} disabled={unavailable} /></label>
        <label className="field-stack"><span className="field-label">Revision UUID</span><input className="input-field" value={revisionId} onChange={(event) => setRevisionId(event.target.value)} disabled={unavailable || Boolean(baselineId.trim())} /></label>
        <label className="field-stack"><span className="field-label">Baseline UUID</span><input className="input-field" value={baselineId} onChange={(event) => setBaselineId(event.target.value)} disabled={unavailable || Boolean(revisionId.trim())} /></label>
        <label className="field-stack"><span className="field-label">操作人</span><input className="input-field" value={actor} onChange={(event) => setActor(event.target.value)} disabled={unavailable} /></label>
      </div>
      <div className="toolbar wrap">
        <button className="button primary" onClick={() => void loadReport()} disabled={unavailable}>{busy ? "处理中…" : "打开追踪报告"}</button>
        <button className="button" onClick={() => void exportReport()} disabled={unavailable || !report}>导出 JSON</button>
        {report && !report.context.baseline && report.context.revision.status === "Draft" ? <>
          <label className="field-stack"><span className="field-label">Baseline 业务编号</span><input className="input-field" value={baselineBusinessId} onChange={(event) => setBaselineBusinessId(event.target.value)} disabled={unavailable} /></label>
          <button className="button" onClick={() => void freezeLoadedRevision()} disabled={unavailable || !baselineBusinessId.trim()}>冻结 Revision</button>
        </> : null}
      </div>
      {error ? <p className="status" role="alert">{error}</p> : null}
      {!report && !error && !busy ? <p className="muted">填写受控项目标识后打开报告；可使用 npm run vg1:demo 生成演示项目。</p> : null}
      {busy ? <p className="status" aria-live="polite">正在处理追踪报告…</p> : null}
      {report ? <div className="scroll-panel">
        <p><strong>{report.context.project.name}</strong> / {report.context.revision.business_id}{report.context.baseline ? ` / ${report.context.baseline.business_id}` : ""}</p>
        <p>Profile：{report.context.standard_profile_version.name} {report.context.standard_profile_version.profile_version}；标准：{report.context.standard_profile_version.standard_references.join("、")}；完整性：{report.metadata.integrity_status}</p>
        <p className="muted">{report.metadata.disclaimer}</p>
        <h4>追踪链</h4>
        <table className="report-table"><thead><tr><th>关系</th><th>来源端</th><th>目标端</th><th>标准引用</th><th>SourceRecord</th></tr></thead><tbody>
          {report.chains.map((chain) => <tr key={chain.trace_link_business_id}>
            <td>{chain.link_type}<br />{chain.trace_link_business_id}</td>
            <td>{chain.source.type} / {chain.source.name}<br />[{chain.source.status ?? "—"}]</td>
            <td>{chain.target.type} / {chain.target.name}<br />[{chain.target.status ?? "—"}]</td>
            <td>{chain.standard_reference ?? "—"}</td><td>{chain.source_record_business_id ?? "—"}</td>
          </tr>)}
          {report.chains.length === 0 ? <tr><td colSpan={5}>当前范围没有 TraceLink。</td></tr> : null}
        </tbody></table>
        <h4>来源与生成信息</h4>
        <p>来源：{report.sources.map((source) => `${source.business_id} (${source.created_by})`).join("、") || "—"}</p>
        <p>生成器：{report.metadata.generator_version}；生成者：{report.metadata.generated_by}</p>
        <p>内容 SHA-256：{report.metadata.content_hash}</p>
      </div> : null}
    </section>
  );
}
