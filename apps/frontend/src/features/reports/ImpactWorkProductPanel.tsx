import { useMemo, useState } from "react";
import {
  createChangeImpactAssessment,
  exportAssuranceWorkProduct,
  getAssuranceWorkProduct,
  getChangeImpactAssessments,
  previewChangeImpact,
  recordImpactDisposition,
} from "../../api";
import type { AssuranceWorkProduct, ImpactPreview, StoredImpactAssessment } from "../../types";

interface Props {
  disabled?: boolean;
  onStatusChange: (message: string) => void;
}

export function ImpactWorkProductPanel({ disabled = false, onStatusChange }: Props) {
  const [projectId, setProjectId] = useState("");
  const [sourceKind, setSourceKind] = useState<"baseline" | "revision">("baseline");
  const [sourceId, setSourceId] = useState("");
  const [revisionId, setRevisionId] = useState("");
  const [actor, setActor] = useState("impact-reviewer");
  const [expectedVersion, setExpectedVersion] = useState("1");
  const [businessId, setBusinessId] = useState("IMPACT-001");
  const [rationale, setRationale] = useState("Assess the engineering consequences of the controlled baseline change.");
  const [preview, setPreview] = useState<ImpactPreview | null>(null);
  const [assessments, setAssessments] = useState<StoredImpactAssessment[]>([]);
  const [itemId, setItemId] = useState("");
  const [decision, setDecision] = useState<"Accept" | "Reanalyze" | "Waive" | "Defer">("Reanalyze");
  const [decisionRationale, setDecisionRationale] = useState("");
  const [dueAt, setDueAt] = useState("");
  const [waiverBasis, setWaiverBasis] = useState("");
  const [workProduct, setWorkProduct] = useState<AssuranceWorkProduct | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const openItems = useMemo(() => assessments.flatMap((assessment) => assessment.items.filter((item) => item.status === "Open").map((item) => ({ assessment, item }))), [assessments]);

  function requireScope() {
    if (!projectId.trim() || !sourceId.trim() || !revisionId.trim()) throw new Error("请输入 Project、对比起点和目标 Revision UUID");
    return {
      project_id: projectId.trim(),
      from: sourceKind === "baseline" ? { baseline_id: sourceId.trim() } : { revision_id: sourceId.trim() },
      to: { revision_id: revisionId.trim() },
    };
  }

  async function run(task: () => Promise<void>) {
    try {
      setBusy(true);
      setError("");
      await task();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "操作失败";
      setError(message);
      onStatusChange(message);
    } finally {
      setBusy(false);
    }
  }

  async function loadAssessments() {
    const loaded = await getChangeImpactAssessments(projectId.trim(), revisionId.trim());
    setAssessments(loaded);
    const firstOpen = loaded.flatMap((assessment) => assessment.items).find((item) => item.status === "Open");
    setItemId(firstOpen?.id ?? "");
  }

  return <section className="review-section impact-work-product-panel">
    <div className="section-heading">
      <div>
        <h3>变更影响与工作产品</h3>
        <p>比较受控版本、记录人工处置，并生成带缺口说明的追踪矩阵。</p>
      </div>
    </div>
    <div className="field-stack">
      <label className="field-label">Project UUID<input className="input-field" value={projectId} onChange={(event) => setProjectId(event.target.value)} /></label>
      <label className="field-label">对比起点
        <select className="input-field" value={sourceKind} onChange={(event) => setSourceKind(event.target.value as "baseline" | "revision")}>
          <option value="baseline">Baseline UUID</option><option value="revision">Revision UUID</option>
        </select>
        <input className="input-field" aria-label="对比起点 UUID" value={sourceId} onChange={(event) => setSourceId(event.target.value)} />
      </label>
      <label className="field-label">目标 Revision UUID<input className="input-field" value={revisionId} onChange={(event) => setRevisionId(event.target.value)} /></label>
      <label className="field-label">执行人<input className="input-field" value={actor} onChange={(event) => setActor(event.target.value)} /></label>
      <label className="field-label">目标 Revision 当前版本<input className="input-field" type="number" min="1" value={expectedVersion} onChange={(event) => setExpectedVersion(event.target.value)} /></label>
    </div>
    <div className="toolbar wrap">
      <button type="button" className="button primary" disabled={disabled || busy} onClick={() => run(async () => {
        const result = await previewChangeImpact(requireScope());
        setPreview(result);
        onStatusChange(`影响预览完成：${result.differences.length} 项变化，${result.impacted.length} 项影响`);
      })}>比较版本</button>
      <button type="button" className="button" disabled={disabled || busy || !projectId.trim() || !revisionId.trim()} onClick={() => run(async () => {
        await loadAssessments();
        onStatusChange("已加载变更影响评估");
      })}>加载评估</button>
      <button type="button" className="button" disabled={disabled || busy || !projectId.trim() || !revisionId.trim()} onClick={() => run(async () => {
        const result = await getAssuranceWorkProduct({ project_id: projectId.trim(), revision_id: revisionId.trim(), actor: actor.trim() || "impact-reviewer" });
        setWorkProduct(result);
        onStatusChange(`工作产品已生成：${result.coverage.percentage}% 链路覆盖`);
      })}>生成工作产品</button>
      <button type="button" className="button" disabled={disabled || busy || !workProduct} onClick={() => run(async () => {
        await exportAssuranceWorkProduct({ project_id: projectId.trim(), revision_id: revisionId.trim(), actor: actor.trim() || "impact-reviewer" });
        onStatusChange("工作产品已导出");
      })}>导出 JSON</button>
    </div>
    {error ? <p className="status error" role="alert">{error}</p> : null}
    {preview ? <div className="preview-card">
      <strong>确定性影响预览</strong>
      <p>{preview.differences.length} 项直接变化，{preview.impacted.filter((item) => item.impact_kind === "Propagated").length} 项传播影响。</p>
      <div className="scroll-panel compact-list">
        {preview.impacted.map((item) => <div className="item vertical" key={`${item.entity.type}:${item.entity.business_id}`}>
          <strong>{item.entity.name}</strong><span>{item.entity.type} · {item.impact_kind} · 距离 {item.distance}</span>
        </div>)}
        {preview.impacted.length === 0 ? <p>两个版本之间没有可识别的工程变化。</p> : null}
      </div>
      <div className="field-stack">
        <label className="field-label">评估业务编号<input className="input-field" value={businessId} onChange={(event) => setBusinessId(event.target.value)} /></label>
        <label className="field-label">评估理由<textarea className="input-field" value={rationale} onChange={(event) => setRationale(event.target.value)} /></label>
      </div>
      <button type="button" className="button primary" disabled={disabled || busy} onClick={() => run(async () => {
        const scope = requireScope();
        const created = await createChangeImpactAssessment({
          actor: actor.trim(), command_id: crypto.randomUUID(), project_id: scope.project_id, revision_id: revisionId.trim(), expected_revision_version: Number(expectedVersion),
          assessment: { business_id: businessId.trim(), title: `Impact assessment ${businessId.trim()}`, from: scope.from, to: scope.to, rationale: rationale.trim() },
        });
        setExpectedVersion(String(created.new_revision_version));
        await loadAssessments();
        onStatusChange(`影响评估已保存：${created.item_count} 个处置项`);
      })}>保存影响评估</button>
    </div> : <p className="status">先比较一个 Baseline/Revision 与目标 Revision。</p>}
    {openItems.length > 0 ? <div className="preview-card">
      <strong>记录影响处置</strong>
      <div className="field-stack">
        <label className="field-label">待处置项<select className="input-field" value={itemId} onChange={(event) => setItemId(event.target.value)}>{openItems.map(({ assessment, item }) => <option value={item.id} key={item.id}>{assessment.business_id} · {item.entity.name}</option>)}</select></label>
        <label className="field-label">决定<select className="input-field" value={decision} onChange={(event) => setDecision(event.target.value as typeof decision)}><option>Accept</option><option>Reanalyze</option><option>Waive</option><option>Defer</option></select></label>
        <label className="field-label">理由<textarea className="input-field" value={decisionRationale} onChange={(event) => setDecisionRationale(event.target.value)} /></label>
        {decision === "Defer" ? <label className="field-label">计划完成时间<input className="input-field" type="datetime-local" value={dueAt} onChange={(event) => setDueAt(event.target.value)} /></label> : null}
        {decision === "Waive" ? <label className="field-label">豁免依据<textarea className="input-field" value={waiverBasis} onChange={(event) => setWaiverBasis(event.target.value)} /></label> : null}
      </div>
      <button type="button" className="button primary" disabled={disabled || busy || !itemId || !decisionRationale.trim()} onClick={() => run(async () => {
        const selected = openItems.find(({ item }) => item.id === itemId);
        if (!selected) throw new Error("请选择待处置项");
        const result = await recordImpactDisposition({
          actor: actor.trim(), command_id: crypto.randomUUID(), project_id: projectId.trim(), revision_id: revisionId.trim(), expected_revision_version: Number(expectedVersion),
          disposition: { business_id: `${selected.item.business_id}:DECISION`, assessment_id: selected.assessment.id, impact_item_id: selected.item.id, decision, rationale: decisionRationale.trim(), reviewer_role: "Security Engineer", due_at: decision === "Defer" ? new Date(dueAt).toISOString() : undefined, waiver_basis: decision === "Waive" ? waiverBasis.trim() : undefined },
        });
        setExpectedVersion(String(result.new_revision_version));
        setDecisionRationale("");
        await loadAssessments();
        onStatusChange(`影响处置已记录，评估状态：${result.assessment_status}`);
      })}>提交处置</button>
    </div> : assessments.length > 0 ? <p className="status success">当前评估没有未处置项。</p> : null}
    {workProduct ? <div className="preview-card">
      <strong>保证工作产品 · {workProduct.metadata.package_status}</strong>
      <p>覆盖 {workProduct.coverage.covered}，部分覆盖 {workProduct.coverage.partial}，缺口 {workProduct.coverage.gaps}。</p>
      <div className="toolbar wrap">{workProduct.sections.map((section) => <span className="pill" key={section.section_id}>{section.title}</span>)}</div>
      <div className="scroll-panel compact-list">{workProduct.gaps.map((gap) => <div className="item vertical" key={`${gap.gap_type}:${gap.entity_type}:${gap.business_id}`}><strong>{gap.gap_type}</strong><span>{gap.entity_type} · {gap.business_id}</span><span>{gap.message}</span></div>)}{workProduct.gaps.length === 0 ? <p>未发现未处置的追踪缺口；该结果仍不是符合性声明。</p> : null}</div>
    </div> : null}
  </section>;
}
