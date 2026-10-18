import { useWorkspaceContext } from "../../app/WorkspaceContext";
import { useMemo, useState, type FormEvent } from "react";
import { createAnalysisRun, getAnalysisMethods, getAnalysisPromotions, getAnalysisRuns, promoteDerivedResult, reviewDerivedResult } from "../../api";
import type { AnalysisMethodDefinition, StoredAnalysisRun, StoredPromotion } from "../../types";

interface Props { onStatusChange: (message: string) => void }
const nextCommand = (prefix: string) => `${prefix}:${crypto.randomUUID()}`;

export function AnalysisRunWorkbench({ onStatusChange }: Props) {
  const scope = useWorkspaceContext();
  const [projectId, setProjectId] = useState(scope.projectId);
  const [revisionId, setRevisionId] = useState(scope.revisionId);
  const [actor, setActor] = useState("analysis-engineer");
  const [expectedVersion, setExpectedVersion] = useState("1");
  const [sourceRecord, setSourceRecord] = useState("");
  const [methods, setMethods] = useState<AnalysisMethodDefinition[]>([]);
  const [methodKey, setMethodKey] = useState("");
  const [methodInput, setMethodInput] = useState("{}");
  const [methodConfig, setMethodConfig] = useState("{}");
  const [runs, setRuns] = useState<StoredAnalysisRun[]>([]);
  const [promotions, setPromotions] = useState<StoredPromotion[]>([]);
  const [selectedResultId, setSelectedResultId] = useState("");
  const [reviewRationale, setReviewRationale] = useState("");
  const [reviewerRole, setReviewerRole] = useState("Analysis Reviewer");
  const [targetType, setTargetType] = useState<"ThreatPoint" | "ThreatScenario" | "AttackPath" | "RiskAssessment">("ThreatPoint");
  const [targetBusinessId, setTargetBusinessId] = useState("");
  const [targetName, setTargetName] = useState("");
  const [promotionRationale, setPromotionRationale] = useState("");
  const [feasibilityRationale, setFeasibilityRationale] = useState("");
  const [segmentValidations, setSegmentValidations] = useState("[]");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const selectedMethod = methods.find((item) => `${item.method_id}@${item.method_version}` === methodKey);
  const results = useMemo(() => runs.flatMap((run) => run.results.map((result) => ({ run, result }))), [runs]);
  const selected = results.find((item) => item.result.id === selectedResultId);

  async function refresh() {
    if (!projectId || !revisionId) throw new Error("请先填写 project_id 和 revision_id");
    const [available, storedRuns, storedPromotions] = await Promise.all([
      methods.length ? Promise.resolve(methods) : getAnalysisMethods(),
      getAnalysisRuns(projectId, revisionId),
      getAnalysisPromotions(projectId, revisionId),
    ]);
    const visible=available.filter(m=>!m.method_id.toLowerCase().includes("f3532"));
      setMethods(visible); setRuns(storedRuns.filter(r=>!r.method.method_id.toLowerCase().includes("f3532"))); setPromotions(storedPromotions.filter(p=>storedRuns.some(r=>r.id===p.run_id&&!r.method.method_id.toLowerCase().includes("f3532"))));
    if (!methodKey && visible[0]) setMethodKey(`${visible[0].method_id}@${visible[0].method_version}`);
    if (!selectedResultId && storedRuns[0]?.results[0]) setSelectedResultId(storedRuns[0].results[0].id);
  }

  async function perform(action: () => Promise<{ new_revision_version?: number }>, success: string) {
    setBusy(true); setError("");
    try {
      const result = await action();
      if (result.new_revision_version) setExpectedVersion(String(result.new_revision_version));
      await refresh(); onStatusChange(success);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "操作失败";
      setError(message); onStatusChange(message);
    } finally { setBusy(false); }
  }

  async function handleLoad() {
    setBusy(true); setError("");
    try { await refresh(); onStatusChange("已加载受控分析运行"); }
    catch (cause) { const message = cause instanceof Error ? cause.message : "加载失败"; setError(message); onStatusChange(message); }
    finally { setBusy(false); }
  }

  function handleRun(event: FormEvent) {
    event.preventDefault();
    if (!selectedMethod) { setError("请先加载并选择分析方法"); return; }
    void perform(() => createAnalysisRun({
      actor, command_id: nextCommand("analysis-run"), project_id: projectId, revision_id: revisionId,
      expected_revision_version: Number(expectedVersion), source_record_business_id: sourceRecord,
      method_id: selectedMethod.method_id, method_version: selectedMethod.method_version,
      method_config_version: "1", execution_limits: {}, method_config: JSON.parse(methodConfig), method_input: JSON.parse(methodInput),
    }), "分析运行已保存，可进入候选审查");
  }

  function handleReview(decision: "Accept" | "Reject") {
    if (!selected) return;
    void perform(() => reviewDerivedResult({
      actor, command_id: nextCommand("derived-result-review"), project_id: projectId, revision_id: revisionId,
      expected_revision_version: Number(expectedVersion), review: {
        business_id: `REVIEW-A-${Date.now()}`, derived_result_id: selected.result.id,
        subject_version: selected.result.revision_version, decision, rationale: reviewRationale, reviewer_role: reviewerRole,
      },
    }), decision === "Accept" ? "候选结果已由人工接受" : "候选结果已被拒绝");
  }

  function handlePromote() {
    if (!selected) return;
    void perform(() => promoteDerivedResult({
      actor, command_id: nextCommand("derived-result-promotion"), project_id: projectId, revision_id: revisionId,
      expected_revision_version: Number(expectedVersion), promotion: {
        business_id: `PROMOTION-${Date.now()}`, derived_result_id: selected.result.id, target_type: targetType,
        target_business_id: targetBusinessId, target_name: targetName,
        target_payload: { source_result_kind: selected.result.result_kind }, rationale: promotionRationale,
        feasibility_rationale: feasibilityRationale || undefined, segment_validations: JSON.parse(segmentValidations),
      },
    }), "已晋级为核心 Draft；仍需独立 Engineering Review");
  }

  return <section className="analysis-run-workbench" aria-label="受控分析运行工作台">
    <div className="section-heading"><div><h2 className="section-title">受控分析运行</h2><p>绑定项目、revision、标准 profile、方法版本和输入快照；机器结果不能直接写入核心模型。</p></div></div>
    <div className="field-stack">
      <label className="field-label" htmlFor="analysis-project">Project ID</label><input id="analysis-project" className="input-field" value={projectId} onChange={(event) => setProjectId(event.target.value)} />
      <label className="field-label" htmlFor="analysis-revision">Revision ID</label><input id="analysis-revision" className="input-field" value={revisionId} onChange={(event) => setRevisionId(event.target.value)} />
      <label className="field-label" htmlFor="analysis-actor">操作者</label><input id="analysis-actor" className="input-field" value={actor} onChange={(event) => setActor(event.target.value)} />
      <label className="field-label" htmlFor="analysis-version">当前 revision version</label><input id="analysis-version" type="number" min="1" className="input-field" value={expectedVersion} onChange={(event) => setExpectedVersion(event.target.value)} />
    </div>
    <button type="button" className="button" onClick={handleLoad} disabled={busy || !projectId || !revisionId}>{busy ? "处理中…" : "加载运行"}</button>
    {error ? <p className="status error" role="alert">{error}</p> : null}

    <details>
      <summary>创建可重现运行</summary>
      <form className="field-stack" onSubmit={handleRun}>
        <label className="field-label" htmlFor="analysis-method">分析方法</label>
        <select id="analysis-method" className="input-field" value={methodKey} onChange={(event) => setMethodKey(event.target.value)}><option value="">请选择</option>{methods.map((method) => <option key={`${method.method_id}@${method.method_version}`} value={`${method.method_id}@${method.method_version}`}>{method.name} · {method.maturity}</option>)}</select>
        <label className="field-label" htmlFor="analysis-source">SourceRecord business_id</label><input id="analysis-source" className="input-field" value={sourceRecord} onChange={(event) => setSourceRecord(event.target.value)} />
        <label className="field-label" htmlFor="analysis-config">方法配置 JSON</label><textarea id="analysis-config" className="input-field code-field" rows={4} value={methodConfig} onChange={(event) => setMethodConfig(event.target.value)} />
        <label className="field-label" htmlFor="analysis-input">方法输入 JSON</label><textarea id="analysis-input" className="input-field code-field" rows={10} value={methodInput} onChange={(event) => setMethodInput(event.target.value)} />
        <button className="button primary" disabled={busy || !selectedMethod || !sourceRecord}>保存并运行</button>
      </form>
    </details>

    <h3>运行与候选结果</h3>
    <div className="scroll-panel analysis-run-list">
      {results.map(({ run, result }) => <button type="button" key={result.id} className={`item vertical clickable ${selectedResultId === result.id ? "active" : ""}`} onClick={() => setSelectedResultId(result.id)}>
        <strong>{result.result_kind} · {result.machine_status}</strong><span>{run.method.method_id}@{run.method.method_version}</span>
        <span>{result.completeness} / {result.termination_reason}{result.topology_only ? " / topology-only" : ""}</span><span>{run.stale ? "输入已过期" : "输入仍为当前"} · {result.result_hash.slice(0, 12)}</span>
      </button>)}
      {results.length === 0 ? <div className="item vertical">尚无运行。填写作用域后加载，或创建第一条受控运行。</div> : null}
    </div>

    {selected ? <div className="preview-card analysis-decision-card">
      <h3>ReviewDecision A</h3>
      <label className="field-label" htmlFor="review-role">评审角色</label><input id="review-role" className="input-field" value={reviewerRole} onChange={(event) => setReviewerRole(event.target.value)} />
      <label className="field-label" htmlFor="review-rationale">评审依据</label><textarea id="review-rationale" className="input-field" rows={3} value={reviewRationale} onChange={(event) => setReviewRationale(event.target.value)} />
      <div className="toolbar wrap"><button type="button" className="button primary" disabled={busy || !reviewRationale} onClick={() => handleReview("Accept")}>接受候选</button><button type="button" className="button" disabled={busy || !reviewRationale} onClick={() => handleReview("Reject")}>拒绝候选</button></div>
      <h3>晋级为 Core Draft</h3>
      <label className="field-label" htmlFor="promotion-type">目标类型</label><select id="promotion-type" className="input-field" value={targetType} onChange={(event) => setTargetType(event.target.value as typeof targetType)}><option>ThreatPoint</option><option>ThreatScenario</option><option>AttackPath</option><option>RiskAssessment</option></select>
      <label className="field-label" htmlFor="promotion-id">目标 business_id</label><input id="promotion-id" className="input-field" value={targetBusinessId} onChange={(event) => setTargetBusinessId(event.target.value)} />
      <label className="field-label" htmlFor="promotion-name">目标名称</label><input id="promotion-name" className="input-field" value={targetName} onChange={(event) => setTargetName(event.target.value)} />
      <label className="field-label" htmlFor="promotion-rationale">晋级依据</label><textarea id="promotion-rationale" className="input-field" rows={3} value={promotionRationale} onChange={(event) => setPromotionRationale(event.target.value)} />
      <label className="field-label" htmlFor="feasibility-rationale">攻击可行性说明（topology-only AttackPath 必填）</label><textarea id="feasibility-rationale" className="input-field" rows={3} value={feasibilityRationale} onChange={(event) => setFeasibilityRationale(event.target.value)} />
      <label className="field-label" htmlFor="segment-validations">逐边验证 JSON</label><textarea id="segment-validations" className="input-field code-field" rows={6} value={segmentValidations} onChange={(event) => setSegmentValidations(event.target.value)} />
      <button type="button" className="button primary" disabled={busy || selected.result.machine_status !== "Reviewed" || !targetBusinessId || !targetName || !promotionRationale} onClick={handlePromote}>创建 Core Draft</button>
    </div> : null}

    <h3>已晋级草稿</h3>
    <div className="scroll-panel analysis-promotion-list">{promotions.map((item) => <div className="item vertical" key={item.id}><strong>{item.target_type} / {item.target_business_id}</strong><span>{item.target_status} · origin={item.origin}</span><span>{item.source_topology_only ? "保留 topology-only 来源" : "方法候选来源"}</span></div>)}{promotions.length === 0 ? <div className="item vertical">尚无晋级草稿。只有 Reviewed 结果可晋级，晋级后仍需 Engineering Review。</div> : null}</div>
  </section>;
}
