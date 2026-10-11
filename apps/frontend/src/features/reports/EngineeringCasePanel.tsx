import { useMemo, useState } from "react";
import { getEngineeringCase, recordReviewDecision } from "../../api";
import type { StoredEngineeringCase } from "../../types";

interface Props {
  disabled?: boolean;
  onStatusChange: (message: string) => void;
}

type Reviewable = {
  type: "ThreatCondition" | "ThreatScenario" | "RiskAssessment" | "SecurityObjective" | "SecurityRequirement" | "Control" | "VerificationCase";
  business_id: string;
  name: string;
  status: string;
  revision_version: number;
};

export function EngineeringCasePanel({ disabled = false, onStatusChange }: Props) {
  const [projectId, setProjectId] = useState("");
  const [revisionId, setRevisionId] = useState("");
  const [actor, setActor] = useState("engineering-reviewer");
  const [reviewerRole, setReviewerRole] = useState("Security Engineer");
  const [decision, setDecision] = useState<"Accept" | "Approve" | "Reject" | "Return">("Accept");
  const [rationale, setRationale] = useState("");
  const [subjectKey, setSubjectKey] = useState("");
  const [engineeringCase, setEngineeringCase] = useState<StoredEngineeringCase | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const reviewables = useMemo<Reviewable[]>(() => {
    if (!engineeringCase) return [];
    return [
      ...engineeringCase.threat_conditions.map((item) => ({ ...item, type: "ThreatCondition" as const })),
      ...engineeringCase.threat_scenarios.map((item) => ({ ...item, type: "ThreatScenario" as const })),
      ...engineeringCase.risk_assessments.map((item) => ({ ...item, type: "RiskAssessment" as const })),
      ...engineeringCase.security_objectives.map((item) => ({ ...item, type: "SecurityObjective" as const })),
      ...engineeringCase.security_requirements.map((item) => ({ ...item, type: "SecurityRequirement" as const })),
      ...engineeringCase.controls.map((item) => ({ ...item, type: "Control" as const })),
      ...engineeringCase.verification_cases.map((item) => ({ ...item, type: "VerificationCase" as const })),
    ];
  }, [engineeringCase]);

  async function loadCase() {
    if (!projectId.trim() || !revisionId.trim()) {
      setError("请输入 Project UUID 与 Revision UUID");
      return;
    }
    try {
      setBusy(true);
      setError("");
      const loaded = await getEngineeringCase(projectId.trim(), revisionId.trim());
      setEngineeringCase(loaded);
      const first = [
        ...loaded.threat_conditions.map((item) => ({ ...item, type: "ThreatCondition" })),
        ...loaded.threat_scenarios.map((item) => ({ ...item, type: "ThreatScenario" })),
      ][0];
      setSubjectKey(first ? first.type + "|" + first.business_id : "");
      onStatusChange("已加载 Phase 3 工程闭环");
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "加载工程闭环失败";
      setError(message);
      onStatusChange(message);
    } finally {
      setBusy(false);
    }
  }

  async function submitReview() {
    const [type, businessId] = subjectKey.split("|");
    const subject = reviewables.find((item) => item.type === type && item.business_id === businessId);
    if (!engineeringCase || !subject || !rationale.trim()) {
      setError("请选择评审对象并填写评审依据");
      return;
    }
    try {
      setBusy(true);
      setError("");
      await recordReviewDecision({
        actor: actor.trim() || "engineering-reviewer",
        command_id: crypto.randomUUID(),
        project_id: engineeringCase.project_id,
        revision_id: engineeringCase.revision_id,
        expected_revision_version: engineeringCase.revision_version,
        review: {
          business_id: "REVIEW-" + crypto.randomUUID(),
          subject: { type: subject.type, business_id: subject.business_id, version: subject.revision_version },
          decision,
          rationale: rationale.trim(),
          reviewer_role: reviewerRole.trim() || "Security Engineer",
        },
      });
      setRationale("");
      await loadCase();
      onStatusChange("人工 ReviewDecision 已记录；对象状态已更新");
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "提交评审失败";
      setError(message);
      onStatusChange(message);
    } finally {
      setBusy(false);
    }
  }

  const unavailable = disabled || busy;
  return (
    <section className="preview-card engineering-case-panel" aria-labelledby="engineering-case-title">
      <div className="section-heading"><div>
        <h3 id="engineering-case-title">Phase 3 工程闭环</h3>
        <p>核查 DO-356A 威胁链到需求、控制、验证与证据；算法结果和人工工程判断保持分离。</p>
      </div></div>
      <div className="toolbar wrap">
        <label className="field-stack"><span className="field-label">Project UUID</span><input className="input-field" value={projectId} onChange={(event) => setProjectId(event.target.value)} disabled={unavailable} /></label>
        <label className="field-stack"><span className="field-label">Revision UUID</span><input className="input-field" value={revisionId} onChange={(event) => setRevisionId(event.target.value)} disabled={unavailable} /></label>
        <label className="field-stack"><span className="field-label">评审人</span><input className="input-field" value={actor} onChange={(event) => setActor(event.target.value)} disabled={unavailable} /></label>
        <button className="button primary" onClick={() => void loadCase()} disabled={unavailable}>{busy ? "处理中…" : "打开工程闭环"}</button>
      </div>
      {error ? <p className="status" role="alert">{error}</p> : null}
      {!engineeringCase && !error && !busy ? <p className="muted">输入受控 Revision，查看 profile、裁剪决定、工程链与人审记录。</p> : null}
      {engineeringCase ? <>
        <div className="engineering-summary-grid">
          <article><strong>{engineeringCase.threat_conditions.length}</strong><span>威胁条件</span></article>
          <article><strong>{engineeringCase.threat_scenarios.length}</strong><span>威胁场景</span></article>
          <article><strong>{engineeringCase.security_requirements.length}</strong><span>安全需求</span></article>
          <article><strong>{engineeringCase.verification_cases.length}</strong><span>验证用例</span></article>
        </div>
        <p><strong>Profile：</strong>{engineeringCase.profile_configuration.name}；F3532 适配器：
          {engineeringCase.profile_configuration.adapters.find((item) => item.adapter_id === "f3532")?.enabled ? "已启用" : "未启用"}
        </p>
        <div className="scroll-panel">
          <table className="report-table"><thead><tr><th>阶段</th><th>对象</th><th>状态</th><th>关键结论</th></tr></thead><tbody>
            {engineeringCase.threat_conditions.map((item) => <tr key={item.business_id}><td>威胁条件</td><td>{item.name}</td><td>{item.status}</td><td>{item.effect}</td></tr>)}
            {engineeringCase.threat_scenarios.map((item) => <tr key={item.business_id}><td>威胁场景</td><td>{item.name}</td><td>{item.status}</td><td>{item.actions.join("；")}</td></tr>)}
            {engineeringCase.risk_assessments.map((item) => <tr key={item.business_id}><td>风险评估</td><td>{item.name}</td><td>{item.status}</td><td>计算：{JSON.stringify(item.computed_result ?? {})}<br />判断：{item.engineering_judgement}</td></tr>)}
            {engineeringCase.security_objectives.map((item) => <tr key={item.business_id}><td>安全目标</td><td>{item.name}</td><td>{item.status}</td><td>{item.statement}</td></tr>)}
            {engineeringCase.security_requirements.map((item) => <tr key={item.business_id}><td>安全需求</td><td>{item.name}</td><td>{item.status}</td><td>{item.statement}</td></tr>)}
            {engineeringCase.controls.map((item) => <tr key={item.business_id}><td>控制措施</td><td>{item.name}</td><td>{item.status}</td><td>{item.implementation_status}</td></tr>)}
            {engineeringCase.verification_cases.map((item) => <tr key={item.business_id}><td>验证</td><td>{item.name}</td><td>{item.status}</td><td>{item.outcome} / {item.result ?? "—"}</td></tr>)}
          </tbody></table>
        </div>
        <div className="engineering-review-form">
          <h4>记录人工 ReviewDecision</h4>
          <div className="toolbar wrap">
            <label className="field-stack"><span className="field-label">对象</span><select className="input-field" value={subjectKey} onChange={(event) => setSubjectKey(event.target.value)} disabled={unavailable}>
              <option value="">请选择</option>
              {reviewables.map((item) => <option key={item.type + item.business_id} value={item.type + "|" + item.business_id}>{item.type} / {item.name} [{item.status}]</option>)}
            </select></label>
            <label className="field-stack"><span className="field-label">决定</span><select className="input-field" value={decision} onChange={(event) => setDecision(event.target.value as typeof decision)} disabled={unavailable}>
              <option value="Accept">接受为已评审</option><option value="Approve">批准</option><option value="Reject">拒绝</option><option value="Return">退回 Draft</option>
            </select></label>
            <label className="field-stack"><span className="field-label">评审角色</span><input className="input-field" value={reviewerRole} onChange={(event) => setReviewerRole(event.target.value)} disabled={unavailable} /></label>
          </div>
          <label className="field-stack"><span className="field-label">评审依据</span><textarea className="input-field" value={rationale} onChange={(event) => setRationale(event.target.value)} disabled={unavailable} rows={3} /></label>
          <button className="button" onClick={() => void submitReview()} disabled={unavailable || !subjectKey || !rationale.trim()}>提交人审决定</button>
        </div>
        <p className="muted">ReviewDecision：{engineeringCase.review_decisions.length} 条；SourceRecord：{engineeringCase.source_record_business_id}；Revision version：{engineeringCase.revision_version}</p>
      </> : null}
    </section>
  );
}
