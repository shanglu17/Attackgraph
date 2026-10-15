import { useMemo, useState } from "react";
import { addReviewComment, createReviewSession, decideReviewSession, getEngineeringCase, getReviewWorkspace } from "../../api";
import { useWorkspaceContext } from "../../app/WorkspaceContext";
import type { ReviewWorkspace, StoredEngineeringCase } from "../../types";

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

export function ReviewWorkbenchPanel({ disabled = false, onStatusChange }: Props) {
  const context = useWorkspaceContext();
  const [engineeringCase, setEngineeringCase] = useState<StoredEngineeringCase | null>(null);
  const [workspace, setWorkspace] = useState<ReviewWorkspace | null>(null);
  const [subjectKey, setSubjectKey] = useState("");
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [title, setTitle] = useState("工程结论受控评审");
  const [candidateIds, setCandidateIds] = useState("");
  const [comment, setComment] = useState("");
  const [decision, setDecision] = useState<"Accept" | "Approve" | "Reject" | "Return">("Approve");
  const [rationale, setRationale] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const reviewables = useMemo<Reviewable[]>(() => engineeringCase ? [
    ...engineeringCase.threat_conditions.map((item) => ({ ...item, type: "ThreatCondition" as const })),
    ...engineeringCase.threat_scenarios.map((item) => ({ ...item, type: "ThreatScenario" as const })),
    ...engineeringCase.risk_assessments.map((item) => ({ ...item, type: "RiskAssessment" as const })),
    ...engineeringCase.security_objectives.map((item) => ({ ...item, type: "SecurityObjective" as const })),
    ...engineeringCase.security_requirements.map((item) => ({ ...item, type: "SecurityRequirement" as const })),
    ...engineeringCase.controls.map((item) => ({ ...item, type: "Control" as const })),
    ...engineeringCase.verification_cases.map((item) => ({ ...item, type: "VerificationCase" as const })),
  ] : [], [engineeringCase]);

  const selectedSession = workspace?.sessions.find((item) => item.id === selectedSessionId) ?? workspace?.sessions[0];

  function requireContext() {
    if (!context.projectId.trim() || !context.revisionId.trim()) throw new Error("请先在页面顶部填写 Project UUID 与 Revision UUID");
    if (!context.apiKey.trim()) throw new Error("请填写当前评审人的 API Key");
    return { projectId: context.projectId.trim(), revisionId: context.revisionId.trim(), apiKey: context.apiKey.trim() };
  }

  async function reload(preferredSessionId?: string) {
    const scope = requireContext();
    const [caseData, reviewData] = await Promise.all([
      getEngineeringCase(scope.projectId, scope.revisionId),
      getReviewWorkspace(scope.projectId, scope.revisionId, scope.apiKey),
    ]);
    setEngineeringCase(caseData);
    setWorkspace(reviewData);
    if (!subjectKey) {
      const first = [caseData.threat_conditions[0] && { ...caseData.threat_conditions[0], type: "ThreatCondition" }, caseData.threat_scenarios[0] && { ...caseData.threat_scenarios[0], type: "ThreatScenario" }].find(Boolean);
      if (first) setSubjectKey(`${first.type}|${first.business_id}`);
    }
    const nextId = preferredSessionId ?? selectedSessionId ?? reviewData.sessions[0]?.id ?? "";
    setSelectedSessionId(nextId);
    onStatusChange(`评审工作台已加载：${reviewData.sessions.length} 个 ReviewSession`);
  }

  async function run(action: () => Promise<void>) {
    try {
      setBusy(true); setError(""); await action();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "评审操作失败";
      setError(message); onStatusChange(message);
    } finally { setBusy(false); }
  }

  async function openSession() {
    const [type, businessId] = subjectKey.split("|");
    const subject = reviewables.find((item) => item.type === type && item.business_id === businessId);
    if (!engineeringCase || !subject || !title.trim()) throw new Error("请选择评审对象并填写评审标题");
    const scope = requireContext();
    const result = await createReviewSession({
      command_id: crypto.randomUUID(), project_id: scope.projectId, revision_id: scope.revisionId,
      expected_revision_version: engineeringCase.revision_version,
      session: {
        business_id: `REVIEW-SESSION-${crypto.randomUUID()}`, title: title.trim(),
        subject: { type: subject.type, business_id: subject.business_id, version: subject.revision_version },
        candidate_business_ids: candidateIds.split(",").map((item) => item.trim()).filter(Boolean).slice(0, 2),
      },
    }, scope.apiKey);
    await reload(result.session_id);
    onStatusChange("受控 ReviewSession 已创建；身份与角色由服务端认证");
  }

  async function submitComment() {
    if (!workspace || !selectedSession || !comment.trim()) throw new Error("请选择评审会话并填写意见");
    const scope = requireContext();
    await addReviewComment({
      command_id: crypto.randomUUID(), project_id: scope.projectId, revision_id: scope.revisionId,
      expected_revision_version: workspace.revision_version, session_id: selectedSession.id,
      comment: { business_id: `REVIEW-COMMENT-${crypto.randomUUID()}`, body: comment.trim() },
    }, scope.apiKey);
    setComment(""); await reload(selectedSession.id);
  }

  async function submitDecision() {
    if (!workspace || !selectedSession || !rationale.trim()) throw new Error("请选择评审会话并填写决定依据");
    const scope = requireContext();
    await decideReviewSession({
      command_id: crypto.randomUUID(), project_id: scope.projectId, revision_id: scope.revisionId,
      expected_revision_version: workspace.revision_version, session_id: selectedSession.id,
      review: { business_id: `REVIEW-DECISION-${crypto.randomUUID()}`, decision, rationale: rationale.trim() },
    }, scope.apiKey);
    setRationale(""); await reload(selectedSession.id);
    onStatusChange("经认证的 ReviewDecision 已记录；会话已关闭");
  }

  const unavailable = disabled || busy;
  return <section className="preview-card review-workbench" aria-labelledby="review-workbench-title">
    <div className="section-heading"><div><h3 id="review-workbench-title">受控评审工作台</h3><p>比较候选结果、核查证据、记录意见，并由不同身份完成批准或退回。</p></div>
      <button className="button primary" type="button" onClick={() => void run(() => reload())} disabled={unavailable}>{busy ? "处理中…" : "加载评审上下文"}</button>
    </div>
    {error ? <p className="status" role="alert">{error}</p> : null}
    {!workspace ? <p className="muted">项目上下文和 API Key 在页面顶部统一设置。服务端会校验 actor、角色与职责分离。</p> : <>
      <div className="review-workbench-grid">
        <article className="preview-card">
          <h4>新建评审会话</h4>
          <label className="field-stack"><span className="field-label">评审对象</span><select className="input-field" value={subjectKey} onChange={(event) => setSubjectKey(event.target.value)} disabled={unavailable}>{reviewables.map((item) => <option key={`${item.type}:${item.business_id}`} value={`${item.type}|${item.business_id}`}>{item.type} / {item.name} [{item.status}]</option>)}</select></label>
          <label className="field-stack"><span className="field-label">标题</span><input className="input-field" value={title} onChange={(event) => setTitle(event.target.value)} disabled={unavailable} /></label>
          <label className="field-stack"><span className="field-label">候选业务编号（最多两个，逗号分隔）</span><input className="input-field" value={candidateIds} onChange={(event) => setCandidateIds(event.target.value)} disabled={unavailable} /></label>
          <button className="button" type="button" onClick={() => void run(openSession)} disabled={unavailable || !subjectKey}>打开 ReviewSession</button>
        </article>
        <article className="preview-card">
          <h4>评审队列</h4>
          <div className="stage-list compact-stage-list">{workspace.sessions.map((session) => <button type="button" className={`item clickable vertical ${selectedSession?.id === session.id ? "active" : ""}`} key={session.id} onClick={() => setSelectedSessionId(session.id)}>
            <strong>{session.title}</strong><span>{session.subject.type} / {session.subject.business_id}</span><small>{session.status} · {session.opened_by_display_name} ({session.opened_by_role})</small>
          </button>)}{workspace.sessions.length === 0 ? <p className="muted">当前 Revision 尚无评审会话。</p> : null}</div>
        </article>
      </div>
      {selectedSession ? <article className="preview-card review-session-detail">
        <div className="subsection-heading"><div><h3>{selectedSession.title}</h3><p>Subject version {selectedSession.subject.version} · Revision version {workspace.revision_version} · 状态 {selectedSession.status}</p></div></div>
        <div className="comparison-grid">
          <section><h4>当前对象</h4><pre>{JSON.stringify(selectedSession.subject_payload ?? {}, null, 2)}</pre></section>
          {selectedSession.candidate_payloads.map((candidate) => <section key={candidate.business_id}><h4>候选 {candidate.business_id}</h4><pre>{JSON.stringify(candidate.payload, null, 2)}</pre></section>)}
        </div>
        <h4>证据</h4>
        <div className="evidence-grid">{selectedSession.evidence.map((evidence) => <div className="item vertical" key={evidence.business_id}><strong>{evidence.name}</strong><span>{evidence.business_id} · {evidence.evidence_type ?? "EvidenceRecord"}</span><small>{evidence.status ?? "状态未声明"}{evidence.location ? ` · ${evidence.location}` : ""}</small></div>)}{selectedSession.evidence.length === 0 ? <p className="muted">当前对象没有通过 TraceLink 关联的 EvidenceRecord。</p> : null}</div>
        <h4>意见记录</h4>
        <div className="stage-list compact-stage-list">{selectedSession.comments.map((item) => <div className="item vertical" key={item.id}><strong>{item.author_display_name} · {item.author_role}</strong><span>{item.body}</span><small>{item.created_at} · revision {item.revision_version}</small></div>)}</div>
        {selectedSession.status === "Open" ? <div className="review-action-grid">
          <label className="field-stack"><span className="field-label">补充意见</span><textarea className="input-field" rows={3} value={comment} onChange={(event) => setComment(event.target.value)} disabled={unavailable} /></label>
          <button className="button" type="button" onClick={() => void run(submitComment)} disabled={unavailable || !comment.trim()}>提交意见</button>
          <label className="field-stack"><span className="field-label">决定</span><select className="input-field" value={decision} onChange={(event) => setDecision(event.target.value as typeof decision)} disabled={unavailable}><option value="Approve">批准</option><option value="Accept">接受为已评审</option><option value="Return">退回 Draft</option><option value="Reject">拒绝</option></select></label>
          <label className="field-stack"><span className="field-label">决定依据</span><textarea className="input-field" rows={3} value={rationale} onChange={(event) => setRationale(event.target.value)} disabled={unavailable} /></label>
          <button className="button primary" type="button" onClick={() => void run(submitDecision)} disabled={unavailable || !rationale.trim()}>记录决定并关闭</button>
        </div> : selectedSession.decision ? <div className="status"><strong>{selectedSession.decision.decision}</strong> · {selectedSession.decision.reviewer_display_name} ({selectedSession.decision.reviewer_role}) · subject version {selectedSession.decision.subject_version}<br />{selectedSession.decision.rationale}</div> : null}
      </article> : null}
    </>}
  </section>;
}
