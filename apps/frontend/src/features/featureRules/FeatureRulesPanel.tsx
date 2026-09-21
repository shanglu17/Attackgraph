import { useReducer, useRef, useState } from "react";
import { previewFeatureRules } from "../../api";
import type { FeatureCheck, FeatureDecision } from "../../types";
import template from "../../../../../examples/feature-rules/draft-preview.json";
import { decisionLabels, exportPreview, initialPreviewState, parseBundle, previewReducer, summarizePreview } from "./model";

const states = { T: "已支持", F: "已否定", U: "未知", C: "冲突" };
function Checks({ title, checks }: { title: string; checks: FeatureCheck[] }) {
  return <div><h4>{title}</h4>{checks.length ? <ul>{checks.map((c, i) => <li key={`${c.feature_id}-${i}`}>
    <strong>{c.feature_id}</strong>：{states[c.state]}{c.action ? ` · 策略：有效时${c.action === "block" ? "阻断" : "降级"}` : ""}
    {c.effect_description && <span> · {c.effect_description}</span>}
    <div>事实证据：{c.evidence_refs.join("、") || "未提供"}{c.basis_evidence_refs && `；策略依据：${c.basis_evidence_refs.join("、") || "未提供"}`}</div>
    {c.reasons.length > 0 && <small>检查原因：{c.reasons.join("、")}</small>}
  </li>)}</ul> : <p>未进入该项检查，或规则未设置此项。</p>}</div>;
}

function GroupChecks({ title, groups }: { title: string; groups: FeatureDecision["required_checks"] }) {
  return <div><h4>{title}（组间全部满足）</h4>{groups.length ? groups.map((group, i) =>
    <Checks key={i} title={`第 ${i + 1} 组：组内任一满足；结果：${states[group.state as keyof typeof states] || group.state}`} checks={group.checks} />
  ) : <p>未进入该项检查，或规则未设置此项。</p>}</div>;
}

export function FeatureRulesPanel({ disabled }: { disabled: boolean }) {
  const [state, dispatch] = useReducer(previewReducer, initialPreviewState);
  const [filename, setFilename] = useState("");
  const [page, setPage] = useState(0);
  const active = useRef(false);
  const locked = disabled || state.busy;
  const summary = state.result ? summarizePreview(state.result) : null;
  async function load(file?: File) {
    if (!file || active.current) return;
    active.current = true; dispatch({ type: "start" });
    try {
      if (file.size > 5 * 1024 * 1024) throw new Error("文件超过 5 MB，请拆分数据包后重试。");
      const text = await file.text();
      dispatch({ type: "edit", text }); setFilename(file.name); setPage(0);
    } catch (e) { dispatch({ type: "error", message: e instanceof Error ? e.message : "读取文件失败" }); }
    finally { active.current = false; }
  }
  async function run() {
    if (active.current) return;
    active.current = true; dispatch({ type: "start" }); setPage(0);
    try {
      const input = parseBundle(state.text);
      const result = await previewFeatureRules(input);
      dispatch({ type: "success", input, result });
    } catch (e) { dispatch({ type: "error", message: e instanceof Error ? e.message : "预览失败，请重试。" }); }
    finally { active.current = false; }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([exportPreview(state)], { type: "application/json;charset=utf-8" }));
    const a = document.createElement("a"); a.href = url; a.download = "feature-rule-preview.json"; a.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <section className="panel feature-rules-panel" aria-label="特征规则分析">
    <h3>特征规则分析</h3>
    <p>导入研究数据包，检查规则判定与证据。预览不会修改图谱，所有候选均需人工复核。</p>
    <div className="toolbar">
      <label className="field-stack"><span className="field-label">研究数据包（JSON，最大 5 MB）</span>
        <input type="file" accept=".json,application/json" disabled={locked} onChange={e => { void load(e.target.files?.[0]); e.target.value = ""; }} /></label>
      <button className="button" disabled={locked} onClick={() => { dispatch({ type: "edit", text: JSON.stringify(template, null, 2) }); setFilename("待审规则模板（非实验数据）"); setPage(0); }}>载入待审规则模板</button>
    </div>
    <p>{filename || "尚未载入文件。可先载入模板了解格式。"}</p>
    <label className="field-stack"><span className="field-label">数据包内容</span>
      <textarea className="input-field feature-rules-json" rows={9} value={state.text} disabled={locked} spellCheck={false}
        onChange={e => { dispatch({ type: "edit", text: e.target.value }); setFilename("已编辑的数据包"); setPage(0); }} /></label>
    <div className="toolbar">
      <button className="button primary" disabled={locked || !state.text.trim()} onClick={() => void run()}>{state.busy ? "处理中…" : "运行规则预览"}</button>
      <button className="button" disabled={locked || !state.result} onClick={download}>导出输入与结果</button>
    </div>
    {state.error && <p className="status" role="alert">{state.error}</p>}
    <div aria-live="polite">{summary && <p className="status">已求值 {summary.executed} 项 · 候选 {summary.candidates} 项 · 未执行 {summary.skipped} 项。{summary.executed === 0 && "尚无已执行的规则判定，不能据此认定没有威胁。"}</p>}</div>
    {!state.result && !state.error && <p>完成预览后，可逐项查看条件、保护措施和证据来源。</p>}
    {state.result && <>
      <p>研究预览 · {state.result.semantics_version} · 人工审查尚未完成</p>
      <details><summary>复现信息</summary><p className="feature-rules-wrap">输入 SHA-256：{state.result.input_sha256}</p></details>
      {state.result.decisions.length === 0 && <p>没有可评价的作用域与规则组合，请检查 scopes 和 rules。</p>}
      {state.result.decisions.slice(page * 50, (page + 1) * 50).map(d => <details className="preview-card" key={`${d.scope_id}\0${d.rule_id}`}>
        <summary>{decisionLabels[d.decision] || d.decision} · {d.asset_id} · {d.rule_id}</summary>
        <p>关联标签：{d.output_threat_id} · 作用域：{d.scope_id}</p>
        <p>规则版本：{d.rule_version} · 特征版本：{d.feature_version || "未提供"} · 策略版本：{d.policy_version || "未提供"}</p>
        {state.result?.scope_index.filter(s => s.scope_id === d.scope_id).map(s => <p key={s.scope_id}>链路/边界：{s.boundary_id} · 阶段：{s.operational_phase} · 攻击者：{s.attacker_profile}</p>)}
        {d.reasons.length > 0 && <p>判定原因：{d.reasons.join("、")}</p>}
        <GroupChecks title="必备条件" groups={d.required_checks} />
        <GroupChecks title="上下文条件" groups={d.context_checks} />
        <Checks title="支持特征" checks={d.supporting_checks} />
        <Checks title="保护检查" checks={d.protection_checks} />
        <h4>证据来源</h4>
        {!d.evidence_refs.length && <p>当前判定未关联证据。</p>}
        {d.evidence_refs.map(ref => {
          const e = state.result?.evidence_index.find(item => item.evidence_id === ref);
          return <div className="preview-card" key={ref}><strong>{ref}</strong>{e ? <>
            <p>{e.source}</p><p>位置：{Object.entries(e.source_locator).filter(([, v]) => v !== null).map(([k, v]) => `${k}: ${v}`).join(" · ") || "未定位"}</p>
            <p>证据状态：{e.review_status} · 版本：{e.version}</p>{e.excerpt && <blockquote>{e.excerpt}</blockquote>}
          </> : <p>引用未找到，请检查结果数据。</p>}</div>;
        })}
      </details>)}
      {state.result.decisions.length > 50 && <div className="toolbar">
        <button className="button" disabled={page === 0} onClick={() => setPage(page - 1)}>上一页</button>
        <span>第 {page + 1} / {Math.ceil(state.result.decisions.length / 50)} 页</span>
        <button className="button" disabled={(page + 1) * 50 >= state.result.decisions.length} onClick={() => setPage(page + 1)}>下一页</button>
      </div>}
    </>}
  </section>;
}
