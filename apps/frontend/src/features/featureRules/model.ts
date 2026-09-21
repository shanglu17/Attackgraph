import type { FeaturePreviewResult, FeatureDecisionStatus } from "../../types";
export interface PreviewState {
  text: string; result: FeaturePreviewResult | null; submitted: Record<string, unknown> | null;
  busy: boolean; error: string;
}
type Action = { type: "edit"; text: string } | { type: "start" } |
  { type: "error"; message: string } | { type: "success"; input: Record<string, unknown>; result: FeaturePreviewResult };
export const initialPreviewState: PreviewState = { text: "", result: null, submitted: null, busy: false, error: "" };
export function previewReducer(state: PreviewState, action: Action): PreviewState {
  switch (action.type) {
    case "edit": return { ...initialPreviewState, text: action.text };
    case "start": return { ...state, busy: true, result: null, submitted: null, error: "" };
    case "error": return { ...state, busy: false, result: null, submitted: null, error: action.message };
    case "success": return { ...state, busy: false, error: "", result: action.result, submitted: action.input };
  }
}
export function parseBundle(text: string): Record<string, unknown> {
  let value: Record<string, unknown>;
  try { value = JSON.parse(text.replace(/^\uFEFF/, "")); }
  catch { throw new Error("JSON 格式错误，请检查括号、逗号和引号。"); }
  if (!value || Array.isArray(value) || typeof value !== "object" || value.contract_version !== "feature-preview-0.1" ||
    typeof value.scenario_id !== "string" || !value.scenario_id.trim() ||
    !["assets", "features", "rules", "evidence", "scopes", "policies"].every(k => Array.isArray(value[k])))
    throw new Error("请输入 feature-preview-0.1 数据包，包含 scenario_id、assets、features、rules、evidence、scopes、policies。完整字段由后端校验。");
  return value;
}
export function exportPreview(state: PreviewState) {
  if (!state.result || !state.submitted || state.busy) throw new Error("请先完成当前输入的预览。");
  return JSON.stringify({ format: "feature-preview-export-0.1", input: state.submitted, result: state.result }, null, 2);
}
export function summarizePreview(result: FeaturePreviewResult) {
  return { executed: result.executed_count,
    candidates: result.decisions.filter(x => ["candidate", "candidate_scoped", "candidate_protection_unresolved"].includes(x.decision)).length,
    skipped: result.decisions.filter(x => x.decision === "rule_not_executed").length };
}
export const decisionLabels: Record<FeatureDecisionStatus, string> = {
  rule_not_executed: "未执行（规则或策略待审）", not_applicable: "不适用", needs_evidence: "待补证据",
  requirements_not_met: "必备条件不满足", blocked: "保护阻断", candidate_scoped: "候选（范围缩小）",
  candidate_protection_unresolved: "候选（保护未确定）", candidate: "候选（待人工审查）"
};
