import type {
  AttackPath,
  BoundaryDataFlowReportRow,
  CxfImportCommitResult,
  CxfImportPreviewResult,
  CxfImportRequest,
  DO326ALink,
  F3532InputImportCommitResult,
  F3532InputImportPreviewResult,
  F3532InputImportRequest,
  F3532Report03Data,
  F353204Defaults,
  F353204GenerationResult,
  FailureCondition,
  FreezeRevisionCommand,
  FhaImportRequest,
  FunctionPropagationReportRow,
  GraphChangeSet,
  GraphData,
  InternalDataFlowReportRow,
  ModelingExportData,
  ReviewStatus,
  StandardArtifactType,
  StandardClause,
  StandardKnowledgeSummary,
  StandardMapping,
  StoredSystemModel,
  SystemModelCommitRequest,
  SystemModelCommitResult,
  SystemModelPreviewRequest,
  SystemModelPreviewResult,
  ThreatCondition,
  ThreatScenario,
  TraceabilityReport,
  TraceabilityReportQuery,
  StoredEngineeringCase,
  ReviewDecisionCommand,
  ReviewDecisionResult,
  TrustBoundaryReportRow,
  AnalysisMethodDefinition,
  AnalysisRunCommand,
  AnalysisRunResult,
  DerivedResultReviewCommand,
  DerivedResultReviewResult,
  PromotionCommand,
  ImpactPreview,
  ImpactAssessmentCommand,
  ImpactAssessmentResult,
  ImpactDispositionCommand,
  ImpactDispositionResult,
  StoredImpactAssessment,
  AssuranceWorkProduct,
  PromotionResult,
  StoredAnalysisRun,
  StoredPromotion
} from "./types";

const baseUrl = "http://localhost:4000";

async function ensureOk(response: Response, fallbackMessage: string): Promise<void> {
  if (!response.ok) {
    let detail = fallbackMessage;
    try {
      const payload = (await response.json()) as { message?: string; errors?: Array<string | { field?: string; message?: string }> };
      if (payload?.message) {
        detail = payload.message;
      } else if (payload?.errors?.length) {
        detail = payload.errors.map((error) =>
          typeof error === "string" ? error : `${error.field ? `${error.field}: ` : ""}${error.message ?? "invalid request"}`
        ).join("; ");
      }
    } catch {
      // ignore JSON parse failure
    }
    throw new Error(detail);
  }
}

export async function getGraph(): Promise<GraphData> {
  const response = await fetch(`${baseUrl}/graph`);
  await ensureOk(response, "Failed to load graph");
  return response.json();
}

export async function previewSystemModelImport(
  payload: SystemModelPreviewRequest
): Promise<SystemModelPreviewResult> {
  const response = await fetch(`${baseUrl}/api/v2/system-model/import/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  await ensureOk(response, "Failed to preview system model import");
  return response.json();
}

export async function commitSystemModelImport(
  payload: SystemModelCommitRequest
): Promise<SystemModelCommitResult> {
  const response = await fetch(`${baseUrl}/api/v2/system-model/import/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  await ensureOk(response, "Failed to commit system model import");
  return response.json();
}

export async function getSystemModel(projectId: string, revisionId: string): Promise<StoredSystemModel> {
  const query = new URLSearchParams({ project_id: projectId, revision_id: revisionId });
  const response = await fetch(`${baseUrl}/api/v2/system-model?${query.toString()}`);
  await ensureOk(response, "Failed to load system model");
  return response.json();
}

export async function getEngineeringCase(projectId: string, revisionId: string): Promise<StoredEngineeringCase> {
  const query = new URLSearchParams({ project_id: projectId, revision_id: revisionId });
  const response = await fetch(`${baseUrl}/api/v2/engineering-cases?${query.toString()}`);
  await ensureOk(response, "Failed to load engineering case");
  return response.json();
}

export async function recordReviewDecision(command: ReviewDecisionCommand): Promise<ReviewDecisionResult> {
  const response = await fetch(`${baseUrl}/api/v2/engineering-cases/review-decisions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(command)
  });
  await ensureOk(response, "Failed to record review decision");
  return response.json();
}

export async function getAnalysisMethods(): Promise<AnalysisMethodDefinition[]> {
  const response = await fetch(`${baseUrl}/api/v2/analysis/methods`);
  await ensureOk(response, "Failed to load analysis methods");
  const payload = await response.json() as { methods: AnalysisMethodDefinition[] };
  return payload.methods;
}

export async function getAnalysisRuns(projectId: string, revisionId: string): Promise<StoredAnalysisRun[]> {
  const query = new URLSearchParams({ project_id: projectId, revision_id: revisionId });
  const response = await fetch(`${baseUrl}/api/v2/analysis/runs?${query.toString()}`);
  await ensureOk(response, "Failed to load analysis runs");
  const payload = await response.json() as { runs: StoredAnalysisRun[] };
  return payload.runs;
}

export async function getAnalysisPromotions(projectId: string, revisionId: string): Promise<StoredPromotion[]> {
  const query = new URLSearchParams({ project_id: projectId, revision_id: revisionId });
  const response = await fetch(`${baseUrl}/api/v2/analysis/promotions?${query.toString()}`);
  await ensureOk(response, "Failed to load analysis promotions");
  const payload = await response.json() as { promotions: StoredPromotion[] };
  return payload.promotions;
}

export async function createAnalysisRun(command: AnalysisRunCommand): Promise<AnalysisRunResult> {
  const response = await fetch(`${baseUrl}/api/v2/analysis/runs`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(command)
  });
  await ensureOk(response, "Failed to create analysis run");
  return response.json();
}

export async function reviewDerivedResult(command: DerivedResultReviewCommand): Promise<DerivedResultReviewResult> {
  const response = await fetch(`${baseUrl}/api/v2/analysis/derived-results/review-decisions`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(command)
  });
  await ensureOk(response, "Failed to review derived result");
  return response.json();
}

export async function promoteDerivedResult(command: PromotionCommand): Promise<PromotionResult> {
  const response = await fetch(`${baseUrl}/api/v2/analysis/promotions`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(command)
  });
  await ensureOk(response, "Failed to promote derived result");
  return response.json();
}

function traceabilityQuery(input: TraceabilityReportQuery): string {
  const query = new URLSearchParams({ project_id: input.project_id });
  if (input.revision_id) query.set("revision_id", input.revision_id);
  if (input.baseline_id) query.set("baseline_id", input.baseline_id);
  return query.toString();
}

export async function getTraceabilityReport(
  input: TraceabilityReportQuery,
  actor: string
): Promise<TraceabilityReport> {
  const response = await fetch(`${baseUrl}/api/v2/traceability/report?${traceabilityQuery(input)}`, {
    headers: { "x-user-id": actor }
  });
  await ensureOk(response, "Failed to load traceability report");
  return response.json();
}

export async function exportTraceabilityReport(input: TraceabilityReportQuery, actor: string): Promise<void> {
  const response = await fetch(`${baseUrl}/api/v2/traceability/report/export?${traceabilityQuery(input)}`, {
    headers: { "x-user-id": actor }
  });
  await ensureOk(response, "Failed to export traceability report");
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = disposition.match(/filename="([^"]+)"/)?.[1] ?? "astra-traceability-report.json";
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export async function freezeRevision(
  command: FreezeRevisionCommand
): Promise<{ value: NonNullable<TraceabilityReport["context"]["baseline"]>; replayed: boolean }> {
  const response = await fetch(`${baseUrl}/api/v2/governance/revisions/freeze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(command)
  });
  await ensureOk(response, "Failed to freeze revision");
  return response.json();
}

export async function previewChangeImpact(input: {
  project_id: string;
  from: { revision_id?: string; baseline_id?: string };
  to: { revision_id?: string; baseline_id?: string };
}): Promise<ImpactPreview> {
  const response = await fetch(`${baseUrl}/api/v2/impact-assessments/preview`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input)
  });
  await ensureOk(response, "Failed to preview change impact");
  return response.json();
}

export async function createChangeImpactAssessment(command: ImpactAssessmentCommand): Promise<ImpactAssessmentResult> {
  const response = await fetch(`${baseUrl}/api/v2/impact-assessments`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(command)
  });
  await ensureOk(response, "Failed to create change impact assessment");
  return response.json();
}

export async function getChangeImpactAssessments(projectId: string, revisionId: string): Promise<StoredImpactAssessment[]> {
  const query = new URLSearchParams({ project_id: projectId, revision_id: revisionId });
  const response = await fetch(`${baseUrl}/api/v2/impact-assessments?${query}`);
  await ensureOk(response, "Failed to load change impact assessments");
  return (await response.json() as { assessments: StoredImpactAssessment[] }).assessments;
}

export async function recordImpactDisposition(command: ImpactDispositionCommand): Promise<ImpactDispositionResult> {
  const response = await fetch(`${baseUrl}/api/v2/impact-assessments/dispositions`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(command)
  });
  await ensureOk(response, "Failed to record impact disposition");
  return response.json();
}

function workProductQuery(input: { project_id: string; revision_id?: string; baseline_id?: string; actor: string }): string {
  const query = new URLSearchParams({ project_id: input.project_id, actor: input.actor });
  if (input.revision_id) query.set("revision_id", input.revision_id);
  if (input.baseline_id) query.set("baseline_id", input.baseline_id);
  return query.toString();
}

export async function getAssuranceWorkProduct(input: { project_id: string; revision_id?: string; baseline_id?: string; actor: string }): Promise<AssuranceWorkProduct> {
  const response = await fetch(`${baseUrl}/api/v2/impact-assessments/work-product?${workProductQuery(input)}`);
  await ensureOk(response, "Failed to generate assurance work product");
  return response.json();
}

export async function exportAssuranceWorkProduct(input: { project_id: string; revision_id?: string; baseline_id?: string; actor: string }): Promise<void> {
  const response = await fetch(`${baseUrl}/api/v2/impact-assessments/work-product/export?${workProductQuery(input)}`);
  await ensureOk(response, "Failed to export assurance work product");
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = disposition.match(/filename="([^"]+)"/)?.[1] ?? "astra-assurance-work-product.json";
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export async function validateChangeSet(changeSet: GraphChangeSet): Promise<{ valid: boolean; errors: string[] }> {
  const response = await fetch(`${baseUrl}/graph/changeset/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changeSet)
  });
  await ensureOk(response, "Failed to validate changeset");
  return response.json();
}

export async function commitChangeSet(
  changeSet: GraphChangeSet
): Promise<{ committed: boolean; commit_id?: string; new_version?: string; errors?: string[] }> {
  const response = await fetch(`${baseUrl}/graph/changeset/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify(changeSet)
  });
  await ensureOk(response, "Failed to commit changeset");
  return response.json();
}

export async function previewCxfImport(payload: CxfImportRequest): Promise<CxfImportPreviewResult> {
  const response = await fetch(`${baseUrl}/imports/cxf-asset-inventory/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return (await response.json()) as CxfImportPreviewResult;
}

export async function commitCxfImport(payload: CxfImportRequest): Promise<CxfImportCommitResult> {
  const response = await fetch(`${baseUrl}/imports/cxf-asset-inventory/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify(payload)
  });
  return (await response.json()) as CxfImportCommitResult;
}

export async function previewF3532InputImport(payload: F3532InputImportRequest): Promise<F3532InputImportPreviewResult> {
  const response = await fetch(`${baseUrl}/imports/f3532-input/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return (await response.json()) as F3532InputImportPreviewResult;
}

export async function commitF3532InputImport(payload: F3532InputImportRequest): Promise<F3532InputImportCommitResult> {
  const response = await fetch(`${baseUrl}/imports/f3532-input/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify(payload)
  });
  return (await response.json()) as F3532InputImportCommitResult;
}

export async function previewFhaImport(payload: FhaImportRequest): Promise<{
  ok: boolean;
  count?: number;
  severity_counts?: Record<string, number>;
  errors: string[];
}> {
  const response = await fetch(`${baseUrl}/imports/fha/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return response.json();
}

export async function commitFhaImport(payload: FhaImportRequest): Promise<{
  committed: boolean;
  imported?: number;
  linked_sdf_count?: number;
  linked_bdf_count?: number;
  unlinked_failure_condition_ids?: string[];
  errors?: string[];
}> {
  const response = await fetch(`${baseUrl}/imports/fha/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify(payload)
  });
  return response.json();
}

export async function getFailureConditions(): Promise<{ count: number; rows: FailureCondition[] }> {
  const response = await fetch(`${baseUrl}/fha/failure-conditions`);
  await ensureOk(response, "Failed to load FHA failure conditions");
  return response.json();
}

export async function getF353204Defaults(): Promise<F353204Defaults> {
  const response = await fetch(`${baseUrl}/analysis/f3532/04/defaults`);
  await ensureOk(response, "Failed to load F3532 04 defaults");
  return response.json();
}

export async function generateF353204(options: {
  cia_mode: "single" | "all_non_empty";
  include_unlinked_failure_conditions?: boolean;
}): Promise<F353204GenerationResult> {
  const response = await fetch(`${baseUrl}/analysis/f3532/generate-04`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options)
  });
  await ensureOk(response, "Failed to generate F3532 04");
  return response.json();
}

export async function commitF353204(
  threat_conditions: ThreatCondition[],
  threat_scenarios: ThreatScenario[]
): Promise<{ committed: boolean; threat_condition_count?: number; threat_scenario_count?: number; errors?: string[] }> {
  const response = await fetch(`${baseUrl}/analysis/f3532/commit-04`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify({ threat_conditions, threat_scenarios })
  });
  return response.json();
}

export async function getF353204Report(): Promise<{
  threat_condition_count: number;
  threat_scenario_count: number;
  threat_conditions: ThreatCondition[];
  threat_scenarios: ThreatScenario[];
}> {
  const response = await fetch(`${baseUrl}/reports/f3532/04`);
  await ensureOk(response, "Failed to load F3532 04 report");
  return response.json();
}

export async function runAnalysis(payload?: {
  analysis_batch_id?: string;
  max_hops?: number;
  generated_by?: string;
  scope_asset_ids?: string[];
  dps_hop_decay?: number;
}): Promise<{ count: number; paths: AttackPath[] }> {
  const response = await fetch(`${baseUrl}/analysis/attack-paths/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      analysis_batch_id: payload?.analysis_batch_id ?? `batch-${Date.now()}`,
      max_hops: payload?.max_hops ?? 3,
      generated_by: payload?.generated_by ?? "frontend-user",
      scope_asset_ids: payload?.scope_asset_ids,
      dps_hop_decay: payload?.dps_hop_decay
    })
  });
  await ensureOk(response, "Failed to run attack path analysis");
  return response.json();
}

export async function seedSampleData(): Promise<{
  seeded: boolean;
  commit_id: string;
  new_version: string;
  counts: { asset_nodes: number; asset_edges: number; threat_points: number; do326a_links: number };
}> {
  const response = await fetch(`${baseUrl}/admin/seed/sample`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-seed" }
  });
  await ensureOk(response, "Failed to seed sample data");
  return response.json();
}

export async function seedGenericData(): Promise<{
  seeded: boolean;
  commit_id: string;
  new_version: string;
  counts: { asset_nodes: number; asset_edges: number; threat_points: number; do326a_links: number };
}> {
  const response = await fetch(`${baseUrl}/admin/seed/generic`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-generic-seed" }
  });
  await ensureOk(response, "Failed to seed generic example data");
  return response.json();
}

export async function persistPaths(paths: AttackPath[]): Promise<{ persisted: number }> {
  const response = await fetch(`${baseUrl}/analysis/attack-paths/persist`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ paths })
  });
  await ensureOk(response, "Failed to persist paths");
  return response.json();
}

export async function getTrustBoundaryReport(): Promise<{ count: number; rows: TrustBoundaryReportRow[] }> {
  const response = await fetch(`${baseUrl}/reports/chapter4/trust-boundaries`);
  await ensureOk(response, "Failed to load trust boundary report");
  return response.json();
}

export async function getBoundaryDataFlowReport(): Promise<{ count: number; rows: BoundaryDataFlowReportRow[] }> {
  const response = await fetch(`${baseUrl}/reports/chapter4/boundary-data-flows`);
  await ensureOk(response, "Failed to load boundary data flow report");
  return response.json();
}

export async function getFunctionPropagationReport(): Promise<{ count: number; rows: FunctionPropagationReportRow[] }> {
  const response = await fetch(`${baseUrl}/reports/chapter4/function-propagation`);
  await ensureOk(response, "Failed to load function propagation report");
  return response.json();
}

export async function getInternalDataFlowReport(): Promise<{ count: number; rows: InternalDataFlowReportRow[] }> {
  const response = await fetch(`${baseUrl}/reports/chapter4/internal-data-flows`);
  await ensureOk(response, "Failed to load internal data flow report");
  return response.json();
}

export type FpGroupBy = "function" | "boundary" | "type";

export async function runFunctionPropagationAnalysis(
  options?: { groupBy?: FpGroupBy; maxHops?: number }
): Promise<{ count: number; fp_count: number; rows: FunctionPropagationReportRow[] }> {
  const body: Record<string, unknown> = {};
  if (options?.groupBy) {
    body.group_by = options.groupBy;
  }
  if (options?.maxHops) {
    body.max_hops = options.maxHops;
  }
  const response = await fetch(`${baseUrl}/analysis/function-propagation/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  await ensureOk(response, "Failed to run function propagation analysis");
  return response.json();
}

export async function runF3532Generate03(
  options?: { groupBy?: FpGroupBy; maxHops?: number }
): Promise<F3532Report03Data> {
  const body: Record<string, unknown> = {};
  if (options?.groupBy) {
    body.group_by = options.groupBy;
  }
  if (options?.maxHops) {
    body.max_hops = options.maxHops;
  }
  const response = await fetch(`${baseUrl}/analysis/f3532/generate-03/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  await ensureOk(response, "Failed to generate F3532 03");
  return response.json();
}

export async function commitF353203(options: {
  expectedGraphVersion: string;
  maxHops?: number;
}): Promise<F3532Report03Data> {
  const response = await fetch(`${baseUrl}/analysis/f3532/generate-03/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      expected_graph_version: options.expectedGraphVersion,
      max_hops: options.maxHops
    })
  });
  await ensureOk(response, "Failed to commit F3532 03");
  return response.json();
}

export async function getF3532Report03(): Promise<F3532Report03Data> {
  const response = await fetch(`${baseUrl}/reports/f3532/03`);
  await ensureOk(response, "Failed to load F3532 03 report");
  return response.json();
}

export async function getDo326aLinks(): Promise<{ count: number; links: DO326ALink[] }> {
  const response = await fetch(`${baseUrl}/compliance/do326a-links`);
  await ensureOk(response, "Failed to load DO326A links");
  return response.json();
}

export async function getF3532StandardSummary(): Promise<StandardKnowledgeSummary> {
  const response = await fetch(`${baseUrl}/standard/f3532/summary`);
  await ensureOk(response, "Failed to load F3532 standard summary");
  return response.json();
}

export async function getF3532Clauses(section?: string): Promise<{ count: number; clauses: StandardClause[] }> {
  const searchParams = new URLSearchParams();
  if (section) {
    searchParams.set("section", section);
  }
  const query = searchParams.toString();
  const response = await fetch(`${baseUrl}/standard/f3532/clauses${query ? `?${query}` : ""}`);
  await ensureOk(response, "Failed to load F3532 clauses");
  return response.json();
}

export async function getF3532Artifacts(): Promise<{ count: number; artifacts: StandardArtifactType[] }> {
  const response = await fetch(`${baseUrl}/standard/f3532/artifacts`);
  await ensureOk(response, "Failed to load F3532 artifacts");
  return response.json();
}

export async function getF3532Mappings(): Promise<{ count: number; mappings: StandardMapping[] }> {
  const response = await fetch(`${baseUrl}/standard/f3532/mappings`);
  await ensureOk(response, "Failed to load F3532 mappings");
  return response.json();
}

export async function createOrUpdateF3532Mapping(mapping: StandardMapping): Promise<{ created: boolean; mapping: StandardMapping }> {
  const response = await fetch(`${baseUrl}/standard/f3532/mappings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(mapping)
  });
  await ensureOk(response, "Failed to save F3532 mapping");
  return response.json();
}

export async function exportModelingResult(analysis_batch_id?: string): Promise<ModelingExportData> {
  const searchParams = new URLSearchParams();
  if (analysis_batch_id && analysis_batch_id.trim().length > 0) {
    searchParams.set("analysis_batch_id", analysis_batch_id.trim());
  }

  const query = searchParams.toString();
  const response = await fetch(`${baseUrl}/exports/modeling-result${query ? `?${query}` : ""}`);
  await ensureOk(response, "Failed to export modeling result");
  return response.json();
}

export async function createOrUpdateDo326aLink(link: DO326ALink): Promise<{ created: boolean; link: DO326ALink }> {
  const response = await fetch(`${baseUrl}/compliance/do326a-links`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(link)
  });
  await ensureOk(response, "Failed to save DO326A link");
  return response.json();
}

export async function reviewDo326aLink(
  link_id: string,
  review_status: ReviewStatus,
  reviewer?: string
): Promise<{ updated: boolean; link: DO326ALink }> {
  const response = await fetch(`${baseUrl}/compliance/do326a-links/${link_id}/review`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ review_status, reviewer })
  });
  await ensureOk(response, "Failed to update review status");
  return response.json();
}


export async function previewFeatureRules(payload: Record<string, unknown>): Promise<import("./types").FeaturePreviewResult> {
  let response: Response;
  try {
    response = await fetch(`${baseUrl}/analysis/feature-rules/preview`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload)
    });
  } catch {
    throw new Error("无法连接后端，请确认 4000 端口的服务已启动。输入已保留，可稍后重试。");
  }
  if (!response.ok) {
    const detail = await response.json().catch(() => ({})) as { message?: string; issues?: Array<{ path: Array<string | number>; message: string }> };
    const issues = detail.issues?.slice(0, 8).map(x => `${x.path.join(".") || "数据包"}：${x.message}`).join("；");
    throw new Error(issues || detail.message || `预览失败（${response.status}），请检查输入或后端状态。`);
  }
  return response.json();
}
