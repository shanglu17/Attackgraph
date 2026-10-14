import { z } from "zod";

const businessId = z.string().trim().min(1).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const uuid = z.string().uuid().transform((value) => value.toLowerCase());
const text = z.string().trim().min(1).max(4_000);

export const analysisContractVersion = "analysis-run.v1" as const;
export const analysisMethodIdSchema = z.enum([
  "feature-rule-preview",
  "feature-topology-trace",
  "dfs-dps-attack-path",
  "f3532-03-deterministic",
]);
export const analysisCompletenessSchema = z.enum(["complete", "partial", "unknown"]);
export const analysisTerminationSchema = z.enum([
  "completed", "search_space_exhausted", "hop_limit", "path_limit", "expansion_limit",
  "cancelled", "validation_error", "execution_error",
]);

export const executionLimitsSchema = z.object({
  max_hops: z.number().int().positive().max(100).optional(),
  max_paths: z.number().int().positive().max(10_000).optional(),
  max_expansions: z.number().int().positive().max(1_000_000).optional(),
  timeout_ms: z.number().int().positive().max(3_600_000).optional(),
}).strict().default({});

export const analysisRunCommandSchema = z.object({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  project_id: uuid,
  revision_id: uuid,
  expected_revision_version: z.number().int().positive(),
  source_record_business_id: businessId,
  method_id: analysisMethodIdSchema,
  method_version: z.string().trim().min(1).max(80),
  method_config_version: z.string().trim().min(1).max(80),
  rule_pack_version: z.string().trim().min(1).max(80).optional(),
  execution_limits: executionLimitsSchema,
  method_config: z.record(z.unknown()).default({}),
  method_input: z.unknown(),
});

export const analysisQuerySchema = z.object({
  project_id: uuid,
  revision_id: uuid,
  run_id: uuid.optional(),
});

export const derivedResultReviewCommandSchema = z.object({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  project_id: uuid,
  revision_id: uuid,
  expected_revision_version: z.number().int().positive(),
  review: z.object({
    business_id: businessId,
    derived_result_id: uuid,
    subject_version: z.number().int().positive(),
    decision: z.enum(["Accept", "Reject"]),
    rationale: text,
    reviewer_role: z.string().trim().min(1).max(160),
    supersedes_business_id: businessId.optional(),
  }),
});

export const promotionCommandSchema = z.object({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  project_id: uuid,
  revision_id: uuid,
  expected_revision_version: z.number().int().positive(),
  promotion: z.object({
    business_id: businessId,
    derived_result_id: uuid,
    target_type: z.enum(["ThreatPoint", "ThreatScenario", "AttackPath", "RiskAssessment"]),
    target_business_id: businessId,
    target_name: z.string().trim().min(1).max(300),
    target_payload: z.record(z.unknown()),
    rationale: text,
    supersedes_business_id: businessId.optional(),
    feasibility_rationale: text.optional(),
    segment_validations: z.array(z.object({
      edge_id: z.string().trim().min(1).max(300),
      semantic_rationale: text,
      evidence_record_business_ids: z.array(businessId).min(1).max(100),
    })).max(1_000).default([]),
  }),
});

export type AnalysisMethodId = z.infer<typeof analysisMethodIdSchema>;
export type AnalysisRunCommand = z.infer<typeof analysisRunCommandSchema>;
export type AnalysisQuery = z.infer<typeof analysisQuerySchema>;
export type DerivedResultReviewCommand = z.infer<typeof derivedResultReviewCommandSchema>;
export type PromotionCommand = z.infer<typeof promotionCommandSchema>;
export type AnalysisCompleteness = z.infer<typeof analysisCompletenessSchema>;
export type AnalysisTermination = z.infer<typeof analysisTerminationSchema>;

export interface AnalysisMethodDefinition {
  method_id: AnalysisMethodId;
  method_version: string;
  name: string;
  maturity: "experimental" | "qualified" | "deprecated";
  availability: "enabled" | "disabled" | "archived";
  input_contract_version: string;
  output_contract_version: string;
  canonicalizer_id: string;
  canonicalizer_version: string;
  implementation_artifact_digest: string;
  supported_result_kinds: string[];
  completeness_rule: string;
}

export interface StoredInputSnapshot {
  id: string;
  snapshot_type: "method_input" | "graph" | "mapping" | "method_config";
  content_hash: string;
  canonicalizer: string;
  payload: unknown;
}

export interface StoredDerivedResult {
  id: string;
  business_id: string;
  run_id: string;
  result_kind: string;
  machine_status: "Experimental" | "Candidate" | "Reviewed" | "Rejected" | "Promoted";
  result_hash: string;
  topology_only: boolean;
  completeness: AnalysisCompleteness;
  termination_reason: AnalysisTermination;
  truncated: boolean;
  diagnostics: Array<{ code: string; severity: "info" | "warning" | "error"; message: string }>;
  payload: unknown;
  revision_version: number;
  supersedes_result_id?: string;
}

export interface StoredAnalysisRun {
  id: string;
  business_id: string;
  project_id: string;
  revision_id: string;
  input_revision_version: number;
  standard_profile_version_id: string;
  standard_profile_version_business_id: string;
  source_record_business_id: string;
  method: AnalysisMethodDefinition;
  contract_version: typeof analysisContractVersion;
  method_config_version: string;
  rule_pack_version?: string;
  command_id: string;
  audit_event_id: string;
  started_at: string;
  completed_at: string;
  actor: string;
  status: "Completed" | "Failed";
  replayability: "reproducible" | "verifiable_only";
  result_summary_hash: string;
  execution_limits: z.infer<typeof executionLimitsSchema>;
  snapshots: StoredInputSnapshot[];
  results: StoredDerivedResult[];
  stale: boolean;
}

export interface AnalysisRunResult {
  contract_version: typeof analysisContractVersion;
  run_id: string;
  run_business_id: string;
  audit_event_id: string;
  new_revision_version: number;
  replayed: boolean;
  result_summary_hash: string;
  result_ids: string[];
}

export interface DerivedResultReviewResult {
  audit_event_id: string;
  new_revision_version: number;
  replayed: boolean;
  derived_result_id: string;
  machine_status: "Reviewed" | "Rejected";
}

export interface PromotionResult {
  audit_event_id: string;
  new_revision_version: number;
  replayed: boolean;
  promotion_id: string;
  core_entity_id: string;
  target_type: "ThreatPoint" | "ThreatScenario" | "AttackPath" | "RiskAssessment";
  target_business_id: string;
  status: "Draft";
}

export interface StoredPromotion {
  id: string;
  business_id: string;
  project_id: string;
  revision_id: string;
  derived_result_id: string;
  derived_result_business_id: string;
  run_id: string;
  run_business_id: string;
  core_entity_id: string;
  target_type: "ThreatPoint" | "ThreatScenario" | "AttackPath" | "RiskAssessment";
  target_business_id: string;
  target_name: string;
  target_status: string;
  origin: "analysis_promotion";
  source_topology_only: boolean;
  rationale: string;
  feasibility_rationale?: string;
  segment_validations: Array<{
    edge_id: string;
    semantic_rationale: string;
    evidence_record_business_ids: string[];
  }>;
  trace_link_business_id: string;
  revision_version: number;
  promoted_at: string;
  promoted_by: string;
}
