import { createHash } from "node:crypto";

export type LegacyDatasetKind = "generic-legacy" | "do356a-appendix-d";
export type DetectedLegacyDatasetKind = LegacyDatasetKind | "unknown";

export interface LegacyContextConfig {
  dataset_kind: LegacyDatasetKind;
  project: { business_id: string; name: string; description: string };
  model: { business_id: string; name: string; level: string };
  revision: { business_id: string };
  standard_profile: {
    business_id: string;
    name: string;
    profile_version: string;
    standard_references: string[];
  };
}

export interface LegacyEntityDefinition {
  label: string;
  key: string;
  source_required: boolean;
}

export const legacyEntityDefinitions: LegacyEntityDefinition[] = [
  { label: "AssetNode", key: "asset_id", source_required: true },
  { label: "FunctionNode", key: "function_id", source_required: true },
  { label: "TrustBoundary", key: "boundary_id", source_required: true },
  { label: "BoundaryInterface", key: "interface_id", source_required: true },
  { label: "SystemDataFlow", key: "sdf_id", source_required: true },
  { label: "ThreatActor", key: "actor_id", source_required: true },
  { label: "FunctionPropagationPath", key: "fp_id", source_required: true },
  { label: "ThreatPoint", key: "threatpoint_id", source_required: true },
  { label: "AttackPath", key: "path_id", source_required: true },
  { label: "FailureCondition", key: "failure_condition_id", source_required: true },
  { label: "ThreatCondition", key: "tc_id", source_required: true },
  { label: "ThreatScenario", key: "ts_id", source_required: true },
  { label: "DO326A_Link", key: "link_id", source_required: true },
  { label: "StandardMapping", key: "mapping_id", source_required: true },
  { label: "CommitAudit", key: "commit_id", source_required: false },
];

export const nonProjectLabels = [
  "MigrationRecord",
  "Project",
  "Model",
  "Revision",
  "Baseline",
  "StandardProfileVersion",
  "AuditEvent",
  "MigrationIssue",
  "LegacyAttachmentRun",
  "GraphVersion",
  "StandardKnowledgeBase",
  "StandardClause",
  "StandardArtifactType",
  "StandardArtifactField",
  "StandardPipelineStage",
];

export interface LegacyInventoryEntry {
  label: string;
  total: number;
  attachable: number;
  fully_scoped: number;
  scope_conflicts: number;
  missing_legacy_id: number;
  missing_source_locator: number;
}

export interface LegacyMigrationIssueCandidate {
  issue_key: string;
  issue_type:
    | "DATASET_CLASSIFICATION_MISMATCH"
    | "UNKNOWN_SCHEMA"
    | "SCOPE_CONFLICT"
    | "DUPLICATE_LEGACY_ID"
    | "MISSING_LEGACY_ID"
    | "MISSING_SOURCE_LOCATOR";
  severity: "High" | "Medium" | "Low";
  blocking: boolean;
  subject_label: string;
  affected_count: number;
  subject_keys: string[];
  message: string;
  candidate_actions: string[];
}

export interface LegacyAttachmentPlan {
  migration_id: "P1.3_LEGACY_ATTACHMENT";
  requested_dataset_kind: LegacyDatasetKind;
  detected_dataset_kind: DetectedLegacyDatasetKind;
  context: LegacyContextConfig;
  inventory: LegacyInventoryEntry[];
  issues: LegacyMigrationIssueCandidate[];
  summary: {
    known_entities: number;
    attachable_entities: number;
    fully_scoped_entities: number;
    blocking_issue_count: number;
    non_blocking_issue_count: number;
  };
  plan_hash: string;
  blocked: boolean;
}

export interface LegacyAttachmentResult {
  run_id: string;
  command_id: string;
  dataset_kind: LegacyDatasetKind;
  project_id: string;
  model_id: string;
  revision_id: string;
  standard_profile_version_id: string;
  attached_count: number;
  issue_count: number;
  plan_hash: string;
  replayed: boolean;
}

export interface LegacyAttachmentVerification {
  ok: boolean;
  context: {
    project_id?: string;
    model_id?: string;
    revision_id?: string;
    standard_profile_version_id?: string;
  };
  attached_count: number;
  open_issue_count: number;
  diagnostics: string[];
}

const contexts: Record<LegacyDatasetKind, LegacyContextConfig> = {
  "generic-legacy": {
    dataset_kind: "generic-legacy",
    project: {
      business_id: "legacy-unclassified",
      name: "Generic Legacy Migration",
      description: "Controlled context for legacy data with no project-specific classification",
    },
    model: {
      business_id: "legacy-primary-model",
      name: "Generic Legacy Primary Model",
      level: "system",
    },
    revision: { business_id: "legacy-import-r1" },
    standard_profile: {
      business_id: "legacy-do326a-do356a",
      name: "Legacy DO-326A / DO-356A Profile",
      profile_version: "legacy-unversioned",
      standard_references: ["DO-326A", "DO-356A"],
    },
  },
  "do356a-appendix-d": {
    dataset_kind: "do356a-appendix-d",
    project: {
      business_id: "legacy-do356a-appendix-d",
      name: "DO-356A Appendix D Legacy Sample",
      description: "Controlled project for the repository DO-356A Appendix D sample dataset",
    },
    model: {
      business_id: "appendix-d-ams-model",
      name: "Appendix D Air Management System",
      level: "system",
    },
    revision: { business_id: "legacy-import-r1" },
    standard_profile: {
      business_id: "do356a-appendix-d",
      name: "DO-356A Appendix D Legacy Profile",
      profile_version: "legacy-unversioned",
      standard_references: ["DO-356A"],
    },
  },
};

export function resolveLegacyContext(datasetKind: LegacyDatasetKind): LegacyContextConfig {
  return structuredClone(contexts[datasetKind]);
}

export function stableIssueKey(input: {
  datasetKind: LegacyDatasetKind;
  issueType: LegacyMigrationIssueCandidate["issue_type"];
  subjectLabel: string;
  subjectKeys?: string[];
}): string {
  const identity = [
    "p1.3",
    input.datasetKind,
    input.issueType,
    input.subjectLabel,
    ...(input.subjectKeys ?? []).slice().sort(),
  ].join("|");
  return createHash("sha256").update(identity, "utf8").digest("hex");
}

export function legacyPlanHash(plan: Omit<LegacyAttachmentPlan, "plan_hash">): string {
  return createHash("sha256").update(JSON.stringify(plan), "utf8").digest("hex");
}
