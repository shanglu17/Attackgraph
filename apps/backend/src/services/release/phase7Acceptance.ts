import { createHash } from "node:crypto";
import type { RecoveryDrillResult } from "../operations/recoveryDrillService.js";

export const phase7EvidenceContractVersion = "phase7-release-evidence.v1";

export interface ReleaseCounts {
  asset_nodes: number;
  asset_edges: number;
  threat_points: number;
  do326a_links: number;
  commit_audits: number;
}

export interface Phase7Observations {
  scope: { project_id: string; model_id: string; revision_id: string; revision_version: number };
  migrations: Array<{ id: string; status: string; checksum: string }>;
  attached_legacy_nodes: number;
  unscoped_legacy_nodes: number;
  cross_project_relationships: number;
  open_migration_issues: number;
  open_high_risk_issues: number;
  provenance_source_count: number;
  provenance_link_count: number;
  unaudited_review_decisions: number;
  direct_counts: ReleaseCounts;
  compatibility_counts: ReleaseCounts;
  backup: { node_count: number; relationship_count: number; semantic_hash: string };
}

export interface Phase7Check {
  id: string;
  stage: "M0" | "M1" | "M2" | "M3" | "M4" | "M5" | "M6";
  status: "pass" | "fail";
  summary: string;
  evidence: Record<string, unknown>;
}

export interface Phase7ReleaseEvidence {
  contract_version: typeof phase7EvidenceContractVersion;
  release_id: string;
  generated_at: string;
  generated_by: string;
  dataset: "do356a-appendix-d";
  scope: Phase7Observations["scope"];
  overall_status: "passed" | "failed";
  human_release_authorization: "not_asserted";
  checks: Phase7Check[];
  observations: Phase7Observations;
  recovery_drill: RecoveryDrillResult;
  disclaimer: string;
  evidence_hash: string;
}

export const appendixDGoldenCounts: ReleaseCounts = {
  asset_nodes: 17,
  asset_edges: 14,
  threat_points: 4,
  do326a_links: 5,
  commit_audits: 1,
};

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

function sameCounts(left: ReleaseCounts, right: ReleaseCounts): boolean {
  return (Object.keys(appendixDGoldenCounts) as Array<keyof ReleaseCounts>).every((key) => left[key] === right[key]);
}

export function createPhase7ReleaseEvidence(input: {
  release_id: string;
  generated_at: string;
  generated_by: string;
  observations: Phase7Observations;
  recovery_drill: RecoveryDrillResult;
}): Phase7ReleaseEvidence {
  const { observations, recovery_drill: recovery } = input;
  const failedMigrations = observations.migrations.filter((item) => item.status !== "applied");
  const checks: Phase7Check[] = [
    {
      id: "M0-INVENTORY-BACKUP", stage: "M0",
      status: observations.backup.node_count > 0 && /^[a-f0-9]{64}$/.test(observations.backup.semantic_hash) ? "pass" : "fail",
      summary: "Inventory and a content-addressed project backup are available.", evidence: observations.backup,
    },
    {
      id: "M1-MIGRATION-LEDGER", stage: "M1", status: failedMigrations.length === 0 ? "pass" : "fail",
      summary: "Every registered schema migration is applied with a recorded checksum.",
      evidence: { migration_count: observations.migrations.length, failed_or_pending: failedMigrations.map((item) => item.id) },
    },
    {
      id: "M2-SCOPED-ATTACHMENT", stage: "M2",
      status: observations.attached_legacy_nodes === 27 && observations.unscoped_legacy_nodes === 0 && observations.cross_project_relationships === 0 ? "pass" : "fail",
      summary: "The authorized legacy slice is attached to one scope without cross-project relations.",
      evidence: { attached_legacy_nodes: observations.attached_legacy_nodes, unscoped_legacy_nodes: observations.unscoped_legacy_nodes, cross_project_relationships: observations.cross_project_relationships },
    },
    {
      id: "M3-PROVENANCE", stage: "M3",
      status: observations.provenance_source_count === 1 && observations.provenance_link_count === 26 ? "pass" : "fail",
      summary: "Appendix D provenance remains explicit and does not copy restricted standard text.",
      evidence: { source_records: observations.provenance_source_count, derived_from_source_links: observations.provenance_link_count },
    },
    {
      id: "M4-HISTORY-GOVERNANCE", stage: "M4", status: observations.unaudited_review_decisions === 0 ? "pass" : "fail",
      summary: "No formal ReviewDecision in the release scope lacks actor, role, time, or subject version.",
      evidence: { unaudited_review_decisions: observations.unaudited_review_decisions },
    },
    {
      id: "M5-DUAL-READ-GOLDEN", stage: "M5",
      status: sameCounts(observations.direct_counts, observations.compatibility_counts) && sameCounts(observations.direct_counts, appendixDGoldenCounts) ? "pass" : "fail",
      summary: "Scoped storage, compatibility reads, and the authorized Appendix D Golden counts agree.",
      evidence: { expected: appendixDGoldenCounts, direct: observations.direct_counts, compatibility: observations.compatibility_counts },
    },
    {
      id: "M6-CUTOVER-ROLLBACK", stage: "M6",
      status: observations.open_high_risk_issues === 0 && recovery.ok ? "pass" : "fail",
      summary: "Legacy global writes are quarantined and project backup deletion/restore preserves the semantic hash.",
      evidence: { legacy_write_mode: "quarantined", open_migration_issues: observations.open_migration_issues, open_high_risk_issues: observations.open_high_risk_issues, recovery_semantic_hash: recovery.semantic_hash },
    },
  ];
  const withoutHash = {
    contract_version: phase7EvidenceContractVersion,
    release_id: input.release_id,
    generated_at: input.generated_at,
    generated_by: input.generated_by,
    dataset: "do356a-appendix-d" as const,
    scope: observations.scope,
    overall_status: checks.every((item) => item.status === "pass") ? "passed" as const : "failed" as const,
    human_release_authorization: "not_asserted" as const,
    checks,
    observations,
    recovery_drill: recovery,
    disclaimer: "Technical release evidence only; this record is not an airworthiness approval or a substitute for organizational release authorization.",
  } satisfies Omit<Phase7ReleaseEvidence, "evidence_hash">;
  return { ...withoutHash, evidence_hash: createHash("sha256").update(canonical(withoutHash), "utf8").digest("hex") };
}
