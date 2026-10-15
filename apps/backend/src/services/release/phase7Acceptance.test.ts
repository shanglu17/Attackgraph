import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { appendixDGoldenCounts, createPhase7ReleaseEvidence, type Phase7Observations } from "./phase7Acceptance.js";

function observations(): Phase7Observations {
  return {
    scope: { project_id: "project", model_id: "model", revision_id: "revision", revision_version: 4 },
    migrations: [{ id: "0015_release_acceptance", status: "applied", checksum: "a".repeat(64) }],
    attached_legacy_nodes: 27, unscoped_legacy_nodes: 0, cross_project_relationships: 0,
    open_migration_issues: 0, open_high_risk_issues: 0,
    provenance_source_count: 1, provenance_link_count: 26, unaudited_review_decisions: 0,
    direct_counts: { ...appendixDGoldenCounts }, compatibility_counts: { ...appendixDGoldenCounts },
    backup: { node_count: 32, relationship_count: 50, semantic_hash: "b".repeat(64) },
  };
}

const recovery = {
  ok: true as const, project_id: "temporary", deleted_nodes: 5,
  restored_nodes: 5, restored_relationships: 8, semantic_hash: "c".repeat(64),
};

describe("Phase 7 technical release evidence", () => {
  it("passes only when M0-M6 evidence and Appendix D Golden counts agree", () => {
    const report = createPhase7ReleaseEvidence({
      release_id: "R1", generated_at: "2026-10-15T00:00:00.000Z", generated_by: "test",
      observations: observations(), recovery_drill: recovery,
    });
    assert.equal(report.overall_status, "passed");
    assert.equal(report.checks.length, 7);
    assert.ok(report.checks.every((item) => item.status === "pass"));
    assert.match(report.evidence_hash, /^[a-f0-9]{64}$/);
    assert.equal(report.human_release_authorization, "not_asserted");
  });

  it("fails closed on unexplained Golden drift or a high-risk migration issue", () => {
    const changed = observations();
    changed.compatibility_counts.asset_nodes += 1;
    changed.open_high_risk_issues = 1;
    const report = createPhase7ReleaseEvidence({
      release_id: "R2", generated_at: "2026-10-15T00:00:00.000Z", generated_by: "test",
      observations: changed, recovery_drill: recovery,
    });
    assert.equal(report.overall_status, "failed");
    assert.equal(report.checks.find((item) => item.id === "M5-DUAL-READ-GOLDEN")?.status, "fail");
    assert.equal(report.checks.find((item) => item.id === "M6-CUTOVER-ROLLBACK")?.status, "fail");
  });
});
