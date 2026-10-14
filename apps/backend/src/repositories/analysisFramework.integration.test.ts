import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import {
  analysisRunCommandSchema,
  derivedResultReviewCommandSchema,
  promotionCommandSchema,
  reviewDecisionCommandSchema,
  systemModelCommitRequestSchema,
} from "@attackgraph/contracts";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { GovernanceRepository } from "./governanceRepository.js";
import { AnalysisRepository, AnalysisScopeError } from "./analysisRepository.js";
import { AnalysisServiceV2 } from "../services/analysisServiceV2.js";
import { EngineeringCaseService } from "../services/engineeringCaseService.js";
import { SystemModelImportService } from "../services/systemModelImportService.js";
import { TraceabilityReportService } from "../services/traceabilityReportService.js";
import { CommandPayloadMismatchError } from "../services/governance/commandReceipt.js";
import { fixture } from "../services/featureRules/testFixture.js";

const projects: string[] = [];

after(async () => {
  if (projects.length > 0) {
    const session = getDriver().session();
    try {
      await session.run("MATCH (node) WHERE node.project_id IN $ids OR (node:Project AND node.id IN $ids) DETACH DELETE node", { ids: projects });
    } finally {
      await session.close();
    }
  }
  await closeDriver();
});

function topologyInput() {
  const featureInput = fixture();
  featureInput.assets[0].prototype_asset_id = "P-A" as never;
  featureInput.evidence.push({ ...featureInput.evidence[0], evidence_id: "MAP-E" });
  return {
    feature_input: featureInput,
    graph: {
      graph_version: "MODEL-SNAPSHOT-1",
      asset_nodes: [{ asset_id: "P-A" }, { asset_id: "P-B" }, { asset_id: "P-C" }],
      asset_edges: [
        { edge_id: "EDGE-1", source_asset_id: "P-A", target_asset_id: "P-B", direction: "Unidirectional" },
        { edge_id: "EDGE-2", source_asset_id: "P-B", target_asset_id: "P-C", direction: "Unidirectional" },
      ],
    },
    mappings: [{ scope_id: "SCOPE", allowed_edge_ids: ["EDGE-1", "EDGE-2"], target_asset_ids: ["P-C"], evidence_refs: ["MAP-E"] }],
    options: { max_hops: 3 },
  };
}

test("Phase 4 reproduces, reviews and promotes a topology result without laundering its origin", async () => {
  const suffix = randomUUID();
  const governance = new GovernanceRepository();
  const workspace = await governance.createProjectWorkspace({
    actor: "phase4-integration", command_id: `p4:${suffix}:workspace`,
    project: { business_id: `P4-${suffix}`, name: "Phase 4 integration" },
    model: { business_id: "MODEL-1", name: "System", level: "system" },
    revision: { business_id: "REV-1" },
    standard_profile: {
      business_id: "PROFILE-326A-356A", name: "DO-326A / DO-356A",
      profile_version: "phase4-test", standard_references: ["DO-326A", "DO-356A"],
    },
  });
  projects.push(workspace.project.id);
  const importer = new SystemModelImportService();
  const imported = await importer.commit(systemModelCommitRequestSchema.parse({
    actor: "phase4-integration", command_id: `p4:${suffix}:import`, project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: 1,
    import: {
      contract_version: "system-model.v2",
      source: { business_id: "SOURCE-P4", source_type: "controlled-example", name: "Phase 4 input", content_hash: "4".repeat(64), parser_name: "test", parser_version: "1" },
      entities: {
        assets: ["P-A", "P-B", "P-C"].map((business_id) => ({ business_id, name: business_id, category: "System" })),
        functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [],
        evidence_records: [{ business_id: "EVID-EDGE", evidence_type: "test", title: "Edge validation", reference: "fixture://phase4" }],
        draft_threats: [], trace_links: [],
      },
    },
  }));

  const service = new AnalysisServiceV2();
  const runCommand = analysisRunCommandSchema.parse({
    actor: "phase4-analyst", command_id: `p4:${suffix}:run-1`, project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: imported.new_revision_version,
    source_record_business_id: "SOURCE-P4", method_id: "feature-topology-trace", method_version: "0.1.0",
    method_config_version: "1", execution_limits: { max_hops: 3 }, method_config: { policy: "explicit-only" },
    method_input: topologyInput(),
  });
  const run1 = await service.run(runCommand);
  assert.equal((await service.run(runCommand)).replayed, true);
  await assert.rejects(
    () => service.run({ ...runCommand, method_config: { policy: "changed" } }),
    CommandPayloadMismatchError,
  );
  const run2 = await service.run({ ...runCommand, command_id: `p4:${suffix}:run-2`, expected_revision_version: run1.new_revision_version });
  assert.equal(run2.result_summary_hash, run1.result_summary_hash);

  const repository = new AnalysisRepository();
  const storedRun = (await repository.readRuns(workspace.project.id, workspace.revision.id, run1.run_id))[0];
  const candidate = storedRun.results.find((item) => item.result_kind === "topology_candidate");
  assert.ok(candidate);
  assert.deepEqual((candidate.payload as { paths: Array<{ edge_ids: string[] }> }).paths[0].edge_ids, ["EDGE-1", "EDGE-2"]);

  const reviewed = await service.review(derivedResultReviewCommandSchema.parse({
    actor: "human-reviewer-a", command_id: `p4:${suffix}:review-a`, project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: run2.new_revision_version,
    review: { business_id: "REVIEW-A", derived_result_id: candidate.id, subject_version: candidate.revision_version,
      decision: "Accept", rationale: "Candidate is relevant for engineering assessment", reviewer_role: "Analysis Reviewer" },
  }));
  const promotion = {
    business_id: "PROMOTION-1", derived_result_id: candidate.id, target_type: "AttackPath" as const,
    target_business_id: "AP-DRAFT-1", target_name: "Reviewed topology candidate", target_payload: { ordered_edge_ids: ["EDGE-1", "EDGE-2"] },
    rationale: "Create a controlled engineering draft", feasibility_rationale: "Both directed segments are feasible in the assessed configuration",
    segment_validations: [] as Array<{ edge_id: string; semantic_rationale: string; evidence_record_business_ids: string[] }>,
  };
  await assert.rejects(
    () => service.promote(promotionCommandSchema.parse({ actor: "promoter", command_id: `p4:${suffix}:invalid-promotion`,
      project_id: workspace.project.id, revision_id: workspace.revision.id, expected_revision_version: reviewed.new_revision_version, promotion })),
    AnalysisScopeError,
  );
  const promoted = await service.promote(promotionCommandSchema.parse({
    actor: "promoter", command_id: `p4:${suffix}:promotion`, project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: reviewed.new_revision_version,
    promotion: { ...promotion, segment_validations: [
      { edge_id: "EDGE-1", semantic_rationale: "Validated producer-to-consumer direction", evidence_record_business_ids: ["EVID-EDGE"] },
      { edge_id: "EDGE-2", semantic_rationale: "Validated downstream reachability", evidence_record_business_ids: ["EVID-EDGE"] },
    ] },
  }));
  const reviewB = await new EngineeringCaseService().review(reviewDecisionCommandSchema.parse({
    actor: "human-reviewer-b", command_id: `p4:${suffix}:review-b`, project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: promoted.new_revision_version,
    review: { business_id: "REVIEW-B", subject: { type: "AttackPath", business_id: "AP-DRAFT-1", version: promoted.new_revision_version },
      decision: "Approve", rationale: "Engineering evidence supports the promoted draft", reviewer_role: "Engineering Approver" },
  }));
  const report = await new TraceabilityReportService().generate({ project_id: workspace.project.id, revision_id: workspace.revision.id }, "reporter");
  assert.equal(report.analysis_runs.length, 2);
  assert.equal(report.promotions[0].origin, "analysis_promotion");
  assert.equal(report.promotions[0].source_topology_only, true);
  assert.equal(report.promotions[0].target_status, "Approved");
  assert.ok(report.chains.some((chain) => chain.link_type === "DERIVED_FROM" && chain.source.business_id === "AP-DRAFT-1"));

  await importer.commit(systemModelCommitRequestSchema.parse({
    actor: "phase4-integration", command_id: `p4:${suffix}:upstream-change`, project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: reviewB.new_revision_version,
    import: {
      contract_version: "system-model.v2",
      source: { business_id: "SOURCE-P4-CHANGE", source_type: "controlled-example", name: "Upstream change", content_hash: "5".repeat(64), parser_name: "test", parser_version: "1" },
      entities: { assets: [], functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [], evidence_records: [], draft_threats: [], trace_links: [] },
    },
  }));
  assert.equal((await repository.readRuns(workspace.project.id, workspace.revision.id, run1.run_id))[0].stale, true);
});
