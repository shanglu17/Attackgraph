import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  analysisRunCommandSchema,
  derivedResultReviewCommandSchema,
  promotionCommandSchema,
  reviewDecisionCommandSchema,
  systemModelCommitRequestSchema,
} from "@attackgraph/contracts";
import { closeDriver } from "../db/neo4j.js";
import { GovernanceRepository } from "../repositories/governanceRepository.js";
import { AnalysisRepository } from "../repositories/analysisRepository.js";
import { AnalysisServiceV2 } from "../services/analysisServiceV2.js";
import { EngineeringCaseService } from "../services/engineeringCaseService.js";
import { SystemModelImportService } from "../services/systemModelImportService.js";
import { TraceabilityReportService } from "../services/traceabilityReportService.js";

const actor = "phase4-controlled-demo";

async function main() {
  const sourcePath = fileURLToPath(new URL("../../../../examples/phase4-feature-topology-input.json", import.meta.url));
  const sourceBytes = await readFile(sourcePath);
  const methodInput = JSON.parse(sourceBytes.toString("utf8"));
  const sourceHash = createHash("sha256").update(sourceBytes).digest("hex");
  const governance = new GovernanceRepository();
  const workspace = await governance.createProjectWorkspace({
    actor, command_id: "phase4-demo-v1:create-workspace",
    project: { business_id: "PHASE4-ANALYSIS-DEMO", name: "Phase 4 governed analysis demonstration" },
    model: { business_id: "P4-MODEL", name: "Phase 4 controlled system model", level: "system" },
    revision: { business_id: "P4-REVISION-001" },
    standard_profile: {
      business_id: "P4-PROFILE-326A-356A", name: "DO-326A / DO-356A Phase 4 profile",
      profile_version: "phase4.1.0", standard_references: ["DO-326A", "DO-356A"],
    },
  });
  const imported = await new SystemModelImportService().commit(systemModelCommitRequestSchema.parse({
    actor, command_id: "phase4-demo-v1:import-system-model", project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: 1,
    import: {
      contract_version: "system-model.v2",
      source: {
        business_id: "P4-SOURCE", source_type: "controlled-example", name: "Phase 4 feature topology input",
        content_hash: sourceHash, media_type: "application/json", parser_name: "phase4-controlled-fixture", parser_version: "1.0.0",
      },
      entities: {
        assets: [
          { business_id: "ASSET-A", name: "Controlled entry asset", category: "Interface" },
          { business_id: "ASSET-B", name: "Controlled target asset", category: "System" },
        ],
        functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [],
        evidence_records: [{ business_id: "EVID-EDGE", evidence_type: "analysis-evidence", title: "Directed segment validation", reference: "fixture://phase4/edge-a-b", content_hash: sourceHash }],
        draft_threats: [], trace_links: [],
      },
    },
  }));

  const analysis = new AnalysisServiceV2();
  const first = await analysis.run(analysisRunCommandSchema.parse({
    actor, command_id: "phase4-demo-v1:run-1", project_id: workspace.project.id, revision_id: workspace.revision.id,
    expected_revision_version: imported.new_revision_version, source_record_business_id: "P4-SOURCE",
    method_id: "feature-topology-trace", method_version: "0.1.0", method_config_version: "1.0.0",
    execution_limits: { max_hops: 3, max_paths: 20, max_expansions: 1000 },
    method_config: { mapping_policy: "explicit-only" }, method_input: methodInput,
  }));
  const replay = await analysis.run(analysisRunCommandSchema.parse({
    actor, command_id: "phase4-demo-v1:run-1", project_id: workspace.project.id, revision_id: workspace.revision.id,
    expected_revision_version: imported.new_revision_version, source_record_business_id: "P4-SOURCE",
    method_id: "feature-topology-trace", method_version: "0.1.0", method_config_version: "1.0.0",
    execution_limits: { max_hops: 3, max_paths: 20, max_expansions: 1000 },
    method_config: { mapping_policy: "explicit-only" }, method_input: methodInput,
  }));
  const second = await analysis.run(analysisRunCommandSchema.parse({
    actor, command_id: "phase4-demo-v1:run-2", project_id: workspace.project.id, revision_id: workspace.revision.id,
    expected_revision_version: first.new_revision_version, source_record_business_id: "P4-SOURCE",
    method_id: "feature-topology-trace", method_version: "0.1.0", method_config_version: "1.0.0",
    execution_limits: { max_hops: 3, max_paths: 20, max_expansions: 1000 },
    method_config: { mapping_policy: "explicit-only" }, method_input: methodInput,
  }));
  const repository = new AnalysisRepository();
  const stored = (await repository.readRuns(workspace.project.id, workspace.revision.id, first.run_id))[0];
  const candidate = stored.results.find((item) => item.result_kind === "topology_candidate");
  if (!candidate) throw new Error("controlled Phase 4 input did not produce a topology candidate");
  const reviewed = await analysis.review(derivedResultReviewCommandSchema.parse({
    actor: "phase4-human-reviewer-a", command_id: "phase4-demo-v1:review-a", project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: second.new_revision_version,
    review: { business_id: "P4-REVIEW-A", derived_result_id: candidate.id, subject_version: candidate.revision_version,
      decision: "Accept", rationale: "Candidate is suitable for controlled engineering assessment", reviewer_role: "Analysis Reviewer" },
  }));
  const promoted = await analysis.promote(promotionCommandSchema.parse({
    actor: "phase4-promoter", command_id: "phase4-demo-v1:promote", project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: reviewed.new_revision_version,
    promotion: {
      business_id: "P4-PROMOTION", derived_result_id: candidate.id, target_type: "AttackPath",
      target_business_id: "P4-ATTACK-PATH-DRAFT", target_name: "Controlled promoted attack path",
      target_payload: { ordered_edge_ids: ["EDGE-A-B"] }, rationale: "Promote the reviewed candidate as a core draft",
      feasibility_rationale: "The directed segment and operational context were reviewed",
      segment_validations: [{ edge_id: "EDGE-A-B", semantic_rationale: "Direction and reachability were reviewed", evidence_record_business_ids: ["EVID-EDGE"] }],
    },
  }));
  await new EngineeringCaseService().review(reviewDecisionCommandSchema.parse({
    actor: "phase4-human-reviewer-b", command_id: "phase4-demo-v1:review-b", project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: promoted.new_revision_version,
    review: { business_id: "P4-REVIEW-B", subject: { type: "AttackPath", business_id: "P4-ATTACK-PATH-DRAFT", version: promoted.new_revision_version },
      decision: "Approve", rationale: "Engineering evidence supports the core draft", reviewer_role: "Engineering Approver" },
  }));
  const report = await new TraceabilityReportService().generate({ project_id: workspace.project.id, revision_id: workspace.revision.id }, actor);
  console.log(JSON.stringify({
    project_id: workspace.project.id, revision_id: workspace.revision.id, run_id: first.run_id,
    deterministic_summary: first.result_summary_hash === second.result_summary_hash,
    command_replayed: replay.replayed, result_status: report.analysis_runs[0]?.results[0]?.machine_status,
    promotion_origin: report.promotions[0]?.origin, promoted_status: report.promotions[0]?.target_status,
    derived_from_visible: report.chains.some((chain) => chain.link_type === "DERIVED_FROM" && chain.source.business_id === "P4-ATTACK-PATH-DRAFT"),
  }, null, 2));
}

main().catch((error) => { console.error(error); process.exitCode = 1; }).finally(() => closeDriver());
