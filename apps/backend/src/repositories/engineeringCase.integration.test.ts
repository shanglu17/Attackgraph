import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import {
  engineeringCaseCommitRequestSchema,
  reviewDecisionCommandSchema,
  systemModelCommitRequestSchema,
} from "@attackgraph/contracts";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { GovernanceRepository } from "./governanceRepository.js";
import { EngineeringCaseRepository } from "./engineeringCaseRepository.js";
import { EngineeringCaseService } from "../services/engineeringCaseService.js";
import { SystemModelImportService } from "../services/systemModelImportService.js";
import { TraceabilityReportService } from "../services/traceabilityReportService.js";

const projects: string[] = [];

after(async () => {
  if (projects.length > 0) {
    const session = getDriver().session();
    try {
      await session.run(
        "MATCH (node) WHERE node.project_id IN $ids OR (node:Project AND node.id IN $ids) DETACH DELETE node",
        { ids: projects },
      );
    } finally {
      await session.close();
    }
  }
  await closeDriver();
});

test("Phase 3 closes, reviews, freezes and replays an Appendix D engineering chain", async () => {
  const suffix = randomUUID();
  const governance = new GovernanceRepository();
  const workspace = await governance.createProjectWorkspace({
    actor: "phase3-integration", command_id: "p3:" + suffix + ":workspace",
    project: { business_id: "P3-" + suffix, name: "Phase 3 integration" },
    model: { business_id: "MODEL-1", name: "System", level: "system" },
    revision: { business_id: "REV-1" },
    standard_profile: {
      business_id: "PROFILE-326A-356A", name: "DO-326A / DO-356A",
      profile_version: "phase3-test", standard_references: ["DO-326A", "DO-356A"],
    },
  });
  projects.push(workspace.project.id);
  const imported = await new SystemModelImportService().commit(systemModelCommitRequestSchema.parse({
    actor: "phase3-integration", command_id: "p3:" + suffix + ":import",
    project_id: workspace.project.id, revision_id: workspace.revision.id, expected_revision_version: 1,
    import: {
      contract_version: "system-model.v2",
      source: { business_id: "SOURCE-D", source_type: "controlled-example", name: "DO-356A Appendix D", content_hash: "d".repeat(64), parser_name: "test", parser_version: "1" },
      entities: {
        assets: [{ business_id: "ASSET-1", name: "Target", category: "System" }],
        functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [],
        evidence_records: [{ business_id: "EVID-1", evidence_type: "test", title: "Evidence", reference: "fixture://phase3" }],
        draft_threats: [], trace_links: [],
      },
    },
  }));
  const base = { tags: [], status: "Draft" as const, standard_references: ["DO-326A", "DO-356A Appendix D"] };
  const request = engineeringCaseCommitRequestSchema.parse({
    actor: "phase3-integration", command_id: "p3:" + suffix + ":case",
    project_id: workspace.project.id, revision_id: workspace.revision.id, expected_revision_version: imported.new_revision_version,
    case: {
      contract_version: "engineering-case.v1", source_record_business_id: "SOURCE-D",
      profile_configuration: {
        ...base, business_id: "PROFILE-CONFIG", name: "Profile configuration",
        standard_profile_version_business_id: "PROFILE-326A-356A",
        do326a_process_activities: ["Risk assessment"], do326a_work_products: ["Requirements"],
        do356a_methods: ["Threat analysis"], do356a_data_fields: ["Scenario"], do356a_work_products: ["Appendix D"],
        adapters: [{ adapter_id: "f3532", adapter_version: "1", enabled: false }],
      },
      tailoring_decisions: [{ ...base, business_id: "TAILOR-1", name: "Applicability", standard_reference: "DO-356A Appendix D", applicability: "Applicable", rationale: "Acceptance example" }],
      threat_points: [{ ...base, business_id: "TP-1", name: "Entry", target: { type: "Asset", business_id: "ASSET-1" }, exposure_type: "Network", applicability: "Applicable" }],
      threat_conditions: [{ ...base, business_id: "TC-1", name: "Integrity condition", affected_elements: [{ type: "Asset", business_id: "ASSET-1" }], security_attributes: ["Integrity"], operational_context: "Operation", effect: "Invalid data", severity_reference: "FHA-1", assumptions: [] }],
      threat_scenarios: [{ ...base, business_id: "TS-1", name: "Crafted input", threat_source: "External", preconditions: [], actions: ["Inject"], entry_point_business_ids: ["TP-1"], target: { type: "Asset", business_id: "ASSET-1" }, threat_condition_business_ids: ["TC-1"], existing_control_business_ids: [] }],
      risk_assessments: [{ ...base, business_id: "RISK-1", name: "Risk", threat_scenario_business_id: "TS-1", method_id: "METHOD-1", method_version: "1", computed_result: { score: 7 }, engineering_judgement: "Mitigation required", treatment: "Mitigate", rationale: "Operational impact" }],
      security_objectives: [{ ...base, business_id: "OBJ-1", name: "Objective", risk_assessment_business_ids: ["RISK-1"], statement: "Preserve integrity", allocated_elements: [{ type: "Asset", business_id: "ASSET-1" }] }],
      security_requirements: [{ ...base, business_id: "REQ-1", name: "Requirement", security_objective_business_ids: ["OBJ-1"], statement: "Reject invalid data", rationale: "Treat risk", owner: "System", verification_criteria: ["Invalid input rejected"], allocated_elements: [{ type: "Asset", business_id: "ASSET-1" }] }],
      controls: [{ ...base, business_id: "CTRL-1", name: "Authentication", security_requirement_business_ids: ["REQ-1"], implementation_status: "Verified", allocated_elements: [{ type: "Asset", business_id: "ASSET-1" }] }],
      verification_cases: [{ ...base, business_id: "VC-1", name: "Negative test", verifies: [{ type: "Control", business_id: "CTRL-1" }], method: "Test", environment: "Bench", procedure: "Inject", acceptance_criteria: ["Rejected"], outcome: "Pass", result: "Passed", evidence_record_business_ids: ["EVID-1"] }],
      trace_links: [
        { business_id: "L1", link_type: "IDENTIFIES", source: { type: "ThreatPoint", business_id: "TP-1" }, target: { type: "ThreatCondition", business_id: "TC-1" } },
        { business_id: "L2", link_type: "REALIZES", source: { type: "ThreatScenario", business_id: "TS-1" }, target: { type: "ThreatCondition", business_id: "TC-1" } },
        { business_id: "L3", link_type: "ASSESSES", source: { type: "RiskAssessment", business_id: "RISK-1" }, target: { type: "ThreatScenario", business_id: "TS-1" } },
        { business_id: "L4", link_type: "MITIGATES", source: { type: "SecurityObjective", business_id: "OBJ-1" }, target: { type: "RiskAssessment", business_id: "RISK-1" } },
        { business_id: "L5", link_type: "SATISFIES", source: { type: "SecurityRequirement", business_id: "REQ-1" }, target: { type: "SecurityObjective", business_id: "OBJ-1" } },
        { business_id: "L6", link_type: "REALIZES", source: { type: "Control", business_id: "CTRL-1" }, target: { type: "SecurityRequirement", business_id: "REQ-1" } },
        { business_id: "L7", link_type: "VERIFIES", source: { type: "VerificationCase", business_id: "VC-1" }, target: { type: "Control", business_id: "CTRL-1" } },
        { business_id: "L8", link_type: "EVIDENCES", source: { type: "EvidenceRecord", business_id: "EVID-1" }, target: { type: "VerificationCase", business_id: "VC-1" } },
      ],
    },
  });
  const service = new EngineeringCaseService();
  const committed = await service.commit(request);
  assert.equal(committed.replayed, false);
  assert.equal((await service.commit(request)).replayed, true);
  const reviewed = await service.review(reviewDecisionCommandSchema.parse({
    actor: "human-reviewer", command_id: "p3:" + suffix + ":review",
    project_id: workspace.project.id, revision_id: workspace.revision.id,
    expected_revision_version: committed.new_revision_version,
    review: {
      business_id: "REVIEW-1", subject: { type: "SecurityRequirement", business_id: "REQ-1", version: committed.new_revision_version },
      decision: "Accept", rationale: "Traceable and testable", reviewer_role: "Security Reviewer",
    },
  }));
  const stored = await new EngineeringCaseRepository().read(workspace.project.id, workspace.revision.id);
  assert.equal(stored?.security_requirements[0].status, "Reviewed");
  assert.equal(stored?.review_decisions.length, 1);
  assert.deepEqual(stored?.risk_assessments[0].computed_result, { score: 7 });
  assert.equal(stored?.risk_assessments[0].engineering_judgement, "Mitigation required");
  const reports = new TraceabilityReportService();
  const report = await reports.generate({ project_id: workspace.project.id, revision_id: workspace.revision.id }, "reporter");
  assert.equal(report.chains.length, 8);
  assert.equal(report.engineering_case?.source_record_business_id, "SOURCE-D");
  const frozen = await governance.freezeRevision({
    actor: "phase3-integration", command_id: "p3:" + suffix + ":freeze",
    project_id: workspace.project.id, revision_id: workspace.revision.id,
    expected_revision_version: reviewed.new_revision_version,
    baseline: { business_id: "BASELINE-1", content_hash: report.metadata.content_hash },
  });
  const frozenReport = await reports.generate({ project_id: workspace.project.id, baseline_id: frozen.value.id }, "reporter");
  assert.equal(frozenReport.metadata.integrity_status, "matched");
  assert.equal(frozenReport.context.standard_profile_version.business_id, "PROFILE-326A-356A");
});
