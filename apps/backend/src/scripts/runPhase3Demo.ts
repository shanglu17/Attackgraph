import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  engineeringCaseCommitRequestSchema,
  reviewDecisionCommandSchema,
  systemModelCommitRequestSchema,
} from "@attackgraph/contracts";
import { closeDriver } from "../db/neo4j.js";
import { GovernanceRepository } from "../repositories/governanceRepository.js";
import { EngineeringCaseService } from "../services/engineeringCaseService.js";
import { SystemModelImportService } from "../services/systemModelImportService.js";
import { TraceabilityReportService } from "../services/traceabilityReportService.js";

const actor = "phase3-controlled-demo";
const refs = ["DO-326A", "DO-356A Appendix D"];

async function main() {
  const path = fileURLToPath(new URL("../../../../examples/phase3-appendix-d-source.json", import.meta.url));
  const bytes = await readFile(path);
  const fixture = JSON.parse(bytes.toString("utf8")) as {
    asset: { business_id: string; name: string };
    evidence: { business_id: string; reference: string };
    engineering: Record<string, string>;
  };
  const hash = createHash("sha256").update(bytes).digest("hex");
  const governance = new GovernanceRepository();
  const workspace = await governance.createProjectWorkspace({
    actor, command_id: "phase3-demo-v2:create-workspace",
    project: { business_id: "PHASE3-APPENDIX-D-DEMO-V2", name: "Phase 3 Appendix D engineering closure" },
    model: { business_id: "P3-MODEL", name: "Phase 3 controlled system model", level: "system" },
    revision: { business_id: "P3-REVISION-001" },
    standard_profile: {
      business_id: "P3-PROFILE-326A-356A", name: "DO-326A / DO-356A Phase 3 profile",
      profile_version: "phase3.1.0", standard_references: ["DO-326A", "DO-356A"],
    },
  });
  const imported = await new SystemModelImportService().commit(systemModelCommitRequestSchema.parse({
    actor, command_id: "phase3-demo-v2:import-system-model",
    project_id: workspace.project.id, revision_id: workspace.revision.id, expected_revision_version: 1,
    import: {
      contract_version: "system-model.v2",
      source: {
        business_id: "P3-SOURCE-APPENDIX-D", source_type: "controlled-example",
        name: "DO-356A Appendix D controlled example source", content_hash: hash,
        media_type: "application/json", parser_name: "phase3-controlled-fixture", parser_version: "1.0.0",
      },
      entities: {
        assets: [{ business_id: fixture.asset.business_id, name: fixture.asset.name, category: "System" }],
        functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [],
        evidence_records: [{
          business_id: fixture.evidence.business_id, evidence_type: "verification-record",
          title: "Controlled verification evidence", reference: fixture.evidence.reference, content_hash: hash,
        }],
        draft_threats: [], trace_links: [],
      },
    },
  }));

  const base = { tags: ["phase3-demo"], status: "Draft" as const, standard_references: refs };
  const caseResult = await new EngineeringCaseService().commit(engineeringCaseCommitRequestSchema.parse({
    actor, command_id: "phase3-demo-v2:commit-engineering-case",
    project_id: workspace.project.id, revision_id: workspace.revision.id,
    expected_revision_version: imported.new_revision_version,
    case: {
      contract_version: "engineering-case.v1", source_record_business_id: "P3-SOURCE-APPENDIX-D",
      profile_configuration: {
        ...base, business_id: "P3-PROFILE-CONFIG", name: "Phase 3 profile configuration",
        standard_profile_version_business_id: "P3-PROFILE-326A-356A",
        do326a_process_activities: ["Security risk assessment", "Security requirements validation"],
        do326a_work_products: ["Risk disposition", "Security requirements", "Verification evidence"],
        do356a_methods: ["Threat condition definition", "Threat scenario analysis", "Verification"],
        do356a_data_fields: ["Threat source", "Security attributes", "Engineering judgement", "Acceptance criteria"],
        do356a_work_products: ["Appendix D example trace"],
        adapters: [{ adapter_id: "f3532", adapter_version: "astra.f3532-compat/1.0.0", enabled: false }],
      },
      tailoring_decisions: [{
        ...base, business_id: "P3-TAILOR-APP-D", name: "Appendix D example applicability",
        standard_reference: "DO-356A Appendix D", applicability: "Applicable",
        rationale: "Selected as the controlled Phase 3 end-to-end acceptance example.",
      }],
      threat_points: [{
        ...base, business_id: "P3-TP-ENTRY", name: fixture.engineering.threat_point,
        target: { type: "Asset", business_id: fixture.asset.business_id }, exposure_type: "External data interface", applicability: "Applicable",
      }],
      threat_conditions: [{
        ...base, business_id: "P3-TC-INTEGRITY", name: fixture.engineering.threat_condition,
        affected_elements: [{ type: "Asset", business_id: fixture.asset.business_id }],
        security_attributes: ["Integrity"], operational_context: "Synthetic operational data reception",
        effect: "Untrusted data could influence downstream behavior.", severity_reference: "Controlled FHA reference P3-FHA-1",
        assumptions: ["The exposed interface is reachable in the modeled state."],
      }],
      threat_scenarios: [{
        ...base, business_id: "P3-TS-CRAFTED-MESSAGE", name: fixture.engineering.threat_scenario,
        threat_source: "External actor", preconditions: ["Interface is reachable"],
        actions: ["Construct unauthenticated message", "Transmit message to target"],
        entry_point_business_ids: ["P3-TP-ENTRY"], target: { type: "Asset", business_id: fixture.asset.business_id },
        threat_condition_business_ids: ["P3-TC-INTEGRITY"], existing_control_business_ids: [],
      }],
      risk_assessments: [{
        ...base, business_id: "P3-RISK-1", name: "Crafted-message risk assessment",
        threat_scenario_business_id: "P3-TS-CRAFTED-MESSAGE", method_id: "P3-QUALITATIVE-METHOD", method_version: "1.0.0",
        computed_result: { likelihood_score: 3, impact_score: 4 },
        engineering_judgement: "Treatment is required because message integrity supports an operational function.",
        treatment: "Mitigate", rationale: "Engineering judgement is recorded separately from the calculated values.",
      }],
      security_objectives: [{
        ...base, business_id: "P3-OBJ-INTEGRITY", name: "Message integrity objective",
        risk_assessment_business_ids: ["P3-RISK-1"], statement: fixture.engineering.objective,
        allocated_elements: [{ type: "Asset", business_id: fixture.asset.business_id }],
      }],
      security_requirements: [{
        ...base, business_id: "P3-REQ-AUTH", name: "Message authenticity requirement",
        security_objective_business_ids: ["P3-OBJ-INTEGRITY"], statement: fixture.engineering.requirement,
        rationale: "Implements the selected risk treatment.", owner: "Receiving system",
        verification_criteria: ["Invalid authentication data is rejected", "Replayed messages are rejected"],
        allocated_elements: [{ type: "Asset", business_id: fixture.asset.business_id }],
      }],
      controls: [{
        ...base, business_id: "P3-CTRL-AUTH", name: fixture.engineering.control,
        security_requirement_business_ids: ["P3-REQ-AUTH"], implementation_status: "Verified",
        allocated_elements: [{ type: "Asset", business_id: fixture.asset.business_id }],
      }],
      verification_cases: [{
        ...base, business_id: "P3-VC-AUTH", name: "Authentication negative test",
        verifies: [{ type: "Control", business_id: "P3-CTRL-AUTH" }], method: "Test",
        environment: "Controlled integration bench", procedure: fixture.engineering.verification,
        acceptance_criteria: ["All invalid and replayed messages are rejected"], outcome: "Pass",
        result: "Controlled fixture records a passing result.", evidence_record_business_ids: [fixture.evidence.business_id],
      }],
      trace_links: [
        { business_id: "P3-LINK-TP-TC", link_type: "IDENTIFIES", source: { type: "ThreatPoint", business_id: "P3-TP-ENTRY" }, target: { type: "ThreatCondition", business_id: "P3-TC-INTEGRITY" }, standard_reference: "DO-356A Appendix D" },
        { business_id: "P3-LINK-TS-TC", link_type: "REALIZES", source: { type: "ThreatScenario", business_id: "P3-TS-CRAFTED-MESSAGE" }, target: { type: "ThreatCondition", business_id: "P3-TC-INTEGRITY" }, standard_reference: "DO-356A Appendix D" },
        { business_id: "P3-LINK-RISK-TS", link_type: "ASSESSES", source: { type: "RiskAssessment", business_id: "P3-RISK-1" }, target: { type: "ThreatScenario", business_id: "P3-TS-CRAFTED-MESSAGE" } },
        { business_id: "P3-LINK-OBJ-RISK", link_type: "MITIGATES", source: { type: "SecurityObjective", business_id: "P3-OBJ-INTEGRITY" }, target: { type: "RiskAssessment", business_id: "P3-RISK-1" } },
        { business_id: "P3-LINK-REQ-OBJ", link_type: "SATISFIES", source: { type: "SecurityRequirement", business_id: "P3-REQ-AUTH" }, target: { type: "SecurityObjective", business_id: "P3-OBJ-INTEGRITY" } },
        { business_id: "P3-LINK-CTRL-REQ", link_type: "REALIZES", source: { type: "Control", business_id: "P3-CTRL-AUTH" }, target: { type: "SecurityRequirement", business_id: "P3-REQ-AUTH" } },
        { business_id: "P3-LINK-VC-CTRL", link_type: "VERIFIES", source: { type: "VerificationCase", business_id: "P3-VC-AUTH" }, target: { type: "Control", business_id: "P3-CTRL-AUTH" } },
        { business_id: "P3-LINK-EVID-VC", link_type: "EVIDENCES", source: { type: "EvidenceRecord", business_id: fixture.evidence.business_id }, target: { type: "VerificationCase", business_id: "P3-VC-AUTH" } },
      ],
    },
  }));

  const reviewed = await new EngineeringCaseService().review(reviewDecisionCommandSchema.parse({
    actor: "phase3-human-reviewer", command_id: "phase3-demo-v2:review-requirement",
    project_id: workspace.project.id, revision_id: workspace.revision.id,
    expected_revision_version: caseResult.new_revision_version,
    review: {
      business_id: "P3-REVIEW-REQ-1",
      subject: { type: "SecurityRequirement", business_id: "P3-REQ-AUTH", version: caseResult.new_revision_version },
      decision: "Accept", rationale: "Requirement is traceable, testable, and allocated in the controlled example.",
      reviewer_role: "Security Engineering Reviewer",
    },
  }));
  const reports = new TraceabilityReportService();
  const report = await reports.generate({ project_id: workspace.project.id, revision_id: workspace.revision.id }, actor);
  const frozen = await governance.freezeRevision({
    actor, command_id: "phase3-demo-v2:freeze", project_id: workspace.project.id,
    revision_id: workspace.revision.id, expected_revision_version: reviewed.new_revision_version,
    baseline: { business_id: "P3-BASELINE-002", content_hash: report.metadata.content_hash },
  });
  const baselineReport = await reports.generate({ project_id: workspace.project.id, baseline_id: frozen.value.id }, actor);
  console.log(JSON.stringify({
    project_id: workspace.project.id, revision_id: workspace.revision.id, baseline_id: frozen.value.id,
    engineering_entities: Object.fromEntries(Object.entries(caseResult.created_ids).map(([key, value]) => [key, value.length])),
    review_status: reviewed.subject_status, report_integrity: baselineReport.metadata.integrity_status,
    trace_chain_count: baselineReport.chains.length,
  }, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}).finally(closeDriver);
