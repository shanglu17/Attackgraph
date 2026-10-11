import assert from "node:assert/strict";
import test from "node:test";
import { engineeringCasePayloadSchema, type EngineeringCasePayload } from "@attackgraph/contracts";
import { validateEngineeringCase } from "./engineeringCaseService.js";
import { mapF353204ToCoreDraft } from "./f3532/standardAdapterRegistry.js";

const base = {
  business_id: "PROFILE-CONFIG-1", name: "Profile", tags: [], status: "Draft" as const,
  standard_references: ["DO-326A", "DO-356A Appendix D"],
};

function payload(): EngineeringCasePayload {
  return engineeringCasePayloadSchema.parse({
    contract_version: "engineering-case.v1", source_record_business_id: "SRC-1",
    profile_configuration: {
      ...base, standard_profile_version_business_id: "PROFILE-1",
      do326a_process_activities: ["Risk assessment"], do326a_work_products: ["Requirements"],
      do356a_methods: ["Scenario construction"], do356a_data_fields: ["Threat condition"],
      do356a_work_products: ["Appendix D example chain"],
      adapters: [{ adapter_id: "f3532", adapter_version: "1.0.0", enabled: false }],
    },
    threat_points: [{ ...base, business_id: "TP-1", name: "Entry", target: { type: "Asset", business_id: "ASSET-1" }, exposure_type: "Network", applicability: "Applicable" }],
    threat_conditions: [{ ...base, business_id: "TC-1", name: "Condition", affected_elements: [{ type: "Asset", business_id: "ASSET-1" }], security_attributes: ["Integrity"], operational_context: "Operation", effect: "Effect", severity_reference: "FHA-1", assumptions: [] }],
    threat_scenarios: [{ ...base, business_id: "TS-1", name: "Scenario", threat_source: "External", preconditions: [], actions: ["Inject"], entry_point_business_ids: ["TP-1"], target: { type: "Asset", business_id: "ASSET-1" }, threat_condition_business_ids: ["TC-1"], existing_control_business_ids: [] }],
    risk_assessments: [{ ...base, business_id: "RISK-1", name: "Risk", threat_scenario_business_id: "TS-1", method_id: "METHOD-1", method_version: "1", computed_result: { score: 7 }, engineering_judgement: "Treat", treatment: "Mitigate", rationale: "Safety context" }],
    security_objectives: [{ ...base, business_id: "OBJ-1", name: "Objective", risk_assessment_business_ids: ["RISK-1"], statement: "Protect integrity", allocated_elements: [{ type: "Asset", business_id: "ASSET-1" }] }],
    security_requirements: [{ ...base, business_id: "REQ-1", name: "Requirement", security_objective_business_ids: ["OBJ-1"], statement: "Authenticate", rationale: "Mitigate", owner: "System", verification_criteria: ["Reject invalid input"], allocated_elements: [{ type: "Asset", business_id: "ASSET-1" }] }],
    controls: [{ ...base, business_id: "CTRL-1", name: "Control", security_requirement_business_ids: ["REQ-1"], implementation_status: "Implemented", allocated_elements: [{ type: "Asset", business_id: "ASSET-1" }] }],
    verification_cases: [{ ...base, business_id: "VC-1", name: "Verification", verifies: [{ type: "Control", business_id: "CTRL-1" }], method: "Test", environment: "Bench", procedure: "Inject invalid message", acceptance_criteria: ["Rejected"], outcome: "Pass", result: "Passed", evidence_record_business_ids: ["EVID-1"] }],
    trace_links: [],
  });
}

test("Phase 3 contract forces imported engineering entities to Draft", () => {
  const candidate = payload() as unknown as Record<string, unknown>;
  (candidate.threat_points as Array<Record<string, unknown>>)[0].status = "Approved";
  assert.equal(engineeringCasePayloadSchema.safeParse(candidate).success, false);
});

test("complete engineering chain validates and unresolved evidence fails", () => {
  const input = payload();
  const scope = {
    exists: true, revision_version: 2, profile_business_id: "PROFILE-1",
    profile_standard_references: ["DO-326A", "DO-356A"], source_exists: true,
    identities: new Set(["Asset:ASSET-1", "EvidenceRecord:EVID-1"]),
  };
  assert.deepEqual(validateEngineeringCase(input, scope), []);
  scope.identities.delete("EvidenceRecord:EVID-1");
  assert.match(validateEngineeringCase(input, scope).join(";"), /EvidenceRecord:EVID-1/);
});

test("F3532 adapter strips external approval assertions", () => {
  const preview = mapF353204ToCoreDraft({
    threat_conditions: [{ tc_id: "TC-X", affected_element_type: "Asset", affected_element_business_id: "ASSET-1", cia: ["Integrity"], review_status: "Approved" }],
    threat_scenarios: [{ ts_id: "TS-X", actions: ["Action"], entry_point_business_ids: ["TP-1"], target_type: "Asset", target_business_id: "ASSET-1", tc_ids: ["TC-X"], review_status: "Reviewed" }],
  });
  assert.equal(preview.external_review_assertions_ignored, true);
  assert.equal(preview.mapped.threat_conditions[0].status, "Draft");
  assert.equal(preview.mapped.threat_scenarios[0].status, "Draft");
});
