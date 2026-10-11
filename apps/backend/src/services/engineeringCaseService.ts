import {
  engineeringCaseContractVersion,
  type EngineeringCaseCommitRequest,
  type EngineeringCaseCommitResult,
  type EngineeringCasePayload,
  type ReviewDecisionCommand,
  type ReviewDecisionResult,
} from "@attackgraph/contracts";
import {
  EngineeringCaseConflictError,
  EngineeringCaseRepository,
  type EngineeringScopeInspection,
} from "../repositories/engineeringCaseRepository.js";
import { RevisionUnitOfWork } from "../repositories/revisionUnitOfWork.js";

const definitions = [
  ["ProfileConfiguration", "profile_configuration"],
  ["TailoringDecision", "tailoring_decisions"],
  ["ThreatPoint", "threat_points"],
  ["ThreatCondition", "threat_conditions"],
  ["ThreatScenario", "threat_scenarios"],
  ["RiskAssessment", "risk_assessments"],
  ["SecurityObjective", "security_objectives"],
  ["SecurityRequirement", "security_requirements"],
  ["Control", "controls"],
  ["VerificationCase", "verification_cases"],
] as const;

function identity(type: string, businessId: string) {
  return type + ":" + businessId;
}

export function validateEngineeringCase(
  payload: EngineeringCasePayload,
  scope: EngineeringScopeInspection,
  checkCreateConflicts = true,
): string[] {
  const errors: string[] = [];
  if (!scope.exists) errors.push("project/revision scope does not exist");
  if (!scope.source_exists) errors.push("source record '" + payload.source_record_business_id + "' does not exist in this revision");
  if (payload.profile_configuration.standard_profile_version_business_id !== scope.profile_business_id) {
    errors.push("profile configuration is not bound to the revision StandardProfileVersion");
  }
  const standards = new Set(scope.profile_standard_references.map((value) => value.toUpperCase()));
  if (![...standards].some((value) => value.includes("DO-326A"))) errors.push("revision profile does not include DO-326A");
  if (![...standards].some((value) => value.includes("DO-356A"))) errors.push("revision profile does not include DO-356A");

  const known = new Set(scope.identities);
  const collections = definitions.map(([type, collection]) => [
    type,
    collection === "profile_configuration" ? [payload.profile_configuration] : payload[collection],
  ] as const);
  for (const [type, values] of collections) {
    const seen = new Set<string>();
    for (const value of values) {
      if (seen.has(value.business_id)) errors.push("duplicate " + type + " business_id '" + value.business_id + "'");
      if (checkCreateConflicts && scope.identities.has(identity(type, value.business_id))) errors.push("create-only conflict for " + identity(type, value.business_id));
      seen.add(value.business_id);
      known.add(identity(type, value.business_id));
    }
  }
  const requireRef = (type: string, businessId: string, owner: string) => {
    if (!known.has(identity(type, businessId))) errors.push(owner + " references unresolved " + identity(type, businessId));
  };
  for (const item of payload.threat_points) requireRef(item.target.type, item.target.business_id, identity("ThreatPoint", item.business_id));
  for (const item of payload.threat_conditions) {
    for (const ref of item.affected_elements) requireRef(ref.type, ref.business_id, identity("ThreatCondition", item.business_id));
  }
  for (const item of payload.threat_scenarios) {
    for (const id of item.entry_point_business_ids) requireRef("ThreatPoint", id, identity("ThreatScenario", item.business_id));
    requireRef(item.target.type, item.target.business_id, identity("ThreatScenario", item.business_id));
    for (const id of item.threat_condition_business_ids) requireRef("ThreatCondition", id, identity("ThreatScenario", item.business_id));
    for (const id of item.existing_control_business_ids) requireRef("Control", id, identity("ThreatScenario", item.business_id));
  }
  for (const item of payload.risk_assessments) requireRef("ThreatScenario", item.threat_scenario_business_id, identity("RiskAssessment", item.business_id));
  for (const item of payload.security_objectives) {
    for (const id of item.risk_assessment_business_ids) requireRef("RiskAssessment", id, identity("SecurityObjective", item.business_id));
    for (const ref of item.allocated_elements) requireRef(ref.type, ref.business_id, identity("SecurityObjective", item.business_id));
  }
  for (const item of payload.security_requirements) {
    for (const id of item.security_objective_business_ids) requireRef("SecurityObjective", id, identity("SecurityRequirement", item.business_id));
    for (const ref of item.allocated_elements) requireRef(ref.type, ref.business_id, identity("SecurityRequirement", item.business_id));
  }
  for (const item of payload.controls) {
    for (const id of item.security_requirement_business_ids) requireRef("SecurityRequirement", id, identity("Control", item.business_id));
    for (const ref of item.allocated_elements) requireRef(ref.type, ref.business_id, identity("Control", item.business_id));
  }
  for (const item of payload.verification_cases) {
    for (const ref of item.verifies) requireRef(ref.type, ref.business_id, identity("VerificationCase", item.business_id));
    for (const id of item.evidence_record_business_ids) requireRef("EvidenceRecord", id, identity("VerificationCase", item.business_id));
  }
  const seenLinks = new Set<string>();
  for (const link of payload.trace_links) {
    if (seenLinks.has(link.business_id) || (checkCreateConflicts && scope.identities.has(identity("TraceLink", link.business_id)))) {
      errors.push("duplicate or existing TraceLink business_id '" + link.business_id + "'");
    }
    seenLinks.add(link.business_id);
    requireRef(link.source.type, link.source.business_id, identity("TraceLink", link.business_id));
    requireRef(link.target.type, link.target.business_id, identity("TraceLink", link.business_id));
  }
  return [...new Set(errors)].sort();
}

export class EngineeringCaseService {
  constructor(
    private readonly repository = new EngineeringCaseRepository(),
    private readonly unitOfWork = new RevisionUnitOfWork(),
  ) {}

  async commit(input: EngineeringCaseCommitRequest): Promise<EngineeringCaseCommitResult> {
    const scope = await this.repository.inspectScope(input.project_id, input.revision_id, input.case.source_record_business_id);
    const errors = validateEngineeringCase(input.case, scope, false);
    if (errors.length > 0) throw new EngineeringCaseConflictError(errors.join("; "));
    const result = await this.unitOfWork.execute(
      {
        actor: input.actor,
        command_id: input.command_id,
        project_id: input.project_id,
        revision_id: input.revision_id,
        expected_revision_version: input.expected_revision_version,
        event_type: "ENGINEERING_CASE_COMMITTED",
        request_canonicalizer: "engineering-case.commit/v1",
        payload: JSON.parse(JSON.stringify(input.case)),
        summary: "Commit profile-driven DO-326A/DO-356A engineering case",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) => this.repository.createCase(transaction, {
        project_id, revision_id, actor: input.actor, revision_version: new_revision_version, payload: input.case,
      }),
    );
    return {
      contract_version: engineeringCaseContractVersion,
      committed: true,
      replayed: result.replayed,
      audit_event_id: result.audit_event_id,
      new_revision_version: result.new_revision_version,
      created_ids: result.value,
    };
  }

  async review(input: ReviewDecisionCommand): Promise<ReviewDecisionResult> {
    const result = await this.unitOfWork.execute(
      {
        actor: input.actor,
        command_id: input.command_id,
        project_id: input.project_id,
        revision_id: input.revision_id,
        expected_revision_version: input.expected_revision_version,
        event_type: "REVIEW_DECISION_RECORDED",
        request_canonicalizer: "engineering-case.review-decision/v1",
        payload: JSON.parse(JSON.stringify(input.review)),
        summary: "Record human engineering review decision",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) => this.repository.recordReview(transaction, {
        project_id, revision_id, actor: input.actor, revision_version: new_revision_version, review: input.review,
      }),
    );
    return {
      recorded: true,
      replayed: result.replayed,
      audit_event_id: result.audit_event_id,
      new_revision_version: result.new_revision_version,
      decision_id: result.value.decision_id,
      subject_status: result.value.subject_status,
    };
  }
}
