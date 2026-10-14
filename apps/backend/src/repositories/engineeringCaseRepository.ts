import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import {
  engineeringCaseContractVersion,
  type EngineeringCasePayload,
  type ReviewDecision,
  type StoredEngineeringCase,
} from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";

const definitions = [
  ["profile_configuration", "ProfileConfiguration"],
  ["tailoring_decisions", "TailoringDecision"],
  ["threat_points", "ThreatPoint"],
  ["threat_conditions", "ThreatCondition"],
  ["threat_scenarios", "ThreatScenario"],
  ["risk_assessments", "RiskAssessment"],
  ["security_objectives", "SecurityObjective"],
  ["security_requirements", "SecurityRequirement"],
  ["controls", "Control"],
  ["verification_cases", "VerificationCase"],
] as const;

export class EngineeringCaseConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EngineeringCaseConflictError";
  }
}

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") return value.toNumber();
  return Number(value);
}

function props(record: { get(key: string): unknown }, key: string): Record<string, unknown> {
  const node = record.get(key);
  if (typeof node !== "object" || node === null || !("properties" in node)) throw new TypeError("Expected Neo4j node " + key);
  return (node as { properties: Record<string, unknown> }).properties;
}

function storedPayload(input: Record<string, unknown>): Record<string, unknown> {
  const value = JSON.parse(String(input.payload_json)) as Record<string, unknown>;
  value.id = String(input.id);
  value.revision_version = numeric(input.revision_version);
  if (input.status !== undefined) value.status = String(input.status);
  return value;
}

export interface EngineeringScopeInspection {
  exists: boolean;
  revision_version?: number;
  profile_business_id?: string;
  profile_standard_references: string[];
  source_exists: boolean;
  identities: Set<string>;
}

export class EngineeringCaseRepository {
  async inspectScope(projectId: string, revisionId: string, sourceBusinessId: string): Promise<EngineeringScopeInspection> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) => tx.run(
        "OPTIONAL MATCH (:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id}) " +
        "OPTIONAL MATCH (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile:StandardProfileVersion) " +
        "OPTIONAL MATCH (source:SourceRecord {project_id: $project_id, revision_id: $revision_id, business_id: $source_business_id}) " +
        "OPTIONAL MATCH (element:CoreEntity {project_id: $project_id, revision_id: $revision_id}) " +
        "RETURN revision.version AS revision_version, profile.business_id AS profile_business_id, profile.standard_references AS standard_references, " +
        "count(DISTINCT source) > 0 AS source_exists, collect(DISTINCT element.entity_type + ':' + element.business_id) AS identities",
        { project_id: projectId, revision_id: revisionId, source_business_id: sourceBusinessId },
      ));
      const row = result.records[0];
      const version = row?.get("revision_version");
      return {
        exists: version !== null && version !== undefined,
        revision_version: version == null ? undefined : numeric(version),
        profile_business_id: row?.get("profile_business_id") == null ? undefined : String(row.get("profile_business_id")),
        profile_standard_references: (row?.get("standard_references") ?? []).map(String),
        source_exists: row?.get("source_exists") === true,
        identities: new Set((row?.get("identities") ?? []).filter(Boolean).map(String)),
      };
    } finally {
      await session.close();
    }
  }

  async createCase(transaction: ManagedTransaction, input: {
    project_id: string; revision_id: string; actor: string; revision_version: number; payload: EngineeringCasePayload;
  }): Promise<Record<string, string[]>> {
    const created: Record<string, string[]> = {};
    const incoming = [
      ...definitions.flatMap(([collection, type]) => {
        const values = collection === "profile_configuration" ? [input.payload.profile_configuration] : input.payload[collection];
        return values.map((value) => ({ type, business_id: value.business_id }));
      }),
      ...input.payload.trace_links.map((value) => ({ type: "TraceLink", business_id: value.business_id })),
    ];
    const conflicts = await transaction.run(
      "UNWIND $incoming AS item MATCH (entity:CoreEntity {project_id: $project_id, revision_id: $revision_id, entity_type: item.type, business_id: item.business_id}) " +
      "RETURN collect(item.type + ':' + item.business_id) AS conflicts",
      { incoming, project_id: input.project_id, revision_id: input.revision_id },
    );
    const conflictIds = (conflicts.records[0]?.get("conflicts") ?? []).map(String);
    if (conflictIds.length > 0) throw new EngineeringCaseConflictError("create-only engineering case conflicts with " + conflictIds.join(", "));
    for (const [collection, type] of definitions) {
      const values = collection === "profile_configuration"
        ? [input.payload.profile_configuration]
        : input.payload[collection];
      const rows = values.map((value) => {
        const id = randomUUID();
        (created[collection] ??= []).push(id);
        return { id, business_id: value.business_id, name: value.name, status: value.status, payload_json: JSON.stringify(value) };
      });
      if (rows.length === 0) continue;
      const query =
        "MATCH (revision:Revision {id: $revision_id, project_id: $project_id}) " +
        "MATCH (source:SourceRecord {project_id: $project_id, revision_id: $revision_id, business_id: $source_business_id}) " +
        "UNWIND $rows AS row CREATE (entity:CoreEntity:EngineeringElement:" + type + " {id: row.id, project_id: $project_id, revision_id: $revision_id, " +
        "business_id: row.business_id, legacy_id: row.business_id, entity_type: $entity_type, name: row.name, status: row.status, payload_json: row.payload_json, " +
        "contract_version: $contract_version, revision_version: $revision_version, created_at: datetime(), created_by: $actor}) " +
        "CREATE (revision)-[:CONTAINS]->(entity) CREATE (entity)-[:DERIVED_FROM_SOURCE]->(source)";
      await transaction.run(query, {
        rows, project_id: input.project_id, revision_id: input.revision_id, actor: input.actor,
        revision_version: input.revision_version, source_business_id: input.payload.source_record_business_id,
        entity_type: type, contract_version: engineeringCaseContractVersion,
      });
    }

    const rows = input.payload.trace_links.map((link) => {
      const id = randomUUID();
      (created.trace_links ??= []).push(id);
      return { id, business_id: link.business_id, source: link.source, target: link.target, payload_json: JSON.stringify(link) };
    });
    if (rows.length > 0) {
      await transaction.run(
        "MATCH (revision:Revision {id: $revision_id, project_id: $project_id}) " +
        "MATCH (sourceRecord:SourceRecord {project_id: $project_id, revision_id: $revision_id, business_id: $source_business_id}) " +
        "UNWIND $rows AS row MATCH (from:CoreEntity {project_id: $project_id, revision_id: $revision_id, entity_type: row.source.type, business_id: row.source.business_id}) " +
        "MATCH (to:CoreEntity {project_id: $project_id, revision_id: $revision_id, entity_type: row.target.type, business_id: row.target.business_id}) " +
        "CREATE (link:CoreEntity:EngineeringElement:TraceLink {id: row.id, project_id: $project_id, revision_id: $revision_id, business_id: row.business_id, " +
        "entity_type: 'TraceLink', source_type: row.source.type, source_business_id: row.source.business_id, target_type: row.target.type, " +
        "target_business_id: row.target.business_id, payload_json: row.payload_json, contract_version: $contract_version, revision_version: $revision_version, " +
        "created_at: datetime(), created_by: $actor}) CREATE (revision)-[:CONTAINS]->(link) CREATE (link)-[:TRACE_FROM]->(from) " +
        "CREATE (link)-[:TRACE_TO]->(to) CREATE (link)-[:DERIVED_FROM_SOURCE]->(sourceRecord)",
        {
          rows, project_id: input.project_id, revision_id: input.revision_id, actor: input.actor,
          revision_version: input.revision_version, source_business_id: input.payload.source_record_business_id,
          contract_version: engineeringCaseContractVersion,
        },
      );
    }
    return created;
  }

  async recordReview(transaction: ManagedTransaction, input: {
    project_id: string; revision_id: string; actor: string; revision_version: number; review: ReviewDecision;
  }): Promise<{ decision_id: string; subject_status: "Draft" | "Reviewed" | "Approved" | "Rejected" }> {
    const subjectStatus = ({ Accept: "Reviewed", Approve: "Approved", Reject: "Rejected", Return: "Draft" } as const)[input.review.decision];
    const decisionId = randomUUID();
    const result = await transaction.run(
      "MATCH (revision:Revision {id: $revision_id, project_id: $project_id}) " +
      "MATCH (subject:CoreEntity {project_id: $project_id, revision_id: $revision_id, entity_type: $subject_type, business_id: $subject_business_id, revision_version: $subject_version}) " +
      "OPTIONAL MATCH (prior:ReviewDecision {project_id: $project_id, revision_id: $revision_id, business_id: $supersedes_business_id}) " +
      "CREATE (decision:ReviewDecision {id: $decision_id, business_id: $business_id, project_id: $project_id, revision_id: $revision_id, subject_type: $subject_type, " +
      "subject_business_id: $subject_business_id, subject_version: $subject_version, decision: $decision, rationale: $rationale, reviewer: $actor, " +
      "reviewer_role: $reviewer_role, revision_version: $revision_version, decided_at: datetime()}) SET subject.status = $subject_status, " +
      "subject.reviewed_at = datetime(), subject.reviewed_by = $actor CREATE (revision)-[:CONTAINS]->(decision) CREATE (decision)-[:DECIDES]->(subject) " +
      "FOREACH (_ IN CASE WHEN prior IS NULL THEN [] ELSE [1] END | CREATE (decision)-[:SUPERSEDES]->(prior)) RETURN decision.id AS id",
      {
        project_id: input.project_id, revision_id: input.revision_id, actor: input.actor, revision_version: input.revision_version,
        decision_id: decisionId, business_id: input.review.business_id, subject_type: input.review.subject.type,
        subject_business_id: input.review.subject.business_id, subject_version: input.review.subject.version,
        decision: input.review.decision, rationale: input.review.rationale, reviewer_role: input.review.reviewer_role,
        supersedes_business_id: input.review.supersedes_business_id ?? null, subject_status: subjectStatus,
      },
    );
    if (result.records.length === 0) throw new EngineeringCaseConflictError("review subject/version is not present in this revision");
    return { decision_id: decisionId, subject_status: subjectStatus };
  }

  async read(projectId: string, revisionId: string): Promise<StoredEngineeringCase | undefined> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (tx) => {
        const revision = await tx.run(
          "MATCH (:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id}) RETURN revision.version AS version",
          { project_id: projectId, revision_id: revisionId },
        );
        if (revision.records.length === 0) return undefined;
        const elements = await tx.run(
          "MATCH (entity:EngineeringElement {project_id: $project_id, revision_id: $revision_id}) RETURN entity ORDER BY entity.business_id",
          { project_id: projectId, revision_id: revisionId },
        );
        if (elements.records.length === 0) return undefined;
        const grouped = new Map<string, Record<string, unknown>[]>();
        for (const record of elements.records) {
          const item = props(record, "entity");
          const list = grouped.get(String(item.entity_type)) ?? [];
          list.push(storedPayload(item));
          grouped.set(String(item.entity_type), list);
        }
        const reviews = await tx.run(
          "MATCH (decision:ReviewDecision {project_id: $project_id, revision_id: $revision_id}) RETURN decision ORDER BY decision.decided_at",
          { project_id: projectId, revision_id: revisionId },
        );
        const many = (type: string) => grouped.get(type) ?? [];
        const profile = many("ProfileConfiguration")[0];
        if (!profile) return undefined;
        const sourceResult = await tx.run(
          "MATCH (profile:ProfileConfiguration {project_id: $project_id, revision_id: $revision_id})-[:DERIVED_FROM_SOURCE]->(source:SourceRecord) RETURN source.business_id AS id LIMIT 1",
          { project_id: projectId, revision_id: revisionId },
        );
        return {
          contract_version: engineeringCaseContractVersion,
          project_id: projectId,
          revision_id: revisionId,
          revision_version: numeric(revision.records[0].get("version")),
          source_record_business_id: String(sourceResult.records[0]?.get("id") ?? ""),
          profile_configuration: profile,
          tailoring_decisions: many("TailoringDecision"),
          threat_points: many("ThreatPoint"),
          threat_conditions: many("ThreatCondition"),
          threat_scenarios: many("ThreatScenario"),
          risk_assessments: many("RiskAssessment"),
          security_objectives: many("SecurityObjective"),
          security_requirements: many("SecurityRequirement"),
          controls: many("Control"),
          verification_cases: many("VerificationCase"),
          trace_links: many("TraceLink"),
          review_decisions: reviews.records.map((record) => {
            const item = props(record, "decision");
            return {
              id: String(item.id), business_id: String(item.business_id),
              subject: { type: item.subject_type, business_id: String(item.subject_business_id), version: numeric(item.subject_version) },
              decision: item.decision, rationale: String(item.rationale), reviewer_role: String(item.reviewer_role),
              reviewer: String(item.reviewer), decided_at: String(item.decided_at),
            };
          }),
        } as StoredEngineeringCase;
      });
    } finally {
      await session.close();
    }
  }
}
