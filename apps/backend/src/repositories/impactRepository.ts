import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import type {
  ImpactCandidate,
  ImpactDifference,
  ImpactDispositionCommand,
  ResolvedImpactContext,
  StoredImpactAssessment,
  StoredImpactDisposition,
  StoredImpactItem,
} from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";
import type { ImpactDependency, ImpactSnapshot, ImpactSnapshotEntity } from "../services/impact/impactEngine.js";

type Properties = Record<string, unknown>;
const excludedEntityTypes = new Set(["ChangeImpactAssessment", "ImpactItem", "ImpactDisposition", "WorkProductSnapshot"]);
const volatileFields = new Set(["id", "project_id", "revision_id", "revision_version", "created_at", "created_by", "updated_at", "updated_by", "reviewed_at", "reviewed_by"]);

export class ImpactScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImpactScopeError";
  }
}

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") return value.toNumber();
  return Number(value ?? 0);
}

function text(value: unknown): string {
  if (value === null || value === undefined) throw new TypeError("Expected a non-null Neo4j value");
  return String(value);
}

function props(record: { get(key: string): unknown }, key: string): Properties {
  const node = record.get(key);
  if (typeof node !== "object" || node === null || !("properties" in node)) throw new TypeError("Expected Neo4j node " + key);
  return (node as { properties: Properties }).properties;
}

function jsonValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return value;
  if (Array.isArray(value)) return value.map(jsonValue);
  if (typeof value === "object" && value !== null) {
    if ("toNumber" in value && typeof value.toNumber === "function") return value.toNumber();
    if ("toString" in value && value.constructor?.name !== "Object") return String(value);
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, jsonValue(item)]));
  }
  return String(value);
}

function semantic(properties: Properties): Record<string, unknown> {
  if (typeof properties.payload_json === "string") {
    const payload = JSON.parse(properties.payload_json) as Record<string, unknown>;
    return { ...payload, status: properties.status ?? payload.status };
  }
  return Object.fromEntries(Object.entries(properties).filter(([key]) => !volatileFields.has(key)).map(([key, value]) => [key, jsonValue(value)]));
}

function entityRef(properties: Properties, labels: string[]): ImpactSnapshotEntity {
  const type = properties.entity_type ? String(properties.entity_type) : labels.includes("SourceRecord") ? "SourceRecord" : labels.find((label) => !["CoreEntity", "SystemModelElement", "EngineeringElement", "PromotedCoreDraft"].includes(label)) ?? "CoreEntity";
  return {
    type,
    business_id: text(properties.business_id),
    name: String(properties.name ?? properties.title ?? properties.business_id),
    status: properties.status == null ? undefined : String(properties.status),
    semantic: semantic(properties),
  };
}

function dateText(value: unknown): string {
  return String(value);
}

export class ImpactRepository {
  async resolveContext(projectId: string, input: { revision_id?: string; baseline_id?: string }): Promise<ResolvedImpactContext> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) => tx.run(
        "MATCH (:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision) " +
        "OPTIONAL MATCH (revision)-[:FROZEN_AS]->(baseline:Baseline) " +
        "WITH revision, baseline " +
        "WHERE ($revision_id IS NOT NULL AND revision.id = $revision_id) OR ($baseline_id IS NOT NULL AND baseline.id = $baseline_id) " +
        "RETURN revision, CASE WHEN $baseline_id IS NULL THEN null ELSE baseline END AS baseline LIMIT 1",
        { project_id: projectId, revision_id: input.revision_id ?? null, baseline_id: input.baseline_id ?? null },
      ));
      if (result.records.length === 0) throw new ImpactScopeError("Impact comparison context was not found in the requested project");
      const revision = props(result.records[0], "revision");
      const baselineNode = result.records[0].get("baseline");
      const baseline = baselineNode == null ? undefined : props(result.records[0], "baseline");
      return {
        revision_id: text(revision.id), revision_business_id: text(revision.business_id), revision_version: numeric(revision.version),
        baseline_id: baseline ? text(baseline.id) : undefined,
        baseline_business_id: baseline ? text(baseline.business_id) : undefined,
        baseline_status: baseline ? text(baseline.status) : undefined,
      };
    } finally {
      await session.close();
    }
  }

  async readSnapshot(projectId: string, revisionId: string): Promise<ImpactSnapshot> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (tx) => {
        const nodes = await tx.run(
          "MATCH (revision:Revision {id: $revision_id, project_id: $project_id})-[:CONTAINS]->(entity) " +
          "WHERE entity:CoreEntity OR entity:SourceRecord RETURN entity, labels(entity) AS labels ORDER BY entity.business_id",
          { project_id: projectId, revision_id: revisionId },
        );
        const entities = nodes.records.map((record) => entityRef(props(record, "entity"), record.get("labels") as string[])).filter((item) => !excludedEntityTypes.has(item.type));
        const links = await tx.run(
          "MATCH (link:TraceLink {project_id: $project_id, revision_id: $revision_id}) " +
          "RETURN link.business_id AS trace, link.source_type AS from_type, link.source_business_id AS from_id, link.target_type AS to_type, link.target_business_id AS to_id",
          { project_id: projectId, revision_id: revisionId },
        );
        const relations = await tx.run(
          "MATCH (from)-[relation:DERIVED_FROM_SOURCE|PRODUCED|DERIVED_FROM]->(to) " +
          "WHERE from.project_id = $project_id AND from.revision_id = $revision_id AND to.project_id = $project_id AND to.revision_id = $revision_id " +
          "RETURN coalesce(from.entity_type, CASE WHEN from:SourceRecord THEN 'SourceRecord' ELSE head([label IN labels(from) WHERE NOT label IN ['CoreEntity','SystemModelElement','EngineeringElement','PromotedCoreDraft']]) END) AS from_type, " +
          "from.business_id AS from_id, coalesce(to.entity_type, CASE WHEN to:SourceRecord THEN 'SourceRecord' ELSE head([label IN labels(to) WHERE NOT label IN ['CoreEntity','SystemModelElement','EngineeringElement','PromotedCoreDraft']]) END) AS to_type, " +
          "to.business_id AS to_id, type(relation) AS relation_type, type(relation) + ':' + coalesce(from.business_id, from.id) + ':' + coalesce(to.business_id, to.id) AS trace",
          { project_id: projectId, revision_id: revisionId },
        );
        const dependencies: ImpactDependency[] = links.records.flatMap((record) => {
          const forward = {
            from: { type: text(record.get("from_type")), business_id: text(record.get("from_id")) },
            to: { type: text(record.get("to_type")), business_id: text(record.get("to_id")) },
            trace_link_business_id: text(record.get("trace")),
          };
          return [forward, { from: forward.to, to: forward.from, trace_link_business_id: forward.trace_link_business_id }];
        });
        for (const record of relations.records) {
          const relation = text(record.get("relation_type"));
          const from = { type: text(record.get("from_type")), business_id: text(record.get("from_id")) };
          const to = { type: text(record.get("to_type")), business_id: text(record.get("to_id")) };
          dependencies.push({
            from: relation === "DERIVED_FROM_SOURCE" || relation === "DERIVED_FROM" ? to : from,
            to: relation === "DERIVED_FROM_SOURCE" || relation === "DERIVED_FROM" ? from : to,
            trace_link_business_id: text(record.get("trace")),
          });
        }
        return { entities, dependencies };
      });
    } finally {
      await session.close();
    }
  }

  async createAssessment(transaction: ManagedTransaction, input: {
    project_id: string; revision_id: string; actor: string; revision_version: number;
    business_id: string; title: string; rationale: string; from: ResolvedImpactContext; to: ResolvedImpactContext;
    preview_hash: string; differences: ImpactDifference[]; impacted: ImpactCandidate[];
  }) {
    if (input.to.revision_id !== input.revision_id) throw new ImpactScopeError("Assessment target must be the writable revision in the command envelope");
    const assessmentId = randomUUID();
    const rows = input.impacted.map((item, index) => ({
      id: randomUUID(), business_id: input.business_id + ":ITEM:" + String(index + 1).padStart(4, "0"),
      entity_type: item.entity.type, entity_business_id: item.entity.business_id, entity_name: item.entity.name,
      entity_status: item.entity.status ?? null, impact_kind: item.impact_kind, distance: item.distance,
      trigger_business_ids: item.trigger_business_ids, via_trace_link_business_ids: item.via_trace_link_business_ids,
    }));
    const result = await transaction.run(
      "MATCH (revision:Revision {id: $revision_id, project_id: $project_id}) " +
      "WHERE NOT EXISTS { MATCH (:ChangeImpactAssessment {project_id: $project_id, revision_id: $revision_id, business_id: $business_id}) } " +
      "CREATE (assessment:CoreEntity:ChangeImpactAssessment {id: $assessment_id, entity_type: 'ChangeImpactAssessment', business_id: $business_id, title: $title, rationale: $rationale, " +
      "project_id: $project_id, revision_id: $revision_id, status: $status, preview_hash: $preview_hash, from_context_json: $from_json, to_context_json: $to_json, differences_json: $differences_json, " +
      "revision_version: $revision_version, created_at: datetime(), created_by: $actor}) CREATE (revision)-[:CONTAINS]->(assessment) " +
      "WITH assessment UNWIND $rows AS row CREATE (item:ImpactItem {id: row.id, business_id: row.business_id, project_id: $project_id, revision_id: $revision_id, " +
      "entity_type: row.entity_type, entity_business_id: row.entity_business_id, entity_name: row.entity_name, entity_status: row.entity_status, impact_kind: row.impact_kind, distance: row.distance, " +
      "trigger_business_ids: row.trigger_business_ids, via_trace_link_business_ids: row.via_trace_link_business_ids, status: 'Open', created_at: datetime(), created_by: $actor}) " +
      "CREATE (assessment)-[:HAS_IMPACT_ITEM]->(item) RETURN assessment.id AS id",
      {
        project_id: input.project_id, revision_id: input.revision_id, actor: input.actor, revision_version: input.revision_version,
        assessment_id: assessmentId, business_id: input.business_id, title: input.title, rationale: input.rationale,
        status: rows.length === 0 ? "Resolved" : "Open", preview_hash: input.preview_hash,
        from_json: JSON.stringify(input.from), to_json: JSON.stringify(input.to), differences_json: JSON.stringify(input.differences), rows,
      },
    );
    if (result.records.length === 0) throw new ImpactScopeError("Impact assessment business id already exists in the target revision");
    return { assessment_id: assessmentId, item_count: rows.length, preview_hash: input.preview_hash };
  }

  async recordDisposition(transaction: ManagedTransaction, input: {
    project_id: string; revision_id: string; actor: string; revision_version: number;
    disposition: ImpactDispositionCommand["disposition"];
  }) {
    const dispositionId = randomUUID();
    const result = await transaction.run(
      "MATCH (assessment:ChangeImpactAssessment {id: $assessment_id, project_id: $project_id, revision_id: $revision_id})-[:HAS_IMPACT_ITEM]->" +
      "(item:ImpactItem {id: $impact_item_id}) OPTIONAL MATCH (item)-[:HAS_DISPOSITION]->(prior:ImpactDisposition {business_id: $supersedes_business_id}) " +
      "WITH assessment, item, prior WHERE (item.status = 'Open' AND $supersedes_business_id IS NULL) OR (item.status = 'Dispositioned' AND prior IS NOT NULL) " +
      "CREATE (decision:ImpactDisposition {id: $disposition_id, business_id: $business_id, project_id: $project_id, revision_id: $revision_id, decision: $decision, rationale: $rationale, " +
      "reviewer: $actor, reviewer_role: $reviewer_role, due_at: CASE WHEN $due_at IS NULL THEN null ELSE datetime($due_at) END, waiver_basis: $waiver_basis, " +
      "supersedes_business_id: $supersedes_business_id, revision_version: $revision_version, decided_at: datetime()}) " +
      "CREATE (item)-[:HAS_DISPOSITION]->(decision) FOREACH (_ IN CASE WHEN prior IS NULL THEN [] ELSE [1] END | CREATE (decision)-[:SUPERSEDES]->(prior)) " +
      "SET item.status = 'Dispositioned', item.current_disposition_id = decision.id " +
      "WITH assessment, decision OPTIONAL MATCH (assessment)-[:HAS_IMPACT_ITEM]->(open:ImpactItem {status: 'Open'}) " +
      "WITH assessment, decision, count(open) AS open_count SET assessment.status = CASE WHEN open_count = 0 THEN 'Resolved' ELSE 'Open' END " +
      "RETURN decision.id AS id, assessment.status AS status",
      {
        project_id: input.project_id, revision_id: input.revision_id, actor: input.actor, revision_version: input.revision_version,
        assessment_id: input.disposition.assessment_id, impact_item_id: input.disposition.impact_item_id,
        disposition_id: dispositionId, business_id: input.disposition.business_id, decision: input.disposition.decision,
        rationale: input.disposition.rationale, reviewer_role: input.disposition.reviewer_role,
        due_at: input.disposition.due_at ?? null, waiver_basis: input.disposition.waiver_basis ?? null,
        supersedes_business_id: input.disposition.supersedes_business_id ?? null,
      },
    );
    if (result.records.length === 0) throw new ImpactScopeError("Impact item was not found or disposition supersession is invalid");
    return { disposition_id: dispositionId, assessment_status: text(result.records[0].get("status")) as "Open" | "Resolved" };
  }

  async readAssessments(projectId: string, revisionId: string, assessmentId?: string): Promise<StoredImpactAssessment[]> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (tx) => {
        const assessments = await tx.run(
          "MATCH (assessment:ChangeImpactAssessment {project_id: $project_id, revision_id: $revision_id}) " +
          "WHERE $assessment_id IS NULL OR assessment.id = $assessment_id RETURN assessment ORDER BY assessment.created_at",
          { project_id: projectId, revision_id: revisionId, assessment_id: assessmentId ?? null },
        );
        const output: StoredImpactAssessment[] = [];
        for (const record of assessments.records) {
          const assessment = props(record, "assessment");
          const items = await tx.run(
            "MATCH (:ChangeImpactAssessment {id: $assessment_id})-[:HAS_IMPACT_ITEM]->(item:ImpactItem) " +
            "OPTIONAL MATCH (item)-[:HAS_DISPOSITION]->(decision:ImpactDisposition) WHERE decision.id = item.current_disposition_id " +
            "RETURN item, decision ORDER BY item.business_id",
            { assessment_id: text(assessment.id) },
          );
          output.push({
            id: text(assessment.id), business_id: text(assessment.business_id), title: text(assessment.title), rationale: text(assessment.rationale),
            project_id: projectId, revision_id: revisionId, status: text(assessment.status) as "Open" | "Resolved", preview_hash: text(assessment.preview_hash),
            from: JSON.parse(text(assessment.from_context_json)), to: JSON.parse(text(assessment.to_context_json)), differences: JSON.parse(text(assessment.differences_json)),
            created_at: dateText(assessment.created_at), created_by: text(assessment.created_by), revision_version: numeric(assessment.revision_version),
            items: items.records.map((itemRecord): StoredImpactItem => {
              const item = props(itemRecord, "item");
              const decisionNode = itemRecord.get("decision");
              let disposition: StoredImpactDisposition | undefined;
              if (decisionNode && typeof decisionNode === "object" && "properties" in decisionNode) {
                const decision = (decisionNode as { properties: Properties }).properties;
                disposition = {
                  id: text(decision.id), business_id: text(decision.business_id), decision: text(decision.decision) as StoredImpactDisposition["decision"],
                  rationale: text(decision.rationale), reviewer: text(decision.reviewer), reviewer_role: text(decision.reviewer_role),
                  due_at: decision.due_at == null ? undefined : dateText(decision.due_at), waiver_basis: decision.waiver_basis == null ? undefined : String(decision.waiver_basis),
                  supersedes_business_id: decision.supersedes_business_id == null ? undefined : String(decision.supersedes_business_id),
                  decided_at: dateText(decision.decided_at), revision_version: numeric(decision.revision_version),
                };
              }
              return {
                id: text(item.id), business_id: text(item.business_id), status: text(item.status) as "Open" | "Dispositioned",
                entity: { type: text(item.entity_type), business_id: text(item.entity_business_id), name: text(item.entity_name), status: item.entity_status == null ? undefined : String(item.entity_status) },
                impact_kind: text(item.impact_kind) as "Direct" | "Propagated", distance: numeric(item.distance),
                trigger_business_ids: (item.trigger_business_ids as unknown[]).map(String), via_trace_link_business_ids: (item.via_trace_link_business_ids as unknown[]).map(String), disposition,
              };
            }),
          });
        }
        return output;
      });
    } finally {
      await session.close();
    }
  }
}
