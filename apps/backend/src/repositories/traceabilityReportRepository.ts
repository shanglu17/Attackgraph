import { getDriver } from "../db/neo4j.js";

type Properties = Record<string, unknown>;

export interface TraceabilityContextRecord {
  project: { id: string; business_id: string; name: string };
  model: { id: string; business_id: string; name: string };
  revision: { id: string; business_id: string; status: string; version: number };
  baseline?: { id: string; business_id: string; status: string; version: number; content_hash: string; frozen_at: string; frozen_by: string };
  standard_profile_version: {
    id: string;
    business_id: string;
    name: string;
    profile_version: string;
    maturity: string;
    standard_references: string[];
  };
}

export class TraceabilityContextNotFoundError extends Error {
  readonly statusCode = 404;
  constructor(message: string) {
    super(message);
    this.name = "TraceabilityContextNotFoundError";
  }
}

function properties(record: { get(key: string): unknown }, key: string): Properties {
  const node = record.get(key);
  if (typeof node !== "object" || node === null || !("properties" in node)) {
    throw new TypeError(`Expected Neo4j node '${key}'`);
  }
  return (node as { properties: Properties }).properties;
}

function required(value: unknown): string {
  if (value === null || value === undefined) throw new TypeError("Expected a non-null property");
  return String(value);
}

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") {
    return value.toNumber();
  }
  return Number(value);
}

export class TraceabilityReportRepository {
  async resolveContext(input: { project_id: string; revision_id?: string; baseline_id?: string }): Promise<TraceabilityContextRecord> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((transaction) => transaction.run(
        `MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->(model:Model)-[:HAS_REVISION]->(revision:Revision)
         OPTIONAL MATCH (revision)-[:FROZEN_AS]->(baseline:Baseline)
         MATCH (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile:StandardProfileVersion)
         WHERE ($revision_id IS NOT NULL AND revision.id = $revision_id)
            OR ($baseline_id IS NOT NULL AND baseline.id = $baseline_id)
         RETURN project, model, revision, baseline, profile
         LIMIT 1`,
        {
          project_id: input.project_id,
          revision_id: input.revision_id ?? null,
          baseline_id: input.baseline_id ?? null,
        },
      ));
      if (result.records.length === 0) {
        throw new TraceabilityContextNotFoundError("project/revision or project/baseline traceability context was not found");
      }
      const record = result.records[0];
      const project = properties(record, "project");
      const model = properties(record, "model");
      const revision = properties(record, "revision");
      const profile = properties(record, "profile");
      const baselineNode = record.get("baseline");
      const baseline = baselineNode === null ? undefined : properties(record, "baseline");
      return {
        project: { id: required(project.id), business_id: required(project.business_id), name: required(project.name) },
        model: { id: required(model.id), business_id: required(model.business_id), name: required(model.name) },
        revision: {
          id: required(revision.id), business_id: required(revision.business_id),
          status: required(revision.status), version: numeric(revision.version),
        },
        baseline: baseline ? {
          id: required(baseline.id), business_id: required(baseline.business_id),
          status: required(baseline.status), version: numeric(baseline.version),
          content_hash: required(baseline.content_hash), frozen_at: required(baseline.frozen_at),
          frozen_by: required(baseline.frozen_by),
        } : undefined,
        standard_profile_version: {
          id: required(profile.id), business_id: required(profile.business_id), name: required(profile.name),
          profile_version: required(profile.profile_version), maturity: required(profile.maturity),
          standard_references: Array.isArray(profile.standard_references) ? profile.standard_references.map(String) : [],
        },
      };
    } finally {
      await session.close();
    }
  }

  async readTraceSourceMap(projectId: string, revisionId: string): Promise<Map<string, string>> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((transaction) => transaction.run(
        `MATCH (link:TraceLink {project_id: $project_id, revision_id: $revision_id})
               -[:DERIVED_FROM_SOURCE]->(source:SourceRecord)
         RETURN link.business_id AS link_id, source.business_id AS source_id`,
        { project_id: projectId, revision_id: revisionId },
      ));
      return new Map(result.records.map((record) => [String(record.get("link_id")), String(record.get("source_id"))]));
    } finally {
      await session.close();
    }
  }

  async readAudit(projectId: string, revisionId: string) {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((transaction) => transaction.run(
        `MATCH (event:AuditEvent {project_id: $project_id})
         WHERE event.subject_id = $revision_id OR event.result_revision_id = $revision_id
         RETURN event.event_type AS event_type, event.actor AS actor,
                toString(event.occurred_at) AS occurred_at, event.command_id AS command_id
         ORDER BY event.occurred_at, event.event_type`,
        { project_id: projectId, revision_id: revisionId },
      ));
      return result.records.map((record) => ({
        event_type: required(record.get("event_type")),
        actor: required(record.get("actor")),
        occurred_at: required(record.get("occurred_at")),
        command_id: required(record.get("command_id")),
      }));
    } finally {
      await session.close();
    }
  }
}
