import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import {
  analysisConfigurationSchema,
  type AnalysisConfiguration,
  type WorkspaceChoice,
  type SystemModelImportPayload,
} from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";
import { SystemModelRepository } from "./systemModelRepository.js";

const collections = {
  assets: "Asset",
  functions: "Function",
  interfaces: "Interface",
  data_flows: "DataFlow",
  security_boundaries: "SecurityBoundary",
  external_entities: "ExternalEntity",
  evidence_records: "EvidenceRecord",
  draft_threats: "DraftThreat",
  trace_links: "TraceLink",
} as const;
export class WorkbenchRepository {
  async list(): Promise<WorkspaceChoice[]> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) =>
        tx.run(`MATCH (p:Project)-[:HAS_MODEL]->(m:Model)-[:HAS_REVISION]->(r:Revision)
        RETURN p.id AS project_id, p.name AS project_name, p.business_id AS project_business_id,
          m.id AS model_id, m.name AS model_name, r.id AS revision_id, r.business_id AS revision_business_id,
          r.version AS revision_version, r.status AS status ORDER BY p.name, r.business_id`),
      );
      return result.records.map(
        (r) =>
          Object.fromEntries(
            r.keys.map((k) => [
              k,
              k === "revision_version" ? Number(r.get(k)) : String(r.get(k)),
            ]),
          ) as unknown as WorkspaceChoice,
      );
    } finally {
      await session.close();
    }
  }
  async configuration(
    project_id: string,
    revision_id: string,
    tx?: ManagedTransaction,
  ): Promise<AnalysisConfiguration> {
    if (!tx) {
      const session = getDriver().session();
      try {
        return await session.executeRead((t) =>
          this.configuration(project_id, revision_id, t),
        );
      } finally {
        await session.close();
      }
    }
    const result = await tx.run(
      "MATCH (r:Revision {id:$revision_id, project_id:$project_id}) OPTIONAL MATCH (r)-[:HAS_ANALYSIS_CONFIGURATION]->(c:AnalysisConfiguration) RETURN c.payload_json AS payload",
      { project_id, revision_id },
    );
    return analysisConfigurationSchema.parse(
      JSON.parse(result.records[0]?.get("payload") ?? "{}"),
    );
  }
  async status(
    project_id: string,
    revision_id: string,
    tx?: ManagedTransaction,
  ): Promise<string> {
    if (!tx) {
      const s = getDriver().session();
      try {
        return await s.executeRead((t) =>
          this.status(project_id, revision_id, t),
        );
      } finally {
        await s.close();
      }
    }
    const result = await tx.run(
      "MATCH (:Project {id:$project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(r:Revision {id:$revision_id}) RETURN r.status AS status",
      { project_id, revision_id },
    );
    return String(result.records[0]?.get("status") ?? "Missing");
  }
  async saveConfiguration(
    tx: ManagedTransaction,
    scope: {
      project_id: string;
      revision_id: string;
      new_revision_version: number;
    },
    configuration: AnalysisConfiguration,
    inventory?: unknown,
  ) {
    await tx.run(
      `MATCH (r:Revision {id:$revision_id, project_id:$project_id})
      MERGE (r)-[:HAS_ANALYSIS_CONFIGURATION]->(c:AnalysisConfiguration)
      ON CREATE SET c.id=$id, c.project_id=$project_id, c.revision_id=$revision_id
      SET c.payload_json=$payload, c.revision_version=$new_revision_version,
          c.inventory_json=coalesce($inventory,c.inventory_json)`,
      {
        project_id: scope.project_id,
        revision_id: scope.revision_id,
        new_revision_version: scope.new_revision_version,
        id: randomUUID(),
        payload: JSON.stringify(configuration),
        inventory: inventory ? JSON.stringify(inventory) : null,
      },
    );
  }
  async applyEntities(
    tx: ManagedTransaction,
    scope: {
      project_id: string;
      revision_id: string;
      new_revision_version: number;
    },
    entities: SystemModelImportPayload["entities"],
    actor: string,
  ) {
    const current = await new SystemModelRepository().read(
      scope.project_id,
      scope.revision_id,
      tx,
    );
    for (const [collection, label] of Object.entries(collections)) {
      const next = entities[collection as keyof typeof entities];
      const removed = current.entities[
        collection as keyof typeof entities
      ].filter((row) => !next.some((n) => n.business_id === row.business_id));
      for (const row of removed) {
        // References from engineering/research modules are not silently detached.
        const refs = await tx.run(
          `MATCH (n:SystemModelElement {project_id:$project_id,revision_id:$revision_id,entity_type:$label,business_id:$business_id})-[rel]-(other)
          WHERE NOT other:SystemModelElement AND NOT other:Revision AND NOT other:SourceRecord
          RETURN count(rel) AS count`,
          {
            project_id: scope.project_id,
            revision_id: scope.revision_id,
            new_revision_version: scope.new_revision_version,
            label,
            business_id: row.business_id,
          },
        );
        if (Number(refs.records[0].get("count")) > 0)
          throw Object.assign(
            new Error(
              `${label}:${row.business_id} 仍被工程或研究实体引用，不能删除`,
            ),
            { statusCode: 409 },
          );
        await tx.run(
          `MATCH (n:SystemModelElement:${label} {project_id:$project_id,revision_id:$revision_id,business_id:$business_id}) DETACH DELETE n`,
          {
            project_id: scope.project_id,
            revision_id: scope.revision_id,
            new_revision_version: scope.new_revision_version,
            business_id: row.business_id,
          },
        );
      }
      for (const item of next) {
        const properties: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(item)) {
          if (key === "analysis" || key === "source_locator")
            properties[key + "_json"] = JSON.stringify(value);
          else if (key !== "source" && key !== "target" && value !== undefined)
            properties[key] = value;
        }
        if (collection === "trace_links") {
          const link =
            item as SystemModelImportPayload["entities"]["trace_links"][number];
          Object.assign(properties, {
            source_type: link.source.type,
            source_business_id: link.source.business_id,
            target_type: link.target.type,
            target_business_id: link.target.business_id,
          });
        }
        await tx.run(
          `MATCH (r:Revision {id:$revision_id,project_id:$project_id})
          MERGE (n:CoreEntity:SystemModelElement:${label} {project_id:$project_id,revision_id:$revision_id,business_id:$business_id})
          WITH r,n,coalesce(n.id,$id) AS saved_id,coalesce(n.created_by,$actor) AS creator,
            coalesce(n.created_at,datetime()) AS created_at
          SET n=$properties,n.id=saved_id,n.project_id=$project_id,n.revision_id=$revision_id,n.entity_type=$label,
            n.created_by=creator,n.created_at=created_at,n.updated_by=$actor,n.revision_version=$new_revision_version
          MERGE (r)-[:CONTAINS]->(n)`,
          {
            project_id: scope.project_id,
            revision_id: scope.revision_id,
            new_revision_version: scope.new_revision_version,
            properties,
            id: randomUUID(),
            actor,
            business_id: item.business_id,
            label,
          },
        );
        if (
          !current.entities[collection as keyof typeof entities].some(
            (row) => row.business_id === item.business_id,
          ) &&
          current.sources[0]
        )
          await tx.run(
            `MATCH (n:SystemModelElement:${label} {project_id:$project_id,revision_id:$revision_id,business_id:$business_id})
          MATCH (s:SourceRecord {id:$source_id}) MERGE (n)-[:DERIVED_FROM_SOURCE]->(s)`,
            {
              project_id: scope.project_id,
              revision_id: scope.revision_id,
              new_revision_version: scope.new_revision_version,
              business_id: item.business_id,
              source_id: current.sources[0].id,
            },
          );
      }
    }
    await tx.run(
      `MATCH (n:SystemModelElement {project_id:$project_id,revision_id:$revision_id})-[rel]->(m:SystemModelElement {project_id:$project_id,revision_id:$revision_id})
      WHERE type(rel) IN ['DECOMPOSES_FROM','CONTAINS_ASSET','EXPOSES_INTERFACE','CROSSES','CONNECTS_EXTERNAL','PRODUCED_BY','CONSUMED_BY','USES_INTERFACE','SUPPORTS_FUNCTION','TARGETS','TRACE_FROM','TRACE_TO'] DELETE rel`,
      { project_id: scope.project_id, revision_id: scope.revision_id },
    );
    await new SystemModelRepository().createSemanticRelationships(
      tx,
      scope.project_id,
      scope.revision_id,
    );
    await tx.run(
      `MATCH (l:SystemModelElement:TraceLink {project_id:$project_id,revision_id:$revision_id})
      MATCH (a:SystemModelElement {project_id:$project_id,revision_id:$revision_id,entity_type:l.source_type,business_id:l.source_business_id})
      MATCH (b:SystemModelElement {project_id:$project_id,revision_id:$revision_id,entity_type:l.target_type,business_id:l.target_business_id})
      MERGE (l)-[:TRACE_FROM]->(a) MERGE (l)-[:TRACE_TO]->(b)`,
      { project_id: scope.project_id, revision_id: scope.revision_id },
    );
  }
}
