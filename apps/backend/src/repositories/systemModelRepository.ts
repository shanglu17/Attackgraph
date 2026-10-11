import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import {
  systemModelContractVersion,
  type StoredSystemModel,
  type SystemModelImportPayload,
} from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";

type EntityCollection = Exclude<keyof SystemModelImportPayload["entities"], "trace_links">;

const entityDefinitions: Array<{
  collection: EntityCollection;
  label: string;
  type: string;
}> = [
  { collection: "assets", label: "Asset", type: "Asset" },
  { collection: "functions", label: "Function", type: "Function" },
  { collection: "interfaces", label: "Interface", type: "Interface" },
  { collection: "data_flows", label: "DataFlow", type: "DataFlow" },
  { collection: "security_boundaries", label: "SecurityBoundary", type: "SecurityBoundary" },
  { collection: "external_entities", label: "ExternalEntity", type: "ExternalEntity" },
  { collection: "evidence_records", label: "EvidenceRecord", type: "EvidenceRecord" },
  { collection: "draft_threats", label: "DraftThreat", type: "DraftThreat" },
];

export interface ExistingSystemModelScope {
  exists: boolean;
  revision_version?: number;
  identities: Set<string>;
}

export interface CreatedSystemModelIds extends Record<string, string[]> {
  sources: string[];
  assets: string[];
  functions: string[];
  interfaces: string[];
  data_flows: string[];
  security_boundaries: string[];
  external_entities: string[];
  evidence_records: string[];
  draft_threats: string[];
  trace_links: string[];
}

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") {
    return value.toNumber();
  }
  return Number(value);
}

function jsonProperties(input: Record<string, unknown>): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (key === "source_locator") {
      properties.source_locator_json = JSON.stringify(value ?? {});
    } else if (value !== undefined) {
      properties[key] = value;
    }
  }
  return properties;
}

function identity(type: string, businessId: string): string {
  return `${type}:${businessId}`;
}

function nodeProperties(record: { get(key: string): unknown }, key: string): Record<string, unknown> {
  const node = record.get(key);
  if (typeof node !== "object" || node === null || !("properties" in node)) {
    throw new TypeError(`Expected Neo4j node '${key}'`);
  }
  return (node as { properties: Record<string, unknown> }).properties;
}

function restore<T>(properties: Record<string, unknown>): T & { id: string } {
  const output = { ...properties } as Record<string, unknown>;
  if (typeof output.source_locator_json === "string") {
    output.source_locator = JSON.parse(output.source_locator_json);
  }
  delete output.source_locator_json;
  delete output.project_id;
  delete output.revision_id;
  delete output.entity_type;
  delete output.created_at;
  return output as T & { id: string };
}

export class SystemModelConflictError extends Error {
  readonly statusCode = 409;
  constructor(message: string) {
    super(message);
    this.name = "SystemModelConflictError";
  }
}

export class SystemModelScopeNotFoundError extends Error {
  readonly statusCode = 404;
  constructor(projectId: string, revisionId: string) {
    super(`revision '${revisionId}' was not found in project '${projectId}'`);
    this.name = "SystemModelScopeNotFoundError";
  }
}

export class SystemModelRepository {
  async inspectScope(projectId: string, revisionId: string): Promise<ExistingSystemModelScope> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((transaction) =>
        transaction.run(
          `OPTIONAL MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id})
           OPTIONAL MATCH (element:SystemModelElement {project_id: $project_id, revision_id: $revision_id})
           OPTIONAL MATCH (source:SourceRecord {project_id: $project_id, revision_id: $revision_id})
           RETURN revision.version AS revision_version,
                  collect(DISTINCT element.entity_type + ':' + element.business_id) +
                  collect(DISTINCT 'SourceRecord:' + source.business_id) AS identities`,
          { project_id: projectId, revision_id: revisionId },
        ),
      );
      const version = result.records[0]?.get("revision_version");
      return {
        exists: version !== null && version !== undefined,
        revision_version: version === null || version === undefined ? undefined : numeric(version),
        identities: new Set((result.records[0]?.get("identities") ?? []).filter(Boolean).map(String)),
      };
    } finally {
      await session.close();
    }
  }

  async assertCreatable(
    transaction: ManagedTransaction,
    projectId: string,
    revisionId: string,
    payload: SystemModelImportPayload,
  ): Promise<void> {
    const incoming = entityDefinitions.flatMap(({ collection, type }) =>
      payload.entities[collection].map((entity) => ({ type, business_id: entity.business_id })),
    );
    incoming.push(...payload.entities.trace_links.map((link) => ({ type: "TraceLink", business_id: link.business_id })));
    incoming.push({ type: "SourceRecord", business_id: payload.source.business_id });
    const result = await transaction.run(
      `UNWIND $incoming AS item
       OPTIONAL MATCH (existing {project_id: $project_id, revision_id: $revision_id, business_id: item.business_id})
       WHERE (item.type = 'SourceRecord' AND existing:SourceRecord)
          OR (item.type <> 'SourceRecord' AND existing:SystemModelElement AND existing.entity_type = item.type)
       WITH item, existing WHERE existing IS NOT NULL
       RETURN collect(item.type + ':' + item.business_id) AS conflicts`,
      { project_id: projectId, revision_id: revisionId, incoming },
    );
    const conflicts = (result.records[0]?.get("conflicts") ?? []).map(String);
    if (conflicts.length > 0) {
      throw new SystemModelConflictError(`create-only import conflicts with existing identities: ${conflicts.join(", ")}`);
    }

    const known = new Set(incoming.filter((item) => item.type !== "TraceLink").map((item) => identity(item.type, item.business_id)));
    const existing = await transaction.run(
      `MATCH (element:SystemModelElement {project_id: $project_id, revision_id: $revision_id})
       RETURN collect(element.entity_type + ':' + element.business_id) AS identities`,
      { project_id: projectId, revision_id: revisionId },
    );
    for (const item of existing.records[0]?.get("identities") ?? []) known.add(String(item));

    const missing: string[] = [];
    const requireIdentity = (type: string, businessId: string, context: string) => {
      if (!known.has(identity(type, businessId))) missing.push(`${context} -> ${type}:${businessId}`);
    };
    for (const item of payload.entities.functions) {
      if (item.parent_function_business_id) requireIdentity("Function", item.parent_function_business_id, item.business_id);
    }
    for (const item of payload.entities.security_boundaries) {
      for (const ref of item.member_asset_business_ids) requireIdentity("Asset", ref, item.business_id);
    }
    for (const item of payload.entities.interfaces) {
      for (const ref of item.asset_business_ids) requireIdentity("Asset", ref, item.business_id);
      if (item.boundary_business_id) requireIdentity("SecurityBoundary", item.boundary_business_id, item.business_id);
      if (item.external_entity_business_id) requireIdentity("ExternalEntity", item.external_entity_business_id, item.business_id);
    }
    for (const item of payload.entities.data_flows) {
      requireIdentity("Asset", item.producer_asset_business_id, item.business_id);
      requireIdentity("Asset", item.consumer_asset_business_id, item.business_id);
      if (item.interface_business_id) requireIdentity("Interface", item.interface_business_id, item.business_id);
      for (const ref of item.supported_function_business_ids) requireIdentity("Function", ref, item.business_id);
    }
    for (const item of payload.entities.draft_threats) {
      requireIdentity("Asset", item.target_asset_business_id, item.business_id);
    }
    for (const link of payload.entities.trace_links) {
      requireIdentity(link.source.type, link.source.business_id, link.business_id);
      requireIdentity(link.target.type, link.target.business_id, link.business_id);
    }
    if (missing.length > 0) {
      throw new SystemModelConflictError(`unresolved scoped references: ${missing.join(", ")}`);
    }
  }

  async createImport(
    transaction: ManagedTransaction,
    input: {
      project_id: string;
      revision_id: string;
      actor: string;
      revision_version: number;
      payload: SystemModelImportPayload;
    },
  ): Promise<CreatedSystemModelIds> {
    await this.assertCreatable(transaction, input.project_id, input.revision_id, input.payload);
    const created: CreatedSystemModelIds = {
      sources: [randomUUID()], assets: [], functions: [], interfaces: [], data_flows: [],
      security_boundaries: [], external_entities: [], evidence_records: [], trace_links: [],
      draft_threats: [],
    };
    const sourceId = created.sources[0];
    await transaction.run(
      `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
       CREATE (source:SourceRecord {
         id: $id, project_id: $project_id, revision_id: $revision_id,
         business_id: $business_id, source_type: $source_type, name: $name,
         content_hash: $content_hash, media_type: $media_type,
         parser_name: $parser_name, parser_version: $parser_version,
         contract_version: $contract_version,
         created_at: datetime(), created_by: $actor
       })
       CREATE (revision)-[:CONTAINS]->(source)`,
      {
        ...input.payload.source,
        id: sourceId,
        project_id: input.project_id,
        revision_id: input.revision_id,
        actor: input.actor,
        contract_version: systemModelContractVersion,
        media_type: input.payload.source.media_type ?? null,
      },
    );

    for (const definition of entityDefinitions) {
      const rows = input.payload.entities[definition.collection].map((entity, index) => {
        const id = randomUUID();
        created[definition.collection].push(id);
        const sourceLocator = entity.source_locator ?? {
          json_pointer: `/entities/${definition.collection}/${index}`,
          field_locators: {},
        };
        return { id, properties: jsonProperties({ ...entity, source_locator: sourceLocator }) };
      });
      if (rows.length === 0) continue;
      await transaction.run(
        `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
         MATCH (source:SourceRecord {id: $source_id, project_id: $project_id, revision_id: $revision_id})
         UNWIND $rows AS row
         CREATE (entity:SystemModelElement:${definition.label})
         SET entity = row.properties,
             entity.id = row.id,
             entity.project_id = $project_id,
             entity.revision_id = $revision_id,
             entity.entity_type = $entity_type,
             entity.created_at = datetime(),
             entity.created_by = $actor,
             entity.revision_version = $revision_version
         CREATE (revision)-[:CONTAINS]->(entity)
         CREATE (entity)-[:DERIVED_FROM_SOURCE {
           source_locator_json: entity.source_locator_json
         }]->(source)`,
        {
          rows,
          source_id: sourceId,
          project_id: input.project_id,
          revision_id: input.revision_id,
          actor: input.actor,
          revision_version: input.revision_version,
          entity_type: definition.type,
        },
      );
    }

    await this.createSemanticRelationships(transaction, input.project_id, input.revision_id);

    const traceRows = input.payload.entities.trace_links.map((link, index) => {
      const id = randomUUID();
      created.trace_links.push(id);
      const sourceLocator = link.source_locator ?? {
        json_pointer: `/entities/trace_links/${index}`,
        field_locators: {},
      };
      return { id, properties: jsonProperties({ ...link, source: undefined, target: undefined, source_locator: sourceLocator }), source: link.source, target: link.target };
    });
    if (traceRows.length > 0) {
      await transaction.run(
        `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
         MATCH (sourceRecord:SourceRecord {id: $source_id})
         UNWIND $rows AS row
         MATCH (from:SystemModelElement {project_id: $project_id, revision_id: $revision_id,
           entity_type: row.source.type, business_id: row.source.business_id})
         MATCH (to:SystemModelElement {project_id: $project_id, revision_id: $revision_id,
           entity_type: row.target.type, business_id: row.target.business_id})
         CREATE (link:SystemModelElement:TraceLink)
         SET link = row.properties,
             link.id = row.id, link.project_id = $project_id, link.revision_id = $revision_id,
             link.entity_type = 'TraceLink', link.source_type = row.source.type,
             link.source_business_id = row.source.business_id, link.target_type = row.target.type,
             link.target_business_id = row.target.business_id,
             link.created_at = datetime(), link.created_by = $actor,
             link.revision_version = $revision_version
         CREATE (revision)-[:CONTAINS]->(link)
         CREATE (link)-[:TRACE_FROM]->(from)
         CREATE (link)-[:TRACE_TO]->(to)
         CREATE (link)-[:DERIVED_FROM_SOURCE {source_locator_json: link.source_locator_json}]->(sourceRecord)`,
        {
          rows: traceRows,
          source_id: sourceId,
          project_id: input.project_id,
          revision_id: input.revision_id,
          actor: input.actor,
          revision_version: input.revision_version,
        },
      );
    }
    return created;
  }

  private async createSemanticRelationships(transaction: ManagedTransaction, projectId: string, revisionId: string) {
    const scope = { project_id: projectId, revision_id: revisionId };
    await transaction.run(
      `MATCH (child:Function {project_id: $project_id, revision_id: $revision_id})
       WHERE child.parent_function_business_id IS NOT NULL
       MATCH (parent:Function {project_id: $project_id, revision_id: $revision_id,
         business_id: child.parent_function_business_id})
       MERGE (child)-[:DECOMPOSES_FROM]->(parent)`, scope,
    );
    await transaction.run(
      `MATCH (boundary:SecurityBoundary {project_id: $project_id, revision_id: $revision_id})
       UNWIND boundary.member_asset_business_ids AS asset_id
       MATCH (asset:Asset {project_id: $project_id, revision_id: $revision_id, business_id: asset_id})
       MERGE (boundary)-[:CONTAINS_ASSET]->(asset)`, scope,
    );
    await transaction.run(
      `MATCH (interface:Interface {project_id: $project_id, revision_id: $revision_id})
       UNWIND interface.asset_business_ids AS asset_id
       MATCH (asset:Asset {project_id: $project_id, revision_id: $revision_id, business_id: asset_id})
       MERGE (asset)-[:EXPOSES_INTERFACE]->(interface)`, scope,
    );
    await transaction.run(
      `MATCH (interface:Interface {project_id: $project_id, revision_id: $revision_id})
       WHERE interface.boundary_business_id IS NOT NULL
       MATCH (boundary:SecurityBoundary {project_id: $project_id, revision_id: $revision_id,
         business_id: interface.boundary_business_id})
       MERGE (interface)-[:CROSSES]->(boundary)`, scope,
    );
    await transaction.run(
      `MATCH (interface:Interface {project_id: $project_id, revision_id: $revision_id})
       WHERE interface.external_entity_business_id IS NOT NULL
       MATCH (external:ExternalEntity {project_id: $project_id, revision_id: $revision_id,
         business_id: interface.external_entity_business_id})
       MERGE (interface)-[:CONNECTS_EXTERNAL]->(external)`, scope,
    );
    await transaction.run(
      `MATCH (flow:DataFlow {project_id: $project_id, revision_id: $revision_id})
       MATCH (producer:Asset {project_id: $project_id, revision_id: $revision_id,
         business_id: flow.producer_asset_business_id})
       MATCH (consumer:Asset {project_id: $project_id, revision_id: $revision_id,
         business_id: flow.consumer_asset_business_id})
       MERGE (flow)-[:PRODUCED_BY]->(producer)
       MERGE (flow)-[:CONSUMED_BY]->(consumer)`, scope,
    );
    await transaction.run(
      `MATCH (flow:DataFlow {project_id: $project_id, revision_id: $revision_id})
       WHERE flow.interface_business_id IS NOT NULL
       MATCH (interface:Interface {project_id: $project_id, revision_id: $revision_id,
         business_id: flow.interface_business_id})
       MERGE (flow)-[:USES_INTERFACE]->(interface)`, scope,
    );
    await transaction.run(
      `MATCH (flow:DataFlow {project_id: $project_id, revision_id: $revision_id})
       UNWIND flow.supported_function_business_ids AS function_id
       MATCH (function:Function {project_id: $project_id, revision_id: $revision_id,
         business_id: function_id})
       MERGE (flow)-[:SUPPORTS_FUNCTION]->(function)`, scope,
    );
    await transaction.run(
      `MATCH (threat:DraftThreat {project_id: $project_id, revision_id: $revision_id})
       MATCH (asset:Asset {project_id: $project_id, revision_id: $revision_id,
         business_id: threat.target_asset_business_id})
       MERGE (threat)-[:TARGETS]->(asset)`, scope,
    );
  }

  async read(projectId: string, revisionId: string): Promise<StoredSystemModel> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (transaction) => {
        const revisionResult = await transaction.run(
          `MATCH (:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id})
           RETURN revision.version AS version`,
          { project_id: projectId, revision_id: revisionId },
        );
        if (revisionResult.records.length === 0) throw new SystemModelScopeNotFoundError(projectId, revisionId);
        const output: StoredSystemModel = {
          contract_version: systemModelContractVersion,
          project_id: projectId,
          revision_id: revisionId,
          revision_version: numeric(revisionResult.records[0].get("version")),
          sources: [],
          entities: { assets: [], functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [], evidence_records: [], draft_threats: [], trace_links: [] },
        };
        const sources = await transaction.run(
          `MATCH (source:SourceRecord {project_id: $project_id, revision_id: $revision_id}) RETURN source ORDER BY source.business_id`,
          { project_id: projectId, revision_id: revisionId },
        );
        output.sources = sources.records.map((record) => restore(nodeProperties(record, "source")));
        for (const definition of entityDefinitions) {
          const result = await transaction.run(
            `MATCH (entity:SystemModelElement:${definition.label} {project_id: $project_id, revision_id: $revision_id})
             RETURN entity ORDER BY entity.business_id`,
            { project_id: projectId, revision_id: revisionId },
          );
          (output.entities[definition.collection] as unknown[]) = result.records.map((record) => restore(nodeProperties(record, "entity")));
        }
        const links = await transaction.run(
          `MATCH (link:SystemModelElement:TraceLink {project_id: $project_id, revision_id: $revision_id}) RETURN link ORDER BY link.business_id`,
          { project_id: projectId, revision_id: revisionId },
        );
        output.entities.trace_links = links.records.map((record) => {
          const link = restore<Record<string, unknown>>(nodeProperties(record, "link"));
          return {
            ...link,
            source: { type: link.source_type, business_id: link.source_business_id },
            target: { type: link.target_type, business_id: link.target_business_id },
          } as StoredSystemModel["entities"]["trace_links"][number];
        });
        return output;
      });
    } finally {
      await session.close();
    }
  }
}
