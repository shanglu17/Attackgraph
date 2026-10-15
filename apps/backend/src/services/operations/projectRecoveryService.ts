import { createHash } from "node:crypto";
import neo4j, { type ManagedTransaction } from "neo4j-driver";
import { getDriver } from "../../db/neo4j.js";

type EncodedValue = null | boolean | number | string | EncodedValue[] | { [key: string]: EncodedValue };

interface SnapshotNode {
  key: string;
  labels: string[];
  properties: Record<string, EncodedValue>;
}

interface SnapshotRelationship {
  type: string;
  start_key: string;
  end_key: string;
  properties: Record<string, EncodedValue>;
}

export interface ProjectRecoverySnapshot {
  format: "astra-project-recovery.v1";
  project_id: string;
  created_at: string;
  nodes: SnapshotNode[];
  relationships: SnapshotRelationship[];
  semantic_hash: string;
}

const identifierPattern = /^[A-Za-z][A-Za-z0-9_]*$/;
const temporalNames = new Set(["DateTime", "LocalDateTime", "Date", "Time", "LocalTime", "Duration"]);

function encode(value: unknown): EncodedValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("snapshot cannot encode non-finite numbers");
    return value;
  }
  if (neo4j.isInt(value)) return { __astra_type: "Integer", value: value.toString() };
  if (Array.isArray(value)) return value.map(encode);
  if (typeof value === "object" && value !== null) {
    const constructorName = value.constructor?.name;
    if (constructorName && temporalNames.has(constructorName) && "toString" in value) {
      return { __astra_type: constructorName, value: String(value) };
    }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encode(item)]));
  }
  throw new TypeError(`snapshot cannot encode value of type ${typeof value}`);
}

function decodeRegular(value: EncodedValue): unknown {
  if (Array.isArray(value)) return value.map(decodeRegular);
  if (value && typeof value === "object") {
    if (value.__astra_type === "Integer" && typeof value.value === "string") return neo4j.int(value.value);
    if (typeof value.__astra_type === "string" && temporalNames.has(value.__astra_type)) return undefined;
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, decodeRegular(item)]));
  }
  return value;
}

function assertIdentifier(value: string, description: string): string {
  if (!identifierPattern.test(value)) throw new TypeError(`invalid ${description}: ${value}`);
  return value;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

function nodeIdentity(node: SnapshotNode): string {
  const id = node.properties.id ?? node.properties.business_id;
  return typeof id === "string" ? id : node.key;
}

export function snapshotSemanticHash(nodes: SnapshotNode[], relationships: SnapshotRelationship[]): string {
  const identityByKey = new Map(nodes.map((node) => [node.key, nodeIdentity(node)]));
  const semantic = {
    nodes: nodes.map((node) => ({ labels: [...node.labels].sort(), properties: node.properties })).sort((left, right) => canonical(left).localeCompare(canonical(right))),
    relationships: relationships.map((relationship) => ({
      type: relationship.type,
      start: identityByKey.get(relationship.start_key) ?? relationship.start_key,
      end: identityByKey.get(relationship.end_key) ?? relationship.end_key,
      properties: relationship.properties,
    })).sort((left, right) => canonical(left).localeCompare(canonical(right))),
  };
  return createHash("sha256").update(canonical(semantic), "utf8").digest("hex");
}

async function setTemporalProperties(transaction: ManagedTransaction, labelExpression: string, restoreKey: string, properties: Record<string, EncodedValue>) {
  for (const [property, encoded] of Object.entries(properties)) {
    if (!encoded || typeof encoded !== "object" || Array.isArray(encoded)) continue;
    const type = typeof encoded.__astra_type === "string" ? encoded.__astra_type : "";
    const value = typeof encoded.value === "string" ? encoded.value : undefined;
    if (!temporalNames.has(type) || value === undefined) continue;
    const conversion = ({ DateTime: "datetime", LocalDateTime: "localdatetime", Date: "date", Time: "time", LocalTime: "localtime", Duration: "duration" } as Record<string, string>)[type];
    assertIdentifier(property, "property name");
    await transaction.run(
      `MATCH (node${labelExpression} {_astra_restore_key: $restore_key}) SET node.\`${property}\` = ${conversion}($value)`,
      { restore_key: restoreKey, value },
    );
  }
}

export class ProjectRecoveryService {
  async capture(projectId: string): Promise<ProjectRecoverySnapshot> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (transaction) => {
        const nodeResult = await transaction.run(
          `MATCH (node)
           WHERE (node:Project AND node.id = $project_id) OR node.project_id = $project_id
           RETURN elementId(node) AS key, labels(node) AS labels, properties(node) AS properties
           ORDER BY key`, { project_id: projectId },
        );
        if (nodeResult.records.length === 0) throw new Error(`project '${projectId}' does not exist`);
        const nodes: SnapshotNode[] = nodeResult.records.map((record) => ({
          key: String(record.get("key")), labels: (record.get("labels") as unknown[]).map(String).sort(),
          properties: Object.fromEntries(Object.entries(record.get("properties") as Record<string, unknown>).map(([key, value]) => [key, encode(value)])),
        }));
        const keys = nodes.map((node) => node.key);
        const relationshipResult = await transaction.run(
          `MATCH (start)-[relationship]->(end)
           WHERE elementId(start) IN $keys AND elementId(end) IN $keys
           RETURN elementId(start) AS start_key, type(relationship) AS type, elementId(end) AS end_key, properties(relationship) AS properties
           ORDER BY start_key, type, end_key`, { keys },
        );
        const relationships: SnapshotRelationship[] = relationshipResult.records.map((record) => ({
          type: String(record.get("type")), start_key: String(record.get("start_key")), end_key: String(record.get("end_key")),
          properties: Object.fromEntries(Object.entries(record.get("properties") as Record<string, unknown>).map(([key, value]) => [key, encode(value)])),
        }));
        return {
          format: "astra-project-recovery.v1", project_id: projectId, created_at: new Date().toISOString(),
          nodes, relationships, semantic_hash: snapshotSemanticHash(nodes, relationships),
        };
      });
    } finally {
      await session.close();
    }
  }

  async deleteProject(projectId: string): Promise<number> {
    if (!/^[0-9a-f-]{36}$/i.test(projectId)) throw new TypeError("project recovery deletion requires an explicit UUID");
    const session = getDriver().session();
    try {
      return await session.executeWrite(async (transaction) => {
        const result = await transaction.run(
          `MATCH (node)
           WHERE (node:Project AND node.id = $project_id) OR node.project_id = $project_id
           WITH collect(node) AS nodes, count(node) AS count
           FOREACH (node IN nodes | DETACH DELETE node)
           RETURN count`, { project_id: projectId },
        );
        return Number(result.records[0]?.get("count")?.toNumber?.() ?? result.records[0]?.get("count") ?? 0);
      });
    } finally {
      await session.close();
    }
  }

  async restore(snapshot: ProjectRecoverySnapshot): Promise<void> {
    if (snapshot.format !== "astra-project-recovery.v1") throw new TypeError("unsupported recovery snapshot format");
    const calculatedHash = snapshotSemanticHash(snapshot.nodes, snapshot.relationships);
    if (calculatedHash !== snapshot.semantic_hash) throw new Error("recovery snapshot semantic hash mismatch");
    const session = getDriver().session();
    try {
      await session.executeWrite(async (transaction) => {
        const existing = await transaction.run(
          `MATCH (node) WHERE (node:Project AND node.id = $project_id) OR node.project_id = $project_id RETURN count(node) AS count`,
          { project_id: snapshot.project_id },
        );
        const count = Number(existing.records[0]?.get("count")?.toNumber?.() ?? existing.records[0]?.get("count") ?? 0);
        if (count !== 0) throw new Error(`refusing to restore project '${snapshot.project_id}' because scoped data already exists`);
        for (const node of snapshot.nodes) {
          const labels = node.labels.map((label) => `:\`${assertIdentifier(label, "node label")}\``).join("");
          const regular = Object.fromEntries(Object.entries(node.properties).flatMap(([key, value]) => {
            const decoded = decodeRegular(value);
            return decoded === undefined ? [] : [[key, decoded]];
          }));
          await transaction.run(`CREATE (node${labels}) SET node = $properties, node._astra_restore_key = $restore_key`, { properties: regular, restore_key: node.key });
          await setTemporalProperties(transaction, labels, node.key, node.properties);
        }
        for (const relationship of snapshot.relationships) {
          const type = assertIdentifier(relationship.type, "relationship type");
          const regular = Object.fromEntries(Object.entries(relationship.properties).flatMap(([key, value]) => {
            const decoded = decodeRegular(value);
            return decoded === undefined ? [] : [[key, decoded]];
          }));
          await transaction.run(
            `MATCH (start {_astra_restore_key: $start_key}), (end {_astra_restore_key: $end_key})
             CREATE (start)-[relationship:\`${type}\`]->(end) SET relationship = $properties`,
            { start_key: relationship.start_key, end_key: relationship.end_key, properties: regular },
          );
        }
        await transaction.run("MATCH (node) WHERE node._astra_restore_key IS NOT NULL REMOVE node._astra_restore_key");
      });
    } finally {
      await session.close();
    }
  }
}
