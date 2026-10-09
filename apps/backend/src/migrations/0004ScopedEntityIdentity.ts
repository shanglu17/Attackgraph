import {
  scopedIdentityConstraintNames,
  scopedNodeIdentityDefinitions,
  scopedRelationshipIdentityDefinitions,
  standardKnowledgeConstraintDefinitions,
} from "../services/identity/scopedIdentity.js";
import type { MigrationDatabase, MigrationDefinition, MigrationVerification } from "./types.js";

const uuidPattern =
  "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

const serializedNodeDefinitions = scopedNodeIdentityDefinitions.map(
  ({ label, legacyKey, businessScope }) => ({
    label,
    legacy_key: legacyKey,
    business_scope: businessScope,
  }),
);

const nodeConstraintDefinitions = scopedNodeIdentityDefinitions.flatMap((definition) => {
  const businessProperties =
    definition.businessScope === "analysis-run"
      ? "n.project_id, n.revision_id, n.analysis_batch_id, n.business_id"
      : "n.project_id, n.revision_id, n.business_id";
  return [
    {
      name: definition.idConstraint,
      query: `CREATE CONSTRAINT ${definition.idConstraint} IF NOT EXISTS FOR (n:${definition.label}) REQUIRE n.id IS UNIQUE`,
    },
    {
      name: definition.businessConstraint,
      query: `CREATE CONSTRAINT ${definition.businessConstraint} IF NOT EXISTS FOR (n:${definition.label}) REQUIRE (${businessProperties}) IS UNIQUE`,
    },
  ];
});

const relationshipConstraintDefinitions = scopedRelationshipIdentityDefinitions.flatMap((definition) => [
  {
    name: definition.idConstraint,
    query: `CREATE CONSTRAINT ${definition.idConstraint} IF NOT EXISTS FOR ()-[r:${definition.relationshipType}]-() REQUIRE r.id IS UNIQUE`,
  },
  {
    name: definition.businessConstraint,
    query: `CREATE CONSTRAINT ${definition.businessConstraint} IF NOT EXISTS FOR ()-[r:${definition.relationshipType}]-() REQUIRE (r.project_id, r.revision_id, r.business_id) IS UNIQUE`,
  },
]);

const allConstraintDefinitions = [
  ...nodeConstraintDefinitions,
  ...relationshipConstraintDefinitions,
  ...standardKnowledgeConstraintDefinitions,
];

function count(result: Awaited<ReturnType<MigrationDatabase["run"]>>, key: string): number {
  const value = result.records[0]?.get(key);
  if (typeof value === "number") return value;
  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    return value.toNumber();
  }
  return Number(value ?? 0);
}

async function assertPreconditions(database: MigrationDatabase): Promise<void> {
  const incomplete = await database.run(
    `UNWIND $definitions AS definition
     MATCH (node)
     WHERE definition.label IN labels(node)
       AND (
         node.project_id IS NULL OR node.revision_id IS NULL
         OR node[definition.legacy_key] IS NULL
         OR trim(toString(node[definition.legacy_key])) = ''
         OR (definition.business_scope = 'analysis-run' AND node.analysis_batch_id IS NULL)
       )
     RETURN count(node) AS count`,
    { definitions: serializedNodeDefinitions },
  );
  if (count(incomplete, "count") > 0) {
    throw new Error("Scoped identity migration requires every registered node to have project/revision scope and a legacy business key");
  }

  const duplicateBusinessIds = await database.run(
    `UNWIND $definitions AS definition
     MATCH (node)
     WHERE definition.label IN labels(node)
     WITH definition, node.project_id AS project_id, node.revision_id AS revision_id,
          CASE WHEN definition.business_scope = 'analysis-run' THEN node.analysis_batch_id ELSE '' END AS nested_scope,
          coalesce(node.business_id, node.legacy_id, toString(node[definition.legacy_key])) AS business_id,
          count(node) AS occurrences
     WHERE occurrences > 1
     RETURN count(*) AS count`,
    { definitions: serializedNodeDefinitions },
  );
  if (count(duplicateBusinessIds, "count") > 0) {
    throw new Error("Duplicate business ids exist inside a project/revision identity scope");
  }

  const invalidExistingIds = await database.run(
    `UNWIND $definitions AS definition
     MATCH (node)
     WHERE definition.label IN labels(node)
       AND node.id IS NOT NULL
       AND NOT toString(node.id) =~ $uuid_pattern
     RETURN count(node) AS count`,
    { definitions: serializedNodeDefinitions, uuid_pattern: uuidPattern },
  );
  if (count(invalidExistingIds, "count") > 0) {
    throw new Error("Registered nodes contain non-UUID internal ids");
  }

  const invalidEdges = await database.run(
    `MATCH (source)-[edge:ASSET_EDGE]->(target)
     WHERE edge.edge_id IS NULL OR trim(toString(edge.edge_id)) = ''
        OR source.project_id IS NULL OR source.revision_id IS NULL
        OR target.project_id IS NULL OR target.revision_id IS NULL
        OR source.project_id <> target.project_id
        OR source.revision_id <> target.revision_id
        OR (edge.id IS NOT NULL AND NOT toString(edge.id) =~ $uuid_pattern)
     RETURN count(edge) AS count`,
    { uuid_pattern: uuidPattern },
  );
  if (count(invalidEdges, "count") > 0) {
    throw new Error("ASSET_EDGE identities require a legacy edge id and same-scope endpoints");
  }

  const duplicateEdges = await database.run(
    `MATCH (source)-[edge:ASSET_EDGE]->(target)
     WITH source.project_id AS project_id, source.revision_id AS revision_id,
          coalesce(edge.business_id, edge.legacy_id, edge.edge_id) AS business_id,
          count(edge) AS occurrences
     WHERE occurrences > 1
     RETURN count(*) AS count`,
  );
  if (count(duplicateEdges, "count") > 0) {
    throw new Error("Duplicate ASSET_EDGE business ids exist inside a project/revision scope");
  }
}

async function verifyIdentity(database: MigrationDatabase): Promise<MigrationVerification> {
  const diagnostics: string[] = [];
  const expectedNames = [
    ...scopedIdentityConstraintNames,
    ...standardKnowledgeConstraintDefinitions.map(({ name }) => name),
  ];
  const constraints = await database.run(
    `SHOW CONSTRAINTS YIELD name
     WHERE name IN $constraint_names
     RETURN collect(name) AS names`,
    { constraint_names: expectedNames },
  );
  const actualNames = new Set<string>(constraints.records[0]?.get("names") ?? []);
  for (const name of expectedNames) {
    if (!actualNames.has(name)) diagnostics.push(`Missing constraint ${name}`);
  }

  const invalidNodes = await database.run(
    `UNWIND $definitions AS definition
     MATCH (node)
     WHERE definition.label IN labels(node)
       AND (
         node.id IS NULL OR NOT toString(node.id) =~ $uuid_pattern
         OR node.project_id IS NULL OR node.revision_id IS NULL
         OR node.business_id IS NULL OR trim(toString(node.business_id)) = ''
         OR node.legacy_id IS NULL OR trim(toString(node.legacy_id)) = ''
         OR (definition.business_scope = 'analysis-run' AND node.analysis_batch_id IS NULL)
       )
     RETURN count(node) AS count`,
    { definitions: serializedNodeDefinitions, uuid_pattern: uuidPattern },
  );
  const invalidNodeCount = count(invalidNodes, "count");
  if (invalidNodeCount > 0) diagnostics.push(`${invalidNodeCount} registered node(s) have invalid scoped identity`);

  const invalidEdges = await database.run(
    `MATCH (source)-[edge:ASSET_EDGE]->(target)
     WHERE edge.id IS NULL OR NOT toString(edge.id) =~ $uuid_pattern
        OR edge.project_id IS NULL OR edge.revision_id IS NULL
        OR edge.business_id IS NULL OR edge.legacy_id IS NULL
        OR source.project_id <> edge.project_id OR target.project_id <> edge.project_id
        OR source.revision_id <> edge.revision_id OR target.revision_id <> edge.revision_id
     RETURN count(edge) AS count`,
    { uuid_pattern: uuidPattern },
  );
  const invalidEdgeCount = count(invalidEdges, "count");
  if (invalidEdgeCount > 0) diagnostics.push(`${invalidEdgeCount} ASSET_EDGE relationship(s) have invalid scoped identity`);

  return { ok: diagnostics.length === 0, diagnostics };
}

export const migration0004: MigrationDefinition = {
  id: "0004_scoped_entity_identity",
  description: "Backfill internal UUIDs and project/revision-scoped business identities",
  signature: [
    "scoped-entity-identity:v1",
    JSON.stringify(serializedNodeDefinitions),
    ...allConstraintDefinitions.map(({ query }) => query),
  ].join("\n"),
  risk: "non-destructive",
  steps: [
    "Verify every registered legacy entity has complete project/revision scope and a business key",
    "Backfill stable internal UUID, business_id and legacy_id on registered nodes",
    "Backfill scoped identity on ASSET_EDGE relationships from their endpoints",
    "Create internal-id and scoped-business-id constraints",
  ],
  async apply(database) {
    await assertPreconditions(database);
    await database.run(
      `UNWIND $definitions AS definition
       MATCH (node)
       WHERE definition.label IN labels(node)
       SET node.id = coalesce(node.id, randomUUID()),
           node.business_id = coalesce(node.business_id, node.legacy_id, toString(node[definition.legacy_key])),
           node.legacy_id = coalesce(node.legacy_id, toString(node[definition.legacy_key])),
           node.legacy_label = coalesce(node.legacy_label, definition.label),
           node.identity_schema_version = 'p1.5-v1'`,
      { definitions: serializedNodeDefinitions },
    );
    await database.run(
      `MATCH (source)-[edge:ASSET_EDGE]->(target)
       SET edge.id = coalesce(edge.id, randomUUID()),
           edge.project_id = source.project_id,
           edge.model_id = coalesce(edge.model_id, source.model_id),
           edge.revision_id = source.revision_id,
           edge.business_id = coalesce(edge.business_id, edge.legacy_id, edge.edge_id),
           edge.legacy_id = coalesce(edge.legacy_id, edge.edge_id),
           edge.identity_schema_version = 'p1.5-v1'`,
    );
    for (const { query } of allConstraintDefinitions) await database.run(query);
  },
  verify: verifyIdentity,
};
