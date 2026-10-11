import type { MigrationDatabase, MigrationDefinition } from "./types.js";

const labels = [
  "Asset",
  "Function",
  "Interface",
  "DataFlow",
  "SecurityBoundary",
  "ExternalEntity",
  "EvidenceRecord",
  "TraceLink",
] as const;

const constraints = [
  ...labels.flatMap((label) => [
    {
      name: `system_model_${label.toLowerCase()}_id_unique`,
      query: `CREATE CONSTRAINT system_model_${label.toLowerCase()}_id_unique IF NOT EXISTS FOR (node:${label}) REQUIRE node.id IS UNIQUE`,
    },
    {
      name: `system_model_${label.toLowerCase()}_business_scope_unique`,
      query: `CREATE CONSTRAINT system_model_${label.toLowerCase()}_business_scope_unique IF NOT EXISTS FOR (node:${label}) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE`,
    },
  ]),
  {
    name: "source_record_id_unique",
    query: "CREATE CONSTRAINT source_record_id_unique IF NOT EXISTS FOR (node:SourceRecord) REQUIRE node.id IS UNIQUE",
  },
  {
    name: "source_record_business_scope_unique",
    query: "CREATE CONSTRAINT source_record_business_scope_unique IF NOT EXISTS FOR (node:SourceRecord) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE",
  },
];

function count(result: Awaited<ReturnType<MigrationDatabase["run"]>>, key: string): number {
  const value = result.records[0]?.get(key);
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") {
    return value.toNumber();
  }
  return Number(value ?? 0);
}

export const migration0007: MigrationDefinition = {
  id: "0007_system_model_core",
  description: "Create scoped identity constraints for the generic Phase 2 system model and provenance records",
  signature: ["system-model-core:v1", ...constraints.map(({ query }) => query)].join("\n"),
  risk: "non-destructive",
  steps: [
    "Create internal UUID constraints for generic system-model entities",
    "Create project/revision-scoped business identity constraints",
    "Create SourceRecord identity and scope constraints",
    "Verify constraints and reject any cross-scope semantic relationship",
  ],
  async apply(database) {
    for (const constraint of constraints) await database.run(constraint.query);
  },
  async verify(database) {
    const diagnostics: string[] = [];
    const names = constraints.map(({ name }) => name);
    const result = await database.run(
      `SHOW CONSTRAINTS YIELD name WHERE name IN $names RETURN collect(name) AS names`,
      { names },
    );
    const actual = new Set<string>(result.records[0]?.get("names") ?? []);
    for (const name of names) if (!actual.has(name)) diagnostics.push(`Missing constraint ${name}`);

    const invalidNodes = await database.run(
      `MATCH (node:SystemModelElement)
       WHERE node.id IS NULL OR node.business_id IS NULL OR node.project_id IS NULL OR node.revision_id IS NULL
          OR node.entity_type IS NULL
       RETURN count(node) AS count`,
    );
    const invalidNodeCount = count(invalidNodes, "count");
    if (invalidNodeCount > 0) diagnostics.push(`${invalidNodeCount} system-model node(s) have incomplete scoped identity`);

    const crossScope = await database.run(
      `MATCH (left:SystemModelElement)-[relationship]->(right:SystemModelElement)
       WHERE left.project_id <> right.project_id OR left.revision_id <> right.revision_id
       RETURN count(relationship) AS count`,
    );
    const crossScopeCount = count(crossScope, "count");
    if (crossScopeCount > 0) diagnostics.push(`${crossScopeCount} cross-scope system-model relationship(s) exist`);
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
