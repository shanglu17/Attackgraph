import type { MigrationDefinition } from "./types.js";

const constraints = [
  {
    name: "system_model_element_id_unique",
    query: "CREATE CONSTRAINT system_model_element_id_unique IF NOT EXISTS FOR (node:SystemModelElement) REQUIRE node.id IS UNIQUE",
  },
  {
    name: "system_model_element_business_scope_unique",
    query: "CREATE CONSTRAINT system_model_element_business_scope_unique IF NOT EXISTS FOR (node:SystemModelElement) REQUIRE (node.project_id, node.revision_id, node.entity_type, node.business_id) IS UNIQUE",
  },
];

export const migration0008: MigrationDefinition = {
  id: "0008_system_model_element_identity",
  description: "Enforce identity across all generic system-model element types",
  signature: ["system-model-element-identity:v1", ...constraints.map(({ query }) => query)].join("\n"),
  risk: "non-destructive",
  steps: [
    "Create a common internal UUID constraint for SystemModelElement",
    "Create a common project/revision/type/business identity constraint",
    "Verify both common constraints exist",
  ],
  async apply(database) {
    for (const constraint of constraints) await database.run(constraint.query);
  },
  async verify(database) {
    const names = constraints.map(({ name }) => name);
    const result = await database.run(
      "SHOW CONSTRAINTS YIELD name WHERE name IN $names RETURN collect(name) AS names",
      { names },
    );
    const actual = new Set<string>(result.records[0]?.get("names") ?? []);
    const diagnostics = names.filter((name) => !actual.has(name)).map((name) => `Missing constraint ${name}`);
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
