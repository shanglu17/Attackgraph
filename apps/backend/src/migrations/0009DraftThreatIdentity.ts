import type { MigrationDefinition } from "./types.js";

const constraints = [
  {
    name: "draft_threat_id_unique",
    query: "CREATE CONSTRAINT draft_threat_id_unique IF NOT EXISTS FOR (node:DraftThreat) REQUIRE node.id IS UNIQUE",
  },
  {
    name: "draft_threat_business_scope_unique",
    query: "CREATE CONSTRAINT draft_threat_business_scope_unique IF NOT EXISTS FOR (node:DraftThreat) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE",
  },
];

export const migration0009: MigrationDefinition = {
  id: "0009_draft_threat_identity",
  description: "Add scoped identity constraints for the VG-1 DraftThreat slice",
  signature: ["draft-threat-identity:v1", ...constraints.map(({ query }) => query)].join("\n"),
  risk: "non-destructive",
  steps: [
    "Create DraftThreat internal UUID constraint",
    "Create DraftThreat project/revision business identity constraint",
    "Verify both constraints exist",
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
