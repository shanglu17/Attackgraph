import type { MigrationDefinition } from "./types.js";

const constraints = [
  {
    name: "core_entity_id_unique",
    query: "CREATE CONSTRAINT core_entity_id_unique IF NOT EXISTS FOR (node:CoreEntity) REQUIRE node.id IS UNIQUE",
  },
  {
    name: "core_entity_business_scope_type_unique",
    query: "CREATE CONSTRAINT core_entity_business_scope_type_unique IF NOT EXISTS FOR (node:CoreEntity) REQUIRE (node.project_id, node.revision_id, node.entity_type, node.business_id) IS UNIQUE",
  },
  {
    name: "review_decision_id_unique",
    query: "CREATE CONSTRAINT review_decision_id_unique IF NOT EXISTS FOR (node:ReviewDecision) REQUIRE node.id IS UNIQUE",
  },
  {
    name: "review_decision_business_scope_unique",
    query: "CREATE CONSTRAINT review_decision_business_scope_unique IF NOT EXISTS FOR (node:ReviewDecision) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE",
  },
];

export const migration0010: MigrationDefinition = {
  id: "0010_engineering_case_core",
  description: "Introduce the Phase 3 standard-neutral engineering case identity boundary",
  signature: ["engineering-case-core:v1", "MATCH (node:SystemModelElement) SET node:CoreEntity", ...constraints.map((item) => item.query)].join("\n"),
  risk: "non-destructive",
  steps: [
    "Backfill CoreEntity on system-model entities and trace links",
    "Create scoped CoreEntity identity constraints",
    "Create ReviewDecision identity constraints",
    "Verify constraints and CoreEntity backfill",
  ],
  async apply(database) {
    await database.run("MATCH (node:SystemModelElement) SET node:CoreEntity");
    for (const constraint of constraints) await database.run(constraint.query);
  },
  async verify(database) {
    const names = constraints.map((item) => item.name);
    const result = await database.run("SHOW CONSTRAINTS YIELD name WHERE name IN $names RETURN collect(name) AS names", { names });
    const actual = new Set<string>(result.records[0]?.get("names") ?? []);
    const diagnostics = names.filter((name) => !actual.has(name)).map((name) => "Missing constraint " + name);
    const backfill = await database.run("MATCH (node:SystemModelElement) WHERE NOT node:CoreEntity RETURN count(node) AS count");
    const missing = Number(backfill.records[0]?.get("count") ?? 0);
    if (missing > 0) diagnostics.push(missing + " SystemModelElement nodes are missing CoreEntity");
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
