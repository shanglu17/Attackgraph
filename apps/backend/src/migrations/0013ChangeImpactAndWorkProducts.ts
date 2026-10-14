import type { MigrationDefinition } from "./types.js";

const constraints = [
  ["change_impact_assessment_id_unique", "CREATE CONSTRAINT change_impact_assessment_id_unique IF NOT EXISTS FOR (node:ChangeImpactAssessment) REQUIRE node.id IS UNIQUE"],
  ["change_impact_assessment_scope_business_unique", "CREATE CONSTRAINT change_impact_assessment_scope_business_unique IF NOT EXISTS FOR (node:ChangeImpactAssessment) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
  ["impact_item_id_unique", "CREATE CONSTRAINT impact_item_id_unique IF NOT EXISTS FOR (node:ImpactItem) REQUIRE node.id IS UNIQUE"],
  ["impact_item_scope_business_unique", "CREATE CONSTRAINT impact_item_scope_business_unique IF NOT EXISTS FOR (node:ImpactItem) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
  ["impact_disposition_id_unique", "CREATE CONSTRAINT impact_disposition_id_unique IF NOT EXISTS FOR (node:ImpactDisposition) REQUIRE node.id IS UNIQUE"],
  ["impact_disposition_scope_business_unique", "CREATE CONSTRAINT impact_disposition_scope_business_unique IF NOT EXISTS FOR (node:ImpactDisposition) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
] as const;

export const migration0013: MigrationDefinition = {
  id: "0013_change_impact_and_work_products",
  description: "Create scoped identities for change impact assessments, items and human dispositions",
  signature: ["change-impact-and-work-products:v1", ...constraints.map((item) => item[1])].join("\n"),
  risk: "non-destructive",
  steps: ["Create change impact assessment constraints", "Create impact item constraints", "Create human disposition constraints", "Verify all identities"],
  async apply(database) {
    for (const [, query] of constraints) await database.run(query);
  },
  async verify(database) {
    const names = constraints.map((item) => item[0]);
    const result = await database.run("SHOW CONSTRAINTS YIELD name WHERE name IN $names RETURN collect(name) AS names", { names });
    const actual = new Set<string>(result.records[0]?.get("names") ?? []);
    const diagnostics = names.filter((name) => !actual.has(name)).map((name) => "Missing constraint " + name);
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
