import { analysisMethods } from "../services/analysis/methodRegistry.js";
import type { MigrationDefinition } from "./types.js";

const constraints = [
  ["analysis_method_identity_unique", "CREATE CONSTRAINT analysis_method_identity_unique IF NOT EXISTS FOR (node:AnalysisMethodDefinition) REQUIRE (node.method_id, node.method_version) IS UNIQUE"],
  ["analysis_run_id_unique", "CREATE CONSTRAINT analysis_run_id_unique IF NOT EXISTS FOR (node:AnalysisRun) REQUIRE node.id IS UNIQUE"],
  ["analysis_run_scope_business_unique", "CREATE CONSTRAINT analysis_run_scope_business_unique IF NOT EXISTS FOR (node:AnalysisRun) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
  ["derived_result_id_unique", "CREATE CONSTRAINT derived_result_id_unique IF NOT EXISTS FOR (node:DerivedResult) REQUIRE node.id IS UNIQUE"],
  ["derived_result_scope_business_unique", "CREATE CONSTRAINT derived_result_scope_business_unique IF NOT EXISTS FOR (node:DerivedResult) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
  ["analysis_input_snapshot_id_unique", "CREATE CONSTRAINT analysis_input_snapshot_id_unique IF NOT EXISTS FOR (node:AnalysisInputSnapshot) REQUIRE node.id IS UNIQUE"],
  ["promotion_id_unique", "CREATE CONSTRAINT promotion_id_unique IF NOT EXISTS FOR (node:Promotion) REQUIRE node.id IS UNIQUE"],
  ["promotion_scope_business_unique", "CREATE CONSTRAINT promotion_scope_business_unique IF NOT EXISTS FOR (node:Promotion) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
] as const;

export const migration0011: MigrationDefinition = {
  id: "0011_analysis_framework",
  description: "Create AnalysisMethodDefinition, AnalysisRun, DerivedResult, snapshot and promotion identities",
  signature: ["analysis-framework:v1", JSON.stringify(analysisMethods), ...constraints.map((item) => item[1])].join("\n"),
  risk: "non-destructive",
  steps: ["Create analysis framework constraints", "Register immutable method definitions", "Verify constraints and definitions"],
  async apply(database) {
    for (const [, query] of constraints) await database.run(query);
    for (const method of analysisMethods) {
      await database.run(
        "MERGE (node:AnalysisMethodDefinition {method_id: $method_id, method_version: $method_version}) " +
        "ON CREATE SET node.id = randomUUID(), node.created_at = datetime() SET node += $properties",
        { method_id: method.method_id, method_version: method.method_version, properties: method },
      );
    }
  },
  async verify(database) {
    const names = constraints.map((item) => item[0]);
    const found = await database.run("SHOW CONSTRAINTS YIELD name WHERE name IN $names RETURN collect(name) AS names", { names });
    const actual = new Set<string>(found.records[0]?.get("names") ?? []);
    const diagnostics = names.filter((name) => !actual.has(name)).map((name) => "Missing constraint " + name);
    const methods = await database.run("MATCH (node:AnalysisMethodDefinition) WHERE [node.method_id, node.method_version] IN $keys RETURN count(node) AS count", {
      keys: analysisMethods.map((item) => [item.method_id, item.method_version]),
    });
    const countValue = methods.records[0]?.get("count");
    const count = typeof countValue === "object" && countValue !== null && "toNumber" in countValue ? countValue.toNumber() : Number(countValue);
    if (count !== analysisMethods.length) diagnostics.push("Expected " + analysisMethods.length + " method definitions, found " + count);
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
