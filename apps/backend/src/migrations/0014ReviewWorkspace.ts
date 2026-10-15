import type { MigrationDefinition } from "./types.js";

const constraints = [
  ["review_session_id_unique", "CREATE CONSTRAINT review_session_id_unique IF NOT EXISTS FOR (node:ReviewSession) REQUIRE node.id IS UNIQUE"],
  ["review_session_scope_business_unique", "CREATE CONSTRAINT review_session_scope_business_unique IF NOT EXISTS FOR (node:ReviewSession) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
  ["review_comment_id_unique", "CREATE CONSTRAINT review_comment_id_unique IF NOT EXISTS FOR (node:ReviewComment) REQUIRE node.id IS UNIQUE"],
  ["review_comment_scope_business_unique", "CREATE CONSTRAINT review_comment_scope_business_unique IF NOT EXISTS FOR (node:ReviewComment) REQUIRE (node.project_id, node.revision_id, node.business_id) IS UNIQUE"],
] as const;

export const migration0014: MigrationDefinition = {
  id: "0014_review_workspace",
  description: "Create scoped review sessions and append-only collaboration comments",
  signature: ["review-workspace:v1", ...constraints.map((item) => item[1])].join("\n"),
  risk: "non-destructive",
  steps: ["Create review session constraints", "Create review comment constraints", "Verify review collaboration identities"],
  async apply(database) {
    for (const [, query] of constraints) await database.run(query);
  },
  async verify(database) {
    const names = constraints.map((item) => item[0]);
    const result = await database.run("SHOW CONSTRAINTS YIELD name WHERE name IN $names RETURN collect(name) AS names", { names });
    const actual = new Set<string>(result.records[0]?.get("names") ?? []);
    const diagnostics = names.filter((name) => !actual.has(name)).map((name) => `Missing constraint ${name}`);
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
