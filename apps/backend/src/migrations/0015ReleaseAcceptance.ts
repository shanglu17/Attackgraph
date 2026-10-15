import type { MigrationDefinition } from "./types.js";

const constraints = [
  ["release_acceptance_run_id_unique", "CREATE CONSTRAINT release_acceptance_run_id_unique IF NOT EXISTS FOR (node:ReleaseAcceptanceRun) REQUIRE node.id IS UNIQUE"],
  ["release_acceptance_run_release_unique", "CREATE CONSTRAINT release_acceptance_run_release_unique IF NOT EXISTS FOR (node:ReleaseAcceptanceRun) REQUIRE node.release_id IS UNIQUE"],
  ["release_acceptance_run_command_unique", "CREATE CONSTRAINT release_acceptance_run_command_unique IF NOT EXISTS FOR (node:ReleaseAcceptanceRun) REQUIRE node.command_id IS UNIQUE"],
] as const;

export const migration0015: MigrationDefinition = {
  id: "0015_release_acceptance",
  description: "Create immutable identities for Phase 7 technical release evidence",
  signature: ["phase7-release-acceptance:v1", ...constraints.map((item) => item[1])].join("\n"),
  risk: "non-destructive",
  steps: ["Create release evidence identities", "Verify technical acceptance constraints"],
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
