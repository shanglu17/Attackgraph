import type { MigrationDefinition } from "./types.js";

const constraints = [
  {
    name: "legacy_attachment_run_id_unique",
    query:
      "CREATE CONSTRAINT legacy_attachment_run_id_unique IF NOT EXISTS FOR (n:LegacyAttachmentRun) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "legacy_attachment_run_command_id_unique",
    query:
      "CREATE CONSTRAINT legacy_attachment_run_command_id_unique IF NOT EXISTS FOR (n:LegacyAttachmentRun) REQUIRE n.command_id IS UNIQUE",
  },
  {
    name: "migration_issue_id_unique",
    query:
      "CREATE CONSTRAINT migration_issue_id_unique IF NOT EXISTS FOR (n:MigrationIssue) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "migration_issue_key_unique",
    query:
      "CREATE CONSTRAINT migration_issue_key_unique IF NOT EXISTS FOR (n:MigrationIssue) REQUIRE n.issue_key IS UNIQUE",
  },
] as const;

export const migration0003: MigrationDefinition = {
  id: "0003_legacy_attachment_support",
  description: "Create ledger and issue constraints for scoped legacy attachment runs",
  signature: ["legacy-attachment-support:v1", ...constraints.map(({ query }) => query)].join("\n"),
  risk: "non-destructive",
  steps: constraints.map(({ name }) => `Create and verify constraint ${name}`),
  async apply(database) {
    for (const { query } of constraints) {
      await database.run(query);
    }
  },
  async verify(database) {
    const expectedNames = constraints.map(({ name }) => name);
    const result = await database.run(
      `SHOW CONSTRAINTS YIELD name
       WHERE name IN $constraint_names
       RETURN collect(name) AS names`,
      { constraint_names: expectedNames },
    );
    const actualNames = new Set<string>(result.records[0]?.get("names") ?? []);
    const missing = expectedNames.filter((name) => !actualNames.has(name));
    return missing.length === 0
      ? { ok: true, diagnostics: [] }
      : { ok: false, diagnostics: missing.map((name) => `Missing constraint ${name}`) };
  },
};
