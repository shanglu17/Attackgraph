import type { MigrationDefinition } from "./types.js";

const constraintName = "migration_record_id_unique";

export const migration0001: MigrationDefinition = {
  id: "0001_migration_ledger",
  description: "Create the unique MigrationRecord ledger constraint",
  signature: [
    "migration-record-schema:v1",
    `CREATE CONSTRAINT ${constraintName} IF NOT EXISTS FOR (m:MigrationRecord) REQUIRE m.migration_id IS UNIQUE`
  ].join("\n"),
  risk: "non-destructive",
  steps: [
    "Create a unique constraint for MigrationRecord.migration_id",
    "Verify the named constraint exists"
  ],
  async apply(database) {
    await database.run(
      `CREATE CONSTRAINT ${constraintName} IF NOT EXISTS FOR (m:MigrationRecord) REQUIRE m.migration_id IS UNIQUE`
    );
  },
  async verify(database) {
    const result = await database.run(
      `SHOW CONSTRAINTS YIELD name
       WHERE name = $constraint_name
       RETURN name`,
      { constraint_name: constraintName }
    );
    return result.records.length === 1
      ? { ok: true, diagnostics: [] }
      : { ok: false, diagnostics: [`Missing constraint ${constraintName}`] };
  }
};
