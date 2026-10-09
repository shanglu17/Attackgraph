import type { MigrationDefinition } from "./types.js";

const constraints = [
  {
    name: "project_id_unique",
    query: "CREATE CONSTRAINT project_id_unique IF NOT EXISTS FOR (n:Project) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "project_business_id_unique",
    query: "CREATE CONSTRAINT project_business_id_unique IF NOT EXISTS FOR (n:Project) REQUIRE n.business_id IS UNIQUE",
  },
  {
    name: "model_id_unique",
    query: "CREATE CONSTRAINT model_id_unique IF NOT EXISTS FOR (n:Model) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "model_project_business_id_unique",
    query:
      "CREATE CONSTRAINT model_project_business_id_unique IF NOT EXISTS FOR (n:Model) REQUIRE (n.project_id, n.business_id) IS UNIQUE",
  },
  {
    name: "revision_id_unique",
    query: "CREATE CONSTRAINT revision_id_unique IF NOT EXISTS FOR (n:Revision) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "revision_model_business_id_unique",
    query:
      "CREATE CONSTRAINT revision_model_business_id_unique IF NOT EXISTS FOR (n:Revision) REQUIRE (n.project_id, n.model_id, n.business_id) IS UNIQUE",
  },
  {
    name: "baseline_id_unique",
    query: "CREATE CONSTRAINT baseline_id_unique IF NOT EXISTS FOR (n:Baseline) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "baseline_model_business_id_unique",
    query:
      "CREATE CONSTRAINT baseline_model_business_id_unique IF NOT EXISTS FOR (n:Baseline) REQUIRE (n.project_id, n.model_id, n.business_id) IS UNIQUE",
  },
  {
    name: "standard_profile_version_id_unique",
    query:
      "CREATE CONSTRAINT standard_profile_version_id_unique IF NOT EXISTS FOR (n:StandardProfileVersion) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "standard_profile_version_scope_unique",
    query:
      "CREATE CONSTRAINT standard_profile_version_scope_unique IF NOT EXISTS FOR (n:StandardProfileVersion) REQUIRE (n.project_id, n.business_id, n.profile_version) IS UNIQUE",
  },
  {
    name: "audit_event_id_unique",
    query: "CREATE CONSTRAINT audit_event_id_unique IF NOT EXISTS FOR (n:AuditEvent) REQUIRE n.id IS UNIQUE",
  },
  {
    name: "audit_event_command_id_unique",
    query:
      "CREATE CONSTRAINT audit_event_command_id_unique IF NOT EXISTS FOR (n:AuditEvent) REQUIRE n.command_id IS UNIQUE",
  },
] as const;

export const migration0002: MigrationDefinition = {
  id: "0002_governance_core_constraints",
  description: "Create identity and scoped business-key constraints for the governance core",
  signature: ["governance-core-schema:v1", ...constraints.map(({ query }) => query)].join("\n"),
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
