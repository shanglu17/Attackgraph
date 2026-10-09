import {
  legacyGlobalBusinessConstraintNames,
  scopedIdentityConstraintNames,
} from "../services/identity/scopedIdentity.js";
import type { MigrationDefinition } from "./types.js";

export const migration0005: MigrationDefinition = {
  id: "0005_retire_global_business_constraints",
  description: "Retire legacy global business-id constraints after scoped identities are active",
  signature: [
    "retire-global-business-constraints:v1",
    ...legacyGlobalBusinessConstraintNames.map((name) => `DROP CONSTRAINT ${name} IF EXISTS`),
  ].join("\n"),
  risk: "destructive",
  steps: [
    "Require an externally verified backup identifier",
    "Verify scoped internal-id and business-id constraints are already active",
    "Drop legacy global business-id uniqueness constraints",
    "Verify legacy constraints are absent and scoped constraints remain active",
  ],
  async apply(database) {
    const scoped = await database.run(
      `SHOW CONSTRAINTS YIELD name
       WHERE name IN $constraint_names
       RETURN collect(name) AS names`,
      { constraint_names: [...scopedIdentityConstraintNames] },
    );
    const actual = new Set<string>(scoped.records[0]?.get("names") ?? []);
    const missing = scopedIdentityConstraintNames.filter((name) => !actual.has(name));
    if (missing.length > 0) {
      throw new Error(`Cannot retire global constraints; scoped replacements are missing: ${missing.join(", ")}`);
    }
    for (const name of legacyGlobalBusinessConstraintNames) {
      await database.run(`DROP CONSTRAINT ${name} IF EXISTS`);
    }
  },
  async verify(database) {
    const result = await database.run(
      `SHOW CONSTRAINTS YIELD name
       WHERE name IN $all_names
       RETURN collect(name) AS names`,
      {
        all_names: [
          ...legacyGlobalBusinessConstraintNames,
          ...scopedIdentityConstraintNames,
        ],
      },
    );
    const actual = new Set<string>(result.records[0]?.get("names") ?? []);
    const diagnostics = [
      ...legacyGlobalBusinessConstraintNames
        .filter((name) => actual.has(name))
        .map((name) => `Legacy global constraint still exists: ${name}`),
      ...scopedIdentityConstraintNames
        .filter((name) => !actual.has(name))
        .map((name) => `Scoped replacement constraint is missing: ${name}`),
    ];
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
