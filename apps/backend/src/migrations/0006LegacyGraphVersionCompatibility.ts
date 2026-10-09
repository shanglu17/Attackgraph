import type { MigrationDefinition } from "./types.js";

const constraintName = "graph_version_unique";
const graphVersionId = "GRAPH_VERSION";

export const migration0006: MigrationDefinition = {
  id: "0006_legacy_graph_version_compatibility",
  description: "Preserve the transitional GraphVersion read/write path on fresh databases",
  signature: [
    "legacy-graph-version-compatibility:v1",
    `CREATE CONSTRAINT ${constraintName} IF NOT EXISTS FOR (n:GraphVersion) REQUIRE n.id IS UNIQUE`,
    `MERGE GraphVersion ${graphVersionId} with initial value v1`,
  ].join("\n"),
  risk: "non-destructive",
  steps: [
    "Create the transitional GraphVersion identity constraint when absent",
    "Create the initial legacy GraphVersion record when absent",
    "Verify the compatibility record and constraint without changing an existing version",
  ],
  async apply(database) {
    await database.run(
      `CREATE CONSTRAINT ${constraintName} IF NOT EXISTS
       FOR (version:GraphVersion) REQUIRE version.id IS UNIQUE`,
    );
    await database.run(
      `MERGE (version:GraphVersion {id: $id})
       ON CREATE SET version.value = 'v1'`,
      { id: graphVersionId },
    );
  },
  async verify(database) {
    const constraints = await database.run(
      `SHOW CONSTRAINTS YIELD name
       WHERE name = $constraint_name
       RETURN count(*) AS constraint_count`,
      { constraint_name: constraintName },
    );
    const versions = await database.run(
      `MATCH (version:GraphVersion {id: $id})
       RETURN count(version) AS version_count,
              head(collect(version.value)) AS version_value`,
      { id: graphVersionId },
    );
    const constraintRecord = constraints.records[0];
    const versionRecord = versions.records[0];
    const rawConstraintCount = constraintRecord?.get("constraint_count");
    const constraintCount =
      typeof rawConstraintCount === "object" && rawConstraintCount !== null && "toNumber" in rawConstraintCount
        ? rawConstraintCount.toNumber()
        : Number(rawConstraintCount ?? 0);
    const rawCount = versionRecord?.get("version_count");
    const versionCount =
      typeof rawCount === "object" && rawCount !== null && "toNumber" in rawCount
        ? rawCount.toNumber()
        : Number(rawCount ?? 0);
    const hasValue =
      versionRecord?.get("version_value") !== null && versionRecord?.get("version_value") !== undefined;
    const diagnostics = [
      ...(constraintCount === 1 ? [] : [`Missing constraint ${constraintName}`]),
      ...(versionCount === 1 ? [] : [`Expected one ${graphVersionId} record, found ${versionCount}`]),
      ...(hasValue ? [] : [`${graphVersionId} has no value`]),
    ];
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
