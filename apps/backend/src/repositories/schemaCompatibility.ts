import { getDriver } from "../db/neo4j.js";

export class SchemaCompatibilityError extends Error {
  constructor(readonly missingConstraints: string[]) {
    super(
      `Database schema is not compatible; missing constraints: ${missingConstraints.join(", ")}. Run the explicit migration CLI.`,
    );
    this.name = "SchemaCompatibilityError";
  }
}

export async function assertConstraintsPresent(requiredNames: readonly string[]): Promise<void> {
  const session = getDriver().session();
  try {
    const result = await session.run(
      `SHOW CONSTRAINTS YIELD name
       WHERE name IN $required_names
       RETURN collect(name) AS names`,
      { required_names: [...requiredNames] },
    );
    const actual = new Set<string>(result.records[0]?.get("names") ?? []);
    const missing = requiredNames.filter((name) => !actual.has(name));
    if (missing.length > 0) throw new SchemaCompatibilityError([...missing]);
  } finally {
    await session.close();
  }
}
