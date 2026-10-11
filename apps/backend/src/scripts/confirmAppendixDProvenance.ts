import { randomUUID } from "node:crypto";
import { closeDriver } from "../db/neo4j.js";
import { AppendixDProvenanceService } from "../services/legacyMigration/appendixDProvenanceService.js";

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main() {
  const service = new AppendixDProvenanceService();
  const scope = await service.resolveScope();
  if (process.argv.includes("--status")) {
    console.log(JSON.stringify({ scope }, null, 2));
    return;
  }
  const actor = option("--actor");
  const expected = Number(option("--expected-revision-version"));
  if (!actor) throw new Error("--actor is required");
  if (!Number.isInteger(expected) || expected <= 0) throw new Error("--expected-revision-version must be a positive integer");
  const result = await service.confirm({
    actor,
    command_id: option("--command-id") ?? randomUUID(),
    expected_revision_version: expected,
  });
  console.log(JSON.stringify({ scope, result }, null, 2));
}

main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(closeDriver);
