import { randomUUID } from "node:crypto";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { Neo4jMigrationStore } from "../migrations/neo4jMigrationStore.js";
import { migrationRegistry } from "../migrations/registry.js";
import { MigrationRunner } from "../migrations/runner.js";

type Command = "status" | "plan" | "apply" | "verify";

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function flag(name: string): boolean {
  return process.argv.includes(name);
}

function command(): Command {
  const value = process.argv[2] ?? "status";
  if (["status", "plan", "apply", "verify"].includes(value)) return value as Command;
  throw new Error(`Unknown migration command: ${value}. Expected status, plan, apply or verify.`);
}

async function main(): Promise<void> {
  const session = getDriver().session();
  try {
    const database = { run: session.run.bind(session) };
    const runner = new MigrationRunner(new Neo4jMigrationStore(session), database, migrationRegistry);
    const requested = command();

    if (requested === "status" || requested === "plan") {
      console.log(JSON.stringify({ command: requested, migrations: await runner.plan() }, null, 2));
      return;
    }

    if (requested === "verify") {
      const results = await runner.verifyApplied();
      console.log(JSON.stringify({ command: requested, results }, null, 2));
      if (results.some((result) => !result.ok)) process.exitCode = 1;
      return;
    }

    const actor = option("--actor");
    if (!actor) throw new Error("apply requires --actor <actor-id>");
    const migrations = await runner.apply({
      actor,
      commandId: option("--command-id") ?? randomUUID(),
      allowDestructive: flag("--allow-destructive"),
      backupId: option("--backup-id"),
      retryFailed: flag("--retry-failed")
    });
    console.log(JSON.stringify({ command: requested, migrations }, null, 2));
  } finally {
    await session.close();
    await closeDriver();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
