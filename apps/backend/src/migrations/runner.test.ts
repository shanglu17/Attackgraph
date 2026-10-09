import assert from "node:assert/strict";
import test from "node:test";
import type { QueryResult } from "neo4j-driver";
import { MigrationRunner, migrationChecksum } from "./runner.js";
import type {
  MigrationDatabase,
  MigrationDefinition,
  MigrationRecord,
  MigrationStore
} from "./types.js";

class MemoryStore implements MigrationStore {
  readonly records = new Map<string, MigrationRecord>();

  async listRecords(): Promise<MigrationRecord[]> {
    return [...this.records.values()];
  }

  async markRunning(input: Parameters<MigrationStore["markRunning"]>[0]): Promise<void> {
    this.records.set(input.migration.id, {
      migration_id: input.migration.id,
      checksum: input.checksum,
      description: input.migration.description,
      status: "running",
      actor: input.actor,
      command_id: input.commandId,
      backup_id: input.backupId
    });
  }

  async markApplied(migrationId: string): Promise<void> {
    this.records.get(migrationId)!.status = "applied";
  }

  async markFailed(migrationId: string, errorSummary: string): Promise<void> {
    const record = this.records.get(migrationId)!;
    record.status = "failed";
    record.error_summary = errorSummary;
  }
}

const database: MigrationDatabase = {
  async run() {
    return { records: [] } as unknown as QueryResult;
  }
};

function migration(id: string, options: { risk?: MigrationDefinition["risk"]; failVerify?: boolean } = {}): MigrationDefinition {
  return {
    id,
    description: id,
    signature: `${id}:v1`,
    risk: options.risk ?? "non-destructive",
    steps: [`apply ${id}`],
    async apply() {},
    async verify() {
      return options.failVerify
        ? { ok: false, diagnostics: ["synthetic postcondition failure"] }
        : { ok: true, diagnostics: [] };
    }
  };
}

test("plan is read-only and apply records migrations in deterministic order", async () => {
  const store = new MemoryStore();
  const runner = new MigrationRunner(store, database, [migration("0002_second"), migration("0001_first")]);
  const before = await runner.plan();
  assert.deepEqual(before.map((entry) => [entry.id, entry.status]), [
    ["0001_first", "pending"],
    ["0002_second", "pending"]
  ]);
  assert.equal(store.records.size, 0);

  const after = await runner.apply({ actor: "tester", commandId: "command-1" });
  assert.deepEqual(after.map((entry) => entry.status), ["applied", "applied"]);
  assert.equal(store.records.get("0001_first")?.command_id, "command-1");
});

test("destructive migrations require explicit confirmation and backup id", async () => {
  const runner = new MigrationRunner(new MemoryStore(), database, [migration("0001_destructive", { risk: "destructive" })]);
  await assert.rejects(
    runner.apply({ actor: "tester", commandId: "command-1", allowDestructive: true }),
    /backup id/i
  );
});

test("failed postconditions stop apply and persist a failed record", async () => {
  const store = new MemoryStore();
  const runner = new MigrationRunner(store, database, [migration("0001_failure", { failVerify: true })]);
  await assert.rejects(runner.apply({ actor: "tester", commandId: "command-1" }), /Postcondition failed/);
  assert.equal(store.records.get("0001_failure")?.status, "failed");
  assert.match(store.records.get("0001_failure")?.error_summary ?? "", /synthetic postcondition failure/);
});

test("an applied migration rejects a changed checksum", async () => {
  const store = new MemoryStore();
  const original = migration("0001_stable");
  store.records.set(original.id, {
    migration_id: original.id,
    checksum: migrationChecksum(original),
    description: original.description,
    status: "applied",
    actor: "tester",
    command_id: "command-1"
  });
  const changed = { ...original, signature: "0001_stable:v2" };
  const runner = new MigrationRunner(store, database, [changed]);
  assert.equal((await runner.plan())[0].status, "checksum_mismatch");
  await assert.rejects(runner.apply({ actor: "tester", commandId: "command-2" }), /checksum differs/);
});
