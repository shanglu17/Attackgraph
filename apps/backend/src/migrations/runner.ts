import { createHash } from "node:crypto";
import type {
  MigrationDatabase,
  MigrationDefinition,
  MigrationPlanEntry,
  MigrationStore,
  MigrationVerification
} from "./types.js";

export interface ApplyMigrationOptions {
  actor: string;
  commandId: string;
  allowDestructive?: boolean;
  backupId?: string;
  retryFailed?: boolean;
}

export interface VerifyMigrationResult extends MigrationVerification {
  id: string;
  description: string;
}

export function migrationChecksum(migration: MigrationDefinition): string {
  return createHash("sha256").update(migration.signature, "utf8").digest("hex");
}

export class MigrationRunner {
  readonly migrations: MigrationDefinition[];

  constructor(
    private readonly store: MigrationStore,
    private readonly database: MigrationDatabase,
    migrations: MigrationDefinition[]
  ) {
    this.migrations = [...migrations].sort((left, right) => left.id.localeCompare(right.id));
    this.validateRegistry();
  }

  async plan(): Promise<MigrationPlanEntry[]> {
    const records = new Map((await this.store.listRecords()).map((record) => [record.migration_id, record]));
    return this.migrations.map((migration) => {
      const checksum = migrationChecksum(migration);
      const record = records.get(migration.id);
      return {
        id: migration.id,
        description: migration.description,
        checksum,
        risk: migration.risk,
        steps: [...migration.steps],
        status: !record ? "pending" : record.checksum !== checksum ? "checksum_mismatch" : record.status,
        recorded_checksum: record?.checksum
      };
    });
  }

  async apply(options: ApplyMigrationOptions): Promise<MigrationPlanEntry[]> {
    if (!options.actor.trim()) throw new Error("Migration apply requires a non-empty actor");
    if (!options.commandId.trim()) throw new Error("Migration apply requires a command/idempotency id");

    const plan = await this.plan();
    const mismatch = plan.find((entry) => entry.status === "checksum_mismatch");
    if (mismatch) throw new Error(`Migration ${mismatch.id} checksum differs from its MigrationRecord`);

    for (const entry of plan) {
      if (entry.status === "applied") continue;
      if (entry.status === "running") throw new Error(`Migration ${entry.id} is already marked running`);
      if (entry.status === "failed" && !options.retryFailed) {
        throw new Error(`Migration ${entry.id} previously failed; inspect it and pass retryFailed explicitly`);
      }
      if (entry.risk === "destructive" && (!options.allowDestructive || !options.backupId?.trim())) {
        throw new Error(`Destructive migration ${entry.id} requires explicit confirmation and backup id`);
      }

      const migration = this.migrations.find((candidate) => candidate.id === entry.id)!;
      await this.store.markRunning({
        migration,
        checksum: entry.checksum,
        actor: options.actor,
        commandId: options.commandId,
        backupId: options.backupId
      });
      try {
        await migration.apply(this.database);
        const verification = await migration.verify(this.database);
        if (!verification.ok) {
          throw new Error(`Postcondition failed: ${verification.diagnostics.join("; ")}`);
        }
        await this.store.markApplied(migration.id);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await this.store.markFailed(migration.id, message.slice(0, 2000));
        throw error;
      }
    }
    return this.plan();
  }

  async verifyApplied(): Promise<VerifyMigrationResult[]> {
    const plan = await this.plan();
    const results: VerifyMigrationResult[] = [];
    for (const entry of plan) {
      const migration = this.migrations.find((candidate) => candidate.id === entry.id)!;
      if (entry.status !== "applied") {
        results.push({
          id: entry.id,
          description: entry.description,
          ok: false,
          diagnostics: [`Migration status is ${entry.status}, expected applied`]
        });
        continue;
      }
      const verification = await migration.verify(this.database);
      results.push({ id: entry.id, description: entry.description, ...verification });
    }
    return results;
  }

  private validateRegistry(): void {
    const ids = new Set<string>();
    for (const migration of this.migrations) {
      if (!/^\d{4}_[a-z0-9_]+$/.test(migration.id)) {
        throw new Error(`Invalid migration id: ${migration.id}`);
      }
      if (ids.has(migration.id)) throw new Error(`Duplicate migration id: ${migration.id}`);
      if (!migration.signature.trim()) throw new Error(`Migration ${migration.id} must define a stable signature`);
      ids.add(migration.id);
    }
  }
}
