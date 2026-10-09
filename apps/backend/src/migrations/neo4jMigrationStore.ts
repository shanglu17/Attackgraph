import type { Session } from "neo4j-driver";
import type { MigrationRecord, MigrationStore } from "./types.js";

export class Neo4jMigrationStore implements MigrationStore {
  constructor(private readonly session: Session) {}

  async listRecords(): Promise<MigrationRecord[]> {
    const result = await this.session.run(
      `MATCH (m:MigrationRecord)
       RETURN m.migration_id AS migration_id, m.checksum AS checksum, m.description AS description,
              m.status AS status, m.actor AS actor, m.command_id AS command_id,
              m.backup_id AS backup_id, toString(m.started_at) AS started_at,
              toString(m.completed_at) AS completed_at, m.error_summary AS error_summary
       ORDER BY migration_id`
    );
    return result.records.map((record) => ({
      migration_id: String(record.get("migration_id")),
      checksum: String(record.get("checksum")),
      description: String(record.get("description")),
      status: record.get("status") as MigrationRecord["status"],
      actor: String(record.get("actor")),
      command_id: String(record.get("command_id")),
      backup_id: record.get("backup_id") == null ? undefined : String(record.get("backup_id")),
      started_at: record.get("started_at") == null ? undefined : String(record.get("started_at")),
      completed_at: record.get("completed_at") == null ? undefined : String(record.get("completed_at")),
      error_summary: record.get("error_summary") == null ? undefined : String(record.get("error_summary"))
    }));
  }

  async markRunning(input: Parameters<MigrationStore["markRunning"]>[0]): Promise<void> {
    await this.session.run(
      `MERGE (m:MigrationRecord {migration_id: $migration_id})
       SET m.checksum = $checksum,
           m.description = $description,
           m.status = 'running',
           m.actor = $actor,
           m.command_id = $command_id,
           m.backup_id = $backup_id,
           m.started_at = datetime(),
           m.completed_at = null,
           m.error_summary = null`,
      {
        migration_id: input.migration.id,
        checksum: input.checksum,
        description: input.migration.description,
        actor: input.actor,
        command_id: input.commandId,
        backup_id: input.backupId ?? null
      }
    );
  }

  async markApplied(migrationId: string): Promise<void> {
    await this.session.run(
      `MATCH (m:MigrationRecord {migration_id: $migration_id})
       SET m.status = 'applied', m.completed_at = datetime(), m.error_summary = null`,
      { migration_id: migrationId }
    );
  }

  async markFailed(migrationId: string, errorSummary: string): Promise<void> {
    await this.session.run(
      `MATCH (m:MigrationRecord {migration_id: $migration_id})
       SET m.status = 'failed', m.completed_at = datetime(), m.error_summary = $error_summary`,
      { migration_id: migrationId, error_summary: errorSummary }
    );
  }
}
