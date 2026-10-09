import type { QueryResult } from "neo4j-driver";

export type MigrationRisk = "non-destructive" | "destructive";
export type MigrationRecordStatus = "running" | "applied" | "failed";
export type MigrationPlanStatus = "pending" | MigrationRecordStatus | "checksum_mismatch";

export interface MigrationDatabase {
  run(query: string, parameters?: Record<string, unknown>): Promise<QueryResult>;
}

export interface MigrationVerification {
  ok: boolean;
  diagnostics: string[];
}

export interface MigrationDefinition {
  id: string;
  description: string;
  signature: string;
  risk: MigrationRisk;
  steps: string[];
  apply(database: MigrationDatabase): Promise<void>;
  verify(database: MigrationDatabase): Promise<MigrationVerification>;
}

export interface MigrationRecord {
  migration_id: string;
  checksum: string;
  description: string;
  status: MigrationRecordStatus;
  actor: string;
  command_id: string;
  backup_id?: string;
  started_at?: string;
  completed_at?: string;
  error_summary?: string;
}

export interface MigrationPlanEntry {
  id: string;
  description: string;
  checksum: string;
  risk: MigrationRisk;
  steps: string[];
  status: MigrationPlanStatus;
  recorded_checksum?: string;
}

export interface MigrationStore {
  listRecords(): Promise<MigrationRecord[]>;
  markRunning(input: {
    migration: MigrationDefinition;
    checksum: string;
    actor: string;
    commandId: string;
    backupId?: string;
  }): Promise<void>;
  markApplied(migrationId: string): Promise<void>;
  markFailed(migrationId: string, errorSummary: string): Promise<void>;
}
