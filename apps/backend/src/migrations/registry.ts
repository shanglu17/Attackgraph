import { migration0001 } from "./0001MigrationLedger.js";
import type { MigrationDefinition } from "./types.js";

export const migrationRegistry: MigrationDefinition[] = [migration0001];
