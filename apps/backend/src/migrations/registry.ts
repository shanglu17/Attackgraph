import { migration0001 } from "./0001MigrationLedger.js";
import { migration0002 } from "./0002GovernanceCoreConstraints.js";
import { migration0003 } from "./0003LegacyAttachmentSupport.js";
import type { MigrationDefinition } from "./types.js";

export const migrationRegistry: MigrationDefinition[] = [migration0001, migration0002, migration0003];
