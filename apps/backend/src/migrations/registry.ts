import { migration0001 } from "./0001MigrationLedger.js";
import { migration0002 } from "./0002GovernanceCoreConstraints.js";
import { migration0003 } from "./0003LegacyAttachmentSupport.js";
import { migration0004 } from "./0004ScopedEntityIdentity.js";
import { migration0005 } from "./0005RetireGlobalBusinessConstraints.js";
import { migration0006 } from "./0006LegacyGraphVersionCompatibility.js";
import { migration0007 } from "./0007SystemModelCore.js";
import { migration0008 } from "./0008SystemModelElementIdentity.js";
import { migration0009 } from "./0009DraftThreatIdentity.js";
import type { MigrationDefinition } from "./types.js";

export const migrationRegistry: MigrationDefinition[] = [
  migration0001,
  migration0002,
  migration0003,
  migration0004,
  migration0005,
  migration0006,
  migration0007,
  migration0008,
  migration0009,
];
