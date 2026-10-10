export const legacyGlobalWriteQuarantineCode = "LEGACY_GLOBAL_WRITE_QUARANTINED";

export const legacyGlobalWriteQuarantineMessage =
  "This compatibility operation uses the retired global GraphVersion write model and is read-only after P1.6; use a scoped command API when Phase 2 provides it";

export class LegacyGlobalWriteQuarantinedError extends Error {
  readonly code = legacyGlobalWriteQuarantineCode;
  readonly statusCode = 409;

  constructor(operation: string) {
    super(`${operation}: ${legacyGlobalWriteQuarantineMessage}`);
    this.name = "LegacyGlobalWriteQuarantinedError";
  }
}
