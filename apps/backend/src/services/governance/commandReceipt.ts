import type { ManagedTransaction } from "neo4j-driver";
import type { CommandFingerprint } from "./commandFingerprint.js";

export type CommandReceiptProperties = Record<string, unknown>;

export class CommandReuseError extends Error {
  constructor(commandId: string, actualEventType: string, expectedEventType: string) {
    super(
      `command_id '${commandId}' was already used for ${actualEventType}; expected ${expectedEventType}`,
    );
    this.name = "CommandReuseError";
  }
}

export class CommandPayloadMismatchError extends Error {
  constructor(commandId: string) {
    super(`command_id '${commandId}' was already used with a different request payload`);
    this.name = "CommandPayloadMismatchError";
  }
}

export class CommandReceiptUnverifiableError extends Error {
  constructor(commandId: string) {
    super(
      `command_id '${commandId}' refers to a legacy receipt without a compatible request fingerprint; use a new command id`,
    );
    this.name = "CommandReceiptUnverifiableError";
  }
}

function requiredString(value: unknown): string {
  if (value === null || value === undefined) {
    throw new TypeError("Expected a non-null command receipt property");
  }
  return String(value);
}

function optionalString(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : String(value);
}

export async function findCommandReceipt(
  transaction: ManagedTransaction,
  commandId: string,
): Promise<CommandReceiptProperties | undefined> {
  const result = await transaction.run(
    "MATCH (event:AuditEvent {command_id: $command_id}) RETURN event",
    { command_id: commandId },
  );
  if (result.records.length === 0) return undefined;

  const node = result.records[0].get("event");
  if (typeof node !== "object" || node === null || !("properties" in node)) {
    throw new TypeError("Expected Neo4j AuditEvent node");
  }
  return node.properties as CommandReceiptProperties;
}

export function assertCommandReceipt(
  commandId: string,
  properties: CommandReceiptProperties,
  expectedEventType: string,
  expectedFingerprint: CommandFingerprint,
): void {
  const actualEventType = requiredString(properties.event_type);
  if (actualEventType !== expectedEventType) {
    throw new CommandReuseError(commandId, actualEventType, expectedEventType);
  }

  const actualHash = optionalString(properties.request_hash);
  const actualAlgorithm = optionalString(properties.request_hash_algorithm);
  const actualCanonicalizer = optionalString(properties.request_canonicalizer);
  if (
    actualHash === undefined ||
    actualAlgorithm !== expectedFingerprint.request_hash_algorithm ||
    actualCanonicalizer !== expectedFingerprint.request_canonicalizer
  ) {
    throw new CommandReceiptUnverifiableError(commandId);
  }
  if (actualHash !== expectedFingerprint.request_hash) {
    throw new CommandPayloadMismatchError(commandId);
  }
}
