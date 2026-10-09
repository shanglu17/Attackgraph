import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import { getDriver } from "../db/neo4j.js";
import {
  fingerprintCommandPayload,
  type CanonicalValue,
} from "../services/governance/commandFingerprint.js";
import {
  assertCommandReceipt,
  CommandReceiptUnverifiableError,
  findCommandReceipt,
  type CommandReceiptProperties,
} from "../services/governance/commandReceipt.js";
import {
  revisionWriteEnvelopeSchema,
  type RevisionWriteEnvelope,
} from "../services/governance/contracts.js";

const eventTypePattern = /^[A-Z][A-Z0-9_]{2,100}$/;
const canonicalizerPattern = /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*\/v[1-9]\d*$/;

export interface RevisionWriteRequest<TPayload extends CanonicalValue> extends RevisionWriteEnvelope {
  event_type: string;
  request_canonicalizer: string;
  payload: TPayload;
  summary: string;
}

export interface RevisionMutationContext {
  transaction: ManagedTransaction;
  project_id: string;
  revision_id: string;
  previous_revision_version: number;
  new_revision_version: number;
}

export interface RevisionWriteResult<TResult extends CanonicalValue> {
  audit_event_id: string;
  new_revision_version: number;
  replayed: boolean;
  value: TResult;
}

export class RevisionWriteScopeError extends Error {
  constructor(projectId: string, revisionId: string) {
    super(`revision '${revisionId}' does not belong to project '${projectId}'`);
    this.name = "RevisionWriteScopeError";
  }
}

export class RevisionNotWritableError extends Error {
  constructor(revisionId: string, status: string) {
    super(`revision '${revisionId}' is not writable in status '${status}'`);
    this.name = "RevisionNotWritableError";
  }
}

export class RevisionWriteConflictError extends Error {
  readonly expectedVersion: number;
  readonly currentVersion: number;

  constructor(revisionId: string, expectedVersion: number, currentVersion: number) {
    super(
      `revision '${revisionId}' version conflict: expected ${expectedVersion}, current ${currentVersion}`,
    );
    this.name = "RevisionWriteConflictError";
    this.expectedVersion = expectedVersion;
    this.currentVersion = currentVersion;
  }
}

function toNumber(value: unknown): number {
  if (typeof value === "number") return value;
  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    return value.toNumber();
  }
  throw new TypeError(`Expected a numeric Neo4j value, received ${String(value)}`);
}

function toRequiredString(value: unknown): string {
  if (value === null || value === undefined) {
    throw new TypeError("Expected a non-null revision write receipt property");
  }
  return String(value);
}

function readReplay<TResult extends CanonicalValue>(
  commandId: string,
  receipt: CommandReceiptProperties,
): RevisionWriteResult<TResult> {
  if (
    receipt.id === null ||
    receipt.id === undefined ||
    receipt.result_json === null ||
    receipt.result_json === undefined ||
    receipt.subject_version_after === null ||
    receipt.subject_version_after === undefined
  ) {
    throw new CommandReceiptUnverifiableError(commandId);
  }

  let value: TResult;
  try {
    value = JSON.parse(String(receipt.result_json)) as TResult;
  } catch {
    throw new CommandReceiptUnverifiableError(commandId);
  }

  return {
    audit_event_id: String(receipt.id),
    new_revision_version: toNumber(receipt.subject_version_after),
    replayed: true,
    value,
  };
}

async function diagnoseReservationFailure(
  transaction: ManagedTransaction,
  envelope: RevisionWriteEnvelope,
): Promise<never> {
  const result = await transaction.run(
    `MATCH (revision:Revision {id: $revision_id})
     OPTIONAL MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision)
     RETURN revision.project_id AS revision_project_id,
            revision.status AS status,
            revision.version AS version,
            project IS NOT NULL AS in_scope`,
    envelope,
  );
  if (result.records.length === 0 || result.records[0].get("in_scope") !== true) {
    throw new RevisionWriteScopeError(envelope.project_id, envelope.revision_id);
  }

  const status = toRequiredString(result.records[0].get("status"));
  if (status !== "Draft") {
    throw new RevisionNotWritableError(envelope.revision_id, status);
  }

  throw new RevisionWriteConflictError(
    envelope.revision_id,
    envelope.expected_revision_version,
    toNumber(result.records[0].get("version")),
  );
}

/**
 * The transaction boundary for all new revision-scoped business writes.
 * Legacy GraphVersion repositories remain compatibility-only until P1.5/P1.6.
 */
export class RevisionUnitOfWork {
  async execute<TPayload extends CanonicalValue, TResult extends CanonicalValue>(
    request: RevisionWriteRequest<TPayload>,
    mutate: (context: RevisionMutationContext) => Promise<TResult>,
  ): Promise<RevisionWriteResult<TResult>> {
    const envelope = revisionWriteEnvelopeSchema.parse(request);
    if (!eventTypePattern.test(request.event_type)) {
      throw new TypeError("event_type must be an uppercase stable event name");
    }
    if (!canonicalizerPattern.test(request.request_canonicalizer)) {
      throw new TypeError("request_canonicalizer must be a stable lowercase id ending in /vN");
    }
    const summary = request.summary.trim();
    if (summary.length === 0 || summary.length > 2_000) {
      throw new TypeError("summary must contain between 1 and 2000 characters");
    }

    const requestFingerprint = fingerprintCommandPayload(request.request_canonicalizer, {
      actor: envelope.actor,
      project_id: envelope.project_id,
      revision_id: envelope.revision_id,
      expected_revision_version: envelope.expected_revision_version,
      event_type: request.event_type,
      payload: request.payload,
    });
    const session = getDriver().session();

    try {
      return await session.executeWrite(async (transaction) => {
        const priorReceipt = await findCommandReceipt(transaction, envelope.command_id);
        if (priorReceipt) {
          assertCommandReceipt(
            envelope.command_id,
            priorReceipt,
            request.event_type,
            requestFingerprint,
          );
          return readReplay<TResult>(envelope.command_id, priorReceipt);
        }

        const reserved = await transaction.run(
          `MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id})
           WHERE revision.project_id = $project_id
           SET revision._revision_write_lock = coalesce(revision._revision_write_lock, 0) + 1
           WITH revision
           WHERE revision.status = 'Draft'
             AND revision.version = $expected_revision_version
           SET revision.version = revision.version + 1,
               revision.updated_at = datetime(),
               revision.updated_by = $actor
           REMOVE revision._revision_write_lock
           RETURN revision.version AS new_version`,
          envelope,
        );

        if (reserved.records.length === 0) {
          const concurrentReceipt = await findCommandReceipt(transaction, envelope.command_id);
          if (concurrentReceipt) {
            assertCommandReceipt(
              envelope.command_id,
              concurrentReceipt,
              request.event_type,
              requestFingerprint,
            );
            await transaction.run(
              "MATCH (revision:Revision {id: $revision_id}) REMOVE revision._revision_write_lock",
              envelope,
            );
            return readReplay<TResult>(envelope.command_id, concurrentReceipt);
          }
          return diagnoseReservationFailure(transaction, envelope);
        }

        const newRevisionVersion = toNumber(reserved.records[0].get("new_version"));
        const value = await mutate({
          transaction,
          project_id: envelope.project_id,
          revision_id: envelope.revision_id,
          previous_revision_version: envelope.expected_revision_version,
          new_revision_version: newRevisionVersion,
        });
        const resultJson = JSON.stringify(value);
        if (resultJson === undefined) {
          throw new TypeError("revision write result must be JSON serializable");
        }

        const auditEventId = randomUUID();
        await transaction.run(
          `MATCH (project:Project {id: $project_id})
           MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
           CREATE (event:AuditEvent {
             id: $audit_event_id,
             command_id: $command_id,
             actor: $actor,
             event_type: $event_type,
             occurred_at: datetime(),
             project_id: $project_id,
             subject_id: $revision_id,
             subject_type: 'Revision',
             subject_version_before: $expected_revision_version,
             subject_version_after: $new_revision_version,
             request_hash: $request_hash,
             request_hash_algorithm: $request_hash_algorithm,
             request_canonicalizer: $request_canonicalizer,
             summary: $summary,
             result_json: $result_json
           })
           CREATE (event)-[:AFFECTS]->(project)
           CREATE (event)-[:AFFECTS]->(revision)`,
          {
            ...envelope,
            ...requestFingerprint,
            audit_event_id: auditEventId,
            event_type: request.event_type,
            new_revision_version: newRevisionVersion,
            summary,
            result_json: resultJson,
          },
        );

        return {
          audit_event_id: auditEventId,
          new_revision_version: newRevisionVersion,
          replayed: false,
          value,
        };
      });
    } finally {
      await session.close();
    }
  }
}
