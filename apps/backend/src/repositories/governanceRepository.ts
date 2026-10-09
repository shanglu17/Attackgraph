import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import { getDriver } from "../db/neo4j.js";
import type {
  Baseline,
  CommandResult,
  Model,
  Project,
  ProjectWorkspace,
  Revision,
  StandardProfileVersion,
} from "../types/governance.js";
import type {
  ApproveBaselineInput,
  CreateProjectWorkspaceInput,
  FreezeRevisionInput,
} from "../services/governance/contracts.js";
import {
  fingerprintApproveBaseline,
  fingerprintCreateProjectWorkspace,
  fingerprintFreezeRevision,
  type CommandFingerprint,
} from "../services/governance/commandFingerprint.js";

const workspaceCreatedEvent = "PROJECT_WORKSPACE_CREATED";
const revisionFrozenEvent = "REVISION_FROZEN";
const baselineApprovedEvent = "BASELINE_APPROVED";

type Properties = Record<string, unknown>;

export class GovernanceConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GovernanceConflictError";
  }
}

export class GovernanceNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GovernanceNotFoundError";
  }
}

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

function toNumber(value: unknown): number {
  if (typeof value === "number") {
    return value;
  }
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

function toStringValue(value: unknown): string {
  if (value === null || value === undefined) {
    throw new TypeError("Expected a non-null string value");
  }
  return String(value);
}

function toOptionalString(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : String(value);
}

function nodeProperties(record: { get(key: string): unknown }, key: string): Properties {
  const node = record.get(key);
  if (typeof node !== "object" || node === null || !("properties" in node)) {
    throw new TypeError(`Expected Neo4j node '${key}'`);
  }
  return node.properties as Properties;
}

function mapProject(properties: Properties): Project {
  return {
    id: toStringValue(properties.id),
    business_id: toStringValue(properties.business_id),
    name: toStringValue(properties.name),
    description: toOptionalString(properties.description),
    status: toStringValue(properties.status) as Project["status"],
    version: toNumber(properties.version),
    created_at: toStringValue(properties.created_at),
    created_by: toStringValue(properties.created_by),
    updated_at: toStringValue(properties.updated_at),
    updated_by: toStringValue(properties.updated_by),
  };
}

function mapModel(properties: Properties): Model {
  return {
    id: toStringValue(properties.id),
    project_id: toStringValue(properties.project_id),
    business_id: toStringValue(properties.business_id),
    name: toStringValue(properties.name),
    level: toStringValue(properties.level) as Model["level"],
    status: toStringValue(properties.status) as Model["status"],
    version: toNumber(properties.version),
    created_at: toStringValue(properties.created_at),
    created_by: toStringValue(properties.created_by),
    updated_at: toStringValue(properties.updated_at),
    updated_by: toStringValue(properties.updated_by),
  };
}

function mapRevision(properties: Properties): Revision {
  return {
    id: toStringValue(properties.id),
    project_id: toStringValue(properties.project_id),
    model_id: toStringValue(properties.model_id),
    standard_profile_version_id: toStringValue(properties.standard_profile_version_id),
    business_id: toStringValue(properties.business_id),
    status: toStringValue(properties.status) as Revision["status"],
    version: toNumber(properties.version),
    created_at: toStringValue(properties.created_at),
    created_by: toStringValue(properties.created_by),
    updated_at: toStringValue(properties.updated_at),
    updated_by: toStringValue(properties.updated_by),
  };
}

function mapStandardProfileVersion(properties: Properties): StandardProfileVersion {
  return {
    id: toStringValue(properties.id),
    project_id: toStringValue(properties.project_id),
    business_id: toStringValue(properties.business_id),
    name: toStringValue(properties.name),
    profile_version: toStringValue(properties.profile_version),
    standard_references: Array.isArray(properties.standard_references)
      ? properties.standard_references.map(String)
      : [],
    maturity: toStringValue(properties.maturity) as StandardProfileVersion["maturity"],
    version: toNumber(properties.version),
    created_at: toStringValue(properties.created_at),
    created_by: toStringValue(properties.created_by),
    updated_at: toStringValue(properties.updated_at),
    updated_by: toStringValue(properties.updated_by),
  };
}

function mapBaseline(properties: Properties): Baseline {
  return {
    id: toStringValue(properties.id),
    project_id: toStringValue(properties.project_id),
    model_id: toStringValue(properties.model_id),
    source_revision_id: toStringValue(properties.source_revision_id),
    standard_profile_version_id: toStringValue(properties.standard_profile_version_id),
    business_id: toStringValue(properties.business_id),
    content_hash: toStringValue(properties.content_hash),
    status: toStringValue(properties.status) as Baseline["status"],
    version: toNumber(properties.version),
    created_at: toStringValue(properties.created_at),
    created_by: toStringValue(properties.created_by),
    frozen_at: toStringValue(properties.frozen_at),
    frozen_by: toStringValue(properties.frozen_by),
    updated_at: toStringValue(properties.updated_at),
    updated_by: toStringValue(properties.updated_by),
    approved_at: toOptionalString(properties.approved_at),
    approved_by: toOptionalString(properties.approved_by),
    approval_rationale: toOptionalString(properties.approval_rationale),
  };
}

async function findCommandEvent(
  transaction: ManagedTransaction,
  commandId: string,
): Promise<Properties | undefined> {
  const result = await transaction.run(
    "MATCH (event:AuditEvent {command_id: $command_id}) RETURN event",
    { command_id: commandId },
  );
  return result.records.length === 0 ? undefined : nodeProperties(result.records[0], "event");
}

function assertEventType(
  commandId: string,
  properties: Properties,
  expectedEventType: string,
): void {
  const actualEventType = toStringValue(properties.event_type);
  if (actualEventType !== expectedEventType) {
    throw new CommandReuseError(commandId, actualEventType, expectedEventType);
  }
}

function assertRequestFingerprint(
  commandId: string,
  properties: Properties,
  expected: CommandFingerprint,
): void {
  const actualHash = toOptionalString(properties.request_hash);
  const actualAlgorithm = toOptionalString(properties.request_hash_algorithm);
  const actualCanonicalizer = toOptionalString(properties.request_canonicalizer);
  if (
    actualHash === undefined ||
    actualAlgorithm !== expected.request_hash_algorithm ||
    actualCanonicalizer !== expected.request_canonicalizer
  ) {
    throw new CommandReceiptUnverifiableError(commandId);
  }
  if (actualHash !== expected.request_hash) {
    throw new CommandPayloadMismatchError(commandId);
  }
}

async function readWorkspace(
  transaction: ManagedTransaction,
  ids: { projectId: string; modelId: string; revisionId: string; profileId: string },
  replayed: boolean,
): Promise<ProjectWorkspace> {
  const result = await transaction.run(
    `MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->(model:Model {id: $model_id})
     MATCH (model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id})
     MATCH (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile:StandardProfileVersion {id: $profile_id})
     RETURN project, model, revision, profile`,
    {
      project_id: ids.projectId,
      model_id: ids.modelId,
      revision_id: ids.revisionId,
      profile_id: ids.profileId,
    },
  );
  if (result.records.length === 0) {
    throw new GovernanceNotFoundError("The workspace referenced by the command receipt no longer exists");
  }
  const record = result.records[0];
  return {
    project: mapProject(nodeProperties(record, "project")),
    model: mapModel(nodeProperties(record, "model")),
    revision: mapRevision(nodeProperties(record, "revision")),
    standard_profile_version: mapStandardProfileVersion(nodeProperties(record, "profile")),
    replayed,
  };
}

async function readBaseline(
  transaction: ManagedTransaction,
  baselineId: string,
): Promise<Baseline> {
  const result = await transaction.run("MATCH (baseline:Baseline {id: $id}) RETURN baseline", {
    id: baselineId,
  });
  if (result.records.length === 0) {
    throw new GovernanceNotFoundError(`Baseline '${baselineId}' not found`);
  }
  return mapBaseline(nodeProperties(result.records[0], "baseline"));
}

export class GovernanceRepository {
  async createProjectWorkspace(input: CreateProjectWorkspaceInput): Promise<ProjectWorkspace> {
    const requestFingerprint = fingerprintCreateProjectWorkspace(input);
    const session = getDriver().session();
    try {
      return await session.executeWrite(async (transaction) => {
        const priorEvent = await findCommandEvent(transaction, input.command_id);
        if (priorEvent) {
          assertEventType(input.command_id, priorEvent, workspaceCreatedEvent);
          assertRequestFingerprint(input.command_id, priorEvent, requestFingerprint);
          return readWorkspace(
            transaction,
            {
              projectId: toStringValue(priorEvent.result_project_id),
              modelId: toStringValue(priorEvent.result_model_id),
              revisionId: toStringValue(priorEvent.result_revision_id),
              profileId: toStringValue(priorEvent.result_profile_id),
            },
            true,
          );
        }

        const ids = {
          projectId: randomUUID(),
          modelId: randomUUID(),
          revisionId: randomUUID(),
          profileId: randomUUID(),
          auditEventId: randomUUID(),
        };
        const now = new Date().toISOString();
        const result = await transaction.run(
          `CREATE (project:Project {
             id: $project_id, business_id: $project_business_id, name: $project_name,
             description: $project_description, status: 'Active', version: 1,
             created_at: datetime($now), created_by: $actor,
             updated_at: datetime($now), updated_by: $actor
           })
           CREATE (model:Model {
             id: $model_id, project_id: $project_id, business_id: $model_business_id,
             name: $model_name, level: $model_level, status: 'Active', version: 1,
             created_at: datetime($now), created_by: $actor,
             updated_at: datetime($now), updated_by: $actor
           })
           CREATE (profile:StandardProfileVersion {
             id: $profile_id, project_id: $project_id, business_id: $profile_business_id,
             name: $profile_name, profile_version: $profile_version,
             standard_references: $standard_references, maturity: 'Draft', version: 1,
             created_at: datetime($now), created_by: $actor,
             updated_at: datetime($now), updated_by: $actor
           })
           CREATE (revision:Revision {
             id: $revision_id, project_id: $project_id, model_id: $model_id,
             standard_profile_version_id: $profile_id, business_id: $revision_business_id,
             status: 'Draft', version: 1,
             created_at: datetime($now), created_by: $actor,
             updated_at: datetime($now), updated_by: $actor
           })
           CREATE (project)-[:HAS_MODEL]->(model)
           CREATE (project)-[:HAS_STANDARD_PROFILE_VERSION]->(profile)
           CREATE (model)-[:HAS_REVISION]->(revision)
           CREATE (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile)
           CREATE (event:AuditEvent {
             id: $audit_event_id, command_id: $command_id, actor: $actor,
             event_type: '${workspaceCreatedEvent}', occurred_at: datetime($now),
             request_hash: $request_hash,
             request_hash_algorithm: $request_hash_algorithm,
             request_canonicalizer: $request_canonicalizer,
             project_id: $project_id, result_project_id: $project_id,
             result_model_id: $model_id, result_revision_id: $revision_id,
             result_profile_id: $profile_id
           })
           CREATE (event)-[:AFFECTS]->(project)
           CREATE (event)-[:AFFECTS]->(model)
           CREATE (event)-[:AFFECTS]->(revision)
           CREATE (event)-[:AFFECTS]->(profile)
           RETURN project, model, revision, profile`,
          {
            project_id: ids.projectId,
            project_business_id: input.project.business_id,
            project_name: input.project.name,
            project_description: input.project.description ?? null,
            model_id: ids.modelId,
            model_business_id: input.model.business_id,
            model_name: input.model.name,
            model_level: input.model.level,
            profile_id: ids.profileId,
            profile_business_id: input.standard_profile.business_id,
            profile_name: input.standard_profile.name,
            profile_version: input.standard_profile.profile_version,
            standard_references: input.standard_profile.standard_references,
            revision_id: ids.revisionId,
            revision_business_id: input.revision.business_id,
            audit_event_id: ids.auditEventId,
            command_id: input.command_id,
            actor: input.actor,
            now,
            ...requestFingerprint,
          },
        );
        const record = result.records[0];
        return {
          project: mapProject(nodeProperties(record, "project")),
          model: mapModel(nodeProperties(record, "model")),
          revision: mapRevision(nodeProperties(record, "revision")),
          standard_profile_version: mapStandardProfileVersion(nodeProperties(record, "profile")),
          replayed: false,
        };
      });
    } finally {
      await session.close();
    }
  }

  async freezeRevision(input: FreezeRevisionInput): Promise<CommandResult<Baseline>> {
    const requestFingerprint = fingerprintFreezeRevision(input);
    const session = getDriver().session();
    try {
      return await session.executeWrite(async (transaction) => {
        const priorEvent = await findCommandEvent(transaction, input.command_id);
        if (priorEvent) {
          assertEventType(input.command_id, priorEvent, revisionFrozenEvent);
          assertRequestFingerprint(input.command_id, priorEvent, requestFingerprint);
          return {
            value: await readBaseline(transaction, toStringValue(priorEvent.result_baseline_id)),
            replayed: true,
          };
        }

        const baselineId = randomUUID();
        const auditEventId = randomUUID();
        const now = new Date().toISOString();
        const result = await transaction.run(
          `MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->(model:Model)
                 -[:HAS_REVISION]->(revision:Revision {
                   id: $revision_id, project_id: $project_id,
                   status: 'Draft', version: $expected_revision_version
                 })
           MATCH (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile:StandardProfileVersion)
           SET revision.status = 'Closed',
               revision.version = revision.version + 1,
               revision.updated_at = datetime($now),
               revision.updated_by = $actor
           CREATE (baseline:Baseline {
             id: $baseline_id, project_id: $project_id, model_id: model.id,
             source_revision_id: revision.id, standard_profile_version_id: profile.id,
             business_id: $baseline_business_id, content_hash: $content_hash,
             status: 'Frozen', version: 1,
             created_at: datetime($now), created_by: $actor,
             frozen_at: datetime($now), frozen_by: $actor,
             updated_at: datetime($now), updated_by: $actor
           })
           CREATE (revision)-[:FROZEN_AS]->(baseline)
           CREATE (model)-[:HAS_BASELINE]->(baseline)
           CREATE (event:AuditEvent {
             id: $audit_event_id, command_id: $command_id, actor: $actor,
             event_type: '${revisionFrozenEvent}', occurred_at: datetime($now),
             request_hash: $request_hash,
             request_hash_algorithm: $request_hash_algorithm,
             request_canonicalizer: $request_canonicalizer,
             project_id: $project_id, subject_id: revision.id,
             subject_version_before: $expected_revision_version,
             subject_version_after: revision.version,
             result_baseline_id: $baseline_id
           })
           CREATE (event)-[:AFFECTS]->(revision)
           CREATE (event)-[:AFFECTS]->(baseline)
           RETURN baseline`,
          {
            project_id: input.project_id,
            revision_id: input.revision_id,
            expected_revision_version: input.expected_revision_version,
            baseline_id: baselineId,
            baseline_business_id: input.baseline.business_id,
            content_hash: input.baseline.content_hash,
            audit_event_id: auditEventId,
            command_id: input.command_id,
            actor: input.actor,
            now,
            ...requestFingerprint,
          },
        );
        if (result.records.length > 0) {
          return {
            value: mapBaseline(nodeProperties(result.records[0], "baseline")),
            replayed: false,
          };
        }

        const actual = await transaction.run(
          `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
           RETURN revision.status AS status, revision.version AS version`,
          { revision_id: input.revision_id, project_id: input.project_id },
        );
        if (actual.records.length === 0) {
          throw new GovernanceNotFoundError(`Revision '${input.revision_id}' not found in project`);
        }
        throw new GovernanceConflictError(
          `Revision '${input.revision_id}' must be Draft at version ${input.expected_revision_version}; ` +
            `actual status=${String(actual.records[0].get("status"))}, ` +
            `version=${toNumber(actual.records[0].get("version"))}`,
        );
      });
    } finally {
      await session.close();
    }
  }

  async approveBaseline(input: ApproveBaselineInput): Promise<CommandResult<Baseline>> {
    const requestFingerprint = fingerprintApproveBaseline(input);
    const session = getDriver().session();
    try {
      return await session.executeWrite(async (transaction) => {
        const priorEvent = await findCommandEvent(transaction, input.command_id);
        if (priorEvent) {
          assertEventType(input.command_id, priorEvent, baselineApprovedEvent);
          assertRequestFingerprint(input.command_id, priorEvent, requestFingerprint);
          return {
            value: await readBaseline(transaction, toStringValue(priorEvent.result_baseline_id)),
            replayed: true,
          };
        }

        const auditEventId = randomUUID();
        const now = new Date().toISOString();
        const result = await transaction.run(
          `MATCH (baseline:Baseline {
             id: $baseline_id, project_id: $project_id,
             status: 'Frozen', version: $expected_baseline_version
           })
           SET baseline.status = 'Approved',
               baseline.version = baseline.version + 1,
               baseline.approved_at = datetime($now),
               baseline.approved_by = $actor,
               baseline.approval_rationale = $rationale,
               baseline.updated_at = datetime($now),
               baseline.updated_by = $actor
           CREATE (event:AuditEvent {
             id: $audit_event_id, command_id: $command_id, actor: $actor,
             event_type: '${baselineApprovedEvent}', occurred_at: datetime($now),
             request_hash: $request_hash,
             request_hash_algorithm: $request_hash_algorithm,
             request_canonicalizer: $request_canonicalizer,
             project_id: $project_id, subject_id: baseline.id,
             subject_version_before: $expected_baseline_version,
             subject_version_after: baseline.version,
             result_baseline_id: baseline.id
           })
           CREATE (event)-[:AFFECTS]->(baseline)
           RETURN baseline`,
          {
            project_id: input.project_id,
            baseline_id: input.baseline_id,
            expected_baseline_version: input.expected_baseline_version,
            rationale: input.rationale,
            audit_event_id: auditEventId,
            command_id: input.command_id,
            actor: input.actor,
            now,
            ...requestFingerprint,
          },
        );
        if (result.records.length > 0) {
          return {
            value: mapBaseline(nodeProperties(result.records[0], "baseline")),
            replayed: false,
          };
        }

        const actual = await transaction.run(
          `MATCH (baseline:Baseline {id: $baseline_id, project_id: $project_id})
           RETURN baseline.status AS status, baseline.version AS version`,
          { baseline_id: input.baseline_id, project_id: input.project_id },
        );
        if (actual.records.length === 0) {
          throw new GovernanceNotFoundError(`Baseline '${input.baseline_id}' not found in project`);
        }
        throw new GovernanceConflictError(
          `Baseline '${input.baseline_id}' must be Frozen at version ${input.expected_baseline_version}; ` +
            `actual status=${String(actual.records[0].get("status"))}, ` +
            `version=${toNumber(actual.records[0].get("version"))}`,
        );
      });
    } finally {
      await session.close();
    }
  }
}
