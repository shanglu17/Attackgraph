import { createHash } from "node:crypto";
import {
  systemModelContractVersion,
  type SystemModelCommitRequest,
  type SystemModelCommitResult,
  type SystemModelCounts,
  type SystemModelImportPayload,
  type SystemModelPreviewRequest,
  type SystemModelPreviewResult,
} from "@attackgraph/contracts";
import { RevisionUnitOfWork } from "../repositories/revisionUnitOfWork.js";
import {
  SystemModelConflictError,
  SystemModelRepository,
  SystemModelScopeNotFoundError,
} from "../repositories/systemModelRepository.js";

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("import payload numbers must be finite");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  throw new TypeError(`unsupported import value: ${typeof value}`);
}

export function hashSystemModelImport(payload: SystemModelImportPayload): string {
  return createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

function counts(payload: SystemModelImportPayload): SystemModelCounts {
  return {
    assets: payload.entities.assets.length,
    functions: payload.entities.functions.length,
    interfaces: payload.entities.interfaces.length,
    data_flows: payload.entities.data_flows.length,
    security_boundaries: payload.entities.security_boundaries.length,
    external_entities: payload.entities.external_entities.length,
    evidence_records: payload.entities.evidence_records.length,
    trace_links: payload.entities.trace_links.length,
  };
}

function key(type: string, businessId: string) {
  return `${type}:${businessId}`;
}

export function validateSystemModelImport(
  payload: SystemModelImportPayload,
  existingIdentities: ReadonlySet<string> = new Set(),
): string[] {
  const errors: string[] = [];
  const known = new Set(existingIdentities);
  if (existingIdentities.has(key("SourceRecord", payload.source.business_id))) {
    errors.push(`create-only import conflicts with existing SourceRecord:${payload.source.business_id}`);
  }
  const collections = [
    ["Asset", payload.entities.assets],
    ["Function", payload.entities.functions],
    ["Interface", payload.entities.interfaces],
    ["DataFlow", payload.entities.data_flows],
    ["SecurityBoundary", payload.entities.security_boundaries],
    ["ExternalEntity", payload.entities.external_entities],
    ["EvidenceRecord", payload.entities.evidence_records],
    ["TraceLink", payload.entities.trace_links],
  ] as const;

  for (const [type, entities] of collections) {
    const seen = new Set<string>();
    for (const entity of entities) {
      const identity = key(type, entity.business_id);
      if (seen.has(entity.business_id)) errors.push(`duplicate ${type} business_id '${entity.business_id}' in import`);
      if (existingIdentities.has(identity)) errors.push(`create-only import conflicts with existing ${identity}`);
      seen.add(entity.business_id);
      if (type !== "TraceLink") known.add(identity);
    }
  }

  const requireIdentity = (type: string, businessId: string, context: string) => {
    if (!known.has(key(type, businessId))) errors.push(`${context} references unresolved ${type}:${businessId}`);
  };
  for (const entity of payload.entities.functions) {
    if (entity.parent_function_business_id) requireIdentity("Function", entity.parent_function_business_id, `Function:${entity.business_id}`);
  }
  for (const entity of payload.entities.security_boundaries) {
    for (const asset of entity.member_asset_business_ids) requireIdentity("Asset", asset, `SecurityBoundary:${entity.business_id}`);
  }
  for (const entity of payload.entities.interfaces) {
    for (const asset of entity.asset_business_ids) requireIdentity("Asset", asset, `Interface:${entity.business_id}`);
    if (entity.boundary_business_id) requireIdentity("SecurityBoundary", entity.boundary_business_id, `Interface:${entity.business_id}`);
    if (entity.external_entity_business_id) requireIdentity("ExternalEntity", entity.external_entity_business_id, `Interface:${entity.business_id}`);
  }
  for (const entity of payload.entities.data_flows) {
    requireIdentity("Asset", entity.producer_asset_business_id, `DataFlow:${entity.business_id}`);
    requireIdentity("Asset", entity.consumer_asset_business_id, `DataFlow:${entity.business_id}`);
    if (entity.interface_business_id) requireIdentity("Interface", entity.interface_business_id, `DataFlow:${entity.business_id}`);
    for (const fn of entity.supported_function_business_ids) requireIdentity("Function", fn, `DataFlow:${entity.business_id}`);
  }
  for (const link of payload.entities.trace_links) {
    requireIdentity(link.source.type, link.source.business_id, `TraceLink:${link.business_id}`);
    requireIdentity(link.target.type, link.target.business_id, `TraceLink:${link.business_id}`);
  }
  return [...new Set(errors)].sort();
}

export class SystemModelImportService {
  constructor(
    private readonly repository = new SystemModelRepository(),
    private readonly unitOfWork = new RevisionUnitOfWork(),
  ) {}

  async preview(input: SystemModelPreviewRequest): Promise<SystemModelPreviewResult> {
    const scope = await this.repository.inspectScope(input.project_id, input.revision_id);
    if (!scope.exists) throw new SystemModelScopeNotFoundError(input.project_id, input.revision_id);
    const errors = validateSystemModelImport(input.import, scope.identities);
    const total = Object.values(counts(input.import)).reduce((sum, value) => sum + value, 0);
    return {
      contract_version: systemModelContractVersion,
      ok: errors.length === 0,
      import_hash: hashSystemModelImport(input.import),
      counts: counts(input.import),
      errors,
      warnings: total === 0 ? ["import contains no model entities"] : [],
    };
  }

  async commit(input: SystemModelCommitRequest): Promise<SystemModelCommitResult> {
    const structuralErrors = validateSystemModelImport(input.import)
      .filter((message) => message.startsWith("duplicate "));
    if (structuralErrors.length > 0) throw new SystemModelConflictError(structuralErrors.join("; "));
    const entityCounts = counts(input.import);
    const preview: SystemModelPreviewResult = {
      contract_version: systemModelContractVersion,
      ok: true,
      import_hash: hashSystemModelImport(input.import),
      counts: entityCounts,
      errors: [],
      warnings: Object.values(entityCounts).every((value) => value === 0)
        ? ["import contains no model entities"]
        : [],
    };
    const canonicalPayload = JSON.parse(JSON.stringify(input.import)) as SystemModelImportPayload;
    const result = await this.unitOfWork.execute(
      {
        actor: input.actor,
        command_id: input.command_id,
        project_id: input.project_id,
        revision_id: input.revision_id,
        expected_revision_version: input.expected_revision_version,
        event_type: "SYSTEM_MODEL_IMPORTED",
        request_canonicalizer: "system-model.import/v2",
        payload: canonicalPayload,
        summary: `Import ${preview.import_hash} into system model revision`,
      },
      async ({ transaction, project_id, revision_id, new_revision_version }) =>
        this.repository.createImport(transaction, {
          project_id,
          revision_id,
          actor: input.actor,
          revision_version: new_revision_version,
          payload: input.import,
        }),
    );
    return {
      ...preview,
      committed: true,
      replayed: result.replayed,
      audit_event_id: result.audit_event_id,
      new_revision_version: result.new_revision_version,
      created_ids: result.value,
    };
  }
}
