import { getDriver } from "../db/neo4j.js";
import { findScopedNodeIdentity } from "../services/identity/scopedIdentity.js";

export interface LegacyIdentityScope {
  project_id: string;
  revision_id: string;
}

export interface LegacyNodeIdentity extends LegacyIdentityScope {
  entity_type: string;
  id: string;
  business_id: string;
  legacy_id: string;
  legacy_key: string;
}

export interface LegacyRelationshipIdentity extends LegacyIdentityScope {
  relationship_type: "ASSET_EDGE";
  id: string;
  business_id: string;
  legacy_id: string;
}

export class UnsupportedLegacyEntityTypeError extends Error {
  constructor(readonly entityType: string) {
    super(`Legacy identity type is not registered: ${entityType}`);
    this.name = "UnsupportedLegacyEntityTypeError";
  }
}

export class LegacyIdentityNotFoundError extends Error {
  constructor(readonly entityType: string, readonly identifier: string) {
    super(`No ${entityType} identity matches ${identifier} inside the requested revision scope`);
    this.name = "LegacyIdentityNotFoundError";
  }
}

export class LegacyIdentityAmbiguousError extends Error {
  constructor(readonly entityType: string, readonly identifier: string) {
    super(`More than one ${entityType} identity matches ${identifier} inside the requested revision scope`);
    this.name = "LegacyIdentityAmbiguousError";
  }
}

function required(value: unknown, field: string): string {
  const normalized = value === null || value === undefined ? "" : String(value).trim();
  if (!normalized) throw new Error(`Resolved identity is missing ${field}`);
  return normalized;
}

/**
 * Compatibility boundary for legacy business identifiers.
 *
 * Every lookup is explicitly scoped. New code should persist and exchange `id`;
 * `business_id`, `legacy_id`, and the original legacy key remain accepted only at
 * this boundary while callers migrate.
 */
export class LegacyIdentityRepository {
  async resolveNode(input: LegacyIdentityScope & {
    entity_type: string;
    identifier: string;
    analysis_batch_id?: string;
  }): Promise<LegacyNodeIdentity> {
    const definition = findScopedNodeIdentity(input.entity_type);
    if (!definition) throw new UnsupportedLegacyEntityTypeError(input.entity_type);

    const nestedScope =
      definition.businessScope === "analysis-run"
        ? "AND node.analysis_batch_id = $analysis_batch_id"
        : "";
    if (definition.businessScope === "analysis-run" && !input.analysis_batch_id?.trim()) {
      throw new Error("AttackPath legacy identity lookup requires analysis_batch_id");
    }

    const session = getDriver().session();
    try {
      const result = await session.run(
        `MATCH (node:${definition.label} {
           project_id: $project_id,
           revision_id: $revision_id
         })
         WHERE (
           node.id = $identifier
           OR node.business_id = $identifier
           OR node.legacy_id = $identifier
           OR toString(node.${definition.legacyKey}) = $identifier
         )
         ${nestedScope}
         RETURN node.id AS id,
                node.business_id AS business_id,
                node.legacy_id AS legacy_id
         LIMIT 2`,
        {
          project_id: input.project_id,
          revision_id: input.revision_id,
          identifier: input.identifier,
          analysis_batch_id: input.analysis_batch_id ?? null,
        },
      );
      if (result.records.length === 0) {
        throw new LegacyIdentityNotFoundError(input.entity_type, input.identifier);
      }
      if (result.records.length > 1) {
        throw new LegacyIdentityAmbiguousError(input.entity_type, input.identifier);
      }
      const record = result.records[0];
      return {
        entity_type: definition.label,
        project_id: input.project_id,
        revision_id: input.revision_id,
        id: required(record.get("id"), "id"),
        business_id: required(record.get("business_id"), "business_id"),
        legacy_id: required(record.get("legacy_id"), "legacy_id"),
        legacy_key: definition.legacyKey,
      };
    } finally {
      await session.close();
    }
  }

  async resolveAssetEdge(input: LegacyIdentityScope & {
    identifier: string;
  }): Promise<LegacyRelationshipIdentity> {
    const session = getDriver().session();
    try {
      const result = await session.run(
        `MATCH ()-[edge:ASSET_EDGE {
           project_id: $project_id,
           revision_id: $revision_id
         }]->()
         WHERE edge.id = $identifier
            OR edge.business_id = $identifier
            OR edge.legacy_id = $identifier
            OR toString(edge.edge_id) = $identifier
         RETURN edge.id AS id,
                edge.business_id AS business_id,
                edge.legacy_id AS legacy_id
         LIMIT 2`,
        input,
      );
      if (result.records.length === 0) {
        throw new LegacyIdentityNotFoundError("ASSET_EDGE", input.identifier);
      }
      if (result.records.length > 1) {
        throw new LegacyIdentityAmbiguousError("ASSET_EDGE", input.identifier);
      }
      const record = result.records[0];
      return {
        relationship_type: "ASSET_EDGE",
        project_id: input.project_id,
        revision_id: input.revision_id,
        id: required(record.get("id"), "id"),
        business_id: required(record.get("business_id"), "business_id"),
        legacy_id: required(record.get("legacy_id"), "legacy_id"),
      };
    } finally {
      await session.close();
    }
  }
}
