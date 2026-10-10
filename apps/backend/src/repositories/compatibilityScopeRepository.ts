import { getDriver } from "../db/neo4j.js";
import {
  resolveLegacyContext,
  type LegacyDatasetKind,
} from "../services/legacyMigration/legacyAttachment.js";

export interface ProjectRevisionScope {
  project_id: string;
  model_id: string;
  revision_id: string;
}

export interface ResolvedCompatibilityScope extends ProjectRevisionScope {
  source: "explicit" | "legacy-default";
  dataset_kind?: LegacyDatasetKind;
}

export class CompatibilityScopeInputError extends Error {
  readonly statusCode = 400;

  constructor(message: string) {
    super(message);
    this.name = "CompatibilityScopeInputError";
  }
}

export class CompatibilityScopeNotFoundError extends Error {
  readonly statusCode = 404;

  constructor(message: string) {
    super(message);
    this.name = "CompatibilityScopeNotFoundError";
  }
}

function optional(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

/** Resolves exactly one Project/Model/Revision boundary for legacy compatibility reads. */
export class CompatibilityScopeRepository {
  constructor(private readonly defaultDatasetKind: LegacyDatasetKind = "do356a-appendix-d") {}

  async resolve(input: {
    project_id?: string;
    revision_id?: string;
  } = {}): Promise<ResolvedCompatibilityScope> {
    const projectId = optional(input.project_id);
    const revisionId = optional(input.revision_id);
    if (Boolean(projectId) !== Boolean(revisionId)) {
      throw new CompatibilityScopeInputError(
        "project_id and revision_id must be supplied together",
      );
    }

    const session = getDriver().session();
    try {
      if (projectId && revisionId) {
        const result = await session.run(
          `MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->
                 (model:Model)-[:HAS_REVISION]->
                 (revision:Revision {id: $revision_id, project_id: $project_id})
           RETURN project.id AS project_id, model.id AS model_id, revision.id AS revision_id
           LIMIT 2`,
          { project_id: projectId, revision_id: revisionId },
        );
        if (result.records.length !== 1) {
          throw new CompatibilityScopeNotFoundError(
            "The requested project/revision scope does not exist or is not uniquely related",
          );
        }
        return {
          project_id: String(result.records[0].get("project_id")),
          model_id: String(result.records[0].get("model_id")),
          revision_id: String(result.records[0].get("revision_id")),
          source: "explicit",
        };
      }

      const config = resolveLegacyContext(this.defaultDatasetKind);
      const result = await session.run(
        `MATCH (project:Project {business_id: $project_business_id})-[:HAS_MODEL]->
               (model:Model {business_id: $model_business_id})-[:HAS_REVISION]->
               (revision:Revision {business_id: $revision_business_id})
         WHERE revision.project_id = project.id AND revision.model_id = model.id
         RETURN project.id AS project_id, model.id AS model_id, revision.id AS revision_id
         LIMIT 2`,
        {
          project_business_id: config.project.business_id,
          model_business_id: config.model.business_id,
          revision_business_id: config.revision.business_id,
        },
      );
      if (result.records.length !== 1) {
        throw new CompatibilityScopeNotFoundError(
          `The configured legacy compatibility workspace (${this.defaultDatasetKind}) is unavailable`,
        );
      }
      return {
        project_id: String(result.records[0].get("project_id")),
        model_id: String(result.records[0].get("model_id")),
        revision_id: String(result.records[0].get("revision_id")),
        source: "legacy-default",
        dataset_kind: this.defaultDatasetKind,
      };
    } finally {
      await session.close();
    }
  }
}
