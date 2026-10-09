import { randomUUID } from "node:crypto";
import { getDriver } from "../db/neo4j.js";
import {
  legacyEntityDefinitions,
  legacyPlanHash,
  nonProjectLabels,
  stableIssueKey,
  type DetectedLegacyDatasetKind,
  type LegacyAttachmentPlan,
  type LegacyAttachmentResult,
  type LegacyAttachmentVerification,
  type LegacyContextConfig,
  type LegacyInventoryEntry,
  type LegacyMigrationIssueCandidate,
} from "../services/legacyMigration/legacyAttachment.js";

export class LegacyAttachmentBlockedError extends Error {
  constructor(readonly plan: LegacyAttachmentPlan) {
    super(
      `Legacy attachment is blocked by ${plan.summary.blocking_issue_count} issue(s); inspect the dry-run report`,
    );
    this.name = "LegacyAttachmentBlockedError";
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
  return Number(value ?? 0);
}

function optionalString(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : String(value);
}

function issue(input: Omit<LegacyMigrationIssueCandidate, "issue_key"> & { datasetKind: LegacyContextConfig["dataset_kind"] }): LegacyMigrationIssueCandidate {
  return {
    issue_key: stableIssueKey({
      datasetKind: input.datasetKind,
      issueType: input.issue_type,
      subjectLabel: input.subject_label,
      subjectKeys: input.subject_keys,
    }),
    issue_type: input.issue_type,
    severity: input.severity,
    blocking: input.blocking,
    subject_label: input.subject_label,
    affected_count: input.affected_count,
    subject_keys: input.subject_keys,
    message: input.message,
    candidate_actions: input.candidate_actions,
  };
}

export class LegacyAttachmentRepository {
  async inspect(config: LegacyContextConfig): Promise<LegacyAttachmentPlan> {
    const session = getDriver().session();
    try {
      const contextResult = await session.run(
        `OPTIONAL MATCH (project:Project {business_id: $project_business_id})
         OPTIONAL MATCH (project)-[:HAS_MODEL]->(model:Model {business_id: $model_business_id})
         OPTIONAL MATCH (model)-[:HAS_REVISION]->(revision:Revision {business_id: $revision_business_id})
         OPTIONAL MATCH (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile:StandardProfileVersion {
           business_id: $profile_business_id,
           profile_version: $profile_version
         })
         RETURN project.id AS project_id, model.id AS model_id,
                revision.id AS revision_id, profile.id AS profile_id`,
        {
          project_business_id: config.project.business_id,
          model_business_id: config.model.business_id,
          revision_business_id: config.revision.business_id,
          profile_business_id: config.standard_profile.business_id,
          profile_version: config.standard_profile.profile_version,
        },
      );
      const contextRecord = contextResult.records[0];
      const target = {
        project_id: optionalString(contextRecord?.get("project_id")),
        model_id: optionalString(contextRecord?.get("model_id")),
        revision_id: optionalString(contextRecord?.get("revision_id")),
      };

      const inventoryResult = await session.run(
        `UNWIND $definitions AS definition
         MATCH (node)
         WHERE definition.label IN labels(node)
         WITH definition, node,
              CASE
                WHEN node.project_id IS NULL AND node.model_id IS NULL AND node.revision_id IS NULL THEN true
                WHEN $target_project_id IS NOT NULL
                 AND (node.project_id IS NULL OR node.project_id = $target_project_id)
                 AND (node.model_id IS NULL OR node.model_id = $target_model_id)
                 AND (node.revision_id IS NULL OR node.revision_id = $target_revision_id)
                 AND (node.project_id IS NULL OR node.model_id IS NULL OR node.revision_id IS NULL) THEN true
                ELSE false
              END AS attachable,
              CASE
                WHEN node.project_id IS NOT NULL AND node.model_id IS NOT NULL AND node.revision_id IS NOT NULL
                THEN true ELSE false
              END AS fully_scoped,
              CASE
                WHEN $target_project_id IS NOT NULL
                 AND node.project_id = $target_project_id
                 AND node.model_id = $target_model_id
                 AND node.revision_id = $target_revision_id
                THEN true ELSE false
              END AS scoped_to_target
         RETURN definition.label AS label,
                count(node) AS total,
                sum(CASE WHEN attachable THEN 1 ELSE 0 END) AS attachable,
                sum(CASE WHEN fully_scoped THEN 1 ELSE 0 END) AS fully_scoped,
                sum(CASE WHEN NOT attachable AND NOT fully_scoped THEN 1 ELSE 0 END) AS scope_conflicts,
                sum(CASE WHEN (attachable OR scoped_to_target) AND (node[definition.key] IS NULL OR trim(toString(node[definition.key])) = '') THEN 1 ELSE 0 END) AS missing_legacy_id,
                sum(CASE WHEN (attachable OR scoped_to_target) AND definition.source_required = true AND node.source IS NULL AND node.source_sheet IS NULL AND node.source_row IS NULL THEN 1 ELSE 0 END) AS missing_source_locator
         ORDER BY label`,
        {
          definitions: legacyEntityDefinitions,
          target_project_id: target.project_id ?? null,
          target_model_id: target.model_id ?? null,
          target_revision_id: target.revision_id ?? null,
        },
      );
      const inventory: LegacyInventoryEntry[] = inventoryResult.records.map((record) => ({
        label: String(record.get("label")),
        total: toNumber(record.get("total")),
        attachable: toNumber(record.get("attachable")),
        fully_scoped: toNumber(record.get("fully_scoped")),
        scope_conflicts: toNumber(record.get("scope_conflicts")),
        missing_legacy_id: toNumber(record.get("missing_legacy_id")),
        missing_source_locator: toNumber(record.get("missing_source_locator")),
      }));

      const markerResult = await session.run(
        `MATCH (node)
         WHERE (node:DO326A_Link AND toString(node.standard_id) STARTS WITH 'DO-356A-AppD')
            OR (node:AssetNode AND toLower(coalesce(node.description, '')) CONTAINS 'appendix d')
         RETURN count(node) AS appendix_d_markers`,
      );
      const appendixMarkers = toNumber(markerResult.records[0]?.get("appendix_d_markers"));
      const detectedDatasetKind: DetectedLegacyDatasetKind =
        appendixMarkers > 0 ? "do356a-appendix-d" : "unknown";

      const issues: LegacyMigrationIssueCandidate[] = [];
      if (
        detectedDatasetKind === "do356a-appendix-d" &&
        config.dataset_kind !== "do356a-appendix-d"
      ) {
        issues.push(
          issue({
            datasetKind: config.dataset_kind,
            issue_type: "DATASET_CLASSIFICATION_MISMATCH",
            severity: "High",
            blocking: true,
            subject_label: "Dataset",
            affected_count: appendixMarkers,
            subject_keys: ["DO-356A-AppD"],
            message:
              "The graph contains explicit DO-356A Appendix D markers and must not be attached to the generic legacy project.",
            candidate_actions: [
              "Run again with --dataset do356a-appendix-d",
              "Separate mixed datasets before attachment",
            ],
          }),
        );
      }

      const recognizedLabels = [
        ...legacyEntityDefinitions.map(({ label }) => label),
        ...nonProjectLabels,
      ];
      const unknownResult = await session.run(
        `MATCH (node)
         WHERE node.project_id IS NULL
           AND none(label IN labels(node) WHERE label IN $recognized_labels)
         RETURN labels(node) AS labels, count(node) AS count
         ORDER BY labels`,
        { recognized_labels: recognizedLabels },
      );
      for (const record of unknownResult.records) {
        const labels = (record.get("labels") as string[]).slice().sort();
        issues.push(
          issue({
            datasetKind: config.dataset_kind,
            issue_type: "UNKNOWN_SCHEMA",
            severity: "High",
            blocking: true,
            subject_label: labels.join("+") || "<unlabelled>",
            affected_count: toNumber(record.get("count")),
            subject_keys: labels,
            message: "Unscoped nodes use labels that are not registered in the legacy migration map.",
            candidate_actions: [
              "Add an reviewed mapping before attachment",
              "Move the nodes to a separately classified dataset",
            ],
          }),
        );
      }

      const conflictResult = await session.run(
        `UNWIND $definitions AS definition
         MATCH (node)
         WHERE definition.label IN labels(node)
           AND NOT (node.project_id IS NOT NULL AND node.model_id IS NOT NULL AND node.revision_id IS NOT NULL)
           AND NOT (
             (node.project_id IS NULL AND node.model_id IS NULL AND node.revision_id IS NULL)
             OR (
               $target_project_id IS NOT NULL
               AND (node.project_id IS NULL OR node.project_id = $target_project_id)
               AND (node.model_id IS NULL OR node.model_id = $target_model_id)
               AND (node.revision_id IS NULL OR node.revision_id = $target_revision_id)
             )
           )
         RETURN definition.label AS label, count(node) AS count,
                collect(coalesce(toString(node[definition.key]), elementId(node)))[..20] AS keys
         ORDER BY label`,
        {
          definitions: legacyEntityDefinitions,
          target_project_id: target.project_id ?? null,
          target_model_id: target.model_id ?? null,
          target_revision_id: target.revision_id ?? null,
        },
      );
      for (const record of conflictResult.records) {
        const label = String(record.get("label"));
        const keys = (record.get("keys") as string[]).map(String);
        issues.push(
          issue({
            datasetKind: config.dataset_kind,
            issue_type: "SCOPE_CONFLICT",
            severity: "High",
            blocking: false,
            subject_label: label,
            affected_count: toNumber(record.get("count")),
            subject_keys: keys,
            message: "Partially scoped nodes conflict with the requested project/model/revision context.",
            candidate_actions: [
              "Review the existing scope and attach through a compensating migration",
              "Move the node to the correct project after human confirmation",
            ],
          }),
        );
      }

      const duplicateResult = await session.run(
        `UNWIND $definitions AS definition
         MATCH (node)
         WHERE definition.label IN labels(node)
           AND (
             (node.project_id IS NULL AND node.model_id IS NULL AND node.revision_id IS NULL)
             OR (
               $target_project_id IS NOT NULL
               AND node.project_id = $target_project_id
               AND node.model_id = $target_model_id
               AND node.revision_id = $target_revision_id
             )
           )
           AND node[definition.key] IS NOT NULL AND trim(toString(node[definition.key])) <> ''
         WITH definition.label AS label, toString(node[definition.key]) AS legacy_id, count(node) AS count
         WHERE count > 1
         RETURN label, legacy_id, count
         ORDER BY label, legacy_id`,
        {
          definitions: legacyEntityDefinitions,
          target_project_id: target.project_id ?? null,
          target_model_id: target.model_id ?? null,
          target_revision_id: target.revision_id ?? null,
        },
      );
      for (const record of duplicateResult.records) {
        const label = String(record.get("label"));
        const legacyId = String(record.get("legacy_id"));
        issues.push(
          issue({
            datasetKind: config.dataset_kind,
            issue_type: "DUPLICATE_LEGACY_ID",
            severity: "High",
            blocking: false,
            subject_label: label,
            affected_count: toNumber(record.get("count")),
            subject_keys: [legacyId],
            message: `Legacy business identifier '${legacyId}' is duplicated within ${label}.`,
            candidate_actions: [
              "Assign distinct scoped business identifiers after review",
              "Document an approved merge decision",
            ],
          }),
        );
      }

      for (const entry of inventory) {
        if (entry.missing_legacy_id > 0) {
          issues.push(
            issue({
              datasetKind: config.dataset_kind,
              issue_type: "MISSING_LEGACY_ID",
              severity: "High",
              blocking: false,
              subject_label: entry.label,
              affected_count: entry.missing_legacy_id,
              subject_keys: [],
              message: `${entry.missing_legacy_id} ${entry.label} node(s) have no registered legacy identifier.`,
              candidate_actions: [
                "Assign a reviewed business identifier",
                "Retain the generated internal UUID and defer business identity resolution",
              ],
            }),
          );
        }
        if (entry.missing_source_locator > 0) {
          issues.push(
            issue({
              datasetKind: config.dataset_kind,
              issue_type: "MISSING_SOURCE_LOCATOR",
              severity: "Medium",
              blocking: false,
              subject_label: entry.label,
              affected_count: entry.missing_source_locator,
              subject_keys: [],
              message: `${entry.missing_source_locator} ${entry.label} node(s) have no source/source_sheet/source_row locator.`,
              candidate_actions: [
                "Resolve a controlled SourceRecord in Phase 2",
                "Keep the source explicitly unresolved; do not infer it from names",
              ],
            }),
          );
        }
      }

      issues.sort((left, right) => left.issue_key.localeCompare(right.issue_key));
      const summary = {
        known_entities: inventory.reduce((sum, entry) => sum + entry.total, 0),
        attachable_entities: inventory.reduce((sum, entry) => sum + entry.attachable, 0),
        fully_scoped_entities: inventory.reduce((sum, entry) => sum + entry.fully_scoped, 0),
        blocking_issue_count: issues.filter(({ blocking }) => blocking).length,
        non_blocking_issue_count: issues.filter(({ blocking }) => !blocking).length,
      };
      const withoutHash = {
        migration_id: "P1.3_LEGACY_ATTACHMENT" as const,
        requested_dataset_kind: config.dataset_kind,
        detected_dataset_kind: detectedDatasetKind,
        context: config,
        inventory,
        issues,
        summary,
        blocked: summary.blocking_issue_count > 0,
      };
      return { ...withoutHash, plan_hash: legacyPlanHash(withoutHash) };
    } finally {
      await session.close();
    }
  }

  async apply(input: {
    config: LegacyContextConfig;
    actor: string;
    command_id: string;
  }): Promise<LegacyAttachmentResult> {
    const session = getDriver().session();
    try {
      const prior = await session.run(
        `MATCH (run:LegacyAttachmentRun {command_id: $command_id})
         RETURN run`,
        { command_id: input.command_id },
      );
      if (prior.records.length > 0) {
        const properties = prior.records[0].get("run").properties as Record<string, unknown>;
        if (String(properties.dataset_kind) !== input.config.dataset_kind) {
          throw new Error(
            `command_id '${input.command_id}' was already used for dataset ${String(properties.dataset_kind)}`,
          );
        }
        return {
          run_id: String(properties.id),
          command_id: String(properties.command_id),
          dataset_kind: properties.dataset_kind as LegacyContextConfig["dataset_kind"],
          project_id: String(properties.project_id),
          model_id: String(properties.model_id),
          revision_id: String(properties.revision_id),
          standard_profile_version_id: String(properties.standard_profile_version_id),
          attached_count: toNumber(properties.attached_count),
          issue_count: toNumber(properties.issue_count),
          plan_hash: String(properties.plan_hash),
          replayed: true,
        };
      }

      const plan = await this.inspect(input.config);
      if (plan.blocked) throw new LegacyAttachmentBlockedError(plan);

      return await session.executeWrite(async (transaction) => {
        const ids = {
          project: randomUUID(),
          model: randomUUID(),
          revision: randomUUID(),
          profile: randomUUID(),
          run: randomUUID(),
          audit: randomUUID(),
        };
        const now = new Date().toISOString();
        const contextResult = await transaction.run(
          `MERGE (project:Project {business_id: $project_business_id})
           ON CREATE SET project.id = $project_id, project.name = $project_name,
             project.description = $project_description, project.status = 'Active', project.version = 1,
             project.created_at = datetime($now), project.created_by = $actor,
             project.updated_at = datetime($now), project.updated_by = $actor
           MERGE (model:Model {project_id: project.id, business_id: $model_business_id})
           ON CREATE SET model.id = $model_id, model.name = $model_name, model.level = $model_level,
             model.status = 'Active', model.version = 1,
             model.created_at = datetime($now), model.created_by = $actor,
             model.updated_at = datetime($now), model.updated_by = $actor
           MERGE (profile:StandardProfileVersion {
             project_id: project.id, business_id: $profile_business_id, profile_version: $profile_version
           })
           ON CREATE SET profile.id = $profile_id, profile.name = $profile_name,
             profile.standard_references = $standard_references, profile.maturity = 'Draft', profile.version = 1,
             profile.created_at = datetime($now), profile.created_by = $actor,
             profile.updated_at = datetime($now), profile.updated_by = $actor
           MERGE (revision:Revision {
             project_id: project.id, model_id: model.id, business_id: $revision_business_id
           })
           ON CREATE SET revision.id = $revision_id, revision.standard_profile_version_id = profile.id,
             revision.status = 'Draft', revision.version = 1,
             revision.created_at = datetime($now), revision.created_by = $actor,
             revision.updated_at = datetime($now), revision.updated_by = $actor
           MERGE (project)-[:HAS_MODEL]->(model)
           MERGE (project)-[:HAS_STANDARD_PROFILE_VERSION]->(profile)
           MERGE (model)-[:HAS_REVISION]->(revision)
           MERGE (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile)
           RETURN project.id AS project_id, model.id AS model_id,
                  revision.id AS revision_id, profile.id AS profile_id`,
          {
            project_id: ids.project,
            project_business_id: input.config.project.business_id,
            project_name: input.config.project.name,
            project_description: input.config.project.description,
            model_id: ids.model,
            model_business_id: input.config.model.business_id,
            model_name: input.config.model.name,
            model_level: input.config.model.level,
            revision_id: ids.revision,
            revision_business_id: input.config.revision.business_id,
            profile_id: ids.profile,
            profile_business_id: input.config.standard_profile.business_id,
            profile_name: input.config.standard_profile.name,
            profile_version: input.config.standard_profile.profile_version,
            standard_references: input.config.standard_profile.standard_references,
            actor: input.actor,
            now,
          },
        );
        const context = {
          project_id: String(contextResult.records[0].get("project_id")),
          model_id: String(contextResult.records[0].get("model_id")),
          revision_id: String(contextResult.records[0].get("revision_id")),
          profile_id: String(contextResult.records[0].get("profile_id")),
        };

        const attachmentResult = await transaction.run(
          `MATCH (revision:Revision {id: $revision_id})
           UNWIND $definitions AS definition
           MATCH (node)
           WHERE definition.label IN labels(node)
             AND (node.project_id IS NULL OR node.project_id = $project_id)
             AND (node.model_id IS NULL OR node.model_id = $model_id)
             AND (node.revision_id IS NULL OR node.revision_id = $revision_id)
             AND (node.project_id IS NULL OR node.model_id IS NULL OR node.revision_id IS NULL)
           SET node.id = coalesce(node.id, randomUUID()),
               node.project_id = $project_id,
               node.model_id = $model_id,
               node.revision_id = $revision_id,
               node.legacy_id = coalesce(node.legacy_id, toString(node[definition.key])),
               node.legacy_label = definition.label,
               node.legacy_migration_id = 'P1.3_LEGACY_ATTACHMENT'
           MERGE (revision)-[:CONTAINS_LEGACY_ENTITY]->(node)
           RETURN count(DISTINCT node) AS attached_count`,
          {
            definitions: legacyEntityDefinitions,
            project_id: context.project_id,
            model_id: context.model_id,
            revision_id: context.revision_id,
          },
        );
        const attachedCount = toNumber(attachmentResult.records[0]?.get("attached_count"));

        await transaction.run(
          `MATCH (revision:Revision {id: $revision_id})
           MATCH (version:GraphVersion {id: 'GRAPH_VERSION'})
           SET revision.legacy_graph_version = toString(version.value)
           MERGE (revision)-[:MIGRATED_FROM_GRAPH_VERSION]->(version)`,
          { revision_id: context.revision_id },
        );

        const persistedIssues = plan.issues.filter(({ blocking }) => !blocking);
        if (persistedIssues.length > 0) {
          await transaction.run(
            `MATCH (revision:Revision {id: $revision_id})
             UNWIND $issues AS candidate
             MERGE (migration_issue:MigrationIssue {issue_key: candidate.issue_key})
             ON CREATE SET migration_issue.id = randomUUID(),
               migration_issue.business_id = 'MI-' + substring(candidate.issue_key, 0, 12),
               migration_issue.created_at = datetime($now), migration_issue.created_by = $actor,
               migration_issue.status = 'Open'
             SET migration_issue.project_id = $project_id,
                 migration_issue.model_id = $model_id,
                 migration_issue.revision_id = $revision_id,
                 migration_issue.migration_id = 'P1.3_LEGACY_ATTACHMENT',
                 migration_issue.issue_type = candidate.issue_type,
                 migration_issue.severity = candidate.severity,
                 migration_issue.subject_label = candidate.subject_label,
                 migration_issue.affected_count = candidate.affected_count,
                 migration_issue.subject_keys = candidate.subject_keys,
                 migration_issue.message = candidate.message,
                 migration_issue.candidate_actions = candidate.candidate_actions,
                 migration_issue.updated_at = datetime($now), migration_issue.updated_by = $actor
             MERGE (revision)-[:HAS_MIGRATION_ISSUE]->(migration_issue)`,
            {
              issues: persistedIssues,
              project_id: context.project_id,
              model_id: context.model_id,
              revision_id: context.revision_id,
              actor: input.actor,
              now,
            },
          );
        }

        await transaction.run(
          `MATCH (migration_issue:MigrationIssue {
             project_id: $project_id,
             revision_id: $revision_id,
             migration_id: 'P1.3_LEGACY_ATTACHMENT',
             status: 'Open'
           })
           WHERE NOT migration_issue.issue_key IN $active_issue_keys
           SET migration_issue.status = 'Superseded',
               migration_issue.resolution_note = 'Superseded by a later deterministic P1.3 inspection',
               migration_issue.resolved_at = datetime($now),
               migration_issue.resolved_by = $actor,
               migration_issue.updated_at = datetime($now),
               migration_issue.updated_by = $actor`,
          {
            project_id: context.project_id,
            revision_id: context.revision_id,
            active_issue_keys: persistedIssues.map(({ issue_key }) => issue_key),
            actor: input.actor,
            now,
          },
        );

        await transaction.run(
          `MATCH (project:Project {id: $project_id})
           MATCH (revision:Revision {id: $revision_id})
           CREATE (run:LegacyAttachmentRun {
             id: $run_id, command_id: $command_id, actor: $actor,
             dataset_kind: $dataset_kind, project_id: $project_id, model_id: $model_id,
             revision_id: $revision_id, standard_profile_version_id: $profile_id,
             attached_count: $attached_count, issue_count: $issue_count,
             plan_hash: $plan_hash, status: 'Completed', created_at: datetime($now)
           })
           CREATE (event:AuditEvent {
             id: $audit_id, command_id: $command_id, actor: $actor,
             event_type: 'LEGACY_SCOPE_ATTACHED', occurred_at: datetime($now),
             project_id: $project_id, subject_id: $revision_id,
             subject_version_before: revision.version,
             subject_version_after: revision.version,
             result_run_id: $run_id, attached_count: $attached_count,
             issue_count: $issue_count, plan_hash: $plan_hash
           })
           CREATE (event)-[:AFFECTS]->(project)
           CREATE (event)-[:AFFECTS]->(revision)
           CREATE (event)-[:RECORDED_RUN]->(run)`,
          {
            run_id: ids.run,
            audit_id: ids.audit,
            command_id: input.command_id,
            actor: input.actor,
            dataset_kind: input.config.dataset_kind,
            project_id: context.project_id,
            model_id: context.model_id,
            revision_id: context.revision_id,
            profile_id: context.profile_id,
            attached_count: attachedCount,
            issue_count: persistedIssues.length,
            plan_hash: plan.plan_hash,
            now,
          },
        );

        return {
          run_id: ids.run,
          command_id: input.command_id,
          dataset_kind: input.config.dataset_kind,
          project_id: context.project_id,
          model_id: context.model_id,
          revision_id: context.revision_id,
          standard_profile_version_id: context.profile_id,
          attached_count: attachedCount,
          issue_count: persistedIssues.length,
          plan_hash: plan.plan_hash,
          replayed: false,
        };
      });
    } finally {
      await session.close();
    }
  }

  async verify(config: LegacyContextConfig): Promise<LegacyAttachmentVerification> {
    const session = getDriver().session();
    try {
      const contextResult = await session.run(
        `MATCH (project:Project {business_id: $project_business_id})-[:HAS_MODEL]->
               (model:Model {business_id: $model_business_id})-[:HAS_REVISION]->
               (revision:Revision {business_id: $revision_business_id})-[:USES_STANDARD_PROFILE_VERSION]->
               (profile:StandardProfileVersion {business_id: $profile_business_id})
         RETURN project.id AS project_id, model.id AS model_id,
                revision.id AS revision_id, profile.id AS profile_id`,
        {
          project_business_id: config.project.business_id,
          model_business_id: config.model.business_id,
          revision_business_id: config.revision.business_id,
          profile_business_id: config.standard_profile.business_id,
        },
      );
      if (contextResult.records.length === 0) {
        return {
          ok: false,
          context: {},
          attached_count: 0,
          open_issue_count: 0,
          diagnostics: ["Legacy project/model/revision/profile context does not exist"],
        };
      }
      const record = contextResult.records[0];
      const context = {
        project_id: String(record.get("project_id")),
        model_id: String(record.get("model_id")),
        revision_id: String(record.get("revision_id")),
        standard_profile_version_id: String(record.get("profile_id")),
      };
      const counts = await session.run(
        `MATCH (revision:Revision {id: $revision_id})
         CALL {
           WITH revision
           UNWIND $definitions AS definition
           MATCH (node)
           WHERE definition.label IN labels(node) AND node.revision_id = revision.id
           OPTIONAL MATCH (revision)-[membership:CONTAINS_LEGACY_ENTITY]->(node)
           RETURN count(DISTINCT node) AS attached_count,
                  count(DISTINCT CASE WHEN membership IS NULL THEN node END) AS missing_membership,
                  count(DISTINCT CASE
                    WHEN node.id IS NULL OR NOT toString(node.id) =~ '(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                    THEN node
                  END) AS invalid_internal_id
         }
         CALL {
           WITH revision
           MATCH (issue:MigrationIssue {revision_id: revision.id, status: 'Open'})
           RETURN count(issue) AS open_issue_count
         }
         CALL {
           WITH revision
           UNWIND $definitions AS definition
           MATCH (node)
           WHERE definition.label IN labels(node)
             AND node.project_id IS NULL AND node.model_id IS NULL AND node.revision_id IS NULL
           RETURN count(DISTINCT node) AS remaining_unscoped
         }
         CALL {
           WITH revision
           MATCH (left)-[relationship]->(right)
           WHERE (left.project_id = revision.project_id AND right.project_id IS NOT NULL AND right.project_id <> revision.project_id)
              OR (right.project_id = revision.project_id AND left.project_id IS NOT NULL AND left.project_id <> revision.project_id)
           RETURN count(DISTINCT relationship) AS cross_scope_relationships
         }
         RETURN attached_count, missing_membership, invalid_internal_id,
                open_issue_count, remaining_unscoped, cross_scope_relationships`,
        { revision_id: context.revision_id, definitions: legacyEntityDefinitions },
      );
      const countsRecord = counts.records[0];
      const attachedCount = toNumber(countsRecord?.get("attached_count"));
      const missingMembership = toNumber(countsRecord?.get("missing_membership"));
      const invalidInternalId = toNumber(countsRecord?.get("invalid_internal_id"));
      const openIssueCount = toNumber(countsRecord?.get("open_issue_count"));
      const remainingUnscoped = toNumber(countsRecord?.get("remaining_unscoped"));
      const crossScopeRelationships = toNumber(countsRecord?.get("cross_scope_relationships"));
      const diagnostics: string[] = [];
      if (missingMembership > 0) {
        diagnostics.push(`${missingMembership} scoped legacy node(s) lack revision membership`);
      }
      if (remainingUnscoped > 0) {
        diagnostics.push(`${remainingUnscoped} known legacy node(s) remain unscoped`);
      }
      if (invalidInternalId > 0) {
        diagnostics.push(`${invalidInternalId} scoped legacy node(s) lack a valid internal UUID`);
      }
      if (crossScopeRelationships > 0) {
        diagnostics.push(`${crossScopeRelationships} relationship(s) cross project scope`);
      }
      return {
        ok: diagnostics.length === 0,
        context,
        attached_count: attachedCount,
        open_issue_count: openIssueCount,
        diagnostics,
      };
    } finally {
      await session.close();
    }
  }
}
