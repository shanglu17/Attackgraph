import { createHash, randomUUID } from "node:crypto";
import { getDriver } from "../../db/neo4j.js";
import { RevisionUnitOfWork } from "../../repositories/revisionUnitOfWork.js";
import { legacyEntityDefinitions, resolveLegacyContext } from "./legacyAttachment.js";

const sourceIdentity = "DO-356A|Appendix D";

export interface AppendixDProvenanceInput {
  actor: string;
  command_id: string;
  expected_revision_version: number;
}

export class AppendixDProvenanceService {
  constructor(private readonly unitOfWork = new RevisionUnitOfWork()) {}

  async resolveScope() {
    const config = resolveLegacyContext("do356a-appendix-d");
    const session = getDriver().session();
    try {
      const result = await session.executeRead((transaction) => transaction.run(
        `MATCH (project:Project {business_id: $project_business_id})-[:HAS_MODEL]->
               (model:Model {business_id: $model_business_id})-[:HAS_REVISION]->
               (revision:Revision {business_id: $revision_business_id})
         RETURN project.id AS project_id, revision.id AS revision_id, revision.version AS revision_version`,
        {
          project_business_id: config.project.business_id,
          model_business_id: config.model.business_id,
          revision_business_id: config.revision.business_id,
        },
      ));
      if (result.records.length === 0) throw new Error("DO-356A Appendix D legacy scope is not attached");
      const record = result.records[0];
      const rawVersion = record.get("revision_version");
      return {
        project_id: String(record.get("project_id")),
        revision_id: String(record.get("revision_id")),
        revision_version: typeof rawVersion === "number" ? rawVersion : rawVersion.toNumber(),
      };
    } finally {
      await session.close();
    }
  }

  async confirm(input: AppendixDProvenanceInput) {
    const scope = await this.resolveScope();
    const referenceHash = createHash("sha256").update(sourceIdentity, "utf8").digest("hex");
    return this.unitOfWork.execute(
      {
        actor: input.actor,
        command_id: input.command_id,
        project_id: scope.project_id,
        revision_id: scope.revision_id,
        expected_revision_version: input.expected_revision_version,
        event_type: "LEGACY_PROVENANCE_CONFIRMED",
        request_canonicalizer: "legacy.appendix-d-provenance/v1",
        payload: {
          source_standard: "DO-356A",
          source_section: "Appendix D",
          reference_hash: referenceHash,
          reference_hash_scope: "logical-source-identity",
        },
        summary: "Record user-confirmed DO-356A Appendix D provenance for attached legacy nodes",
      },
      async ({ transaction, project_id, revision_id, new_revision_version }) => {
        const sourceId = randomUUID();
        await transaction.run(
          `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
           MERGE (source:SourceRecord {
             project_id: $project_id, revision_id: $revision_id,
             business_id: 'DO356A-APPENDIX-D-SOURCE'
           })
           ON CREATE SET source.id = $source_id, source.created_at = datetime(), source.created_by = $actor
           SET source.source_type = 'standard-reference',
               source.name = 'DO-356A Appendix D',
               source.content_hash = $reference_hash,
               source.content_hash_scope = 'logical-source-identity',
               source.media_type = 'application/x-standard-reference',
               source.parser_name = 'manual-provenance-confirmation',
               source.parser_version = '1.0.0',
               source.confirmation_basis = 'user-confirmed',
               source.confirmed_at = datetime(), source.confirmed_by = $actor,
               source.revision_version = $revision_version
           MERGE (revision)-[:CONTAINS]->(source)`,
          {
            project_id, revision_id, source_id: sourceId, actor: input.actor,
            reference_hash: referenceHash, revision_version: new_revision_version,
          },
        );
        const attached = await transaction.run(
          `MATCH (source:SourceRecord {
             project_id: $project_id, revision_id: $revision_id,
             business_id: 'DO356A-APPENDIX-D-SOURCE'
           })
           UNWIND $labels AS legacy_label
           MATCH (node {project_id: $project_id, revision_id: $revision_id})
           WHERE legacy_label IN labels(node)
             AND node.source IS NULL AND node.source_sheet IS NULL AND node.source_row IS NULL
           SET node.source = 'DO-356A', node.source_section = 'Appendix D',
               node.source_locator_json = $source_locator_json,
               node.provenance_confirmed_by = $actor,
               node.provenance_confirmed_at = datetime()
           MERGE (node)-[:DERIVED_FROM_SOURCE {source_locator_json: $source_locator_json}]->(source)
           RETURN count(DISTINCT node) AS attached_count`,
          {
            project_id, revision_id, actor: input.actor,
            labels: legacyEntityDefinitions.filter((item) => item.source_required).map((item) => item.label),
            source_locator_json: JSON.stringify({
              standard: "DO-356A", section: "Appendix D", locator_status: "confirmed-by-user",
            }),
          },
        );
        const resolved = await transaction.run(
          `MATCH (issue:MigrationIssue {
             project_id: $project_id, revision_id: $revision_id,
             issue_type: 'MISSING_SOURCE_LOCATOR', status: 'Open'
           })
           SET issue.status = 'Resolved',
               issue.resolution_note = 'Source confirmed by user as DO-356A Appendix D; no restricted standard text copied.',
               issue.resolved_at = datetime(), issue.resolved_by = $actor,
               issue.updated_at = datetime(), issue.updated_by = $actor
           RETURN count(issue) AS resolved_issue_count`,
          { project_id, revision_id, actor: input.actor },
        );
        const number = (value: unknown) => typeof value === "number" ? value : (value as { toNumber(): number }).toNumber();
        return {
          source_record_business_id: "DO356A-APPENDIX-D-SOURCE",
          attached_count: number(attached.records[0].get("attached_count")),
          resolved_issue_count: number(resolved.records[0].get("resolved_issue_count")),
        };
      },
    );
  }
}
