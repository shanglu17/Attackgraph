import { randomUUID } from "node:crypto";
import { getDriver } from "../db/neo4j.js";
import { Neo4jMigrationStore } from "../migrations/neo4jMigrationStore.js";
import { migrationRegistry } from "../migrations/registry.js";
import { migrationChecksum } from "../migrations/runner.js";
import { legacyEntityDefinitions, resolveLegacyContext } from "../services/legacyMigration/legacyAttachment.js";
import type { Phase7ReleaseEvidence, ReleaseCounts } from "../services/release/phase7Acceptance.js";

function number(value: unknown): number {
  return typeof value === "number" ? value : Number((value as { toNumber?: () => number })?.toNumber?.() ?? value ?? 0);
}

export class Phase7AcceptanceRepository {
  async readRecorded(commandId: string, releaseId: string): Promise<{ id: string; evidence: Phase7ReleaseEvidence } | undefined> {
    const session = getDriver().session();
    try {
      const result = await session.run(
        `MATCH (run:ReleaseAcceptanceRun)
         WHERE run.command_id = $command_id OR run.release_id = $release_id
         RETURN run LIMIT 1`, { command_id: commandId, release_id: releaseId },
      );
      if (result.records.length === 0) return undefined;
      const properties = result.records[0].get("run").properties as Record<string, unknown>;
      if (String(properties.command_id) !== commandId || String(properties.release_id) !== releaseId) {
        throw new Error("release id or command id is already bound to another technical acceptance record");
      }
      return { id: String(properties.id), evidence: JSON.parse(String(properties.report_json)) as Phase7ReleaseEvidence };
    } finally {
      await session.close();
    }
  }

  async collect() {
    const config = resolveLegacyContext("do356a-appendix-d");
    const session = getDriver().session();
    try {
      const contextResult = await session.run(
        `MATCH (project:Project {business_id: $project_business_id})-[:HAS_MODEL]->
               (model:Model {business_id: $model_business_id})-[:HAS_REVISION]->
               (revision:Revision {business_id: $revision_business_id})
         RETURN project.id AS project_id, model.id AS model_id, revision.id AS revision_id, revision.version AS revision_version`,
        { project_business_id: config.project.business_id, model_business_id: config.model.business_id, revision_business_id: config.revision.business_id },
      );
      if (contextResult.records.length !== 1) throw new Error("DO-356A Appendix D release scope is missing or ambiguous");
      const context = {
        project_id: String(contextResult.records[0].get("project_id")),
        model_id: String(contextResult.records[0].get("model_id")),
        revision_id: String(contextResult.records[0].get("revision_id")),
        revision_version: number(contextResult.records[0].get("revision_version")),
      };

      const countsResult = await session.run(
        `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
         CALL { WITH revision MATCH (node) WHERE node.project_id = revision.project_id AND node.revision_id = revision.id AND node.legacy_migration_id = 'P1.3_LEGACY_ATTACHMENT' RETURN count(node) AS attached }
         CALL { WITH revision MATCH (asset:AssetNode {project_id: revision.project_id, revision_id: revision.id}) RETURN count(asset) AS assets }
         CALL { WITH revision MATCH (:AssetNode {project_id: revision.project_id, revision_id: revision.id})-[edge:ASSET_EDGE {project_id: revision.project_id, revision_id: revision.id}]->(:AssetNode {project_id: revision.project_id, revision_id: revision.id}) RETURN count(edge) AS edges }
         CALL { WITH revision MATCH (threat:ThreatPoint {project_id: revision.project_id, revision_id: revision.id}) RETURN count(threat) AS threats }
         CALL { WITH revision MATCH (link:DO326A_Link {project_id: revision.project_id, revision_id: revision.id}) RETURN count(link) AS links }
         CALL { WITH revision MATCH (audit:CommitAudit {project_id: revision.project_id, revision_id: revision.id}) RETURN count(audit) AS audits }
         CALL { WITH revision MATCH (issue:MigrationIssue {project_id: revision.project_id, revision_id: revision.id, status: 'Open'}) RETURN count(issue) AS open_issues, count(CASE WHEN issue.severity IN ['High', 'Critical'] THEN 1 END) AS high_issues }
         CALL { WITH revision MATCH (source:SourceRecord {project_id: revision.project_id, revision_id: revision.id, business_id: 'DO356A-APPENDIX-D-SOURCE'}) RETURN count(source) AS sources }
         CALL { WITH revision MATCH (node {project_id: revision.project_id, revision_id: revision.id})-[:DERIVED_FROM_SOURCE]->(:SourceRecord {project_id: revision.project_id, revision_id: revision.id, business_id: 'DO356A-APPENDIX-D-SOURCE'}) RETURN count(DISTINCT node) AS provenance_links }
         CALL { WITH revision MATCH (decision:ReviewDecision {project_id: revision.project_id, revision_id: revision.id}) WHERE decision.reviewer IS NULL OR decision.reviewer_role IS NULL OR decision.decided_at IS NULL OR decision.subject_version IS NULL RETURN count(decision) AS unaudited_decisions }
         RETURN attached, assets, edges, threats, links, audits, open_issues, high_issues, sources, provenance_links, unaudited_decisions`,
        context,
      );
      const counts = countsResult.records[0];
      const direct_counts: ReleaseCounts = {
        asset_nodes: number(counts.get("assets")), asset_edges: number(counts.get("edges")),
        threat_points: number(counts.get("threats")), do326a_links: number(counts.get("links")),
        commit_audits: number(counts.get("audits")),
      };

      const unscopedResult = await session.run(
        `UNWIND $definitions AS definition MATCH (node)
         WHERE definition.label IN labels(node) AND node.project_id IS NULL AND node.revision_id IS NULL
         RETURN count(DISTINCT node) AS count`, { definitions: legacyEntityDefinitions },
      );
      const crossResult = await session.run(
        `MATCH (left)-[relationship]->(right)
         WHERE left.project_id IS NOT NULL AND right.project_id IS NOT NULL AND left.project_id <> right.project_id
         RETURN count(relationship) AS count`,
      );
      const migrationRecords = new Map((await new Neo4jMigrationStore(session).listRecords()).map((item) => [item.migration_id, item]));
      const migrations = migrationRegistry.map((migration) => {
        const expectedChecksum = migrationChecksum(migration);
        const recorded = migrationRecords.get(migration.id);
        return {
          id: migration.id,
          status: !recorded ? "pending" : recorded.checksum !== expectedChecksum ? "checksum_mismatch" : recorded.status,
          checksum: expectedChecksum,
        };
      });
      return {
        context, migrations, attached_legacy_nodes: number(counts.get("attached")),
        unscoped_legacy_nodes: number(unscopedResult.records[0]?.get("count")),
        cross_project_relationships: number(crossResult.records[0]?.get("count")),
        open_migration_issues: number(counts.get("open_issues")), open_high_risk_issues: number(counts.get("high_issues")),
        provenance_source_count: number(counts.get("sources")), provenance_link_count: number(counts.get("provenance_links")),
        unaudited_review_decisions: number(counts.get("unaudited_decisions")), direct_counts,
      };
    } finally {
      await session.close();
    }
  }

  async record(evidence: Phase7ReleaseEvidence, actor: string, commandId: string): Promise<{ id: string; replayed: boolean }> {
    const session = getDriver().session();
    try {
      return await session.executeWrite(async (transaction) => {
        const prior = await transaction.run(
          `MATCH (run:ReleaseAcceptanceRun) WHERE run.command_id = $command_id OR run.release_id = $release_id RETURN run LIMIT 1`,
          { command_id: commandId, release_id: evidence.release_id },
        );
        if (prior.records.length > 0) {
          const properties = prior.records[0].get("run").properties as Record<string, unknown>;
          if (String(properties.evidence_hash) !== evidence.evidence_hash) throw new Error("release id or command id was already used with different evidence");
          return { id: String(properties.id), replayed: true };
        }
        const id = randomUUID();
        await transaction.run(
          `CREATE (run:ReleaseAcceptanceRun {
             id: $id, release_id: $release_id, command_id: $command_id, actor: $actor,
             status: $status, evidence_hash: $evidence_hash, contract_version: $contract_version,
             project_id: $project_id, revision_id: $revision_id, report_json: $report_json,
             human_release_authorization: 'not_asserted', created_at: datetime($created_at)
           })
           CREATE (event:AuditEvent {
             id: randomUUID(), command_id: $command_id, actor: $actor,
             event_type: 'TECHNICAL_RELEASE_ACCEPTANCE_RECORDED', occurred_at: datetime($created_at),
             project_id: $project_id, subject_id: $id, subject_version_before: 0, subject_version_after: 1,
             evidence_hash: $evidence_hash
           })
           CREATE (event)-[:RECORDED_RUN]->(run)`,
          {
            id, release_id: evidence.release_id, command_id: commandId, actor,
            status: evidence.overall_status, evidence_hash: evidence.evidence_hash,
            contract_version: evidence.contract_version, project_id: evidence.scope.project_id,
            revision_id: evidence.scope.revision_id, report_json: JSON.stringify(evidence), created_at: evidence.generated_at,
          },
        );
        return { id, replayed: false };
      });
    } finally {
      await session.close();
    }
  }
}
