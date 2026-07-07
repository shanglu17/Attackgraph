import type { ManagedTransaction } from "neo4j-driver";
import { getDriver } from "../db/neo4j.js";
import type { F3532StandardImportRequest } from "../types/api.js";
import type {
  StandardArtifactField,
  StandardArtifactType,
  StandardClause,
  StandardKnowledgeSummary,
  StandardMapping,
  StandardRelationType
} from "../types/domain.js";

const f3532StandardId = "ASTM-F3532-23";

const relationTypeMap: Record<StandardRelationType, string> = {
  PARENT_OF: "PARENT_OF",
  REFERENCES: "REFERENCES",
  TRIGGERS: "TRIGGERS",
  ITERATES_WITH: "ITERATES_WITH",
  DEPENDS_ON: "DEPENDS_ON",
  TAILORS: "TAILORS",
  DEFINES: "DEFINES",
  CHECKS: "CHECKS",
  PRODUCES: "PRODUCES"
};

function asStringList(values: unknown[]): string[] {
  return values.filter((value) => value !== null && value !== undefined).map((value) => String(value));
}

export class StandardRepository {
  async ensureConstraints(): Promise<void> {
    const session = getDriver().session();
    try {
      await session.run("CREATE CONSTRAINT standard_clause_unique IF NOT EXISTS FOR (c:StandardClause) REQUIRE (c.std, c.clause_id) IS UNIQUE");
      await session.run("CREATE CONSTRAINT standard_artifact_type_unique IF NOT EXISTS FOR (a:StandardArtifactType) REQUIRE a.artifact_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT standard_artifact_field_unique IF NOT EXISTS FOR (f:StandardArtifactField) REQUIRE f.field_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT standard_pipeline_stage_unique IF NOT EXISTS FOR (s:StandardPipelineStage) REQUIRE s.stage_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT standard_mapping_unique IF NOT EXISTS FOR (m:StandardMapping) REQUIRE m.mapping_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT standard_kb_unique IF NOT EXISTS FOR (kb:StandardKnowledgeBase) REQUIRE kb.standard_id IS UNIQUE");
    } finally {
      await session.close();
    }
  }

  async importF3532KnowledgeBase(input: F3532StandardImportRequest): Promise<StandardKnowledgeSummary> {
    await this.ensureConstraints();
    const standardId = input.standard_id || f3532StandardId;
    const importedAt = new Date().toISOString();
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run(
          `MERGE (kb:StandardKnowledgeBase {standard_id: $standard_id})
           SET kb.model_version = $model_version,
               kb.source_ref = $source_ref,
               kb.imported_by = $imported_by,
               kb.imported_at = datetime($imported_at)`,
          {
            standard_id: standardId,
            model_version: input.source?.model_version ?? null,
            source_ref: input.source?.source_ref ?? null,
            imported_by: input.source?.imported_by ?? null,
            imported_at: importedAt
          }
        );

        await tx.run(
          `UNWIND $clauses AS row
           MERGE (c:StandardClause {std: row.std, clause_id: row.clause_id})
           SET c.parent_id = row.parent_id,
               c.level = row.level,
               c.number = row.number,
               c.section = row.section,
               c.title_zh = row.title_zh,
               c.title_en = row.title_en,
               c.clause_type = row.clause_type,
               c.normative = row.normative,
               c.keywords = row.keywords,
               c.pdf_page = row.pdf_page,
               c.text_zh = row.text_zh,
               c.text_en = row.text_en,
               c.notes = row.notes
           WITH c
           MATCH (kb:StandardKnowledgeBase {standard_id: $standard_id})
           MERGE (kb)-[:HAS_CLAUSE]->(c)`,
          {
            standard_id: standardId,
            clauses: input.clauses.map((clause) => ({
              ...clause,
              std: clause.std || standardId,
              parent_id: clause.parent_id ?? null,
              level: clause.level ?? null,
              number: clause.number ?? null,
              section: clause.section ?? null,
              title_zh: clause.title_zh ?? null,
              title_en: clause.title_en ?? null,
              clause_type: clause.clause_type ?? null,
              normative: clause.normative ?? null,
              keywords: clause.keywords ?? [],
              pdf_page: clause.pdf_page ?? null,
              text_zh: clause.text_zh ?? null,
              text_en: clause.text_en ?? null,
              notes: clause.notes ?? null
            }))
          }
        );

        await tx.run(
          `UNWIND $clauses AS row
           WITH row WHERE row.parent_id IS NOT NULL AND row.parent_id <> ""
           MATCH (parent:StandardClause {std: row.std, clause_id: row.parent_id})
           MATCH (child:StandardClause {std: row.std, clause_id: row.clause_id})
           MERGE (parent)-[:PARENT_OF]->(child)`,
          { clauses: input.clauses.map((clause) => ({ ...clause, std: clause.std || standardId })) }
        );

        for (const [relationType, neo4jType] of Object.entries(relationTypeMap)) {
          const rows = input.clause_relations.filter((relation) => relation.relation_type === relationType);
          if (rows.length === 0) {
            continue;
          }
          await tx.run(
            `UNWIND $rows AS row
             MATCH (source:StandardClause {std: $standard_id, clause_id: row.source_clause_id})
             MATCH (target:StandardClause {std: $standard_id, clause_id: row.target_clause_id})
             MERGE (source)-[r:${neo4jType} {relation_id: row.relation_id}]->(target)
             SET r.description = row.description,
                 r.relation_type = row.relation_type`,
            { standard_id: standardId, rows: rows.map((row) => ({ ...row, description: row.description ?? null })) }
          );
        }

        await tx.run(
          `UNWIND $artifacts AS row
           MERGE (a:StandardArtifactType {artifact_id: row.artifact_id})
           SET a.name_zh = row.name_zh,
               a.name_en = row.name_en,
               a.io_role = row.io_role,
               a.pipeline_slot = row.pipeline_slot,
               a.primary_clause_id = row.primary_clause_id,
               a.primary_clause_title = row.primary_clause_title,
               a.scope_status = row.scope_status,
               a.source_ref = row.source_ref,
               a.description = row.description,
               a.standard_id = $standard_id
           WITH a, row
           MATCH (kb:StandardKnowledgeBase {standard_id: $standard_id})
           MERGE (kb)-[:HAS_ARTIFACT_TYPE]->(a)
           WITH a, row WHERE row.primary_clause_id IS NOT NULL AND row.primary_clause_id <> ""
           MATCH (c:StandardClause {std: $standard_id, clause_id: row.primary_clause_id})
           MERGE (a)-[:DERIVED_FROM]->(c)`,
          {
            standard_id: standardId,
            artifacts: input.artifact_types.map((artifact) => ({
              ...artifact,
              name_en: artifact.name_en ?? null,
              primary_clause_id: artifact.primary_clause_id ?? null,
              primary_clause_title: artifact.primary_clause_title ?? null,
              scope_status: artifact.scope_status ?? null,
              source_ref: artifact.source_ref ?? null,
              description: artifact.description ?? null
            }))
          }
        );

        await tx.run(
          `UNWIND $fields AS row
           MERGE (f:StandardArtifactField {field_id: row.field_id})
           SET f.artifact_id = row.artifact_id,
               f.artifact_name = row.artifact_name,
               f.seq = row.seq,
               f.field_name_zh = row.field_name_zh,
               f.required = row.required,
               f.data_type = row.data_type,
               f.enum_or_ref = row.enum_or_ref,
               f.fill_guidance = row.fill_guidance,
               f.example = row.example,
               f.clause_ref = row.clause_ref,
               f.clause_title = row.clause_title,
               f.source = row.source,
               f.trace_role = row.trace_role,
               f.standard_id = $standard_id
           WITH f, row
           MATCH (a:StandardArtifactType {artifact_id: row.artifact_id})
           MERGE (f)-[:BELONGS_TO]->(a)
           WITH f, row WHERE row.clause_ref IS NOT NULL AND row.clause_ref <> ""
           MATCH (c:StandardClause {std: $standard_id, clause_id: row.clause_ref})
           MERGE (f)-[:TRACE_TO]->(c)`,
          {
            standard_id: standardId,
            fields: input.artifact_fields.map((field) => ({
              ...field,
              artifact_name: field.artifact_name ?? null,
              enum_or_ref: field.enum_or_ref ?? null,
              fill_guidance: field.fill_guidance ?? null,
              example: field.example ?? null,
              clause_ref: field.clause_ref ?? null,
              clause_title: field.clause_title ?? null,
              source: field.source ?? null,
              trace_role: field.trace_role ?? null
            }))
          }
        );

        await tx.run(
          `UNWIND $stages AS row
           MERGE (s:StandardPipelineStage {stage_id: row.stage_id})
           SET s.stage_name = row.stage_name,
               s.key_question = row.key_question,
               s.inputs = row.inputs,
               s.activities = row.activities,
               s.outputs = row.outputs,
               s.termination_condition = row.termination_condition,
               s.standard_id = $standard_id
           WITH s, row
           MATCH (kb:StandardKnowledgeBase {standard_id: $standard_id})
           MERGE (kb)-[:HAS_PIPELINE_STAGE]->(s)
           WITH s, row
           UNWIND row.inputs AS input_artifact
           MATCH (a:StandardArtifactType {artifact_id: input_artifact})
           MERGE (s)-[:REQUIRES_ARTIFACT]->(a)
           WITH DISTINCT s, row
           UNWIND row.outputs AS output_artifact
           MATCH (a:StandardArtifactType {artifact_id: output_artifact})
           MERGE (s)-[:PRODUCES_ARTIFACT]->(a)`,
          {
            standard_id: standardId,
            stages: input.pipeline_stages.map((stage) => ({
              ...stage,
              stage_name: stage.stage_name ?? null,
              key_question: stage.key_question ?? null,
              inputs: stage.inputs ?? [],
              activities: stage.activities ?? null,
              outputs: stage.outputs ?? [],
              termination_condition: stage.termination_condition ?? null
            }))
          }
        );
      });

      return {
        standard_id: standardId,
        counts: {
          clauses: input.clauses.length,
          clause_relations: input.clause_relations.length,
          artifact_types: input.artifact_types.length,
          artifact_fields: input.artifact_fields.length,
          pipeline_stages: input.pipeline_stages.length
        },
        imported_at: importedAt
      };
    } finally {
      await session.close();
    }
  }

  async getKnowledgeSummary(standardId = f3532StandardId): Promise<StandardKnowledgeSummary> {
    await this.ensureConstraints();
    const session = getDriver().session();
    try {
      const result = await session.executeRead(async (tx) => {
        const [clauses, relations, artifacts, fields, stages, kb] = await Promise.all([
          tx.run("MATCH (c:StandardClause {std: $standard_id}) RETURN count(c) AS count", { standard_id: standardId }),
          tx.run("MATCH (:StandardClause {std: $standard_id})-[r]->(:StandardClause {std: $standard_id}) WHERE r.relation_id IS NOT NULL RETURN count(r) AS count", { standard_id: standardId }),
          tx.run("MATCH (a:StandardArtifactType {standard_id: $standard_id}) RETURN count(a) AS count", { standard_id: standardId }),
          tx.run("MATCH (f:StandardArtifactField {standard_id: $standard_id}) RETURN count(f) AS count", { standard_id: standardId }),
          tx.run("MATCH (s:StandardPipelineStage {standard_id: $standard_id}) RETURN count(s) AS count", { standard_id: standardId }),
          tx.run("MATCH (kb:StandardKnowledgeBase {standard_id: $standard_id}) RETURN toString(kb.imported_at) AS imported_at", { standard_id: standardId })
        ]);
        return { clauses, relations, artifacts, fields, stages, kb };
      });
      return {
        standard_id: standardId,
        counts: {
          clauses: Number(result.clauses.records[0]?.get("count") ?? 0),
          clause_relations: Number(result.relations.records[0]?.get("count") ?? 0),
          artifact_types: Number(result.artifacts.records[0]?.get("count") ?? 0),
          artifact_fields: Number(result.fields.records[0]?.get("count") ?? 0),
          pipeline_stages: Number(result.stages.records[0]?.get("count") ?? 0)
        },
        imported_at: (result.kb.records[0]?.get("imported_at") as string | null) ?? undefined
      };
    } finally {
      await session.close();
    }
  }

  async getClauses(standardId = f3532StandardId, section?: string): Promise<StandardClause[]> {
    await this.ensureConstraints();
    const session = getDriver().session();
    try {
      const where = section ? "AND c.section STARTS WITH $section" : "";
      const result = await session.run(
        `MATCH (c:StandardClause {std: $standard_id})
         WHERE true ${where}
         RETURN c
         ORDER BY coalesce(c.level, 99), c.clause_id`,
        { standard_id: standardId, section }
      );
      return result.records.map((record) => this.toClause(record.get("c").properties as Record<string, unknown>));
    } finally {
      await session.close();
    }
  }

  async getArtifacts(standardId = f3532StandardId): Promise<Array<StandardArtifactType & { fields: StandardArtifactField[] }>> {
    await this.ensureConstraints();
    const session = getDriver().session();
    try {
      const result = await session.run(
        `MATCH (a:StandardArtifactType {standard_id: $standard_id})
         OPTIONAL MATCH (f:StandardArtifactField)-[:BELONGS_TO]->(a)
         RETURN a, collect(f) AS fields
         ORDER BY a.pipeline_slot, a.artifact_id`,
        { standard_id: standardId }
      );
      return result.records.map((record) => ({
        ...this.toArtifact(record.get("a").properties as Record<string, unknown>),
        fields: ((record.get("fields") as unknown[]) ?? [])
          .filter(Boolean)
          .map((node) => this.toField((node as { properties: Record<string, unknown> }).properties))
          .sort((a, b) => a.seq - b.seq)
      }));
    } finally {
      await session.close();
    }
  }

  async upsertMapping(mapping: StandardMapping): Promise<StandardMapping> {
    await this.ensureConstraints();
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run(
          `MERGE (m:StandardMapping {mapping_id: $mapping_id})
           SET m.standard_id = $standard_id,
               m.clause_id = $clause_id,
               m.semantic_element_type = $semantic_element_type,
               m.semantic_element_id = $semantic_element_id,
               m.linkage_type = $linkage_type,
               m.evidence_reference = $evidence_reference,
               m.review_status = $review_status
           WITH m
           MATCH (c:StandardClause {std: $standard_id, clause_id: $clause_id})
           MERGE (m)-[:MAPS_CLAUSE]->(c)`,
          { ...mapping, evidence_reference: mapping.evidence_reference ?? null }
        );

        await this.linkMappingTarget(tx, mapping);
      });
      return mapping;
    } finally {
      await session.close();
    }
  }

  async getMappings(standardId = f3532StandardId): Promise<StandardMapping[]> {
    await this.ensureConstraints();
    const session = getDriver().session();
    try {
      const result = await session.run("MATCH (m:StandardMapping {standard_id: $standard_id}) RETURN m ORDER BY m.mapping_id", {
        standard_id: standardId
      });
      return result.records.map((record) => {
        const props = record.get("m").properties as Record<string, unknown>;
        return {
          mapping_id: String(props.mapping_id),
          standard_id: String(props.standard_id),
          clause_id: String(props.clause_id),
          semantic_element_type: String(props.semantic_element_type),
          semantic_element_id: String(props.semantic_element_id),
          linkage_type: props.linkage_type as StandardMapping["linkage_type"],
          evidence_reference: (props.evidence_reference as string | undefined) ?? undefined,
          review_status: props.review_status as StandardMapping["review_status"]
        };
      });
    } finally {
      await session.close();
    }
  }

  private async linkMappingTarget(tx: ManagedTransaction, mapping: StandardMapping): Promise<void> {
    await tx.run("MATCH (m:StandardMapping {mapping_id: $mapping_id}) OPTIONAL MATCH (m)-[old:MAPS_TO]->() DELETE old", {
      mapping_id: mapping.mapping_id
    });
    await tx.run(
      `MATCH (m:StandardMapping {mapping_id: $mapping_id})
       OPTIONAL MATCH (a:AssetNode {asset_id: $semantic_element_id})
       OPTIONAL MATCH (th:ThreatPoint {threatpoint_id: $semantic_element_id})
       OPTIONAL MATCH (p:AttackPath {path_id: $semantic_element_id})
       OPTIONAL MATCH (f:FunctionNode {function_id: $semantic_element_id})
       OPTIONAL MATCH (sb:TrustBoundary {boundary_id: $semantic_element_id})
       OPTIONAL MATCH (ta:ThreatActor {actor_id: $semantic_element_id})
       OPTIONAL MATCH (bi:BoundaryInterface {interface_id: $semantic_element_id})
       OPTIONAL MATCH (sdf:SystemDataFlow {sdf_id: $semantic_element_id})
       WITH m, coalesce(a, th, p, f, sb, ta, bi, sdf) AS target
       WHERE target IS NOT NULL
       MERGE (m)-[:MAPS_TO]->(target)`,
      { mapping_id: mapping.mapping_id, semantic_element_id: mapping.semantic_element_id }
    );
  }

  private toClause(props: Record<string, unknown>): StandardClause {
    return {
      clause_id: String(props.clause_id),
      std: String(props.std),
      parent_id: (props.parent_id as string | undefined) ?? undefined,
      level: props.level === undefined || props.level === null ? undefined : Number(props.level),
      number: (props.number as string | undefined) ?? undefined,
      section: (props.section as string | undefined) ?? undefined,
      title_zh: (props.title_zh as string | undefined) ?? undefined,
      title_en: (props.title_en as string | undefined) ?? undefined,
      clause_type: (props.clause_type as string | undefined) ?? undefined,
      normative: (props.normative as string | undefined) ?? undefined,
      keywords: Array.isArray(props.keywords) ? asStringList(props.keywords) : undefined,
      pdf_page: props.pdf_page === undefined || props.pdf_page === null ? undefined : Number(props.pdf_page),
      text_zh: (props.text_zh as string | undefined) ?? undefined,
      text_en: (props.text_en as string | undefined) ?? undefined,
      notes: (props.notes as string | undefined) ?? undefined
    };
  }

  private toArtifact(props: Record<string, unknown>): StandardArtifactType {
    return {
      artifact_id: String(props.artifact_id),
      name_zh: String(props.name_zh),
      name_en: (props.name_en as string | undefined) ?? undefined,
      io_role: props.io_role as StandardArtifactType["io_role"],
      pipeline_slot: String(props.pipeline_slot),
      primary_clause_id: (props.primary_clause_id as string | undefined) ?? undefined,
      primary_clause_title: (props.primary_clause_title as string | undefined) ?? undefined,
      scope_status: (props.scope_status as StandardArtifactType["scope_status"] | undefined) ?? undefined,
      source_ref: (props.source_ref as string | undefined) ?? undefined,
      description: (props.description as string | undefined) ?? undefined
    };
  }

  private toField(props: Record<string, unknown>): StandardArtifactField {
    return {
      field_id: String(props.field_id),
      artifact_id: String(props.artifact_id),
      artifact_name: (props.artifact_name as string | undefined) ?? undefined,
      seq: Number(props.seq),
      field_name_zh: String(props.field_name_zh),
      required: Boolean(props.required),
      data_type: String(props.data_type),
      enum_or_ref: (props.enum_or_ref as string | undefined) ?? undefined,
      fill_guidance: (props.fill_guidance as string | undefined) ?? undefined,
      example: (props.example as string | undefined) ?? undefined,
      clause_ref: (props.clause_ref as string | undefined) ?? undefined,
      clause_title: (props.clause_title as string | undefined) ?? undefined,
      source: (props.source as string | undefined) ?? undefined,
      trace_role: (props.trace_role as string | undefined) ?? undefined
    };
  }
}
