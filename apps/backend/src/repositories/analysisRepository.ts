import { int as neo4jInteger } from "neo4j-driver";
import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import type {
  AnalysisMethodDefinition,
  StoredPromotion,
  StoredAnalysisRun,
  StoredDerivedResult,
  StoredInputSnapshot,
} from "@attackgraph/contracts";
import { analysisContractVersion } from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";
import type { ExecutedResult } from "../services/analysis/methodExecutor.js";
import type { ProjectRevisionScope } from "./compatibilityScopeRepository.js";
import { amsPropagationVersion, obsoleteSavedProjection } from "../services/analysis/propagationPolicy.js";

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") return value.toNumber();
  return Number(value);
}

function props(record: { get(key: string): unknown }, key: string): Record<string, unknown> {
  const node = record.get(key);
  if (typeof node !== "object" || node === null || !("properties" in node)) throw new TypeError("Expected Neo4j node " + key);
  return (node as { properties: Record<string, unknown> }).properties;
}

function dateText(value: unknown) {
  return String(value ?? "");
}

export class AnalysisScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnalysisScopeError";
  }
}

export interface CreateAnalysisRunInput {
  status?: "Completed" | "Failed";
  started_at?: string;
  completed_at?: string;
  project_id: string;
  revision_id: string;
  actor: string;
  command_id: string;
  revision_version: number;
  input_revision_version: number;
  source_record_business_id: string;
  method: AnalysisMethodDefinition;
  method_config_version: string;
  rule_pack_version?: string;
  projection_version?: string;
  execution_limits: Record<string, unknown>;
  input_snapshot: { payload: unknown; content_hash: string };
  config_snapshot: { payload: unknown; content_hash: string };
  extra_snapshots: Array<{ snapshot_type: "graph" | "mapping"; payload: unknown; content_hash: string }>;
  results: ExecutedResult[];
  result_summary_hash: string;
}

export class AnalysisRepository {
  async readSummaries(projectId: string, revisionId: string, limit = 20, cursor?: string, runId?: string): Promise<import("@attackgraph/contracts").AnalysisHistoryPage> {
    await this.resolveProjectRevisionScope(projectId, revisionId);
    const s = getDriver().session();
    try {
      return await s.executeRead(async tx => {
        const params={project_id:projectId,revision_id:revisionId,cursor:cursor??null,run_id:runId??null,limit:neo4jInteger(limit+1),projection_version:amsPropagationVersion};
        if(cursor){const anchor=await tx.run("MATCH(r:AnalysisRun {project_id:$project_id,revision_id:$revision_id,id:$cursor,method_id:'dfs-dps-attack-path'}) RETURN r.id",params);if(!anchor.records.length)throw new AnalysisScopeError("History cursor is outside the current project/revision");}
        const r=await tx.run(`OPTIONAL MATCH(anchor:AnalysisRun {id:$cursor,project_id:$project_id,revision_id:$revision_id})
          WITH anchor MATCH(run:AnalysisRun {project_id:$project_id,revision_id:$revision_id,method_id:'dfs-dps-attack-path'})
          WHERE ($run_id IS NULL OR run.id=$run_id) AND ($cursor IS NULL OR run.started_at<anchor.started_at OR (run.started_at=anchor.started_at AND run.id<anchor.id))
          OPTIONAL MATCH(audit:AuditEvent {command_id:run.command_id})
          RETURN run.id AS id,run.input_revision_version AS input_revision_version,run.started_at AS started_at,run.completed_at AS completed_at,run.status AS status,
            CASE WHEN audit.request_canonicalizer='workbench.saved-analysis/v1' THEN 'saved-model' ELSE 'caller-provided' END AS input_origin,
            ((audit.request_canonicalizer='workbench.saved-analysis/v1' AND run.rule_pack_version='do356a-ams/v1' AND coalesce(run.projection_version,'')<>$projection_version) OR EXISTS { MATCH(e:AuditEvent {project_id:$project_id,subject_id:$revision_id})
              WHERE e.subject_version_after>run.revision_version AND e.event_type IN ['SYSTEM_MODEL_IMPORTED','SYSTEM_MODEL_EDITED','ANALYSIS_CONFIGURATION_UPDATED','ENGINEERING_CASE_COMMITTED'] }) AS stale
          ORDER BY run.started_at DESC,run.id DESC LIMIT $limit`,params);
        const rows=r.records.slice(0,limit).map(row=>({id:String(row.get("id")),project_id:projectId,revision_id:revisionId,
          input_revision_version:numeric(row.get("input_revision_version")),started_at:dateText(row.get("started_at")),completed_at:dateText(row.get("completed_at")),
          status:row.get("status") as "Completed"|"Failed",stale:row.get("stale")===true,input_origin:row.get("input_origin") as "saved-model"|"caller-provided"}));
        return {runs:rows,next_cursor:r.records.length>limit?rows[rows.length-1].id:null};
      });
    } finally {await s.close();}
  }
  async resolveProjectRevisionScope(projectId: string, revisionId: string): Promise<ProjectRevisionScope> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) => tx.run(
        "MATCH (project:Project {id: $project_id})-[:HAS_MODEL]->(model:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id}) " +
        "WHERE project.deleted_at IS NULL RETURN model.id AS model_id",
        { project_id: projectId, revision_id: revisionId },
      ));
      if (result.records.length !== 1) throw new AnalysisScopeError("Project/revision scope was not found or is ambiguous");
      return { project_id: projectId, model_id: String(result.records[0].get("model_id")), revision_id: revisionId };
    } finally {
      await session.close();
    }
  }

  async inspectAssetScope(projectId: string, revisionId: string, assetBusinessIds: string[]): Promise<string[]> {
    if (assetBusinessIds.length === 0) return [];
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) => tx.run(
        "UNWIND $asset_business_ids AS business_id " +
        "OPTIONAL MATCH (asset:CoreEntity:Asset {project_id: $project_id, revision_id: $revision_id, business_id: business_id}) " +
        "WITH business_id, count(asset) AS matches WHERE matches = 0 RETURN collect(business_id) AS unresolved",
        { project_id: projectId, revision_id: revisionId, asset_business_ids: [...new Set(assetBusinessIds)] },
      ));
      return (result.records[0]?.get("unresolved") ?? []).map(String);
    } finally {
      await session.close();
    }
  }

  async createRun(transaction: ManagedTransaction, input: CreateAnalysisRunInput) {
    const runId = randomUUID();
    const runBusinessId = "ANRUN-" + runId;
    const startedAt = input.started_at ?? new Date().toISOString();
    const completedAt = input.completed_at ?? startedAt;
    const scope = await transaction.run(
      "MATCH (:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id}) " +
      "MATCH (revision)-[:USES_STANDARD_PROFILE_VERSION]->(profile:StandardProfileVersion) " +
      "MATCH (source:SourceRecord {project_id: $project_id, revision_id: $revision_id, business_id: $source_record_business_id}) " +
      "MATCH (method:AnalysisMethodDefinition {method_id: $method_id, method_version: $method_version}) " +
      "RETURN revision, profile, source, method",
      { ...input, method_id: input.method.method_id, method_version: input.method.method_version },
    );
    if (scope.records.length === 0) throw new AnalysisScopeError("Revision, StandardProfileVersion, SourceRecord, or method definition was not found");
    const profile = props(scope.records[0], "profile");
    await transaction.run(
      "MATCH (revision:Revision {id: $revision_id, project_id: $project_id}) " +
      "MATCH (profile:StandardProfileVersion {id: $profile_id}) " +
      "MATCH (source:SourceRecord {project_id: $project_id, revision_id: $revision_id, business_id: $source_record_business_id}) " +
      "MATCH (method:AnalysisMethodDefinition {method_id: $method_id, method_version: $method_version}) " +
      "CREATE (run:CoreEntity:AnalysisRun {id: $run_id, business_id: $run_business_id, entity_type: 'AnalysisRun', project_id: $project_id, " +
      "revision_id: $revision_id, input_revision_version: $input_revision_version, revision_version: $revision_version, contract_version: $contract_version, " +
      "method_id: $method_id, method_version: $method_version, method_config_version: $method_config_version, rule_pack_version: $rule_pack_version, " +
      "projection_version: $projection_version, " +
      "implementation_artifact_digest: $implementation_artifact_digest, canonicalizer_id: $canonicalizer_id, canonicalizer_version: $canonicalizer_version, " +
      "execution_limits_json: $execution_limits_json, command_id: $command_id, actor: $actor, status: $status, replayability: $replayability, " +
      "result_summary_hash: $result_summary_hash, started_at: datetime($started_at), completed_at: datetime($completed_at), created_at: datetime($completed_at)}) " +
      "CREATE (revision)-[:CONTAINS]->(run) CREATE (run)-[:USES_METHOD]->(method) CREATE (run)-[:USES_PROFILE]->(profile) CREATE (run)-[:DERIVED_FROM_SOURCE]->(source)",
      {
        project_id: input.project_id, revision_id: input.revision_id, profile_id: String(profile.id),
        source_record_business_id: input.source_record_business_id, method_id: input.method.method_id,
        method_version: input.method.method_version, run_id: runId, run_business_id: runBusinessId,
        input_revision_version: input.input_revision_version, revision_version: input.revision_version,
        contract_version: analysisContractVersion, method_config_version: input.method_config_version,
        rule_pack_version: input.rule_pack_version ?? null,
        projection_version: input.projection_version ?? null,
        implementation_artifact_digest: input.method.implementation_artifact_digest,
        canonicalizer_id: input.method.canonicalizer_id, canonicalizer_version: input.method.canonicalizer_version,
        execution_limits_json: JSON.stringify(input.execution_limits), command_id: input.command_id,
        actor: input.actor, result_summary_hash: input.result_summary_hash, started_at: startedAt, completed_at: completedAt,
        status:input.status ?? "Completed",replayability:input.status === "Failed"?"verifiable_only":"reproducible",
      },
    );

    const snapshotSeeds = [
      { snapshot_type: "method_input", ...input.input_snapshot },
      { snapshot_type: "method_config", ...input.config_snapshot },
      ...input.extra_snapshots,
    ];
    const snapshots = snapshotSeeds.map((item) => ({
      id: randomUUID(), snapshot_type: item.snapshot_type, content_hash: item.content_hash,
      canonicalizer: input.method.canonicalizer_id + "@" + input.method.canonicalizer_version,
      payload_json: JSON.stringify(item.payload),
    }));
    await transaction.run(
      "MATCH (run:AnalysisRun {id: $run_id}) UNWIND $snapshots AS row " +
      "CREATE (snapshot:AnalysisInputSnapshot {id: row.id, project_id: $project_id, revision_id: $revision_id, snapshot_type: row.snapshot_type, " +
      "content_hash: row.content_hash, canonicalizer: row.canonicalizer, payload_json: row.payload_json, created_at: datetime($started_at)}) " +
      "CREATE (run)-[:HAS_INPUT_SNAPSHOT]->(snapshot)",
      { run_id: runId, snapshots, project_id: input.project_id, revision_id: input.revision_id, started_at: startedAt },
    );

    const resultRows = input.results.map((result, index) => ({
      id: randomUUID(), business_id: runBusinessId + "-RESULT-" + String(index + 1).padStart(4, "0"),
      result_kind: result.result_kind, machine_status: result.machine_status, result_hash: result.result_hash,
      topology_only: result.topology_only, completeness: result.completeness,
      termination_reason: result.termination_reason, truncated: result.truncated,
      diagnostics_json: JSON.stringify(result.diagnostics), payload_json: JSON.stringify(result.payload),
    }));
    if (resultRows.length > 0) {
      await transaction.run(
        "MATCH (run:AnalysisRun {id: $run_id}) UNWIND $results AS row " +
        "CREATE (result:CoreEntity:DerivedResult {id: row.id, business_id: row.business_id, entity_type: 'DerivedResult', project_id: $project_id, " +
        "revision_id: $revision_id, run_id: $run_id, result_kind: row.result_kind, machine_status: row.machine_status, result_hash: row.result_hash, " +
        "topology_only: row.topology_only, completeness: row.completeness, termination_reason: row.termination_reason, truncated: row.truncated, " +
        "diagnostics_json: row.diagnostics_json, payload_json: row.payload_json, revision_version: $revision_version, created_at: datetime($started_at), created_by: $actor}) " +
        "CREATE (run)-[:PRODUCED]->(result)",
        { run_id: runId, results: resultRows, project_id: input.project_id, revision_id: input.revision_id, revision_version: input.revision_version, started_at: startedAt, actor: input.actor },
      );
    }
    return { run_id: runId, run_business_id: runBusinessId, result_ids: resultRows.map((item) => item.id), result_summary_hash: input.result_summary_hash };
  }

  async reviewResult(transaction: ManagedTransaction, input: {
    project_id: string; revision_id: string; actor: string; revision_version: number;
    review: { business_id: string; derived_result_id: string; subject_version: number; decision: "Accept" | "Reject"; rationale: string; reviewer_role: string; supersedes_business_id?: string };
  }) {
    const decisionId = randomUUID();
    const status = input.review.decision === "Accept" ? "Reviewed" : "Rejected";
    const result = await transaction.run(
      "MATCH (revision:Revision {id: $revision_id, project_id: $project_id}) " +
      "MATCH (subject:DerivedResult {id: $derived_result_id, project_id: $project_id, revision_id: $revision_id, revision_version: $subject_version}) " +
      "OPTIONAL MATCH (prior:ReviewDecision {project_id: $project_id, revision_id: $revision_id, business_id: $supersedes_business_id}) " +
      "CREATE (decision:ReviewDecision {id: $decision_id, business_id: $business_id, project_id: $project_id, revision_id: $revision_id, " +
      "subject_type: 'DerivedResult', subject_id: subject.id, subject_business_id: subject.business_id, subject_version: $subject_version, " +
      "decision: $decision, rationale: $rationale, reviewer: $actor, reviewer_role: $reviewer_role, revision_version: $revision_version, decided_at: datetime()}) " +
      "SET subject.machine_status = $status CREATE (revision)-[:CONTAINS]->(decision) CREATE (decision)-[:DECIDES]->(subject) " +
      "FOREACH (_ IN CASE WHEN prior IS NULL THEN [] ELSE [1] END | CREATE (decision)-[:SUPERSEDES]->(prior)) RETURN subject.id AS id",
      {
        project_id: input.project_id, revision_id: input.revision_id, actor: input.actor, revision_version: input.revision_version,
        derived_result_id: input.review.derived_result_id, subject_version: input.review.subject_version,
        supersedes_business_id: input.review.supersedes_business_id ?? null, decision_id: decisionId,
        business_id: input.review.business_id, decision: input.review.decision, rationale: input.review.rationale,
        reviewer_role: input.review.reviewer_role, status,
      },
    );
    if (result.records.length === 0) throw new AnalysisScopeError("DerivedResult subject/version was not found in the requested scope");
    return { derived_result_id: input.review.derived_result_id, machine_status: status as "Reviewed" | "Rejected" };
  }

  async promote(transaction: ManagedTransaction, input: {
    project_id: string; revision_id: string; actor: string; revision_version: number;
    promotion: {
      business_id: string; derived_result_id: string; target_type: "ThreatPoint" | "ThreatScenario" | "AttackPath" | "RiskAssessment";
      target_business_id: string; target_name: string; target_payload: Record<string, unknown>; rationale: string;
      supersedes_business_id?: string; feasibility_rationale?: string;
      segment_validations: Array<{ edge_id: string; semantic_rationale: string; evidence_record_business_ids: string[] }>;
    };
  }) {
    const promotionId = randomUUID();
    const coreId = randomUUID();
    const traceId = randomUUID();
    const source = await transaction.run(
      "MATCH (result:DerivedResult {id: $derived_result_id, project_id: $project_id, revision_id: $revision_id, machine_status: 'Reviewed'})<-[:PRODUCED]-(run:AnalysisRun) " +
      "RETURN result, run",
      { derived_result_id: input.promotion.derived_result_id, project_id: input.project_id, revision_id: input.revision_id },
    );
    if (source.records.length === 0) throw new AnalysisScopeError("Promotion requires a human-reviewed DerivedResult in the same scope");
    const resultProps = props(source.records[0], "result");
    const payload = JSON.parse(String(resultProps.payload_json)) as Record<string, unknown>;
    if (input.promotion.target_type === "AttackPath" && resultProps.topology_only === true) {
      const paths = Array.isArray(payload.paths) ? payload.paths as Array<{ edge_ids?: string[] }> : [];
      const requiredEdges = new Set(paths.flatMap((path) => path.edge_ids ?? []));
      const supplied = new Set(input.promotion.segment_validations.map((item) => item.edge_id));
      if (!input.promotion.feasibility_rationale || requiredEdges.size === 0 || [...requiredEdges].some((edge) => !supplied.has(edge))) {
        throw new AnalysisScopeError("Topology-only AttackPath promotion requires feasibility rationale and evidence-backed validation for every edge");
      }
      const evidenceIds = [...new Set(input.promotion.segment_validations.flatMap((item) => item.evidence_record_business_ids))];
      const evidence = await transaction.run(
        "UNWIND $ids AS id OPTIONAL MATCH (evidence:EvidenceRecord {project_id: $project_id, revision_id: $revision_id, business_id: id}) " +
        "RETURN count(evidence) AS count",
        { ids: evidenceIds, project_id: input.project_id, revision_id: input.revision_id },
      );
      if (numeric(evidence.records[0].get("count")) !== evidenceIds.length) throw new AnalysisScopeError("Segment validation references unresolved EvidenceRecord");
    }
    const targetLabel = input.promotion.target_type;
    const query =
      "MATCH (revision:Revision {id: $revision_id, project_id: $project_id}) " +
      "MATCH (result:DerivedResult {id: $derived_result_id})<-[:PRODUCED]-(run:AnalysisRun) " +
      "OPTIONAL MATCH (prior:PromotedCoreDraft {project_id: $project_id, revision_id: $revision_id, business_id: $supersedes_business_id}) " +
      "CREATE (core:CoreEntity:PromotedCoreDraft:" + targetLabel + " {id: $core_id, business_id: $target_business_id, legacy_id: $target_business_id, entity_type: $target_type, " +
      "project_id: $project_id, revision_id: $revision_id, name: $target_name, status: 'Draft', origin: 'analysis_promotion', source_run_id: run.id, " +
      "source_derived_result_id: result.id, source_topology_only: result.topology_only, payload_json: $target_payload_json, feasibility_rationale: $feasibility_rationale, " +
      "segment_validations_json: $segment_validations_json, analysis_batch_id: run.business_id, revision_version: $revision_version, created_at: datetime(), created_by: $actor}) " +
      "CREATE (promotion:Promotion {id: $promotion_id, business_id: $business_id, project_id: $project_id, revision_id: $revision_id, " +
      "derived_result_id: result.id, core_entity_id: core.id, target_type: $target_type, rationale: $rationale, revision_version: $revision_version, promoted_at: datetime(), promoted_by: $actor}) " +
      "CREATE (trace:CoreEntity:AnalysisTraceLink:TraceLink {id: $trace_id, business_id: $trace_business_id, entity_type: 'TraceLink', project_id: $project_id, " +
      "revision_id: $revision_id, link_type: 'DERIVED_FROM', source_type: $target_type, source_business_id: $target_business_id, " +
      "target_type: 'DerivedResult', target_business_id: result.business_id, revision_version: $revision_version, created_at: datetime(), created_by: $actor}) " +
      "CREATE (revision)-[:CONTAINS]->(core) CREATE (revision)-[:CONTAINS]->(promotion) CREATE (revision)-[:CONTAINS]->(trace) " +
      "CREATE (core)-[:DERIVED_FROM]->(result) CREATE (promotion)-[:PROMOTES]->(result) CREATE (promotion)-[:CREATED]->(core) " +
      "CREATE (trace)-[:TRACE_FROM]->(core) CREATE (trace)-[:TRACE_TO]->(result) " +
      "FOREACH (_ IN CASE WHEN prior IS NULL THEN [] ELSE [1] END | CREATE (core)-[:SUPERSEDES]->(prior)) " +
      "SET result.machine_status = 'Promoted' RETURN core.id AS id";
    const created = await transaction.run(query, {
      project_id: input.project_id, revision_id: input.revision_id, actor: input.actor, revision_version: input.revision_version,
      derived_result_id: input.promotion.derived_result_id, supersedes_business_id: input.promotion.supersedes_business_id ?? null,
      core_id: coreId, promotion_id: promotionId, trace_id: traceId, trace_business_id: input.promotion.business_id + ":DERIVED_FROM",
      business_id: input.promotion.business_id, target_business_id: input.promotion.target_business_id,
      target_type: input.promotion.target_type, target_name: input.promotion.target_name,
      target_payload_json: JSON.stringify(input.promotion.target_payload), feasibility_rationale: input.promotion.feasibility_rationale ?? null,
      segment_validations_json: JSON.stringify(input.promotion.segment_validations), rationale: input.promotion.rationale,
    });
    if (created.records.length === 0) throw new AnalysisScopeError("Promotion target could not be created");
    return { promotion_id: promotionId, core_entity_id: coreId, target_type: input.promotion.target_type, target_business_id: input.promotion.target_business_id, status: "Draft" as const };
  }

  async readRuns(projectId: string, revisionId: string, runId?: string, withInputOrigin=false, includeInputs=true): Promise<StoredAnalysisRun[]> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (tx) => {
        const runs = await tx.run(
          "MATCH (run:AnalysisRun {project_id: $project_id, revision_id: $revision_id}) WHERE $run_id IS NULL OR run.id = $run_id " +
          "MATCH (run)-[:USES_METHOD]->(method:AnalysisMethodDefinition) " +
          "MATCH (run)-[:USES_PROFILE]->(profile:StandardProfileVersion) MATCH (run)-[:DERIVED_FROM_SOURCE]->(source:SourceRecord) " +
          "OPTIONAL MATCH (audit:AuditEvent {command_id: run.command_id}) " +
          "RETURN run, method, profile, source, audit ORDER BY run.started_at",
          { project_id: projectId, revision_id: revisionId, run_id: runId ?? null },
        );
        const output: StoredAnalysisRun[] = [];
        for (const record of runs.records) {
          const run = props(record, "run");
          const method = props(record, "method");
          const profile = props(record, "profile");
          const source = props(record, "source");
          const auditNode = record.get("audit");
          const audit = typeof auditNode === "object" && auditNode !== null && "properties" in auditNode ? (auditNode as { properties: Record<string, unknown> }).properties : {};
          const snapshotsResult = await tx.run("MATCH (:AnalysisRun {id: $id})-[:HAS_INPUT_SNAPSHOT]->(snapshot:AnalysisInputSnapshot) WHERE $include_inputs OR snapshot.snapshot_type='method_config' RETURN snapshot ORDER BY snapshot.snapshot_type", { id: run.id, include_inputs:includeInputs });
          const resultsResult = await tx.run("MATCH (:AnalysisRun {id: $id})-[:PRODUCED]->(result:DerivedResult) RETURN result ORDER BY result.business_id", { id: run.id });
          const staleResult = await tx.run(
            "MATCH (event:AuditEvent {project_id: $project_id, subject_id: $revision_id}) " +
            "WHERE event.subject_version_after > $run_revision_version AND event.event_type IN ['SYSTEM_MODEL_IMPORTED', 'SYSTEM_MODEL_EDITED', 'ANALYSIS_CONFIGURATION_UPDATED', 'ENGINEERING_CASE_COMMITTED'] RETURN count(event) AS count",
            { project_id: projectId, revision_id: revisionId, run_revision_version: numeric(run.revision_version) },
          );
          const snapshots: StoredInputSnapshot[] = snapshotsResult.records.map((row) => {
            const item = props(row, "snapshot");
            return { id: String(item.id), snapshot_type: item.snapshot_type as StoredInputSnapshot["snapshot_type"], content_hash: String(item.content_hash), canonicalizer: String(item.canonicalizer), payload: JSON.parse(String(item.payload_json)) };
          });
          const results: StoredDerivedResult[] = resultsResult.records.map((row) => {
            const item = props(row, "result");
            return {
              id: String(item.id), business_id: String(item.business_id), run_id: String(item.run_id),
              result_kind: String(item.result_kind), machine_status: item.machine_status as StoredDerivedResult["machine_status"],
              result_hash: String(item.result_hash), topology_only: item.topology_only === true,
              completeness: item.completeness as StoredDerivedResult["completeness"],
              termination_reason: item.termination_reason as StoredDerivedResult["termination_reason"],
              truncated: item.truncated === true, diagnostics: JSON.parse(String(item.diagnostics_json)),
              payload: JSON.parse(String(item.payload_json)), revision_version: numeric(item.revision_version),
            };
          });
          output.push({
            ...(withInputOrigin ? {input_origin: (audit.request_canonicalizer === "workbench.saved-analysis/v1" ? "saved-model" : "caller-provided") as StoredAnalysisRun["input_origin"]} : {}),
            id: String(run.id), business_id: String(run.business_id), project_id: projectId, revision_id: revisionId,
            input_revision_version: numeric(run.input_revision_version), standard_profile_version_id: String(profile.id),
            standard_profile_version_business_id: String(profile.business_id), source_record_business_id: String(source.business_id),
            method: {
              method_id: method.method_id as AnalysisMethodDefinition["method_id"], method_version: String(method.method_version),
              name: String(method.name), maturity: method.maturity as AnalysisMethodDefinition["maturity"],
              availability: method.availability as AnalysisMethodDefinition["availability"],
              input_contract_version: String(method.input_contract_version), output_contract_version: String(method.output_contract_version),
              canonicalizer_id: String(method.canonicalizer_id), canonicalizer_version: String(method.canonicalizer_version),
              implementation_artifact_digest: String(method.implementation_artifact_digest),
              supported_result_kinds: Array.isArray(method.supported_result_kinds) ? method.supported_result_kinds.map(String) : [],
              completeness_rule: String(method.completeness_rule),
            },
            contract_version: analysisContractVersion, method_config_version: String(run.method_config_version),
            rule_pack_version: run.rule_pack_version == null ? undefined : String(run.rule_pack_version),
            command_id: String(run.command_id), audit_event_id: String(audit.id ?? ""), started_at: dateText(run.started_at),
            completed_at: dateText(run.completed_at), actor: String(run.actor), status: run.status as "Completed" | "Failed",
            replayability: run.replayability as "reproducible" | "verifiable_only", result_summary_hash: String(run.result_summary_hash),
            execution_limits: JSON.parse(String(run.execution_limits_json)), snapshots, results,
            stale: numeric(staleResult.records[0].get("count")) > 0 || (withInputOrigin && obsoleteSavedProjection(audit.request_canonicalizer, run.rule_pack_version, run.projection_version)),
          });
        }
        return output;
      });
    } finally {
      await session.close();
    }
  }

  async readPromotions(projectId: string, revisionId: string): Promise<StoredPromotion[]> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) => tx.run(
        "MATCH (promotion:Promotion {project_id: $project_id, revision_id: $revision_id})-[:CREATED]->(core:PromotedCoreDraft) " +
        "MATCH (promotion)-[:PROMOTES]->(derived:DerivedResult)<-[:PRODUCED]-(run:AnalysisRun) " +
        "MATCH (trace:AnalysisTraceLink)-[:TRACE_FROM]->(core) WHERE (trace)-[:TRACE_TO]->(derived) " +
        "RETURN promotion, core, derived, run, trace ORDER BY promotion.promoted_at",
        { project_id: projectId, revision_id: revisionId },
      ));
      return result.records.map((record) => {
        const promotion = props(record, "promotion");
        const core = props(record, "core");
        const derived = props(record, "derived");
        const run = props(record, "run");
        const trace = props(record, "trace");
        return {
          id: String(promotion.id), business_id: String(promotion.business_id), project_id: projectId, revision_id: revisionId,
          derived_result_id: String(derived.id), derived_result_business_id: String(derived.business_id),
          run_id: String(run.id), run_business_id: String(run.business_id), core_entity_id: String(core.id),
          target_type: core.entity_type as StoredPromotion["target_type"], target_business_id: String(core.business_id),
          target_name: String(core.name), target_status: String(core.status), origin: "analysis_promotion" as const,
          source_topology_only: core.source_topology_only === true, rationale: String(promotion.rationale),
          feasibility_rationale: core.feasibility_rationale == null ? undefined : String(core.feasibility_rationale),
          segment_validations: JSON.parse(String(core.segment_validations_json)), trace_link_business_id: String(trace.business_id),
          revision_version: numeric(promotion.revision_version), promoted_at: dateText(promotion.promoted_at), promoted_by: String(promotion.promoted_by),
        };
      });
    } finally {
      await session.close();
    }
  }
}
