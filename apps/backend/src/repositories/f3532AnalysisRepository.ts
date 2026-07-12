import { getDriver } from "../db/neo4j.js";
import type { FhaImportRequest } from "../types/api.js";
import type { FailureCondition, ThreatCondition, ThreatScenario, ThreatActorType } from "../types/domain.js";

export interface FailureConditionContext extends FailureCondition {
  sdf_ids: string[];
  function_ids: string[];
  path_ids: string[];
}

export interface ThreatPathActorContext {
  actor_id: string;
  actor_name: string;
  actor_type: ThreatActorType;
}

export interface ThreatPathContext {
  path_id: string;
  system_path: string;
  function_ids: string[];
  boundary_ids: string[];
  threat_actors: ThreatPathActorContext[];
}

const toStrings = (value: unknown): string[] =>
  ((value as unknown[]) ?? []).filter((item) => item !== null && item !== undefined).map((item) => String(item));

export class F3532AnalysisRepository {
  async importFailureConditions(input: FhaImportRequest): Promise<{
    imported: number;
    linked_sdf_count: number;
    unlinked_failure_condition_ids: string[];
  }> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run(
          `UNWIND $rows AS row
           MERGE (fc:FailureCondition {failure_condition_id: row.failure_condition_id})
           SET fc.name = row.name,
               fc.flight_phases = row.flight_phases,
               fc.hazard_class = row.hazard_class,
               fc.severity = row.severity,
               fc.max_failure_probability = row.max_failure_probability,
               fc.source_ref = row.source_ref,
               fc.notes = row.notes,
               fc.imported_at = datetime($imported_at),
               fc.imported_by = $imported_by`,
          {
            rows: input.failure_conditions.map((row) => ({
              ...row,
              max_failure_probability: row.max_failure_probability ?? null,
              source_ref: row.source_ref ?? input.source.file_name,
              notes: row.notes ?? null
            })),
            imported_at: input.source.submitted_at,
            imported_by: input.source.submitted_by
          }
        );
        await tx.run(
          `MATCH (sdf:SystemDataFlow)
           UNWIND coalesce(sdf.failure_condition_ids, []) AS failure_condition_id
           MATCH (fc:FailureCondition {failure_condition_id: failure_condition_id})
           MERGE (sdf)-[:TRACES_TO]->(fc)`
        );
      });

      const summary = await session.executeRead(async (tx) => {
        const [linked, unlinked] = await Promise.all([
          tx.run("MATCH (sdf:SystemDataFlow)-[:TRACES_TO]->(:FailureCondition) RETURN count(DISTINCT sdf) AS count"),
          tx.run(
            `MATCH (fc:FailureCondition)
             WHERE NOT EXISTS { MATCH (:SystemDataFlow)-[:TRACES_TO]->(fc) }
             RETURN collect(fc.failure_condition_id) AS ids`
          )
        ]);
        return {
          linked_sdf_count: Number(linked.records[0]?.get("count") ?? 0),
          unlinked_failure_condition_ids: toStrings(unlinked.records[0]?.get("ids"))
        };
      });
      return { imported: input.failure_conditions.length, ...summary };
    } finally {
      await session.close();
    }
  }

  async getFailureConditionContexts(): Promise<FailureConditionContext[]> {
    const session = getDriver().session();
    try {
      const result = await session.run(
        `MATCH (fc:FailureCondition)
         OPTIONAL MATCH (sdf:SystemDataFlow)-[:TRACES_TO]->(fc)
         OPTIONAL MATCH (sdf)-[:SUPPORTS_FUNCTION]->(f:FunctionNode)
         OPTIONAL MATCH (fp:FunctionPropagationPath)-[:INCLUDES_SDF]->(sdf)
         RETURN fc,
                collect(DISTINCT sdf.sdf_id) AS sdf_ids,
                collect(DISTINCT f.function_id) AS function_ids,
                collect(DISTINCT fp.fp_id) AS path_ids
         ORDER BY fc.failure_condition_id`
      );
      return result.records.map((record) => {
        const props = record.get("fc").properties as Record<string, unknown>;
        return {
          failure_condition_id: String(props.failure_condition_id),
          name: String(props.name),
          flight_phases: Array.isArray(props.flight_phases) ? props.flight_phases.map(String) : [],
          hazard_class: String(props.hazard_class),
          severity: props.severity as FailureCondition["severity"],
          max_failure_probability: (props.max_failure_probability as string | undefined) ?? undefined,
          source_ref: (props.source_ref as string | undefined) ?? undefined,
          notes: (props.notes as string | undefined) ?? undefined,
          sdf_ids: toStrings(record.get("sdf_ids")),
          function_ids: toStrings(record.get("function_ids")),
          path_ids: toStrings(record.get("path_ids"))
        };
      });
    } finally {
      await session.close();
    }
  }

  async getThreatPathContexts(): Promise<ThreatPathContext[]> {
    const session = getDriver().session();
    try {
      const result = await session.run(
        `MATCH (fp:FunctionPropagationPath)
         OPTIONAL MATCH (fp)-[:INCLUDES_SDF]->(sdf:SystemDataFlow)-[:SUPPORTS_FUNCTION]->(f:FunctionNode)
         OPTIONAL MATCH (fp)-[:INCLUDES_BDF]->(bdf:AssetNode)
         OPTIONAL MATCH (bi:BoundaryInterface)-[:CARRIES|CARRIES_FLOW]->(bdf)
         OPTIONAL MATCH (sb:TrustBoundary)-[:HAS_INTERFACE]->(bi)
         OPTIONAL MATCH (ta:ThreatActor)-[:THREATENS]->(sb)
         RETURN fp.fp_id AS path_id, fp.system_path_text AS system_path,
                collect(DISTINCT f.function_id) AS function_ids,
                collect(DISTINCT sb.boundary_id) AS boundary_ids,
                collect(DISTINCT {actor_id: ta.actor_id, actor_name: ta.name, actor_type: ta.actor_type}) AS threat_actors
         ORDER BY path_id`
      );
      return result.records.map((record) => ({
        path_id: String(record.get("path_id")),
        system_path: (record.get("system_path") as string | null) ?? "",
        function_ids: toStrings(record.get("function_ids")),
        boundary_ids: toStrings(record.get("boundary_ids")),
        threat_actors: ((record.get("threat_actors") as Array<Record<string, unknown>>) ?? [])
          .filter((actor) => actor.actor_id)
          .map((actor) => ({
            actor_id: String(actor.actor_id),
            actor_name: String(actor.actor_name ?? actor.actor_id),
            actor_type: actor.actor_type as ThreatActorType
          }))
      }));
    } finally {
      await session.close();
    }
  }

  async replaceF353204(threatConditions: ThreatCondition[], threatScenarios: ThreatScenario[]): Promise<void> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run("MATCH (n) WHERE n:ThreatCondition OR n:ThreatScenario DETACH DELETE n");
        for (const tc of threatConditions) {
          await tx.run(
            `CREATE (tc:ThreatCondition {
               tc_id: $tc_id, function_id: $function_id, failure_condition_ids: $failure_condition_ids,
               cia_attributes: $cia_attributes, description: $description, aircraft_effect: $aircraft_effect,
               system_effect: $system_effect, crew_effect: $crew_effect, occupant_effect: $occupant_effect,
               severity: $severity, severity_source: $severity_source, path_ids: $path_ids,
               coverage_status: $coverage_status, review_status: $review_status, is_default: $is_default
             })`,
            {
              ...tc,
              function_id: tc.function_id ?? null,
              description: tc.description ?? null,
              aircraft_effect: tc.aircraft_effect ?? null,
              system_effect: tc.system_effect ?? null,
              crew_effect: tc.crew_effect ?? null,
              occupant_effect: tc.occupant_effect ?? null,
              is_default: tc.is_default ?? false
            }
          );
          await tx.run(
            `MATCH (tc:ThreatCondition {tc_id: $tc_id})
             UNWIND $failure_condition_ids AS fcid
             MATCH (fc:FailureCondition {failure_condition_id: fcid})
             MERGE (tc)-[:DERIVED_FROM]->(fc)`,
            { tc_id: tc.tc_id, failure_condition_ids: tc.failure_condition_ids }
          );
          if (tc.function_id) {
            await tx.run(
              "MATCH (tc:ThreatCondition {tc_id: $tc_id}), (f:FunctionNode {function_id: $function_id}) MERGE (tc)-[:AFFECTS_FUNCTION]->(f)",
              { tc_id: tc.tc_id, function_id: tc.function_id }
            );
          }
          await tx.run(
            `MATCH (tc:ThreatCondition {tc_id: $tc_id})
             UNWIND $path_ids AS path_id
             MATCH (fp:FunctionPropagationPath {fp_id: path_id})
             MERGE (tc)-[:REACHABLE_BY]->(fp)`,
            { tc_id: tc.tc_id, path_ids: tc.path_ids }
          );
        }

        for (const ts of threatScenarios) {
          await tx.run(
            `CREATE (ts:ThreatScenario {
               ts_id: $ts_id, threat_actor_id: $threat_actor_id, tc_ids: $tc_ids,
               attack_vector: $attack_vector, attack_path: $attack_path,
               existing_security_measures: $existing_security_measures,
               review_status: $review_status, is_default: $is_default
             })`,
            {
              ...ts,
              threat_actor_id: ts.threat_actor_id ?? null,
              attack_vector: ts.attack_vector ?? null,
              existing_security_measures: ts.existing_security_measures ?? null,
              is_default: ts.is_default ?? false
            }
          );
          await tx.run(
            `MATCH (ts:ThreatScenario {ts_id: $ts_id})
             UNWIND $tc_ids AS tc_id
             MATCH (tc:ThreatCondition {tc_id: tc_id})
             MERGE (ts)-[:TRIGGERS]->(tc)`,
            { ts_id: ts.ts_id, tc_ids: ts.tc_ids }
          );
          if (ts.threat_actor_id) {
            await tx.run(
              "MATCH (ts:ThreatScenario {ts_id: $ts_id}), (ta:ThreatActor {actor_id: $actor_id}) MERGE (ts)-[:ORIGINATES_FROM]->(ta)",
              { ts_id: ts.ts_id, actor_id: ts.threat_actor_id }
            );
          }
        }
      });
    } finally {
      await session.close();
    }
  }

  async getF353204(): Promise<{ threat_conditions: ThreatCondition[]; threat_scenarios: ThreatScenario[] }> {
    const session = getDriver().session();
    try {
      const [tcResult, tsResult] = await Promise.all([
        session.run("MATCH (tc:ThreatCondition) RETURN tc ORDER BY tc.tc_id"),
        session.run("MATCH (ts:ThreatScenario) RETURN ts ORDER BY ts.ts_id")
      ]);
      return {
        threat_conditions: tcResult.records.map((record) => record.get("tc").properties as ThreatCondition),
        threat_scenarios: tsResult.records.map((record) => record.get("ts").properties as ThreatScenario)
      };
    } finally {
      await session.close();
    }
  }
}
