import type { QueryResult } from "neo4j-driver";
import type { SystemDataFlow } from "../types/domain.js";

// Preserve atomicity and reset-before-rebuild order in the caller's transaction.
export async function writeSystemDataFlows(tx: { run(query: string, parameters?: Record<string, unknown>): Promise<QueryResult> }, rows: SystemDataFlow[]): Promise<void> {
  if (rows.length === 0) return;
  // Preserve last-write-wins behavior for repeated IDs.
  const unique = [...new Map(rows.map(row => [row.sdf_id, row])).values()];
  const parameters = {
    rows: unique.map(sdf => ({
      sdf_id: sdf.sdf_id,
      producer: sdf.producer ?? null,
      consumer: sdf.consumer ?? null,
      content: sdf.content ?? null,
      data_flow_type: sdf.data_flow_type ?? null,
      description: sdf.description ?? null,
      failure_condition_ids: sdf.failure_condition_ids ?? [],
      system_interface_id: sdf.system_interface_id ?? null,
      producer_system_id: sdf.producer_system_id ?? null,
      consumer_system_id: sdf.consumer_system_id ?? null,
      topic_ids: sdf.topic_ids ?? [],
      function_ids: sdf.function_ids ?? []
    }))
  };
  await tx.run("UNWIND $rows AS row MERGE (sdf:SystemDataFlow {sdf_id: row.sdf_id}) SET sdf.producer = row.producer, sdf.consumer = row.consumer, sdf.content = row.content, sdf.data_flow_type = row.data_flow_type, sdf.description = row.description, sdf.failure_condition_ids = row.failure_condition_ids, sdf.system_interface_id = row.system_interface_id, sdf.producer_system_id = row.producer_system_id, sdf.consumer_system_id = row.consumer_system_id, sdf.topic_ids = row.topic_ids WITH sdf OPTIONAL MATCH (sdf)-[old:SUPPORTS_FUNCTION|TRACES_TO]->() DELETE old", parameters);
  await tx.run("UNWIND $rows AS row MATCH (sdf:SystemDataFlow {sdf_id: row.sdf_id}) UNWIND row.function_ids AS fid MATCH (f:FunctionNode {function_id: fid}) MERGE (sdf)-[:SUPPORTS_FUNCTION]->(f)", parameters);
  await tx.run("UNWIND $rows AS row MATCH (sdf:SystemDataFlow {sdf_id: row.sdf_id}) UNWIND row.failure_condition_ids AS fcid MATCH (fc:FailureCondition {failure_condition_id: fcid}) MERGE (sdf)-[:TRACES_TO]->(fc)", parameters);
}
