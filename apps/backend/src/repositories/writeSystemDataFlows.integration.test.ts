import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { getDriver, closeDriver } from "../db/neo4j.js";
import { writeSystemDataFlows } from "./writeSystemDataFlows.js";

test("SDF batch replaces relationships, preserves empty rows, uses three queries and rolls back", async () => {
  const session = getDriver().session();
  const tx = session.beginTransaction();
  const prefix = `test-${randomUUID()}`;
  let calls = 0;
  const runner = { run: (query: string, params?: Record<string, unknown>) => {
    calls += 1;
    return tx.run(query, params);
  }};
  try {
    await tx.run("CREATE (:FunctionNode {function_id: $f1}), (:FunctionNode {function_id: $f2}), (:FailureCondition {failure_condition_id: $fc})", { f1: `${prefix}-f1`, f2: `${prefix}-f2`, fc: `${prefix}-fc` });
    await writeSystemDataFlows(runner, [
      { sdf_id: `${prefix}-a`, producer: "A", consumer: "B", function_ids: [`${prefix}-f1`], failure_condition_ids: [`${prefix}-fc`] },
      { sdf_id: `${prefix}-b`, content: "empty links", function_ids: [] }
    ]);
    const initial = await tx.run("MATCH (s:SystemDataFlow {sdf_id: $id})-[r]->() RETURN collect(type(r)) AS links", { id: `${prefix}-a` });
    assert.deepEqual(initial.records[0].get("links").sort(), ["SUPPORTS_FUNCTION", "TRACES_TO"]);
    await writeSystemDataFlows(runner, [
      { sdf_id: `${prefix}-a`, producer: "ignored earlier duplicate", function_ids: [`${prefix}-f1`] },
      { sdf_id: `${prefix}-a`, producer: "C", function_ids: [`${prefix}-f2`] },
      { sdf_id: `${prefix}-b`, content: "still present", function_ids: [] }
    ]);
    const result = await tx.run("MATCH (s:SystemDataFlow) WHERE s.sdf_id STARTS WITH $prefix OPTIONAL MATCH (s)-[r]->(target) RETURN s.sdf_id AS id, properties(s) AS props, collect(type(r)) AS links, collect(target.function_id) AS functions ORDER BY id", { prefix });
    assert.equal(result.records.length, 2);
    assert.equal(result.records[0].get("props").producer, "C");
    assert.equal(result.records[0].get("props").consumer, undefined);
    assert.deepEqual(result.records[0].get("props").failure_condition_ids, []);
    assert.deepEqual(result.records[0].get("functions"), [`${prefix}-f2`]);
    assert.deepEqual(result.records[0].get("links"), ["SUPPORTS_FUNCTION"]);
    assert.equal(result.records[1].get("props").content, "still present");
    assert.deepEqual(result.records[1].get("links"), []);
    assert.equal(calls, 6, "Each batch must use only 3 database round trips");
    await writeSystemDataFlows(runner, []);
    assert.equal(calls, 6, "Empty batches must not query the database");
  } finally {
    await tx.rollback();
    const result = await session.run("MATCH (n) WHERE n.sdf_id STARTS WITH $prefix OR n.function_id STARTS WITH $prefix OR n.failure_condition_id STARTS WITH $prefix RETURN count(n) AS count", { prefix });
    assert.equal(result.records[0].get("count").toNumber(), 0);
    await session.close();
    await closeDriver();
  }
});
