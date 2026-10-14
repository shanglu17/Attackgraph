import assert from "node:assert/strict";
import test from "node:test";
import { compareImpactSnapshots, type ImpactSnapshot } from "./impactEngine.js";

function entity(type: string, business_id: string, value: string) {
  return { type, business_id, name: business_id, semantic: { value } };
}

test("impact comparison is deterministic and propagates through explicit dependencies", () => {
  const before: ImpactSnapshot = {
    entities: [entity("ThreatScenario", "TS-1", "a"), entity("RiskAssessment", "RISK-1", "a"), entity("SecurityObjective", "OBJ-1", "a")],
    dependencies: [
      { from: { type: "ThreatScenario", business_id: "TS-1" }, to: { type: "RiskAssessment", business_id: "RISK-1" }, trace_link_business_id: "L1" },
      { from: { type: "RiskAssessment", business_id: "RISK-1" }, to: { type: "SecurityObjective", business_id: "OBJ-1" }, trace_link_business_id: "L2" },
    ],
  };
  const after: ImpactSnapshot = { ...before, entities: [entity("ThreatScenario", "TS-1", "b"), entity("RiskAssessment", "RISK-1", "a"), entity("SecurityObjective", "OBJ-1", "a")] };
  const result = compareImpactSnapshots(before, after);
  assert.equal(result.differences.length, 1);
  assert.deepEqual(result.impacted.map((item) => [item.entity.business_id, item.distance]), [["TS-1", 0], ["RISK-1", 1], ["OBJ-1", 2]]);
  assert.equal(compareImpactSnapshots(before, after).preview_hash, result.preview_hash);
});

test("added and removed entities remain explicit direct changes", () => {
  const result = compareImpactSnapshots(
    { entities: [entity("Asset", "OLD", "a")], dependencies: [] },
    { entities: [entity("Asset", "NEW", "b")], dependencies: [] },
  );
  assert.deepEqual(result.differences.map((item) => item.change_kind), ["Added", "Removed"]);
  assert.equal(result.impacted.every((item) => item.impact_kind === "Direct"), true);
});

test("modified entities report added and removed fields without treating absence as null", () => {
  const before: ImpactSnapshot = {
    entities: [{ type: "Asset", business_id: "ASSET-1", name: "Asset", semantic: { retained: "same", removed: null } }],
    dependencies: [],
  };
  const after: ImpactSnapshot = {
    entities: [{ type: "Asset", business_id: "ASSET-1", name: "Asset", semantic: { retained: "same", added: null } }],
    dependencies: [],
  };
  const result = compareImpactSnapshots(before, after);
  assert.deepEqual(result.differences[0].changed_fields, ["added", "removed"]);
});
