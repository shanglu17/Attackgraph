import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { fixture } from "../featureRules/testFixture.js";
import { analysisDigest } from "./canonicalization.js";
import { executeAnalysisMethod } from "./methodExecutor.js";
import { getAnalysisMethod } from "./methodRegistry.js";

function topologyInput() {
  const input = fixture();
  input.assets[0].prototype_asset_id = "P-A" as never;
  input.evidence.push({ ...input.evidence[0], evidence_id: "MAP-E" });
  return {
    feature_input: input,
    graph: {
      graph_version: "G-1",
      asset_nodes: [{ asset_id: "P-A" }, { asset_id: "P-B" }, { asset_id: "P-C" }],
      asset_edges: [
        { edge_id: "E-1", source_asset_id: "P-A", target_asset_id: "P-B", direction: "Unidirectional" },
        { edge_id: "E-2", source_asset_id: "P-B", target_asset_id: "P-C", direction: "Unidirectional" },
      ],
    },
    mappings: [{ scope_id: "SCOPE", allowed_edge_ids: ["E-1", "E-2"], target_asset_ids: ["P-C"], evidence_refs: ["MAP-E"] }],
    options: { max_hops: 3 },
  };
}

test("method registry uses the accepted AnalysisMethodDefinition name and separates maturity from availability", () => {
  const feature = getAnalysisMethod("feature-rule-preview", "0.1.0");
  assert.equal(feature.maturity, "experimental");
  assert.equal(feature.availability, "enabled");
  assert.match(feature.implementation_artifact_digest, /^[a-f0-9]{64}$/);
});

test("feature execution is deterministic and external reviewer assertions remain method payload only", () => {
  const method = getAnalysisMethod("feature-rule-preview", "0.1.0");
  const first = executeAnalysisMethod(method, fixture());
  const second = executeAnalysisMethod(method, fixture());
  assert.equal(first.result_summary_hash, second.result_summary_hash);
  assert.ok(first.results.every((item) => ["Experimental", "Candidate"].includes(item.machine_status)));
  assert.equal(JSON.stringify(first.results).includes("ReviewDecision"), false);
});

test("topology execution preserves ordered steps and reports complete exhaustion", () => {
  const method = getAnalysisMethod("feature-topology-trace", "0.1.0");
  const run = executeAnalysisMethod(method, topologyInput());
  assert.equal(run.results[0].topology_only, true);
  assert.equal(run.results[0].completeness, "complete");
  assert.equal(run.results[0].termination_reason, "search_space_exhausted");
  const payload = run.results[0].payload as { paths: Array<{ edge_ids: string[] }> };
  assert.deepEqual(payload.paths[0].edge_ids, ["E-1", "E-2"]);
});

test("ordered canonicalizer distinguishes reversed attack-path steps", () => {
  assert.notEqual(analysisDigest({ edge_ids: ["E-1", "E-2"] }), analysisDigest({ edge_ids: ["E-2", "E-1"] }));
});

test("checked-in Phase 4 example produces an evidence-scoped topology candidate", async () => {
  const path = fileURLToPath(new URL("../../../../../examples/phase4-feature-topology-input.json", import.meta.url));
  const input = JSON.parse(await readFile(path, "utf8"));
  const execution = executeAnalysisMethod(getAnalysisMethod("feature-topology-trace", "0.1.0"), input);
  const candidate = execution.results.find((item) => item.result_kind === "topology_candidate");
  assert.ok(candidate);
  assert.equal(candidate.topology_only, true);
  assert.equal(candidate.completeness, "complete");
});

