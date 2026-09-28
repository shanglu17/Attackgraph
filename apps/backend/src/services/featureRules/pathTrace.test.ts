import assert from "node:assert/strict";
import test from "node:test";
import { fixture, fact } from "./testFixture.js";
import { traceFeaturePaths } from "./pathTrace.js";

const graph = {
  graph_version: "synthetic-test-only",
  asset_nodes: [
    { asset_id: "P-A", asset_name: "entry", asset_type: "Interface" as const, criticality: "Low" as const },
    { asset_id: "P-B", asset_name: "middle", asset_type: "Terminal" as const, criticality: "Low" as const },
    { asset_id: "P-C", asset_name: "target", asset_type: "Data" as const, criticality: "High" as const }
  ],
  asset_edges: [
    { edge_id: "E-1", source_asset_id: "P-A", target_asset_id: "P-B", link_type: "DataFlow" as const, direction: "Unidirectional" as const },
    { edge_id: "E-2", source_asset_id: "P-B", target_asset_id: "P-C", link_type: "DataFlow" as const, direction: "Unidirectional" as const },
    { edge_id: "E-OUT", source_asset_id: "P-A", target_asset_id: "P-C", link_type: "DataFlow" as const, direction: "Unidirectional" as const }
  ]
};
const mapping = [{ scope_id: "SCOPE", allowed_edge_ids: ["E-1", "E-2"], target_asset_ids: ["P-C"], evidence_refs: ["MAP-E"] }];

function withPathEvidence(input: ReturnType<typeof fixture>) {
  return { ...input, evidence: [...input.evidence, { ...input.evidence[0], evidence_id: "MAP-E" }] };
}

function candidate() {
  const input = withPathEvidence(fixture());
  return { ...input, assets: input.assets.map(asset => ({ ...asset, prototype_asset_id: "P-A" })) };
}

test("candidate traces only explicitly scoped directed edges and retains evidence", () => {
  const result = traceFeaturePaths(candidate(), graph, mapping, { max_hops: 3, max_paths_per_decision: 10 });
  assert.equal(result.graph_version, "synthetic-test-only");
  assert.equal(result.records[0].status, "topology_candidate");
  assert.equal(result.records[0].review_status, "pending_review");
  assert.deepEqual(result.records[0].paths, [{
    asset_ids: ["P-A", "P-B", "P-C"], edge_ids: ["E-1", "E-2"],
    reverse_edge_ids: [], hop_count: 2, topology_only: true
  }]);
  assert.deepEqual(result.records[0].evidence_refs, ["FACT-E", "MAP-E", "REVIEW-E"]);
});

test("blocked and unreviewed decisions never produce topology candidates", () => {
  const blockedInput = withPathEvidence(fixture());
  blockedInput.features[0].protections = [fact("strong_mutual_auth", "present")];
  const withMapping = () => ({ ...blockedInput,
    assets: blockedInput.assets.map(asset => ({ ...asset, prototype_asset_id: "P-A" })) });
  assert.equal(traceFeaturePaths(withMapping(), graph, mapping).records[0].status, "decision_not_candidate");
  blockedInput.rules[0].review_status = "TODO_REVIEW";
  assert.equal(traceFeaturePaths(withMapping(), graph, mapping).records[0].status, "decision_not_candidate");
});

test("missing prototype or scope mapping remains unresolved instead of inventing a path", () => {
  assert.equal(traceFeaturePaths(withPathEvidence(fixture()), graph, mapping).records[0].status, "asset_unmapped");
  assert.equal(traceFeaturePaths(candidate(), graph, []).records[0].status, "scope_unmapped");
  const noLocator = structuredClone(candidate());
  noLocator.evidence.find(item => item.evidence_id === "MAP-E")!.review_status = "pending_review";
  assert.equal(traceFeaturePaths(noLocator, graph, mapping).records[0].status, "mapping_evidence_unverified");
});

test("edge direction, hop bound and supplied topology determine the result", () => {
  const original = structuredClone(graph);
  const reverse = { ...graph, asset_edges: graph.asset_edges.map(edge => ({ ...edge, direction: "Bidirectional" as const })) };
  const preview = structuredClone(candidate());
  preview.assets[0].prototype_asset_id = "P-C";
  const reverseMapping = [{ ...mapping[0], target_asset_ids: ["P-A"] }];
  assert.equal(traceFeaturePaths(preview, graph, reverseMapping).records[0].status, "no_path_in_snapshot");
  const found = traceFeaturePaths(preview, reverse, reverseMapping);
  assert.deepEqual(found.records[0].paths[0].asset_ids, ["P-C", "P-B", "P-A"]);
  assert.deepEqual(found.records[0].paths[0].reverse_edge_ids, ["E-2", "E-1"]);
  assert.equal(traceFeaturePaths(candidate(), graph, mapping, { max_hops: 1 }).records[0].status, "search_incomplete");
  assert.deepEqual(graph, original);
});

test("unmapped edge IDs are rejected rather than silently widening scope", () => {
  assert.throws(() => traceFeaturePaths(candidate(), graph, [{ ...mapping[0], allowed_edge_ids: ["MISSING"] }]), /Unknown edge/);
});

test("exhausted search budget never reports that the supplied graph has no path", () => {
  const result = traceFeaturePaths(candidate(), graph, mapping, { max_expansions_per_decision: 1 });
  assert.equal(result.records[0].status, "search_incomplete");
  assert.equal(result.records[0].truncated, true);
  assert.deepEqual(result.records[0].paths, []);
});

test("fully searched disconnected topology can report no path", () => {
  const disconnected = { ...graph, asset_edges: graph.asset_edges.filter(edge => edge.edge_id === "E-1") };
  const disconnectedMapping = [{ ...mapping[0], allowed_edge_ids: ["E-1"] }];
  const result = traceFeaturePaths(candidate(), disconnected, disconnectedMapping, { max_hops: 3 });
  assert.equal(result.records[0].status, "no_path_in_snapshot");
  assert.equal(result.records[0].truncated, false);
});

test("malformed graph fails with a field validation error before traversal", () => {
  const malformed = { graph_version: "v", asset_nodes: [{ asset_id: "P-A" }], asset_edges: [{ edge_id: "E" }] };
  assert.throws(() => traceFeaturePaths(candidate(), malformed as typeof graph, mapping), /source_asset_id/);
});

test("trace records distinguish changed topology and scope mapping under the same version", () => {
  const initial = traceFeaturePaths(candidate(), graph, mapping);
  const changedGraph = structuredClone(graph);
  changedGraph.asset_edges[2].target_asset_id = "P-B";
  const changedMapping = [{ ...mapping[0], allowed_edge_ids: ["E-1"] }];
  assert.notEqual(traceFeaturePaths(candidate(), changedGraph, mapping).graph_sha256, initial.graph_sha256);
  assert.notEqual(traceFeaturePaths(candidate(), graph, changedMapping).mapping_sha256, initial.mapping_sha256);
});

test("path trace reevaluates its bundle so path origin and input hash change together", () => {
  const firstInput = candidate();
  const first = traceFeaturePaths(firstInput, graph, mapping);
  const changedInput = structuredClone(firstInput);
  changedInput.assets[0].prototype_asset_id = "P-C";
  const reverse = { ...graph, asset_edges: graph.asset_edges.map(edge => ({ ...edge, direction: "Bidirectional" as const })) };
  const reverseMapping = [{ ...mapping[0], target_asset_ids: ["P-A"] }];
  const second = traceFeaturePaths(changedInput, reverse, reverseMapping);
  assert.notEqual(second.input_sha256, first.input_sha256);
  assert.equal(second.records[0].prototype_asset_id, "P-C");
  assert.deepEqual(second.records[0].paths[0].asset_ids, ["P-C", "P-B", "P-A"]);
});

test("separate scopes retain separate edge sets when adjacency is reused", () => {
  const input = candidate();
  input.scopes.push({ ...input.scopes[0], scope_id: "SCOPE-2" });
  input.features[0].EXP[0].scope.push("SCOPE-2");
  input.features[0].protections[0].scope.push("SCOPE-2");
  const mappings = [mapping[0], { ...mapping[0], scope_id: "SCOPE-2", allowed_edge_ids: ["E-OUT"] }];
  const result = traceFeaturePaths(input, graph, mappings);
  assert.deepEqual(result.records.map(record => record.scope_id), ["SCOPE", "SCOPE-2"]);
  assert.deepEqual(result.records[0].paths[0].edge_ids, ["E-1", "E-2"]);
  assert.deepEqual(result.records[1].paths[0].edge_ids, ["E-OUT"]);
});
