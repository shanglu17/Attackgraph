import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fixture } from "./testFixture.js";

test("offline path trace CLI combines the actual evaluator with an explicit topology", () => {
  const root = fileURLToPath(new URL("../../../../../", import.meta.url));
  const dir = mkdtempSync(join(root, ".tmp", "path-trace-test-"));
  const base = fixture();
  const input = { ...base, assets: base.assets.map(asset => ({ ...asset, prototype_asset_id: "P-A" })) };
  const graph = { graph_version: "synthetic-test-only",
    asset_nodes: [{ asset_id: "P-A" }, { asset_id: "P-B" }],
    asset_edges: [{ edge_id: "E-1", source_asset_id: "P-A", target_asset_id: "P-B", direction: "Unidirectional" }] };
  const mapping = [{ scope_id: "SCOPE", allowed_edge_ids: ["E-1"], target_asset_ids: ["P-B"], evidence_refs: ["FACT-E"] }];
  const files = ["bundle.json", "graph.json", "mapping.json"].map(name => join(dir, name));
  try {
    [input, graph, mapping].forEach((data, index) => writeFileSync(files[index], JSON.stringify(data)));
    const run = spawnSync(process.execPath, ["--import", "tsx", "scripts/trace-feature-paths.ts", ...files],
      { cwd: root, encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    const output = JSON.parse(run.stdout);
    assert.equal(output.records[0].status, "topology_candidate");
    assert.deepEqual(output.records[0].paths[0].edge_ids, ["E-1"]);
    assert.equal(output.records[0].edge_evidence_status, "not_supplied_by_graph");
  } finally {
    files.forEach(unlinkSync);
    rmdirSync(dir);
  }
});
