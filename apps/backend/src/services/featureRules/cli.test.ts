import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

test("offline CLI works without a database and reports an unexecuted draft", () => {
  const root = fileURLToPath(new URL("../../../../../", import.meta.url));
  const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/preview-feature-rules.ts",
    "examples/feature-rules/draft-preview.json"], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.executed_count, 0);
  assert.equal(output.decisions[0].decision, "rule_not_executed");
});
