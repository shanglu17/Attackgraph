import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  LegacyGlobalWriteQuarantinedError,
  legacyGlobalWriteQuarantineCode,
} from "./legacyWriteQuarantine.js";

describe("legacy global write quarantine", () => {
  it("provides a stable HTTP/CLI error contract", () => {
    const error = new LegacyGlobalWriteQuarantinedError("seed sample");
    assert.equal(error.code, legacyGlobalWriteQuarantineCode);
    assert.equal(error.statusCode, 409);
    assert.match(error.message, /seed sample/);
    assert.match(error.message, /scoped command API/);
  });

  it("keeps destructive seed and clear CLIs disconnected from database writers", async () => {
    for (const relativePath of [
      "../../scripts/seedSample.ts",
      "../../scripts/seedGeneric.ts",
      "../../scripts/clearGraph.ts",
    ]) {
      const source = await readFile(new URL(relativePath, import.meta.url), "utf8");
      assert.match(source, /LegacyGlobalWriteQuarantinedError/);
      assert.doesNotMatch(source, /getDriver|seedSampleData|seedGenericExample|DETACH DELETE/);
    }
  });
});
