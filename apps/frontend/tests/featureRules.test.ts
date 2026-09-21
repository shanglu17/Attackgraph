import assert from "node:assert/strict";
import test from "node:test";
import { initialPreviewState, previewReducer, parseBundle, exportPreview, summarizePreview } from "../src/features/featureRules/model";

const result = { executed_count: 0, decisions: [{ decision: "rule_not_executed" }] } as any;
test("changing input invalidates prior results so export cannot use stale decisions", () => {
  const state = previewReducer({ ...initialPreviewState, result, submitted: { old: true } }, { type: "edit", text: "new" });
  assert.equal(state.result, null);
  assert.equal(state.submitted, null);
  assert.throws(() => exportPreview(state));
});
test("invalid JSON and incomplete bundles are rejected before a request", () => {
  assert.throws(() => parseBundle("{"));
  assert.throws(() => parseBundle('{"contract_version":"feature-preview-0.1"}'));
});
test("unexecuted rules are not presented as no threats", () => {
  assert.deepEqual(summarizePreview(result), { executed: 0, candidates: 0, skipped: 1 });
});
test("export contains the submitted input and full result; failure disables export", () => {
  const ready = previewReducer(initialPreviewState, { type: "success", input: { example: true }, result });
  const output = JSON.parse(exportPreview(ready));
  assert.deepEqual(output.input, { example: true });
  assert.deepEqual(output.result, result);
  assert.equal(previewReducer(ready, { type: "error", message: "failed" }).result, null);
});
