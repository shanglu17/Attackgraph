import { test } from "node:test";
import assert from "node:assert/strict";
import { restoreDraft } from "../src/shared/model/draftPersistence";
import { currentRun } from "../src/shared/model/workbench";
test("draft restoration strips extraneous credentials and checks scope/version shape", () => {
  const saved = {
    project_id: "p",
    revision_id: "r",
    base_version: 2,
    entities: { assets: [] },
    configuration: { mapping_version: "core-dps/v1", threat_overrides: {} },
    apiKey: "must-not-be-restored",
  };
  const restored = restoreDraft(saved, "p", "r");
  assert.equal(restored?.base_version, 2);
  assert.equal("apiKey" in restored!, false);
  assert.equal(restoreDraft(saved, "other", "r"), null);
  assert.equal(restoreDraft({ ...saved, base_version: "2" }, "p", "r"), null);
});
test("current reports require saved model digest, parameters, status and stale flag to agree", () => {
  const parameters = { max_hops: 3, dps_hop_decay: 0.95 };
  const run = {
    status: "Completed", input_origin:"saved-model",
    stale: false,
    method_config_version: "saved-model-analysis.v1",
    snapshots: [
      {
        snapshot_type: "method_config",
        payload: { model_hash: "a", parameters },
      },
    ],
  } as never;
  const model = { model_hash: "a" } as never;
  assert.equal(currentRun(run, model, parameters), true);
  assert.equal(currentRun({...run as object,input_origin:"caller-provided"} as never,model,parameters),false);
  assert.equal(
    currentRun({ ...(run as object), stale: true } as never, model, parameters),
    false,
  );
  assert.equal(
    currentRun(run, { model_hash: "changed" } as never, parameters),
    false,
  );
  assert.equal(currentRun(run, model, { ...parameters, max_hops: 2 }), false);
  assert.equal(
    currentRun(
      { ...(run as object), status: "Failed" } as never,
      model,
      parameters,
    ),
    false,
  );
});
