import assert from "node:assert/strict";
import test from "node:test";
import express from "express";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import router from "./index.js";
import { fixture } from "../services/featureRules/testFixture.js";

test("mounted preview returns auditable results and validation failures over HTTP", async t => {
  const app = express();
  app.use(express.json());
  app.use(router);
  const server = app.listen(0, "127.0.0.1");
  t.after(() => new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve())));
  await once(server, "listening");
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (body: unknown) => fetch(`${url}/analysis/feature-rules/preview`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  const good = await post(fixture());
  assert.equal(good.status, 200);
  assert.equal((await good.json()).decisions[0].decision, "candidate");
  const bad = await post({ scenario_id: "missing-contract" });
  assert.equal(bad.status, 400);
  assert.ok((await bad.json()).issues.length > 0);
  const brokenRef = fixture();
  brokenRef.features[0].EXP[0].evidence_refs = ["missing"];
  assert.equal((await post(brokenRef)).status, 400);
});
