import assert from "node:assert/strict";
import express from "express";
import { after, before, describe, it } from "node:test";
import type { AddressInfo } from "node:net";
import { closeDriver, getDriver } from "../db/neo4j.js";
import router from "./index.js";

let server: ReturnType<express.Express["listen"]>;
let baseUrl = "";

async function nodeCount(): Promise<number> {
  const session = getDriver().session();
  try {
    const result = await session.run("MATCH (node) RETURN count(node) AS count");
    return result.records[0].get("count").toNumber();
  } finally {
    await session.close();
  }
}

before(async () => {
  const app = express();
  app.use(express.json());
  app.use(router);
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const statusCode =
      typeof error === "object" && error !== null && "statusCode" in error
        ? Number(error.statusCode)
        : 500;
    res.status(statusCode).json({ message: error instanceof Error ? error.message : String(error) });
  });
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  await closeDriver();
});

describe("P1.6 compatibility HTTP boundary", () => {
  it("projects the registered legacy revision and exposes the resolved scope in headers", async () => {
    const response = await fetch(`${baseUrl}/graph`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-astra-scope-source"), "legacy-default");
    assert.match(response.headers.get("x-astra-project-id") ?? "", /^[0-9a-f-]{36}$/);
    assert.match(response.headers.get("x-astra-revision-id") ?? "", /^[0-9a-f-]{36}$/);
    const body = (await response.json()) as { asset_nodes: unknown[] };
    assert.equal(body.asset_nodes.length, 17);
  });

  it("rejects partial scope instead of guessing the revision", async () => {
    const response = await fetch(`${baseUrl}/graph?project_id=missing-revision`);
    assert.equal(response.status, 400);
    const body = (await response.json()) as { message: string };
    assert.match(body.message, /must be supplied together/);
  });

  it("rejects contradictory header and query scopes", async () => {
    const response = await fetch(`${baseUrl}/graph?project_id=query-project&revision_id=query-revision`, {
      headers: {
        "X-Project-Id": "header-project",
        "X-Revision-Id": "query-revision",
      },
    });
    assert.equal(response.status, 400);
    const body = (await response.json()) as { message: string };
    assert.match(body.message, /conflicts between request header and query parameter/);
  });

  it("quarantines global legacy writes without changing the database", async () => {
    const before = await nodeCount();
    const response = await fetch(`${baseUrl}/admin/seed/sample`, { method: "POST" });
    const afterCount = await nodeCount();
    assert.equal(response.status, 409);
    assert.equal(afterCount, before);
    const body = (await response.json()) as { code: string };
    assert.equal(body.code, "LEGACY_GLOBAL_WRITE_QUARANTINED");
  });
});
