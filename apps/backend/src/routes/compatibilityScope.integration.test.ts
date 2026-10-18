import assert from "node:assert/strict";
import express from "express";
import { after, before, describe, it } from "node:test";
import type { AddressInfo } from "node:net";
import { closeDriver, getDriver } from "../db/neo4j.js";
import router from "./index.js";
import { GovernanceRepository } from "../repositories/governanceRepository.js";
import { randomUUID } from "node:crypto";
let fixtureProjectId:string|undefined;

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
  // A clean acceptance database has no user legacy dataset. Build the exact
  // registered read fixture without enabling any quarantined write endpoint.
  if(process.env.ASTRA_TEST_DATABASE === "1"){
    const session=getDriver().session();
    try {
      const existing=await session.run("MATCH(p:Project {business_id:'legacy-do356a-appendix-d'}) RETURN p.id AS id");
      if(!existing.records.length){
        const workspace=await new GovernanceRepository().createProjectWorkspace({actor:"compatibility-test",command_id:randomUUID(),project:{business_id:"legacy-do356a-appendix-d",name:"Isolated compatibility fixture"},model:{business_id:"appendix-d-ams-model",name:"Fixture",level:"system"},revision:{business_id:"legacy-import-r1"},standard_profile:{business_id:"COMPAT-TEST",name:"Fixture",profile_version:"1",standard_references:["DO-356A"]}});
        fixtureProjectId=workspace.project.id;
        await session.run("UNWIND range(1,17) AS i CREATE (a:AssetNode {id:randomUUID(),project_id:$project_id,revision_id:$revision_id,business_id:'FIX-'+toString(i),asset_id:'FIX-'+toString(i),legacy_id:'FIX-'+toString(i),asset_name:'Fixture '+toString(i),asset_type:'Terminal',criticality:'Medium'})",{project_id:workspace.project.id,revision_id:workspace.revision.id});
      }
    } finally {await session.close();}
  }
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
  if(fixtureProjectId){const session=getDriver().session();try{await session.run("MATCH(n) WHERE n.project_id=$id OR (n:Project AND n.id=$id) DETACH DELETE n",{id:fixtureProjectId});}finally{await session.close();}}
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
