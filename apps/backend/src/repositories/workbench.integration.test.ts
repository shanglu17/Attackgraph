import { test, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createApp } from "../app.js";
import { getDriver, closeDriver } from "../db/neo4j.js";
import { systemModelImportPayloadSchema } from "@attackgraph/contracts";
import { env } from "../config/env.js";
import { WorkbenchService } from "../services/workbenchService.js";
import { savedAnalysisSchema } from "@attackgraph/contracts";

if (process.env.ASTRA_TEST_DATABASE !== "1" || !env.neo4jUri.includes(":17687"))
  throw new Error(
    "Workbench integration requires ASTRA_TEST_DATABASE=1 and independent Neo4j port 17687",
  );
const projects: string[] = [];
const server = createApp({ log: () => {} }).listen(0, "127.0.0.1");
await new Promise<void>((resolve) => server.once("listening", resolve));
const address = server.address();
if (!address || typeof address === "string")
  throw new Error("Missing test server address");
const base = `http://127.0.0.1:${address.port}`;
async function request(path: string, body?: unknown, expected = 200) {
  console.log("request", path.split("?")[0]);
  const response = await fetch(base + path, {
    signal: AbortSignal.timeout(20000),
    ...(body
      ? {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        }
      : {}),
  });
  const result = await response.json();
  assert.equal(response.status, expected, JSON.stringify(result));
  return result;
}
after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (projects.length) {
    const session = getDriver().session();
    try {
      await session.run(
        "MATCH(n) WHERE n.project_id IN $ids OR (n:Project AND n.id IN $ids) DETACH DELETE n",
        { ids: projects },
      );
    } finally {
      await session.close();
    }
  }
  await closeDriver();
});
test("real database: scope → import → edit → saved DPS → replay → stale → freeze", async () => {
  const uid = randomUUID();
  const workspace = await request(
    "/api/v2/governance/workspaces",
    {
      actor: "acceptance",
      command_id: uid,
      project: { business_id: "ACCEPT-" + uid, name: "Workbench acceptance" },
      model: { business_id: "MODEL", name: "System", level: "system" },
      revision: { business_id: "REV-1" },
      standard_profile: {
        business_id: "PROFILE",
        name: "326A/356A",
        profile_version: "1",
        standard_references: ["DO-326A", "DO-356A"],
      },
    },
    201,
  );
  const project_id = workspace.project.id,
    revision_id = workspace.revision.id;
  projects.push(project_id);
  const scope = { project_id, revision_id };
  const invalidInventory=await request("/api/v2/system-model/import/preview",{...scope,contract_version:"inventory-import.v1",conversion_profile:"do356a-ams/v1",file_sha256:"a".repeat(64),inventory:{template_version:"cxf_asset_inventory_v1",source:{aircraft_model:"DO356A-AMS",submitted_by:"acceptance",submitted_at:new Date().toISOString()},workbook:{functional_assets:[],support_assets:[],data_assets:[],interface_assets:[{id:"SI.1",producer:"A",consumer:"B",excel_row:7,source_sheet:"接口资产",enters_internal_propagation:"maybe"}]}}},400);
  assert.equal(invalidInventory.errors[0].sheet,"接口资产");assert.equal(invalidInventory.errors[0].row,7);assert.equal(invalidInventory.errors[0].record_id,"SI.1");
  const query = new URLSearchParams(scope);
  const runQuery=query.toString()+"&view=workbench.v1";
  const list = await request("/api/v2/governance/workspaces");
  assert.ok(
    list.workspaces.some(
      (w: { project_id: string }) => w.project_id === project_id,
    ),
  );
  const payload = systemModelImportPayloadSchema.parse({
    contract_version: "system-model.v2",
    source: {
      business_id: "SRC",
      source_type: "json",
      name: "Fixture",
      content_hash: "a".repeat(64),
      parser_name: "acceptance",
      parser_version: "1",
    },
    entities: {
      assets: [
        {
          business_id: "A",
          name: "External terminal",
          category: "Terminal",
          analysis: { security_domain: "External" },
        },
        {
          business_id: "B",
          name: "Controller",
          category: "Terminal",
          criticality: "High",
          tags: ["controller"],
          analysis: { security_domain: "Internal" },
        },
      ],
      data_flows: [
        {
          business_id: "AB",
          name: "Connection",
          producer_asset_business_id: "A",
          consumer_asset_business_id: "B",
        },
      ],
      draft_threats: [
        {
          business_id: "T",
          name: "Automatic candidate",
          threat_type: "Tampering",
          target_asset_business_id: "A",
          standard_reference: "DO-356A",
        },
      ],
    },
  });
  const imported = await request(
    "/api/v2/system-model/import/commit",
    {
      ...scope,
      actor: "acceptance",
      command_id: uid + "-import",
      expected_revision_version: 1,
      import: payload,
    },
    201,
  );
  assert.equal(imported.new_revision_version, 2);
  let snapshot = await request(`/api/v2/system-model/workbench?${query}`);
  assert.equal(snapshot.graph.asset_nodes.length, 2);
  assert.deepEqual(snapshot.target_ids, ["B"]);
  const edit = {
    ...scope,
    actor: "acceptance",
    command_id: uid + "-edit",
    expected_revision_version: 2,
    contract_version: "model-edit.v1",
    entities: structuredClone(snapshot.model.entities),
    configuration: snapshot.configuration,
  };
  edit.entities.assets[0].name = "Edited terminal";
  const preview = await request("/api/v2/system-model/changes/preview", edit);
  assert.equal(preview.ok, true);
  assert.ok(
    preview.differences.some((d: { field: string }) => d.field === "name"),
  );
  const changed = await request("/api/v2/system-model/changes/commit", edit);
  assert.equal(changed.new_revision_version, 3);
  const auditSession=getDriver().session();try{const audit=await auditSession.run("MATCH(e:AuditEvent {id:$id}) RETURN e.result_json AS payload",{id:changed.audit_event_id});const receipt=JSON.parse(audit.records[0].get("payload"));assert.ok(receipt.differences.some((d:{field:string;before:string;after:string})=>d.field==="name"&&d.before==="External terminal"&&d.after==="Edited terminal"));}finally{await auditSession.close();}
  const replay = await request("/api/v2/system-model/changes/commit", edit);
  assert.equal(replay.replayed, true);
  assert.equal(replay.audit_event_id, changed.audit_event_id);
  await request(
    "/api/v2/system-model/changes/commit",
    { ...edit, command_id: uid + "-stale" },
    409,
  );
  snapshot = await request(`/api/v2/system-model/workbench?${query}`);
  assert.equal(snapshot.model.entities.assets[0].name, "Edited terminal");
  const orphan = structuredClone(edit);
  orphan.command_id = uid + "-orphan";
  orphan.expected_revision_version = 3;
  orphan.entities.assets = orphan.entities.assets.filter(
    (a: { business_id: string }) => a.business_id !== "A",
  );
  assert.equal(
    (await request("/api/v2/system-model/changes/preview", orphan)).ok,
    false,
  );
  await request("/api/v2/system-model/changes/commit", orphan, 409);
  const analysis = {
    ...scope,
    actor: "acceptance",
    command_id: uid + "-run",
    expected_revision_version: 3,
    contract_version: "saved-model-analysis.v1",
    parameters: { max_hops: 3, dps_hop_decay: 0.95 },
  };
  const run = await request("/api/v2/analysis/runs", analysis, 201);
  assert.equal(run.new_revision_version, 4);
  const runReplay = await request("/api/v2/analysis/runs", analysis, 201);
  assert.equal(runReplay.replayed, true);
  assert.equal(runReplay.run_id, run.run_id);
  const runs = await request(`/api/v2/analysis/runs?${runQuery}`);
  const saved = runs.runs.find((r: { id: string }) => r.id === run.run_id);
  assert.equal(saved.stale, false);
  assert.equal(
    saved.results.filter(
      (r: { result_kind: string }) => r.result_kind === "attack_path_candidate",
    ).length,
    1,
  );
  const input = saved.snapshots.find(
    (s: { snapshot_type: string }) => s.snapshot_type === "method_input",
  ).payload;
  assert.equal(saved.input_origin,"saved-model");
  const classic=await request(`/api/v2/analysis/runs?${query}`);assert.equal("input_origin" in classic.runs[0],false);
  assert.equal(input.asset_nodes[0].asset_name, "Edited terminal");
  assert.equal(input.mapping_version, "core-dps/v1");
  const exported = await request("/api/v2/analysis/runs/export", {
    ...scope,
    run_id: run.run_id,
    parameters: analysis.parameters,
  });
  assert.equal(
    exported.snapshot.model.entities.assets[0].name,
    "Edited terminal",
  );
  await request(
    "/api/v2/analysis/runs/export",
    {
      ...scope,
      run_id: run.run_id,
      parameters: { max_hops: 2, dps_hop_decay: 0.95 },
    },
    409,
  );
  await request(
    "/api/v2/analysis/runs",
    { ...analysis, command_id: uid + "-graph", graph: {} },
    400,
  );
  const wrong = { ...scope, revision_id: randomUUID() };
  await request(
    `/api/v2/system-model/workbench?${new URLSearchParams(wrong)}`,
    undefined,
    404,
  );
  snapshot = await request(`/api/v2/system-model/workbench?${query}`);
  const override = {
    ...edit,
    command_id: uid + "-override",
    expected_revision_version: 4,
    entities: snapshot.model.entities,
    configuration: {
      ...snapshot.configuration,
      threat_overrides: {
        T: {
          entry_likelihood_level: "Low",
          attack_complexity_level: "High",
          threat_source: "external",
          stride_category: "Tampering",
          attack_vector: "Network",
        },
      },
    },
  };
  await request("/api/v2/system-model/changes/commit", override);
  assert.equal(
    (await request(`/api/v2/analysis/runs?${runQuery}`)).runs[0].stale,
    true,
  );
  await request(
    "/api/v2/analysis/runs/export",
    { ...scope, run_id: run.run_id, parameters: analysis.parameters },
    409,
  );
  const second = await request(
    "/api/v2/analysis/runs",
    { ...analysis, command_id: uid + "-run-2", expected_revision_version: 5 },
    201,
  );
  assert.equal(second.new_revision_version, 6);
  const failedCommand=savedAnalysisSchema.parse({...analysis,command_id:uid+"-failed",expected_revision_version:6});
  const failureService=new WorkbenchService(async()=>{throw new Error("分析超时，搜索已中止（验收故障注入）");});
  const failure=await failureService.run(failedCommand);
  assert.equal(failure.status,"Failed");
  const failedRun=(await request(`/api/v2/analysis/runs?${runQuery}`)).runs.find((r:{id:string})=>r.id===failure.run_id);
  assert.equal(failedRun.status,"Failed");assert.equal(failedRun.results.filter((r:{result_kind:string})=>r.result_kind==="attack_path_candidate").length,0);
  assert.equal(failedRun.results[0].termination_reason,"execution_error");
  assert.equal((await failureService.run(failedCommand)).replayed,true);
  await request("/api/v2/analysis/runs/export",{...scope,run_id:failure.run_id,parameters:analysis.parameters},409);
  const actual=await request(`/api/v2/system-model/workbench?${query}`);
  const forged=await request("/api/v2/analysis/runs",{...scope,actor:"acceptance",command_id:uid+"-caller-input",expected_revision_version:7,source_record_business_id:"SRC",method_id:"dfs-dps-attack-path",method_version:"1.0.0",method_config_version:"saved-model-analysis.v1",execution_limits:{},method_config:{model_hash:actual.model_hash,parameters:analysis.parameters},method_input:input},201);
  const callerRun=(await request(`/api/v2/analysis/runs?${runQuery}`)).runs.find((r:{id:string})=>r.id===forged.run_id);
  assert.equal(callerRun.input_origin,"caller-provided");
  await request("/api/v2/analysis/runs/export",{...scope,run_id:forged.run_id,parameters:analysis.parameters},409);
  const frozen = await request(
    "/api/v2/governance/revisions/freeze",
    {
      ...scope,
      actor: "acceptance",
      command_id: uid + "-freeze",
      expected_revision_version: 8,
      baseline: { business_id: "BASE-1", content_hash: "b".repeat(64) },
    },
    201,
  );
  assert.ok(frozen);
  await request(
    "/api/v2/system-model/changes/commit",
    { ...override, command_id: uid + "-frozen", expected_revision_version: 9 },
    409,
  );
  assert.notEqual(
    (await request(`/api/v2/system-model/workbench?${query}`)).status,
    "Draft",
  );
});
