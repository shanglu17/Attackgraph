import { test, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createApp } from "../app.js";
import { getDriver, closeDriver } from "../db/neo4j.js";
import { env } from "../config/env.js";
import { RevisionUnitOfWork, RevisionNotWritableError } from "./revisionUnitOfWork.js";
if(process.env.ASTRA_TEST_DATABASE!=="1"||!env.neo4jUri.includes(":17687"))throw Error("Lifecycle integration requires independent test Neo4j on 17687");
const ids:string[]=[];
const server=createApp({log:()=>{}}).listen(0,"127.0.0.1");
await new Promise<void>(resolve=>server.once("listening",resolve));
const addr=server.address();if(!addr||typeof addr==="string")throw Error("Missing test address");
const base=`http://127.0.0.1:${addr.port}/api/v2`;
async function request(url:string,body?:unknown,status=200){const r=await fetch(base+url,{...(body?{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(15000)});const value=await r.json();assert.equal(r.status,status,JSON.stringify(value));return value;}
after(async()=>{await new Promise<void>(resolve=>server.close(()=>resolve()));const s=getDriver().session();try{await s.run("MATCH(n) WHERE n.project_id IN $ids OR (n:Project AND n.id IN $ids) DETACH DELETE n",{ids});}finally{await s.close();await closeDriver();}});
test("project lifecycle: confirmation, CAS, replay, archive write guard, recycle, restore and scoped audit",async()=>{
  const uid=randomUUID();
  async function create(suffix:string){const r=await request("/governance/workspaces",{actor:"acceptance",command_id:uid+suffix,project:{business_id:uid+suffix,name:"Same visible name"},model:{business_id:"MODEL",name:"Model",level:"system"},revision:{business_id:"REV"},standard_profile:{business_id:"PROFILE",name:"Profile",profile_version:"1",standard_references:["DO-356A"]}},201);ids.push(r.project.id);return r;}
  const a=await create("-a"),b=await create("-b");
  const scope={project_id:a.project.id,revision_id:a.revision.id};
  const action={project_id:a.project.id,expected_project_version:1,actor:"acceptance",command_id:uid+"archive",action:"archive",confirmation:uid+"-a",reason:"归档测试项目"};
  await request("/governance/projects/lifecycle",{...action,confirmation:"wrong"},409);
  const responses=await Promise.all([request("/governance/projects/lifecycle",action),request("/governance/projects/lifecycle",action)]);
  assert.equal(responses.filter(r=>r.replayed).length,1);assert.equal(responses[0].audit_event_id,responses[1].audit_event_id);
  await request("/governance/projects/lifecycle",{...action,reason:"更换原因"},409);
  await request("/governance/projects/lifecycle",{...action,command_id:uid+"old",action:"restore"},409);
  const overview=await request(`/governance/projects/${a.project.id}/overview`);assert.equal(overview.state,"Archived");assert.equal(overview.version,2);
  const uow=new RevisionUnitOfWork();const write={...scope,actor:"acceptance",command_id:uid+"write",expected_revision_version:1,event_type:"LIFECYCLE_TEST_WRITE",request_canonicalizer:"test.lifecycle/v1",summary:"Verify archive write guard",payload:{test:true}};
  await assert.rejects(()=>uow.execute(write,async()=>({ok:true})),RevisionNotWritableError);
  const query=new URLSearchParams(scope).toString();assert.equal((await request("/system-model/workbench?"+query)).status,"Archived");
  await request("/governance/revisions/freeze",{...scope,actor:"acceptance",command_id:uid+"freeze-archived",expected_revision_version:1,baseline:{business_id:"BASE",content_hash:"a".repeat(64)}},409);
  const deleted=await request("/governance/projects/lifecycle",{...action,action:"delete",command_id:uid+"delete",expected_project_version:2});assert.equal(deleted.state,"Deleted");
  assert.equal((await request("/governance/workspaces")).workspaces.some((p:{project_id:string})=>p.project_id===scope.project_id),false);
  const listing=(await request("/governance/workspaces?view=management.v1")).workspaces;
  assert.equal(listing.find((p:{project_id:string})=>p.project_id===scope.project_id).project_state,"Deleted");
  assert.equal(listing.find((p:{project_id:string})=>p.project_id===b.project.id).project_state,"Active");
  await request("/system-model/workbench?"+query,undefined,404);
  await assert.rejects(()=>uow.execute({...write,command_id:uid+"deleted-write"},async()=>({ok:true})),RevisionNotWritableError);
  const restored=await request("/governance/projects/lifecycle",{...action,action:"restore",command_id:uid+"restore",expected_project_version:3});assert.equal(restored.state,"Archived");
  await request("/governance/projects/lifecycle",{...action,action:"restore",command_id:uid+"unarchive",expected_project_version:4});
  assert.equal((await request("/system-model/workbench?"+query)).status,"Draft");
  await uow.execute({...write,command_id:uid+"active-write"},async()=>({ok:true}));
  const frozen=await request("/governance/revisions/freeze",{...scope,actor:"acceptance",command_id:uid+"freeze",expected_revision_version:2,baseline:{business_id:"BASE",content_hash:"b".repeat(64)}},201);assert.ok(frozen);
  await request("/governance/projects/lifecycle",{...action,action:"delete",command_id:uid+"delete-frozen",expected_project_version:5});
  await request("/governance/projects/lifecycle",{...action,action:"restore",command_id:uid+"restore-frozen",expected_project_version:6});
  assert.notEqual((await request("/system-model/workbench?"+query)).status,"Draft");
  const s=getDriver().session();try{const count=await s.run("MATCH(b:Baseline {project_id:$id}) RETURN count(b) AS count",{id:scope.project_id});assert.equal(Number(count.records[0].get("count")),1);const audits=await s.run("MATCH(e:AuditEvent {project_id:$id}) WHERE e.event_type IN ['PROJECT_ARCHIVED','PROJECT_RECYCLED','PROJECT_RESTORED'] RETURN count(e) AS count",{id:scope.project_id});assert.equal(Number(audits.records[0].get("count")),6);}finally{await s.close();}
});
