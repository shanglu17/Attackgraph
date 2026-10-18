import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { pathToFileURL } from "node:url";
assert.equal(process.env.ASTRA_TEST_DATABASE,"1");
const root=process.env.WORKBENCH_URL??"http://127.0.0.1:15173";
assert.ok(["127.0.0.1","localhost"].includes(new URL(root).hostname));
const output=path.resolve(process.env.WORKBENCH_EVIDENCE??".tmp/workbench-ui");
const verified=JSON.parse(await readFile(path.join(output,"verification.json"),"utf8"));
const scope=verified.results[1];
const modules=process.env.CODEX_BUNDLED_NODE_MODULES??path.join(os.homedir(),".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules");
const {chromium}=await import(pathToFileURL(path.join(modules,"playwright/index.mjs")).href);
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH??"C:/Program Files/Google/Chrome/Application/chrome.exe"});
try{
 const projects=await(await fetch(root+"/api/v2/governance/workspaces")).json();
 const empty=projects.workspaces.find(p=>p.project_name==="Context isolation"&&p.status==="Draft");assert.ok(empty,"Run context acceptance first to create an empty test project");
 const scenarios=[];
 for(const [name,workspace,selection,action] of [["empty_project","imports",empty,null],["saved_graph","analysis",scope,null],["first_excel_read","imports",empty,"excel"],["first_advanced","reports",scope,"advanced"],["first_document_parse","reports",scope,"document"]]){
  const page=await browser.newPage({viewport:{width:1440,height:900}}),requests=[],pending=new Set();
  page.on("requestfinished",r=>{const operation=(async()=>{const response=await r.response();if(!response)return;const size=await r.sizes();requests.push({url:r.url(),type:r.resourceType(),content_encoding:response.headers()["content-encoding"]??"identity",...size});})().finally(()=>pending.delete(operation));pending.add(operation);});
  await page.addInitScript(({workspace,selection})=>{sessionStorage.setItem("astra.workspace-scope.v1",JSON.stringify({projectId:selection.project_id,revisionId:selection.revision_id,profileId:"",baselineId:""}));sessionStorage.setItem("astra.production.workspace",workspace);},{workspace,selection});
  await page.goto(root,{waitUntil:"networkidle"});
  if(name==="saved_graph")await page.locator(".react-flow__node").first().waitFor();
  if(action==="excel"){await page.getByLabel("转换适用范围",{exact:true}).selectOption("DO356A-AMS");await page.getByLabel(/上传 Excel/).setInputFiles(path.join(output,"sample-1280.xlsx"));await page.getByRole("button",{name:"提交保存",exact:true}).waitFor();}
  if(action==="advanced"||action==="document"){await page.getByRole("button",{name:"高级：工程审查与研究工具",exact:true}).click();await page.getByRole("tab",{name:"工程与受控审查",exact:true}).waitFor();}
  if(action==="document"){await page.getByRole("tab",{name:"文档解析",exact:true}).click();await page.getByLabel("选择 FHA DOCX",{exact:true}).setInputFiles(path.join(output,"fha-fixture.docx"));await page.getByText("已解析 1 条 FHA 记录。",{exact:true}).waitFor();}
  await page.waitForLoadState("networkidle");await Promise.all([...pending]);
  const staticRequests=requests.filter(r=>["script","stylesheet","document"].includes(r.type));
  scenarios.push({name,requests,script_wire_bytes:requests.filter(r=>r.type==="script").reduce((n,r)=>n+r.responseBodySize,0),static_wire_bytes:staticRequests.reduce((n,r)=>n+r.responseBodySize,0),api_wire_bytes:requests.filter(r=>r.url.includes("/api/")).reduce((n,r)=>n+r.responseBodySize,0),script_modules:requests.filter(r=>r.type==="script").map(r=>new URL(r.url).pathname)});
  await page.close();
 }
 await writeFile(path.join(output,"cold-loading.json"),JSON.stringify({scenarios},null,2));console.log(JSON.stringify(scenarios.map(({requests,...s})=>s),null,2));
}finally{await browser.close();}
