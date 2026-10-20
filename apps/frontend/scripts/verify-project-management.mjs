import assert from "node:assert/strict";
import {readFile,writeFile,mkdir} from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import {pathToFileURL} from "node:url";
assert.equal(process.env.ASTRA_TEST_DATABASE,"1","Use an independent test backend");
const root=process.env.WORKBENCH_URL??"http://127.0.0.1:15173";
assert.ok(["127.0.0.1","localhost"].includes(new URL(root).hostname));
const output=path.resolve(process.env.WORKBENCH_EVIDENCE??".tmp/workbench-ui");
const evidence=JSON.parse(await readFile(path.join(output,"verification.json"),"utf8"));
const scope=evidence.results[1]; // Draft model; context acceptance freezes only the first viewport.
const modules=process.env.CODEX_BUNDLED_NODE_MODULES??path.join(os.homedir(),".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules");
const {chromium}=await import(pathToFileURL(path.join(modules,"playwright/index.mjs")).href);
async function api(route,body){const response=await fetch(root+"/api/v2"+route,body?{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)}:undefined);const value=await response.json();assert.equal(response.ok,true,JSON.stringify(value));return value;}
const uid=crypto.randomUUID(),fixtures=[];
for(const business_id of ["LIFE-A-"+uid,"LIFE-B-"+uid,"PHASE5-IMPACT-DEMO-"+uid]){
  const w=await api("/governance/workspaces",{actor:"acceptance",command_id:business_id,project:{business_id,name:"同名项目验收"},model:{business_id:"MODEL",name:"Model",level:"system"},revision:{business_id:"REV"},standard_profile:{business_id:"PROFILE",name:"Profile",profile_version:"1",standard_references:["DO-356A"]}});
  fixtures.push({id:w.project.id,business_id});
}
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH??"C:/Program Files/Google/Chrome/Application/chrome.exe"});
const results=[];
try{
 for(const viewport of [{width:1440,height:900},{width:1280,height:800},{width:390,height:844}]){
  const before=await api(`/governance/projects/${scope.project_id}/overview`);assert.equal(before.state,"Active");assert.equal(before.assets,34);
  const page=await browser.newPage({viewport});page.setDefaultTimeout(30000);const errors=[],requests=[];
  page.on("pageerror",e=>errors.push(e.message));page.on("console",m=>{if(m.type()==="error")errors.push(m.text());});page.on("request",r=>{if(r.url().includes("/api/"))requests.push(r.url());});
  await page.addInitScript(scope=>{sessionStorage.setItem("astra.workspace-scope.v1",JSON.stringify({projectId:scope.project_id,revisionId:scope.revision_id,baselineId:"",profileId:""}));sessionStorage.setItem("astra.production.workspace","reports");},scope);
  await page.goto(root,{waitUntil:"networkidle"});
  const selector=page.getByLabel("项目",{exact:true});
  assert.equal(await selector.locator(`option[value="${fixtures[2].id}"]`).count(),0);
  const labelA=await selector.locator(`option[value="${fixtures[0].id}"]`).textContent(),labelB=await selector.locator(`option[value="${fixtures[1].id}"]`).textContent();
  assert.notEqual(labelA,labelB);assert.ok(labelA.includes(fixtures[0].business_id));
  await page.getByLabel("项目列表筛选",{exact:true}).selectOption("example");assert.equal(await selector.locator(`option[value="${fixtures[2].id}"]`).count(),1);
  await page.getByLabel("项目列表筛选",{exact:true}).selectOption("user");
  await page.getByText("项目管理（归档、回收站与恢复）",{exact:true}).click();
  await page.getByText(/范围：1 个修订、34 个资产/).waitFor();
  assert.ok((await page.locator(".workbench-identity").textContent()).includes(scope.project_id));
  await page.getByLabel("输入项目编号确认",{exact:true}).fill("WRONG");await page.getByLabel("项目操作原因",{exact:true}).fill("浏览器生命周期验收");
  assert.equal(await page.getByRole("button",{name:"归档项目",exact:true}).isDisabled(),true);
  const confirm=async()=>{await page.getByLabel("输入项目编号确认",{exact:true}).fill(before.business_id);await page.getByLabel("项目操作原因",{exact:true}).fill("浏览器生命周期验收");};
  await confirm();await page.getByRole("button",{name:"归档项目",exact:true}).click();await page.getByText(/只读 · 修订 v/).waitFor();
  await page.getByRole("tab",{name:/图谱分析/}).click();assert.equal(await page.getByRole("button",{name:"运行 DPS 分析",exact:true}).isDisabled(),true);
  await page.getByRole("button",{name:"恢复为活动项目",exact:true}).waitFor();await confirm();await page.getByRole("button",{name:"恢复为活动项目",exact:true}).click();await page.getByText(/可编辑 · 修订 v/).waitFor();
  await page.getByRole("tab",{name:/变更管理/}).click();await page.getByRole("button",{name:"开始编辑",exact:true}).click();await page.getByLabel("名称",{exact:true}).fill("Uncommitted lifecycle draft");
  assert.ok(await page.evaluate(()=>Object.keys(localStorage).some(k=>k.startsWith("astra.production.draft.v1:"))));
  await confirm();await page.getByRole("button",{name:"删除项目（移入回收站）",exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('select[aria-label="项目"]').value==="");
  assert.equal(await page.evaluate(id=>Object.keys(localStorage).some(k=>k.startsWith("astra.production.draft.v1:"+id+":")),scope.project_id),false);
  await page.getByLabel("项目列表筛选",{exact:true}).selectOption("deleted");await selector.selectOption(scope.project_id);
  await page.getByRole("button",{name:"从回收站恢复",exact:true}).waitFor();await page.getByText(/范围：1 个修订、34 个资产/).waitFor();
  await confirm();await page.getByRole("button",{name:"从回收站恢复",exact:true}).click();
  await page.waitForFunction(()=>!document.querySelector('select[aria-label="修订"]').disabled);
  await page.getByLabel("修订",{exact:true}).selectOption(scope.revision_id);await page.getByText(/可编辑 · 修订 v/).waitFor();
  await page.getByRole("tab",{name:/报告中心/}).click();await page.getByRole("button",{name:"导出 JSON",exact:true}).waitFor();
  await page.waitForFunction(()=>!Array.from(document.querySelectorAll("button")).find(b=>b.textContent.trim()==="导出 JSON").disabled);
  assert.ok(requests.some(u=>u.includes("/runs/summaries?")));assert.ok(requests.some(u=>u.includes("/runs/detail?")));assert.ok(!requests.some(u=>/\/analysis\/runs\?/.test(u)));
  // Switching runs must reset a path selection from the previous run.
  const runs=await page.getByLabel("查看运行",{exact:true}).locator("option").evaluateAll(options=>options.map(o=>o.value));
  assert.ok(runs.length>=2);
  await page.getByRole("tab",{name:/图谱分析/}).click();await page.locator(".workbench-path-list button").nth(1).click();
  await page.getByRole("tab",{name:/报告中心/}).click();
  const older=page.waitForResponse(r=>r.url().includes("/runs/detail?")&&r.url().includes("run_id="+runs[1]));
  await page.getByLabel("查看运行",{exact:true}).selectOption(runs[1]);assert.equal((await older).ok(),true);
  await page.waitForFunction(scope=>JSON.parse(sessionStorage.getItem("astra.production.ui:"+scope.project_id+":"+scope.revision_id)).selectedPath==="",scope);
  await page.getByLabel("查看运行",{exact:true}).selectOption(runs[0]);
  await page.waitForFunction(()=>!Array.from(document.querySelectorAll("button")).find(b=>b.textContent.trim()==="导出 JSON").disabled);
  const details=page.getByText("查看此运行的输入快照、评分和诊断（历史保留）",{exact:true});await details.click();
  const fullInput=page.waitForResponse(r=>r.url().includes("/runs/detail?")&&r.url().includes("include_inputs=true"));await page.getByRole("button",{name:"加载完整输入快照",exact:true}).click();assert.equal((await fullInput).ok(),true);
  await details.click();await page.waitForLoadState("networkidle");
  const after=await api(`/governance/projects/${scope.project_id}/overview`);assert.equal(after.state,"Active");assert.equal(after.assets,before.assets);assert.equal(after.runs,before.runs);
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);assert.equal(overflow,false);assert.deepEqual(errors,[]);
  await page.screenshot({path:path.join(output,`project-management-${viewport.width}.png`),fullPage:true});
  results.push({viewport,archive_readonly:true,recycle_restore:true,local_draft_removed:true,data_retained:true,duplicate_labels_distinguished:true,examples_filtered:true,input_snapshot_on_demand:true,run_selection_resets_path:true,horizontal_scroll:overflow,errors});await page.close();
 }
 // External deletion is detected by a normal refresh and clears a stale saved selection.
 const other=await browser.newPage({viewport:{width:1280,height:800}});
 await other.addInitScript(p=>{sessionStorage.setItem("astra.workspace-scope.v1",JSON.stringify({projectId:p.id,revisionId:p.revision_id,baselineId:"",profileId:""}));}, {...fixtures[0],revision_id:(await api("/governance/workspaces?view=management.v1")).workspaces.find(p=>p.project_id===fixtures[0].id).revision_id});
 await other.goto(root,{waitUntil:"networkidle"});
 const fresh=await api(`/governance/projects/${fixtures[0].id}/overview`);
 await api("/governance/projects/lifecycle",{project_id:fresh.project_id,expected_project_version:fresh.version,actor:"acceptance",command_id:crypto.randomUUID(),action:"delete",confirmation:fresh.business_id,reason:"验证另一客户端删除后的刷新"});
 await other.getByRole("button",{name:"刷新服务端数据",exact:true}).click();
 await other.waitForFunction(()=>document.querySelector('select[aria-label="项目"]').value==="");await other.close();
 await mkdir(output,{recursive:true});await writeFile(path.join(output,"project-management.json"),JSON.stringify({ok:true,external_deletion_refresh:true,results},null,2));console.log(JSON.stringify({ok:true,viewports:results.length}));
}finally{
 await browser.close();
 for(const p of fixtures){const overview=await api(`/governance/projects/${p.id}/overview`);if(overview.state!=="Deleted")await api("/governance/projects/lifecycle",{project_id:p.id,expected_project_version:overview.version,actor:"acceptance",command_id:crypto.randomUUID(),action:"delete",confirmation:p.business_id,reason:"完成浏览器验收，回收测试项目"});}
}
