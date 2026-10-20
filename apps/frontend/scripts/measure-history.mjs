import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
assert.equal(process.env.ASTRA_TEST_DATABASE,"1");
const root=process.env.WORKBENCH_URL??"http://127.0.0.1:15173";
assert.ok(["127.0.0.1","localhost"].includes(new URL(root).hostname));
const output=path.resolve(process.env.WORKBENCH_EVIDENCE??".tmp/workbench-ui");
const verified=JSON.parse(await readFile(path.join(output,"verification.json"),"utf8"));
const scope=verified.results[1],q=new URLSearchParams({project_id:scope.project_id,revision_id:scope.revision_id}).toString();
async function measure(route){const r=await fetch(root+"/api/v2/analysis/"+route);assert.equal(r.ok,true);const body=await r.text();return {bytes:Buffer.byteLength(body),data:JSON.parse(body)};}
const old=await measure(`runs?${q}&view=workbench.v1`),list=await measure(`runs/summaries?${q}&limit=20`);
assert.ok(list.data.runs.length);const id=list.data.runs[0].id;
const detail=await measure(`runs/detail?${q}&run_id=${id}`),inputs=await measure(`runs/detail?${q}&run_id=${id}&include_inputs=true`);
assert.equal(old.data.runs.length,list.data.runs.length);
const result={measured_at:new Date().toISOString(),project_id:scope.project_id,revision_id:scope.revision_id,run_count:old.data.runs.length,
  same_project_comparison:true,units:"UTF-8 response body bytes; API is not gzip encoded in this local proxy",
  legacy_full_history:old.bytes,paged_summaries:list.bytes,selected_result:detail.bytes,selected_with_inputs:inputs.bytes,
  summary_has_no_results_or_snapshots:list.data.runs.every(r=>!("results" in r)&&!("snapshots" in r)),
  detail_omits_input:!detail.data.run.snapshots.some(s=>s.snapshot_type==="method_input"),
  explicit_inputs_present:inputs.data.run.snapshots.some(s=>s.snapshot_type==="method_input")};
await writeFile(path.join(output,"history-loading.json"),JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
