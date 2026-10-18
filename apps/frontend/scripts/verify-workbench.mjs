import assert from "node:assert/strict";
import { mkdir, readFile, writeFile, readdir } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import path from "node:path";
import os from "node:os";
import { pathToFileURL } from "node:url";
import * as xlsx from "xlsx";
import JSZip from "jszip";
const modules =
  process.env.CODEX_BUNDLED_NODE_MODULES ??
  path.join(
    os.homedir(),
    ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules",
  );
const { chromium } = await import(
  pathToFileURL(path.join(modules, "playwright/index.mjs")).href
);
const root = process.env.WORKBENCH_URL ?? "http://127.0.0.1:15173";
assert.equal(process.env.ASTRA_TEST_DATABASE,"1","Browser acceptance requires ASTRA_TEST_DATABASE=1 and an independent test backend");
assert.ok(["127.0.0.1","localhost"].includes(new URL(root).hostname),"Acceptance must use a local test service");
const output = path.resolve(
  process.env.WORKBENCH_EVIDENCE ?? ".tmp/workbench-ui",
);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({
  headless: true,
  executablePath:
    process.env.CHROME_PATH ??
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
});
const results = [];
async function coldProbe(viewport,scope,workspace,advanced=false){
  const page=await browser.newPage({viewport});const requests=[];
  page.on("request",r=>{if(r.resourceType()==="script")requests.push(r.url());});
  await page.addInitScript(({scope,workspace})=>{sessionStorage.setItem("astra.workspace-scope.v1",JSON.stringify({projectId:scope.project_id,revisionId:scope.revision_id,profileId:"",baselineId:""}));sessionStorage.setItem("astra.production.workspace",workspace);},{scope,workspace});
  await page.goto(root,{waitUntil:"networkidle"});
  if(workspace==="analysis")await page.locator(".react-flow__node").first().waitFor();
  if(advanced){await page.getByRole("button",{name:"高级：工程审查与研究工具",exact:true}).click();await page.getByRole("tab",{name:"工程与受控审查",exact:true}).waitFor();}
  await page.waitForLoadState("networkidle");const urls=[...new Set(requests)];await page.close();return urls;
}
async function saveDownload(page, button, filename) {
  const pending = page.waitForEvent("download");
  await button.click();
  const d = await pending;
  await d.saveAs(path.join(output, filename));
  return path.join(output, filename);
}
async function fhaFixture(){
  const zip=new JSZip();zip.file("[Content_Types].xml",`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`);
  zip.file("_rels/.rels",`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`);
  const rows=[["序号","飞行阶段","失效状态及其编号","危害等级","最大失效概率"],["1","起飞/巡航","FC1.1 控制失效","II","1e-7"]];
  zip.file("word/document.xml",`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:tbl>${rows.map(row=>`<w:tr>${row.map(value=>`<w:tc><w:p><w:r><w:t>${value}</w:t></w:r></w:p></w:tc>`).join("")}</w:tr>`).join("")}</w:tbl></w:body></w:document>`);
  const filename=path.join(output,"fha-fixture.docx");await writeFile(filename,await zip.generateAsync({type:"nodebuffer"}));return filename;
}
try {
  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 1280, height: 800 },
    { width: 390, height: 844 },
  ]) {
    const page = await browser.newPage({ viewport });
    page.setDefaultTimeout(30000);
    const errors = [],
      requests = [],network=[];
    const sizes=new Set();
    page.on("requestfinished",r=>{if(r.resourceType()!=="script")return;const pending=r.sizes().then(size=>network.push({url:r.url(),...size})).catch(()=>{}).finally(()=>sizes.delete(pending));sizes.add(pending);});
    page.on("pageerror", (e) => {
      errors.push(e.message);
      console.error("browser error", e.message);
    });
    page.on("console", (m) => {
      if (m.type() === "error") {
        errors.push(m.text());
        console.error("console error", m.text());
      }
    });
    page.on("request", (r) => {
      assert.ok(!/\/demo\/|\/admin\/seed|\/graph\/changeset|\/f3532\//i.test(r.url()),"Production must not call Demo, global writes or F3532");
      if (r.resourceType() === "script") requests.push(r.url());
    });
    const phases = {};
    const layouts=[];
    const checkLayout=async(state)=>{const metrics=await page.evaluate(()=>({horizontal_scroll:document.documentElement.scrollWidth>innerWidth,unnamed_buttons:[...document.querySelectorAll("button")].filter(b=>!b.textContent.trim()&&!b.getAttribute("aria-label")).length}));assert.equal(metrics.horizontal_scroll,false,state+" horizontal overflow");assert.equal(metrics.unnamed_buttons,0,state+" unnamed control");layouts.push({state,...metrics});};
    const measure = async (name) => {
      await page.waitForLoadState("networkidle");
      phases[name] = [...new Set(requests)];
    };
    await page.goto(root, { waitUntil: "networkidle" });
    await page.getByText("创建项目与初始修订", { exact: true }).click();
    const id = `UI-${viewport.width}-${Date.now()}`;
    await page.getByLabel("项目编号", { exact: true }).fill(id);
    await page.getByLabel("项目名称", { exact: true }).fill(id);
    await page.getByRole("button", { name: "创建项目", exact: true }).click();
    await page.getByText(/可编辑 · 修订 v1/).waitFor();
    await measure("empty_project");
    assert.ok(
      !requests.some((u) =>
        /xlsx|reactflow|AdvancedTools|AssuranceReview|AnalysisRunWorkbench/.test(
          u,
        ),
      ),
      "empty first screen must stay lazy",
    );
    const sample = await saveDownload(
      page,
      page.getByRole("button", { name: "下载填写示例", exact: true }),
      `sample-${viewport.width}.xlsx`,
    );
    await measure("first_excel");
    await page.getByLabel("转换适用范围",{exact:true}).selectOption("UNCONFIRMED");
    await page.getByLabel(/上传 Excel/).setInputFiles(sample);
    await page.getByText(/当前机型未确认适用性/).first().waitFor();
    assert.equal(await page.getByRole("button",{name:"提交保存",exact:true}).isDisabled(),true);
    await page.getByLabel("转换适用范围",{exact:true}).selectOption("DO356A-AMS");
    await page.getByLabel(/上传 Excel/).setInputFiles(sample);
    await page.getByRole("button", { name: "提交保存", exact: true }).waitFor();
    await checkLayout("import_preview");await page.screenshot({path:path.join(output,`imports-${viewport.width}.png`),fullPage:false});
    await page.getByRole("button", { name: "提交保存", exact: true }).click();
    await page
      .getByRole("button", { name: "检查模型 →", exact: true })
      .waitFor();
    await page.getByRole("button", { name: "检查模型 →", exact: true }).click();
    await page.locator(".react-flow__node").first().waitFor();
    await measure("first_saved_graph");
    const scope=await page.evaluate(()=>{const s=JSON.parse(sessionStorage.getItem("astra.workspace-scope.v1"));return {project_id:s.projectId,revision_id:s.revisionId};});
    phases.first_saved_graph_cold=await coldProbe(viewport,scope,"analysis");
    await page
      .getByRole("button", { name: "运行 DPS 分析", exact: true })
      .click();
    await page.locator(".workbench-path-list .button").first().waitFor();
    await page.locator(".workbench-path-list .button").nth(1).click();
    await page.locator(".workbench-path-edge").first().waitFor();
    await page.locator(".workbench-path-node").first().waitFor();
    await checkLayout("analysis");
    await page.evaluate(()=>scrollTo(0,0));await page.screenshot({
      path: path.join(output, `analysis-${viewport.width}.png`),
      fullPage: false,
    });
    await page.getByRole("tab", { name: /变更管理/ }).click();
    await page.getByRole("button", { name: "开始编辑", exact: true }).click();
    await page
      .getByLabel("编辑类型", { exact: true })
      .selectOption("draft_threats");
    const likelihood = page.getByLabel("入口可能性", { exact: true });
    const editedThreat=await page.getByLabel("对象",{exact:true}).inputValue();
    const value = (await likelihood.inputValue()) === "Low" ? "High" : "Low";
    await likelihood.selectOption(value);
    await page.getByRole("tab", { name: /数据导入/ }).click();
    await page.getByRole("tab", { name: /变更管理/ }).click();
    await page
      .getByLabel("编辑类型", { exact: true })
      .selectOption("draft_threats");
    assert.equal(
      await likelihood.inputValue(),
      value,
      "draft survives workspace switch",
    );
    await page.reload({ waitUntil: "networkidle" });
    await page
      .getByLabel("编辑类型", { exact: true })
      .selectOption("draft_threats");
    assert.equal(
      await likelihood.inputValue(),
      value,
      "draft survives refresh",
    );
    await page.getByRole("button", { name: "服务端校验", exact: true }).click();
    await page
      .getByText("服务端校验通过，可以保存。", { exact: true })
      .waitFor();
    await checkLayout("changes");
    await page.screenshot({
      path: path.join(output, `changes-${viewport.width}.png`),
      fullPage: false,
    });
    await page
      .getByRole("button", { name: "保存到服务端", exact: true })
      .click();
    await page.getByRole("button", { name: "开始编辑", exact: true }).waitFor();
    await page.getByRole("tab", { name: /报告中心/ }).click();
    assert.equal(
      await page
        .getByRole("button", { name: "导出 JSON", exact: true })
        .isDisabled(),
      true,
      "model change invalidates results",
    );
    await page.getByRole("tab", { name: /图谱分析/ }).click();
    await page
      .getByRole("button", { name: "运行 DPS 分析", exact: true })
      .click();
    await page
      .getByText("分析完成。点击排名查看路径高亮与评分解释。", { exact: true })
      .waitFor();
    await page.getByRole("tab", { name: /报告中心/ }).click();
    const jsonFile = await saveDownload(
      page,
      page.getByRole("button", { name: "导出 JSON", exact: true }),
      `result-${viewport.width}.json`,
    );
    const bundle = JSON.parse(await readFile(jsonFile, "utf8"));
    assert.equal(bundle.status, "current");
    assert.equal(bundle.metadata.path_count, 1984);
    assert.ok(bundle.run.snapshots.length >= 3);
    assert.equal(bundle.configuration.threat_overrides[editedThreat].entry_likelihood_level,value);
    const excel = await saveDownload(
      page,
      page.getByRole("button", { name: "导出 Excel", exact: true }),
      `result-${viewport.width}.xlsx`,
    );
    assert.ok((await readFile(excel)).length > 1000);
    const exportedWorkbook=xlsx.read(await readFile(excel),{type:"buffer"});
    assert.deepEqual(exportedWorkbook.SheetNames,["路径汇总","逐跳明细","评分解释","运行信息"]);
    assert.equal(xlsx.utils.sheet_to_json(exportedWorkbook.Sheets["路径汇总"]).length,bundle.metadata.path_count);
    const expectedHops=bundle.run.results.filter(r=>r.result_kind==="attack_path_candidate").reduce((sum,r)=>sum+r.payload.traverses.length,0);
    assert.equal(xlsx.utils.sheet_to_json(exportedWorkbook.Sheets["逐跳明细"]).length,expectedHops);
    assert.ok(JSON.stringify(xlsx.utils.sheet_to_json(exportedWorkbook.Sheets["运行信息"])).includes(bundle.model_hash));
    await checkLayout("reports");
    await page.screenshot({
      path: path.join(output, `reports-${viewport.width}.png`),
      fullPage: false,
    });
    await page
      .getByRole("button", { name: "高级：工程审查与研究工具", exact: true })
      .click();
    await page
      .getByRole("tab", { name: "工程与受控审查", exact: true })
      .waitFor();
    await measure("first_advanced");
    await page.getByLabel("受控审查 API Key（仅在内存中使用）",{exact:true}).fill("acceptance-secret-not-persisted");
    const persisted=await page.evaluate(()=>JSON.stringify([Object.values(localStorage),Object.values(sessionStorage)]));assert.ok(!persisted.includes("acceptance-secret-not-persisted"));
    phases.first_advanced_cold=await coldProbe(viewport,scope,"reports",true);
    if(viewport.width===1440){await page.getByRole("tab",{name:"文档解析",exact:true}).click();await page.getByLabel("选择 FHA DOCX",{exact:true}).setInputFiles(await fhaFixture());await page.getByText("已解析 1 条 FHA 记录。",{exact:true}).waitFor();await measure("first_document_parse");}
    const metrics = await page.evaluate(() => ({
      horizontal_scroll: document.documentElement.scrollWidth > innerWidth,
      unnamed_buttons: [...document.querySelectorAll("button")].filter(
        (b) => !b.textContent.trim() && !b.getAttribute("aria-label"),
      ).length,
      selected_workspaces: document.querySelectorAll(
        '.workspace-tab[aria-selected="true"]',
      ).length,
    }));
    assert.equal(metrics.horizontal_scroll, false);
    assert.equal(metrics.unnamed_buttons, 0);
    assert.equal(metrics.selected_workspaces, 1);
    assert.deepEqual(errors, []);
    await Promise.all([...sizes]);
    results.push({
      viewport,
      project_id: bundle.model.project_id,
      revision_id: bundle.model.revision_id,
      metrics,
      errors,
      phases,
      network,
      layouts,
    });
    await page.close();
  }
  const assets = path.resolve("apps/frontend/dist/assets");
  const build = [];
  for (const name of await readdir(assets)) {
    const b = await readFile(path.join(assets, name));
    build.push({ name, raw: b.length, gzip: gzipSync(b).length });
  }
  for (const result of results)
    result.phase_bytes = Object.fromEntries(
      Object.entries(result.phases).map(([k, urls]) => {
        const files = urls
          .map((u) => build.find((b) => u.endsWith("/" + b.name)))
          .filter(Boolean);
        return [
          k,
          {
            raw: files.reduce((n, f) => n + f.raw, 0),
            gzip: files.reduce((n, f) => n + f.gzip, 0),
            modules: files.map((f) => f.name),
          },
        ];
      }),
    );
  await writeFile(
    path.join(output, "verification.json"),
    JSON.stringify({ ok: true, results, build }, null, 2),
  );
  console.log(
    JSON.stringify(
      { ok: true, viewports: results.map((r) => r.viewport), output },
      null,
      2,
    ),
  );
} finally {
  await browser.close();
}
