import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as xlsx from "xlsx";
import {
  parseCxfWorkbook,
  fullSheetHeaders,
  sheetNames,
  normalizeLegacyWorkbook,
} from "../src/cxfWorkbook";
import {
  prepareInventory,
  mapCoreModel,
} from "../../backend/src/services/workbenchMapping";
import { CxfImportService } from "../../backend/src/services/cxfImportService";
import { AnalysisService } from "../../backend/src/services/analysisService";
const source = new URL(
  "../../../docs/DO356A_example_filled.xlsx",
  import.meta.url,
);
const file = (wb: xlsx.WorkBook) =>
  new File([xlsx.write(wb, { type: "buffer", bookType: "xlsx" })], "test.xlsx");
const example = async () =>
  xlsx.read(await readFile(source), { type: "buffer" });
const prepare = (
  inventory: Parameters<typeof prepareInventory>[0]["inventory"],
) =>
  prepareInventory({
    project_id: "00000000-0000-4000-8000-000000000001",
    revision_id: "00000000-0000-4000-8000-000000000002",
    contract_version: "inventory-import.v1",
    conversion_profile: "do356a-ams/v1",
    file_sha256: "a".repeat(64),
    inventory,
  });
test("legacy sample preserves physical interface and load description; maps to scoped core", async () => {
  const parsed = await parseCxfWorkbook(file(await example()), "DO356A-AMS");
  assert.deepEqual(
    [
      parsed.sheet_counts.functional_assets,
      parsed.sheet_counts.interface_assets,
      parsed.sheet_counts.support_assets,
      parsed.sheet_counts.data_assets,
    ],
    [7, 9, 8, 14],
  );
  assert.ok(parsed.payload.workbook.interface_assets[0].physical_interface);
  assert.ok(parsed.payload.workbook.data_assets[0].load_description);
  assert.equal(parsed.payload.workbook.interface_assets[0].source_sheet,"接口资产");
  assert.equal(parsed.payload.workbook.interface_assets[0].field_locators?.physical_interface,"E2");
  assert.equal(parsed.payload.workbook.data_assets[0].field_locators?.load_description,"D2");
  const result = prepare(parsed.payload);
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.deepEqual(result.generated_counts, {
    assets: 34,
    edges: 61,
    threats: 46,
  });
  assert.equal(
    result.model?.entities.draft_threats.every((t) => t.status === "Draft"),
    true,
  );
});
test("nine-sheet empty template parses but cannot be committed; missing core Sheet is located", async () => {
  const wb = xlsx.utils.book_new();
  for (const key of Object.keys(sheetNames) as Array<keyof typeof sheetNames>)
    xlsx.utils.book_append_sheet(
      wb,
      xlsx.utils.aoa_to_sheet([fullSheetHeaders[key]]),
      sheetNames[key],
    );
  const result = prepare(
    (await parseCxfWorkbook(file(wb), "DO356A-AMS")).payload,
  );
  assert.equal(result.ok, false);
  delete wb.Sheets["功能资产"];
  wb.SheetNames = wb.SheetNames.filter((s) => s !== "功能资产");
  await assert.rejects(
    parseCxfWorkbook(file(wb), "DO356A-AMS"),
    (e: { sheet?: string }) => e.sheet === "功能资产",
  );
});
test("blank rows keep actual row locations; illegal booleans and duplicate identifiers fail", async () => {
  const wb = await example();
  normalizeLegacyWorkbook(wb, xlsx);
  const rows = xlsx.utils.sheet_to_json<string[]>(wb.Sheets["边界数据流表"], {
    header: 1,
    defval: "",
  });
  rows.splice(1, 0, [], []);
  rows[3][7] = "maybe";
  wb.Sheets["边界数据流表"] = xlsx.utils.aoa_to_sheet(rows);
  await assert.rejects(
    parseCxfWorkbook(file(wb), "DO356A-AMS"),
    (e: { row?: number; field?: string }) =>
      e.row === 4 && e.field === "进入内部传播",
  );
  rows[3][7] = "";
  rows.splice(4, 0, rows[3]);
  wb.Sheets["边界数据流表"] = xlsx.utils.aoa_to_sheet(rows);
  await assert.rejects(
    parseCxfWorkbook(file(wb), "DO356A-AMS"),
    (e: { row?: number; field?: string }) => e.row === 5 && e.field === "id",
  );
});
test("unresolved references retain Sheet, field and real Excel row; unknown aircraft is rejected", async () => {
  const parsed = await parseCxfWorkbook(file(await example()), "DO356A-AMS");
  parsed.payload.workbook.support_assets[0].linked_interfaces = ["SI.999"];
  const result = prepare(parsed.payload);
  assert.equal(result.ok, false);
  assert.ok(result.error_details.some((d) => d.row === 2 && d.field));
  parsed.payload.source.aircraft_model = "Unknown";
  assert.match(prepare(parsed.payload).errors.join(), /适用/);
});
test("real sample core mapping preserves original DPS paths, ordering, scores and explanations", async () => {
  const inventory = (
    await parseCxfWorkbook(file(await example()), "DO356A-AMS")
  ).payload;
  const original = new CxfImportService().prepareChangeSet(
    inventory,
    "fixture",
  ).change_set!;
  const mapped = prepare(inventory);
  assert.ok(mapped.model && mapped.configuration);
  const graph = mapCoreModel(mapped.model, mapped.configuration);
  assert.deepEqual(JSON.parse(JSON.stringify(graph.threat_points)),JSON.parse(JSON.stringify(original.threat_points.add)));
  // Neo4j reads business IDs in order; mapping_order must preserve conversion ordering.
  const input = {
    analysis_batch_id: "regression",
    max_hops: 3,
    dps_hop_decay: 0.95,
    generated_by: "test",
  };
  const service = new AnalysisService();
  const expected = service.run({
    ...input,
    asset_nodes: original.asset_nodes.add,
    asset_edges: original.asset_edges.add,
    threat_points: original.threat_points.add,
  });
  const actual = service.run({ ...input, ...graph });
  const stable = (rows: typeof actual) =>
    rows.map(({ generated_at, ...row }) => row);
  assert.equal(actual.length, 1984);
  assert.deepEqual(stable(actual), stable(expected));
});
test("all nine Sheets persist core records without silently adding DPS edges", async () => {
  const inventory = (
    await parseCxfWorkbook(file(await example()), "DO356A-AMS")
  ).payload;
  inventory.workbook.threat_actors = [
    {
      id: "TA-E-1",
      name: "External actor",
      actor_type: "external",
      excel_row: 4,
    },
  ];
  inventory.workbook.trust_boundaries = [
    { id: "SB1", name: "Boundary", threat_actor_ids: ["TA-E-1"], excel_row: 3 },
  ];
  inventory.workbook.boundary_interfaces = [
    {
      id: "BI01",
      interface_class: "Network",
      access_object: inventory.workbook.support_assets[0].name,
      boundary_id: "SB1",
      excel_row: 5,
    },
  ];
  inventory.workbook.system_data_flows = [
    {
      id: "SDF01",
      producer: inventory.workbook.support_assets[0].name,
      consumer: inventory.workbook.support_assets[1].name,
      excel_row: 6,
    },
  ];
  const result = prepare(inventory);
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.model!.entities.interfaces.length, 1);
  assert.equal(result.model!.entities.external_entities.length, 1);
  assert.equal(result.model!.entities.security_boundaries.length, 1);
  assert.ok(result.model!.entities.functions.length > 0);
  assert.equal(
    result.model!.entities.data_flows.find((f) => f.business_id === "SDF01")
      ?.analysis?.dps_enabled,
    false,
  );
  assert.equal(result.generated_counts.edges, 61);
  inventory.workbook.trust_boundaries.push({
    ...inventory.workbook.trust_boundaries[0],
    excel_row: 9,
  });
  const duplicate = prepare(inventory);
  assert.equal(duplicate.ok, false);
  assert.ok(
    duplicate.error_details.some((e) => e.row === 9 && e.record_id === "SB1"),
  );
});

test("conversion schema failures retain the originating inventory record",async()=>{
  const inventory=(await parseCxfWorkbook(file(await example()),"DO356A-AMS")).payload;
  inventory.workbook.support_assets[0].id="SSA"+"1".repeat(40);
  const result=prepare(inventory);assert.equal(result.ok,false);
  assert.ok(result.error_details.some(d=>d.sheet==="支持资产"&&d.row===2&&d.record_id===inventory.workbook.support_assets[0].id));
});
