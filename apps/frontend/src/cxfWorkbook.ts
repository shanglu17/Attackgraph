import type { WorkBook } from "xlsx";
import type {
  CxfBoundaryInterfaceRow,
  CxfDataAssetRow,
  CxfDomainPropertyRow,
  CxfFunctionalAssetRow,
  CxfImportRequest,
  CxfInterfaceAssetRow,
  CxfSheetName,
  CxfSupportAssetRow,
  CxfSystemDataFlowRow,
  CxfThreatActorRow,
  CxfTrustBoundaryRow
} from "./types";
import { assertSafeLocalFile } from "./fileSafety";

const templateVersion = "cxf_asset_inventory_v1";
const rowNumbers = new WeakMap<string[], number>();
const rowSheets = new WeakMap<string[], string>();
const originalSheets = new WeakMap<WorkBook, Record<string,string>>();
const originalColumns = new WeakMap<WorkBook, Record<string,string[]>>();
const rowFieldLocators = new WeakMap<string[], Record<string,string>>();
const stopMarkers = ["以下是样例", "填写要求", "填表要求", "注"];

import { sheetNames, fullSheetHeaders, inventoryFields } from "@attackgraph/contracts";
export { sheetNames, fullSheetHeaders };

// Minimum legacy prefix lengths; every canonical title still comes from the
// shared definition used by templates, help and server validation.
const legacyHeaderLengths:Record<CxfSheetName,number>={functional_assets:3,interface_assets:7,support_assets:3,data_assets:7,domain_properties:5,trust_boundaries:3,threat_actors:3,boundary_interfaces:3,system_data_flows:3};
const sheetHeaders=Object.fromEntries(Object.entries(fullSheetHeaders).map(([key,headers])=>[key,headers.slice(0,legacyHeaderLengths[key as CxfSheetName])])) as Record<CxfSheetName,string[]>;


const sheetIdPatterns: Record<CxfSheetName, RegExp> = {
  functional_assets: /^[A-Z]{2,4}\.?[A-Z0-9]+$/i,
  interface_assets: /^(SI|BI|SD|SDF|ACD|BD|BDF|SSD|ACI)\.?[A-Z0-9]+$/i,
  support_assets: /^(ASA|SSA)\.?\d+$/i,
  data_assets: /^[A-Z]{2,4}\.?[A-Z0-9]+$/i,
  domain_properties: /^D\.?\d+$/i,
  trust_boundaries: /^SB-?[A-Z0-9]+$/i,
  threat_actors: /^TA-?[EI]?-?[A-Z0-9]+$/i,
  boundary_interfaces: /^BI\.?\d+$/i,
  system_data_flows: /^SDF\.?\d+$/i
};

let xlsxModule: typeof import("xlsx") | null = null;

/** Recognized legacy DO-356A headers only; never guess unknown column layouts. */
export function normalizeLegacyWorkbook(workbook: WorkBook, xlsx: typeof import("xlsx")): void {
  const read = (name: string) => xlsx.utils.sheet_to_json<string[]>(workbook.Sheets[name], { header: 1, raw: false, defval: "" });
  const rowsBeforeFooter = (rows: string[][]) => {
    const result: string[][] = [];
    for (const row of rows.slice(1)) {
      if (stopMarkers.some(marker => String(row[0] ?? "").trim().startsWith(marker))) break;
      result.push(row);
    }
    return result;
  };
  if (!workbook.Sheets["边界数据流表"] && workbook.Sheets["接口资产"]) {
    const rows = read("接口资产");
    const legacy = ["接口编号", "产生者", "用户", "数据流描述", "物理接口", "逻辑接口", "网络域", "区域", "目的"];
    if (legacy.every((v, i) => rows[0]?.[i] === v)) {
      originalSheets.set(workbook,{...originalSheets.get(workbook),interface_assets:"接口资产"});
      originalColumns.set(workbook,{...originalColumns.get(workbook),interface_assets:["id","producer","consumer","data_flow_description","physical_interface","logical_interface","network_domain","zone","purpose"]});
      workbook.Sheets["边界数据流表"] = xlsx.utils.aoa_to_sheet([fullSheetHeaders.interface_assets,
        ...rowsBeforeFooter(rows).map(r => [r[0], r[1], r[2], r[3], "", "", "", "", r[4], r[5], r[6], r[7], r[8]])]);
      workbook.SheetNames = workbook.SheetNames.map(name => name === "接口资产" ? "边界数据流表" : name);
      delete workbook.Sheets["接口资产"];
    }
  }
  if (workbook.Sheets["数据资产"]) {
    const rows = read("数据资产");
    if (["编号", "数据名称", "数据类型", "加载描述", "资产说明"].every((v, i) => rows[0]?.[i] === v)) {
      originalColumns.set(workbook,{...originalColumns.get(workbook),data_assets:["id","name","data_type","load_description","description"]});
      workbook.Sheets["数据资产"] = xlsx.utils.aoa_to_sheet([fullSheetHeaders.data_assets,
        ...rowsBeforeFooter(rows).map(r => [r[0], r[1], r[2], "", "", "", r[4], "", r[3]])]);
    }
  }
}

export interface CxfWorkbookParseError {
  kind: "file";
  message: string;
  sheet?: string;
  row?: number;
  field?: string;
}

export interface ParsedCxfWorkbook {
  payload: CxfImportRequest;
  sheet_counts: Record<CxfSheetName, number>;
}

export async function parseCxfWorkbook(file: File, aircraftModel: string): Promise<ParsedCxfWorkbook> {
  assertSafeLocalFile(file, [".xlsx"], 15);
  xlsxModule ??= await import("xlsx");
  const workbook = xlsxModule.read(await file.arrayBuffer(), {
    type: "array",
    dense: true
  });

  normalizeLegacyWorkbook(workbook, xlsxModule);

  const functionalAssets = parseFunctionalAssets(workbook);
  const interfaceAssets = parseInterfaceAssets(workbook);
  const supportAssets = tryParseSheet(workbook, "support_assets", parseSupportAssets);
  const dataAssets = parseDataAssets(workbook);
  const domainProperties = tryParseSheet(workbook, "domain_properties", parseDomainProperties);
  const trustBoundaries = tryParseSheet(workbook, "trust_boundaries", parseTrustBoundaries);
  const threatActors = tryParseSheet(workbook, "threat_actors", parseThreatActors);
  const boundaryInterfaces = tryParseSheet(workbook, "boundary_interfaces", parseBoundaryInterfaces);
  const systemDataFlows = tryParseSheet(workbook, "system_data_flows", parseSystemDataFlows);

  return {
    payload: {
      template_version: templateVersion,
      source: {
        aircraft_model: aircraftModel.trim() || "DO356A-AMS",
        file_name: file.name,
        submitted_by: "frontend-user",
        submitted_at: new Date().toISOString()
      },
      workbook: {
        functional_assets: functionalAssets,
        interface_assets: interfaceAssets,
        support_assets: supportAssets,
        data_assets: dataAssets,
        domain_properties: domainProperties,
        trust_boundaries: trustBoundaries,
        threat_actors: threatActors,
        boundary_interfaces: boundaryInterfaces,
        system_data_flows: systemDataFlows
      }
    },
    sheet_counts: {
      functional_assets: functionalAssets.length,
      interface_assets: interfaceAssets.length,
      support_assets: supportAssets.length,
      data_assets: dataAssets.length,
      domain_properties: domainProperties.length,
      trust_boundaries: trustBoundaries.length,
      threat_actors: threatActors.length,
      boundary_interfaces: boundaryInterfaces.length,
      system_data_flows: systemDataFlows.length
    }
  };
}

function tryParseSheet<T>(
  workbook: WorkBook,
  sheetKey: CxfSheetName,
  parseFn: (wb: WorkBook) => T[]
): T[] {
  const worksheet = workbook.Sheets[sheetNames[sheetKey]];
  if (!worksheet) {
    return [];
  }
  return parseFn(workbook);
}

function parseFunctionalAssets(workbook: WorkBook): CxfFunctionalAssetRow[] {
  const rows = readSheetRows(workbook, "functional_assets");
  return rows.map((row, index) =>
    cleanObject<CxfFunctionalAssetRow>({
      id: requiredCell(row, 0, "functional_assets", rowNumbers.get(row) ?? index + 2, "id"),
      name: requiredCell(row, 1, "functional_assets", rowNumbers.get(row) ?? index + 2, "name"),
      description: cell(row, 2),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseInterfaceAssets(workbook: WorkBook): CxfInterfaceAssetRow[] {
  const rows = readSheetRows(workbook, "interface_assets");
  return rows.map((row, index) =>
    cleanObject<CxfInterfaceAssetRow>({
      id: requiredCell(row, 0, "interface_assets", rowNumbers.get(row) ?? index + 2, "id"),
      producer: requiredCell(row, 1, "interface_assets", rowNumbers.get(row) ?? index + 2, "producer"),
      consumer: requiredCell(row, 2, "interface_assets", rowNumbers.get(row) ?? index + 2, "consumer"),
      data_flow_description: cell(row, 3),
      data_flow_type: cell(row, 4),
      target_function: cell(row, 5),
      boundary_interface_id: cell(row, 6),
      enters_internal_propagation: parseBool(cell(row, 7)),
      physical_interface: cell(row, 8),
      logical_interface: cell(row, 9),
      network_domain: cell(row, 10),
      zone: cell(row, 11),
      purpose: cell(row, 12),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseBoundaryInterfaces(workbook: WorkBook): CxfBoundaryInterfaceRow[] {
  const rows = readSheetRows(workbook, "boundary_interfaces");
  return rows.map((row, index) =>
    cleanObject<CxfBoundaryInterfaceRow>({
      id: requiredCell(row, 0, "boundary_interfaces", rowNumbers.get(row) ?? index + 2, "id"),
      interface_class: cell(row, 1),
      external_entity: cell(row, 2),
      access_object: cell(row, 3),
      physical_interconnect: cell(row, 4),
      logical_protocol: cell(row, 5),
      direction: cell(row, 6),
      boundary_id: cell(row, 7),
      description: cell(row, 8),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseTrustBoundaries(workbook: WorkBook): CxfTrustBoundaryRow[] {
  const rows = readSheetRows(workbook, "trust_boundaries");
  return rows.map((row, index) =>
    cleanObject<CxfTrustBoundaryRow>({
      id: requiredCell(row, 0, "trust_boundaries", rowNumbers.get(row) ?? index + 2, "id"),
      name: requiredCell(row, 1, "trust_boundaries", rowNumbers.get(row) ?? index + 2, "name"),
      description: cell(row, 2),
      covered_domain_ids: splitRefs(cell(row, 3)),
      threat_actor_ids: splitRefs(cell(row, 4)),
      enters_internal_propagation: parseBool(cell(row, 5)),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseThreatActors(workbook: WorkBook): CxfThreatActorRow[] {
  const rows = readSheetRows(workbook, "threat_actors");
  return rows.map((row, index) =>
    cleanObject<CxfThreatActorRow>({
      id: requiredCell(row, 0, "threat_actors", rowNumbers.get(row) ?? index + 2, "id"),
      name: requiredCell(row, 1, "threat_actors", rowNumbers.get(row) ?? index + 2, "name"),
      actor_type: cell(row, 2),
      description: cell(row, 3),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseSystemDataFlows(workbook: WorkBook): CxfSystemDataFlowRow[] {
  const rows = readSheetRows(workbook, "system_data_flows");
  return rows.map((row, index) =>
    cleanObject<CxfSystemDataFlowRow>({
      id: requiredCell(row, 0, "system_data_flows", rowNumbers.get(row) ?? index + 2, "id"),
      producer: cell(row, 1),
      consumer: cell(row, 2),
      content: cell(row, 3),
      data_flow_type: cell(row, 4),
      target_function: cell(row, 5),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseSupportAssets(workbook: WorkBook): CxfSupportAssetRow[] {
  const rows = readSheetRows(workbook, "support_assets");
  return rows.map((row, index) =>
    cleanObject<CxfSupportAssetRow>({
      id: requiredCell(row, 0, "support_assets", rowNumbers.get(row) ?? index + 2, "id"),
      name: requiredCell(row, 1, "support_assets", rowNumbers.get(row) ?? index + 2, "name"),
      linked_interfaces: splitInterfaceRefs(cell(row, 2)),
      security_domain: cell(row, 3),
      criticality: cell(row, 4),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseDataAssets(workbook: WorkBook): CxfDataAssetRow[] {
  const rows = readSheetRows(workbook, "data_assets");
  return rows.map((row, index) =>
    cleanObject<CxfDataAssetRow>({
      id: requiredCell(row, 0, "data_assets", rowNumbers.get(row) ?? index + 2, "id"),
      name: requiredCell(row, 1, "data_assets", rowNumbers.get(row) ?? index + 2, "name"),
      data_type: cell(row, 2),
      data_flow_type: cell(row, 3),
      linked_interfaces: cell(row, 4),
      domain_id: cell(row, 5),
      description: cell(row, 6),
      target_function: cell(row, 7),
      load_description: cell(row, 8),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function parseDomainProperties(workbook: WorkBook): CxfDomainPropertyRow[] {
  const rows = readSheetRows(workbook, "domain_properties");
  return rows.map((row, index) =>
    cleanObject<CxfDomainPropertyRow>({
      id: requiredCell(row, 0, "domain_properties", rowNumbers.get(row) ?? index + 2, "id"),
      name: requiredCell(row, 1, "domain_properties", rowNumbers.get(row) ?? index + 2, "name"),
      trust_level: requiredCell(row, 2, "domain_properties", rowNumbers.get(row) ?? index + 2, "trust_level"),
      security_domain: requiredCell(row, 3, "domain_properties", rowNumbers.get(row) ?? index + 2, "security_domain"),
      description: cell(row, 4),
      source_sheet: rowSheets.get(row),
      field_locators: rowFieldLocators.get(row),
      excel_row: rowNumbers.get(row) ?? index + 2
    })
  );
}

function readSheetRows(workbook: WorkBook, sheetKey: CxfSheetName): string[][] {
  const sourceSheet=originalSheets.get(workbook)?.[sheetKey]??sheetNames[sheetKey];
  const worksheet = workbook.Sheets[sheetNames[sheetKey]];
  if (!worksheet) {
    throw toParseError(`Missing required sheet: ${sheetNames[sheetKey]}`, sheetNames[sheetKey]);
  }
  if (!xlsxModule) {
    throw toParseError("Excel parser module is not loaded.");
  }

  const matrix = xlsxModule.utils.sheet_to_json<string[]>(worksheet, {
    header: 1,
    raw: false,
    defval: ""
  }) as string[][];
  const headerRow = (matrix[0] ?? []).map((value) => normalizeCell(value));
  const expected = sheetHeaders[sheetKey];
  if (headerRow.length < expected.length || expected.some((header, index) => headerRow[index] !== header)) {
    throw toParseError(
      `Sheet header mismatch. Expected: ${expected.join(" / ")}`,
      sourceSheet,
      1
    );
  }

  const extended = fullSheetHeaders[sheetKey];
  for (let col = expected.length; col < extended.length; col++) {
    if (headerRow[col] && headerRow[col] !== extended[col]) throw toParseError(`扩展列标题应为：${extended[col]}`, sourceSheet, 1, extended[col]);
  }
  const rows: string[][] = [];
  for (let index = 1; index < matrix.length; index += 1) {
    const row = (matrix[index] ?? []).map((value) => normalizeCell(value));
    if (row.every((value) => value.length === 0)) {
      continue;
    }

    const firstNonEmpty = row.find((value) => value.length > 0) ?? "";
    if (stopMarkers.some((marker) => firstNonEmpty.startsWith(marker))) {
      break;
    }
    if (!sheetIdPatterns[sheetKey].test(row[0] ?? "")) {
      throw toParseError("Unexpected non-data row encountered before template footer marker.", sourceSheet, index + 1);
    }

    if (rows.some(existing => existing[0] === row[0])) throw toParseError("编号重复", sourceSheet, index + 1, "id");
    const boolColumn = sheetKey === "interface_assets" ? 7 : sheetKey === "trust_boundaries" ? 5 : -1;
    if (boolColumn >= 0 && row[boolColumn] && parseBool(row[boolColumn]) === undefined) throw toParseError("请填写 是/否 或 true/false", sourceSheet, index + 1, extended[boolColumn]);
    rowNumbers.set(row, index + 1);
    rowSheets.set(row,sourceSheet);
    const keys=originalColumns.get(workbook)?.[sheetKey]??inventoryFields[sheetKey].map(f=>f.key);
    rowFieldLocators.set(row,Object.fromEntries(keys.map((key,col)=>[key,`${String.fromCharCode(65+col)}${index+1}`])));
    rows.push(row);
  }

  return rows;
}

function cell(row: string[], index: number): string | undefined {
  const value = row[index] ?? "";
  return value.length > 0 ? value : undefined;
}

function requiredCell(row: string[], index: number, sheet: CxfSheetName, excelRow: number, field: string): string {
  const value = cell(row, index);
  if (value) {
    return value;
  }
  throw toParseError("Required cell is empty in workbook.", rowSheets.get(row)??sheetNames[sheet], excelRow, field);
}

function normalizeCell(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  }
  return String(value).trim();
}

function parseBool(value: string | undefined): boolean | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (["是", "yes", "y", "true", "1", "✓"].includes(normalized)) {
    return true;
  }
  if (["否", "no", "n", "false", "0", "×"].includes(normalized)) {
    return false;
  }
  return undefined;
}

/** Split on list separators only (keeps hyphens/dots), e.g. "TA-E-01;TA-I-01" -> ["TA-E-01","TA-I-01"]. */
function splitRefs(value: string | undefined): string[] | undefined {
  if (!value) {
    return undefined;
  }
  const items = value
    .split(/[,，;；、\s]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return items.length > 0 ? items : undefined;
}

function splitInterfaceRefs(value: string | undefined): string[] | undefined {
  if (!value) {
    return undefined;
  }
  const items = value
    .split(/[^A-Za-z0-9.]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return items.length > 0 ? items : undefined;
}

function cleanObject<T extends object>(value: T): T {
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).filter(([, entry]) => entry !== undefined && entry !== "")
  ) as T;
}

function toParseError(message: string, sheet?: string, row?: number, field?: string): CxfWorkbookParseError {
  return {
    kind: "file",
    message,
    sheet,
    row,
    field
  };
}
