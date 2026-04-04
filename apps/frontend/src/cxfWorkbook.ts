import type { WorkBook } from "xlsx";
import type {
  CxfDataAssetRow,
  CxfFunctionalAssetRow,
  CxfImportRequest,
  CxfInterfaceAssetRow,
  CxfSheetName,
  CxfSupportAssetRow
} from "./types";

const templateVersion = "cxf_asset_inventory_v1";
const stopMarkers = ["以下是样例", "填写要求", "填表要求", "注"];

const sheetNames: Record<CxfSheetName, string> = {
  functional_assets: "功能资产",
  interface_assets: "接口资产",
  support_assets: "支持资产",
  data_assets: "数据资产"
};

const sheetHeaders: Record<CxfSheetName, string[]> = {
  functional_assets: ["编号", "功能资产名称", "资产说明"],
  interface_assets: ["接口编号", "产生者", "用户", "数据流描述", "物理接口", "逻辑接口", "网络域", "区域", "目的"],
  support_assets: ["编号", "名称", "交联接口"],
  data_assets: ["编号", "数据名称", "数据类型", "加载描述", "资产说明"]
};

const sheetIdPatterns: Record<CxfSheetName, RegExp> = {
  functional_assets: /^[A-Z]{2,4}\.[A-Z0-9]+$/i,
  interface_assets: /^SI\.\d+$/i,
  support_assets: /^(ASA|SSA)\.\d+$/i,
  data_assets: /^[A-Z]{2,4}\.[A-Z0-9]+$/i
};

let xlsxModule: typeof import("xlsx") | null = null;

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
  xlsxModule ??= await import("xlsx");
  const workbook = xlsxModule.read(await file.arrayBuffer(), {
    type: "array",
    dense: true
  });

  const functionalAssets = parseFunctionalAssets(workbook);
  const interfaceAssets = parseInterfaceAssets(workbook);
  const supportAssets = parseSupportAssets(workbook);
  const dataAssets = parseDataAssets(workbook);

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
        data_assets: dataAssets
      }
    },
    sheet_counts: {
      functional_assets: functionalAssets.length,
      interface_assets: interfaceAssets.length,
      support_assets: supportAssets.length,
      data_assets: dataAssets.length
    }
  };
}

function parseFunctionalAssets(workbook: WorkBook): CxfFunctionalAssetRow[] {
  const rows = readSheetRows(workbook, "functional_assets");
  return rows.map((row, index) =>
    cleanObject<CxfFunctionalAssetRow>({
      id: requiredCell(row, 0, "functional_assets", index + 2, "id"),
      name: requiredCell(row, 1, "functional_assets", index + 2, "name"),
      description: cell(row, 2),
      excel_row: index + 2
    })
  );
}

function parseInterfaceAssets(workbook: WorkBook): CxfInterfaceAssetRow[] {
  const rows = readSheetRows(workbook, "interface_assets");
  return rows.map((row, index) =>
    cleanObject<CxfInterfaceAssetRow>({
      id: requiredCell(row, 0, "interface_assets", index + 2, "id"),
      producer: requiredCell(row, 1, "interface_assets", index + 2, "producer"),
      consumer: requiredCell(row, 2, "interface_assets", index + 2, "consumer"),
      data_flow_description: cell(row, 3),
      physical_interface: cell(row, 4),
      logical_interface: cell(row, 5),
      network_domain: cell(row, 6),
      zone: cell(row, 7),
      purpose: cell(row, 8),
      excel_row: index + 2
    })
  );
}

function parseSupportAssets(workbook: WorkBook): CxfSupportAssetRow[] {
  const rows = readSheetRows(workbook, "support_assets");
  return rows.map((row, index) =>
    cleanObject<CxfSupportAssetRow>({
      id: requiredCell(row, 0, "support_assets", index + 2, "id"),
      name: requiredCell(row, 1, "support_assets", index + 2, "name"),
      linked_interfaces: splitInterfaceRefs(cell(row, 2)),
      excel_row: index + 2
    })
  );
}

function parseDataAssets(workbook: WorkBook): CxfDataAssetRow[] {
  const rows = readSheetRows(workbook, "data_assets");
  return rows.map((row, index) =>
    cleanObject<CxfDataAssetRow>({
      id: requiredCell(row, 0, "data_assets", index + 2, "id"),
      name: requiredCell(row, 1, "data_assets", index + 2, "name"),
      data_type: cell(row, 2),
      load_description: cell(row, 3),
      description: cell(row, 4),
      excel_row: index + 2
    })
  );
}

function readSheetRows(workbook: WorkBook, sheetKey: CxfSheetName): string[][] {
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
      sheetNames[sheetKey],
      1
    );
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
      throw toParseError("Unexpected non-data row encountered before template footer marker.", sheetNames[sheetKey], index + 1);
    }

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
  throw toParseError("Required cell is empty in workbook.", sheetNames[sheet], excelRow, field);
}

function normalizeCell(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  }
  return String(value).trim();
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
