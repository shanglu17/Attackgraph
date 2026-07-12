import type { WorkBook } from "xlsx";
import type {
  F3532BoundaryDataFlowRow,
  F3532BoundaryInterfaceRow,
  F3532InputImportRequest,
  F3532SystemDataFlowRow,
  F3532SystemInterfaceRow,
  F3532ThreatActorRow,
  F3532TrustBoundaryRow
} from "./types";

export type F3532SheetName =
  | "boundary_interfaces"
  | "boundary_data_flows"
  | "system_interfaces"
  | "system_data_flows"
  | "threat_actors"
  | "trust_boundaries";

export interface F3532WorkbookParseError {
  kind: "file";
  message: string;
  sheet?: string;
  row?: number;
  field?: string;
}

export interface ParsedF3532Workbook {
  payload: F3532InputImportRequest;
  sheet_counts: Record<F3532SheetName, number>;
}

const templateVersion = "f3532_input_01_02_v1";

const sheetNames: Record<F3532SheetName, string> = {
  boundary_interfaces: "边界接口",
  boundary_data_flows: "边界数据流",
  system_interfaces: "系统间接口",
  system_data_flows: "系统间数据流",
  threat_actors: "威胁主体",
  trust_boundaries: "安保边界"
};

const sheetHeaders: Record<F3532SheetName, string[]> = {
  boundary_interfaces: [
    "编号",
    "接口类别",
    "外部实体",
    "边界接入对象",
    "接入设备",
    "物理互连类型（§6.2.2）",
    "逻辑协议（§6.2.3）",
    "方向性",
    "接口说明",
    "备注"
  ],
  boundary_data_flows: ["编号", "Producer", "Consumer", "Destination", "描述", "类型", "关联功能", "关联的重大失效状态", "备注", "对应边界接口编号"],
  system_interfaces: ["编号", "Producer", "Consumer", "接口类型", "协议", "方向性", "交互数据内容/类型", "备注"],
  system_data_flows: [
    "编号",
    "Producer",
    "Consumer",
    "Destination",
    "内容",
    "类型",
    "关联功能",
    "关联的重大失效状态（精确）",
    "备注",
    "对应系统间接口编号"
  ],
  threat_actors: ["编号", "名称", "类别", "描述"],
  trust_boundaries: ["边界编号", "边界名称", "边界说明", "覆盖域", "相关威胁主体"]
};

let xlsxModule: typeof import("xlsx") | null = null;

export async function parseF3532Workbooks(
  file01: File,
  file02: File,
  aircraftModel: string
): Promise<ParsedF3532Workbook> {
  xlsxModule ??= await import("xlsx");
  const workbook01 = xlsxModule.read(await file01.arrayBuffer(), { type: "array", dense: true });
  const workbook02 = xlsxModule.read(await file02.arrayBuffer(), { type: "array", dense: true });

  const boundaryInterfaces = parseBoundaryInterfaces(workbook01);
  const boundaryDataFlows = parseBoundaryDataFlows(workbook01);
  const systemInterfaces = parseSystemInterfaces(workbook01);
  const systemDataFlows = parseSystemDataFlows(workbook01);
  const threatActors = parseThreatActors(workbook02);
  const trustBoundaries = parseTrustBoundaries(workbook02);

  return {
    payload: {
      template_version: templateVersion,
      source: {
        aircraft_model: aircraftModel.trim() || "F3532-ASTRA",
        file_names: [file01.name, file02.name],
        submitted_by: "frontend-user",
        submitted_at: new Date().toISOString()
      },
      workbook: {
        boundary_interfaces: boundaryInterfaces,
        boundary_data_flows: boundaryDataFlows,
        system_interfaces: systemInterfaces,
        system_data_flows: systemDataFlows,
        threat_actors: threatActors,
        trust_boundaries: trustBoundaries
      }
    },
    sheet_counts: {
      boundary_interfaces: boundaryInterfaces.length,
      boundary_data_flows: boundaryDataFlows.length,
      system_interfaces: systemInterfaces.length,
      system_data_flows: systemDataFlows.length,
      threat_actors: threatActors.length,
      trust_boundaries: trustBoundaries.length
    }
  };
}

function parseBoundaryInterfaces(workbook: WorkBook): F3532BoundaryInterfaceRow[] {
  return readSheetRows(workbook, "boundary_interfaces").map((row, index) =>
    cleanObject<F3532BoundaryInterfaceRow>({
      id: requiredCell(row, 0, "boundary_interfaces", index + 2, "id"),
      interface_class: cell(row, 1),
      external_entity: cell(row, 2),
      access_object: cell(row, 3),
      access_device: cell(row, 4),
      physical_interconnect: cell(row, 5),
      logical_protocol: cell(row, 6),
      direction: cell(row, 7),
      description: cell(row, 8),
      notes: cell(row, 9),
      excel_row: index + 2
    })
  );
}

function parseBoundaryDataFlows(workbook: WorkBook): F3532BoundaryDataFlowRow[] {
  return readSheetRows(workbook, "boundary_data_flows").map((row, index) =>
    cleanObject<F3532BoundaryDataFlowRow>({
      id: requiredCell(row, 0, "boundary_data_flows", index + 2, "id"),
      producer: cell(row, 1),
      consumer: cell(row, 2),
      destination: cell(row, 3),
      description: cell(row, 4),
      data_flow_type: cell(row, 5),
      target_function: cell(row, 6),
      failure_condition: cell(row, 7),
      notes: cell(row, 8),
      boundary_interface_id: cell(row, 9),
      excel_row: index + 2
    })
  );
}

function parseSystemInterfaces(workbook: WorkBook): F3532SystemInterfaceRow[] {
  return readSheetRows(workbook, "system_interfaces").map((row, index) =>
    cleanObject<F3532SystemInterfaceRow>({
      id: requiredCell(row, 0, "system_interfaces", index + 2, "id"),
      producer: cell(row, 1),
      consumer: cell(row, 2),
      interface_type: cell(row, 3),
      protocol: cell(row, 4),
      direction: cell(row, 5),
      content: cell(row, 6),
      notes: cell(row, 7),
      excel_row: index + 2
    })
  );
}

function parseSystemDataFlows(workbook: WorkBook): F3532SystemDataFlowRow[] {
  return readSheetRows(workbook, "system_data_flows").map((row, index) =>
    cleanObject<F3532SystemDataFlowRow>({
      id: requiredCell(row, 0, "system_data_flows", index + 2, "id"),
      producer: cell(row, 1),
      consumer: cell(row, 2),
      destination: cell(row, 3),
      content: cell(row, 4),
      data_flow_type: cell(row, 5),
      target_function: cell(row, 6),
      failure_condition: cell(row, 7),
      notes: cell(row, 8),
      system_interface_id: cell(row, 9),
      excel_row: index + 2
    })
  );
}

function parseThreatActors(workbook: WorkBook): F3532ThreatActorRow[] {
  return readSheetRows(workbook, "threat_actors").map((row, index) =>
    cleanObject<F3532ThreatActorRow>({
      id: requiredCell(row, 0, "threat_actors", index + 2, "id"),
      name: cell(row, 1),
      actor_type: cell(row, 2),
      description: cell(row, 3),
      excel_row: index + 2
    })
  );
}

function parseTrustBoundaries(workbook: WorkBook): F3532TrustBoundaryRow[] {
  return readSheetRows(workbook, "trust_boundaries").map((row, index) =>
    cleanObject<F3532TrustBoundaryRow>({
      boundary_id: requiredCell(row, 0, "trust_boundaries", index + 2, "boundary_id"),
      name: cell(row, 1),
      description: cell(row, 2),
      covered_scope: cell(row, 3),
      threat_actor_refs: cell(row, 4),
      excel_row: index + 2
    })
  );
}

function readSheetRows(workbook: WorkBook, sheetKey: F3532SheetName): string[][] {
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
  const isLegacyBoundaryDataFlow =
    sheetKey === "boundary_data_flows" &&
    headerRow.length >= 9 &&
    expected.slice(0, 7).every((header, index) => headerRow[index] === header) &&
    headerRow[7] === "备注" &&
    headerRow[8] === "对应边界接口编号";
  const isCurrentBoundaryDataFlow =
    sheetKey === "boundary_data_flows" &&
    headerRow.length >= 10 &&
    expected.slice(0, 7).every((header, index) => headerRow[index] === header) &&
    /^关联的重大失效状态/.test(headerRow[7]) &&
    headerRow[8] === "备注" &&
    headerRow[9] === "对应边界接口编号";
  if (
    !isLegacyBoundaryDataFlow &&
    !isCurrentBoundaryDataFlow &&
    (headerRow.length < expected.length || expected.some((header, index) => headerRow[index] !== header))
  ) {
    throw toParseError(`Sheet header mismatch. Expected: ${expected.join(" / ")}`, sheetNames[sheetKey], 1);
  }

  const rows: string[][] = [];
  for (let index = 1; index < matrix.length; index += 1) {
    const row = (matrix[index] ?? []).map((value) => normalizeCell(value));
    if (row.every((value) => value.length === 0)) {
      continue;
    }
    rows.push(isLegacyBoundaryDataFlow ? [...row.slice(0, 7), "", row[7] ?? "", row[8] ?? ""] : row);
  }
  return rows;
}

function cell(row: string[], index: number): string | undefined {
  const value = row[index] ?? "";
  return value.length > 0 ? value : undefined;
}

function requiredCell(row: string[], index: number, sheet: F3532SheetName, excelRow: number, field: string): string {
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

function cleanObject<T extends object>(value: T): T {
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).filter(([, entry]) => entry !== undefined && entry !== "")
  ) as T;
}

function toParseError(message: string, sheet?: string, row?: number, field?: string): F3532WorkbookParseError {
  return { kind: "file", message, sheet, row, field };
}
