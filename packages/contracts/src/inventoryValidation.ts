import type { Inventory } from "./inventory.js";
import {
  inventoryFields,
  sheetNames,
  type InventorySheet,
} from "./inventoryFields.js";
export interface InventoryDiagnostic {
  sheet: string;
  row?: number;
  field: string;
  record_id: string;
  message: string;
}
export function validateInventoryRecords(
  inventory: Inventory,
): InventoryDiagnostic[] {
  const diagnostics: InventoryDiagnostic[] = [];
  for (const [sheet, list] of Object.entries(inventory.workbook)) {
    const seen = new Set<string>();
    for (const row of list) {
      const record = row as unknown as Record<string, unknown>;
      const id = row.id.trim().toUpperCase();
      const add = (field: string, message: string) =>
        diagnostics.push({
          sheet: row.source_sheet ?? sheetNames[sheet as InventorySheet],
          row: row.excel_row,
          field,
          record_id: row.id,
          message,
        });
      if (seen.has(id)) add("id", "编号重复，不会覆盖已有记录");
      seen.add(id);
      for (const field of inventoryFields[sheet as InventorySheet]) {
        const value = record[field.key];
        if (value === undefined || value === "") continue;
        if (
          field.enum.length &&
          field.type !== "boolean" &&
          !field.enum.includes(String(value))
        )
          add(
            field.key,
            `非法值 ${String(value)}；允许：${field.enum.join(" / ")}`,
          );
        // Legacy network-domain and function descriptions can be free text. Their
        // AMS interpretation is validated by the versioned converter.
        if (
          field.reference &&
          !["network_domain", "target_function"].includes(field.key)
        ) {
          const values = Array.isArray(value)
            ? value
            : String(value)
                .split(/[,，;；、\s]+/)
                .filter(Boolean);
          const target = inventory.workbook[field.reference as InventorySheet];
          for (const ref of values)
            if (
              !target.some(
                (r) => r.id.toUpperCase() === String(ref).toUpperCase(),
              )
            )
              add(field.key, `引用不存在：${field.reference}:${String(ref)}`);
        }
      }
    }
  }
  return diagnostics;
}
