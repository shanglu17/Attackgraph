import { fullSheetHeaders, sheetNames } from "@attackgraph/contracts";
import type { CxfSheetName } from "../../types";

export async function downloadInventoryTemplate(example?: ArrayBuffer) {
  const xlsx = await import("xlsx");
  const wb = example
    ? xlsx.read(example, { type: "array" })
    : xlsx.utils.book_new();
  if (example) {
    const { normalizeLegacyWorkbook } = await import("../../cxfWorkbook");
    normalizeLegacyWorkbook(wb, xlsx);
  }
  for (const key of Object.keys(sheetNames) as CxfSheetName[]) {
    const name = sheetNames[key];
    const rows = wb.Sheets[name]
      ? xlsx.utils.sheet_to_json<unknown[]>(wb.Sheets[name], {
          header: 1,
          defval: "",
        })
      : [];
    const sheet = xlsx.utils.aoa_to_sheet([
      fullSheetHeaders[key],
      ...rows.slice(1),
    ]);
    sheet["!cols"] = fullSheetHeaders[key].map(() => ({ wch: 24 }));
    if (!wb.Sheets[name]) wb.SheetNames.push(name);
    wb.Sheets[name] = sheet;
  }
  xlsx.writeFile(
    wb,
    example ? "DO356A-系统资产清单-示例.xlsx" : "系统资产清单-空模板.xlsx",
  );
}
