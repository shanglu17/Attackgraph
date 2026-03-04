import { z } from "zod";

const singleSheetTemplateSchema = z.array(
  z.object({
    rowType: z.enum(["AssetNode", "AssetEdge", "ThreatPoint"]),
    id: z.string().min(1),
    name: z.string().optional(),
    sourceId: z.string().optional(),
    targetId: z.string().optional(),
    relationType: z.string().optional(),
    severityBase: z.number().int().min(1).max(5).optional(),
    mountedAssetId: z.string().optional()
  })
);

export class ImportService {
  preview(rows: unknown): {
    accepted: number;
    rejected: number;
    errors: string[];
    summary: { assets: number; edges: number; threats: number };
  } {
    const parsed = singleSheetTemplateSchema.safeParse(rows);
    if (!parsed.success) {
      return {
        accepted: 0,
        rejected: Array.isArray(rows) ? rows.length : 0,
        errors: parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`),
        summary: { assets: 0, edges: 0, threats: 0 }
      };
    }

    let assets = 0;
    let edges = 0;
    let threats = 0;
    const errors: string[] = [];

    for (const [index, row] of parsed.data.entries()) {
      if (row.rowType === "AssetNode") {
        assets += 1;
      }
      if (row.rowType === "AssetEdge") {
        edges += 1;
        if (!row.sourceId || !row.targetId) {
          errors.push(`第 ${index + 1} 行 AssetEdge 缺失 sourceId/targetId`);
        }
      }
      if (row.rowType === "ThreatPoint") {
        threats += 1;
        if (!row.mountedAssetId) {
          errors.push(`第 ${index + 1} 行 ThreatPoint 缺失 mountedAssetId`);
        }
      }
    }

    return {
      accepted: parsed.data.length - errors.length,
      rejected: errors.length,
      errors,
      summary: { assets, edges, threats }
    };
  }
}
