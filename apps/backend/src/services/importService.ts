import { z } from "zod";

const singleSheetTemplateSchema = z.array(
  z.object({
    row_type: z.enum(["AssetNode", "AssetEdge", "ThreatPoint", "DO326A_Link"]),
    id: z.string().min(1),
    source_asset_id: z.string().optional(),
    target_asset_id: z.string().optional(),
    related_asset_id: z.string().optional(),
    link_type: z.string().optional(),
    linkage_type: z.string().optional(),
    semantic_element_id: z.string().optional()
  })
);

export class ImportService {
  preview(rows: unknown): {
    accepted: number;
    rejected: number;
    errors: string[];
    summary: { asset_nodes: number; asset_edges: number; threat_points: number; do326a_links: number };
  } {
    const parsed = singleSheetTemplateSchema.safeParse(rows);
    if (!parsed.success) {
      return {
        accepted: 0,
        rejected: Array.isArray(rows) ? rows.length : 0,
        errors: parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`),
        summary: { asset_nodes: 0, asset_edges: 0, threat_points: 0, do326a_links: 0 }
      };
    }

    let asset_nodes = 0;
    let asset_edges = 0;
    let threat_points = 0;
    let do326a_links = 0;
    const errors: string[] = [];

    for (const [index, row] of parsed.data.entries()) {
      if (row.row_type === "AssetNode") {
        asset_nodes += 1;
      }
      if (row.row_type === "AssetEdge") {
        asset_edges += 1;
        if (!row.source_asset_id || !row.target_asset_id) {
          errors.push(`row ${index + 1}: AssetEdge missing source_asset_id/target_asset_id`);
        }
      }
      if (row.row_type === "ThreatPoint") {
        threat_points += 1;
        if (!row.related_asset_id) {
          errors.push(`row ${index + 1}: ThreatPoint missing related_asset_id`);
        }
      }
      if (row.row_type === "DO326A_Link") {
        do326a_links += 1;
        if (!row.linkage_type || !row.semantic_element_id) {
          errors.push(`row ${index + 1}: DO326A_Link missing linkage_type/semantic_element_id`);
        }
      }
    }

    return {
      accepted: parsed.data.length - errors.length,
      rejected: errors.length,
      errors,
      summary: { asset_nodes, asset_edges, threat_points, do326a_links }
    };
  }
}
