import { getSystemDisplayName } from "../../config/f3532/systemAliases.js";
import type { GeneratedBusinessPath } from "../../types/domain.js";

/** Builds branch-aware display text. It never invents a node or member not present in the path DTO. */
export class PathExplanationBuilder {
  buildSystemPath(path: GeneratedBusinessPath): string {
    const byBranch = new Map<string, typeof path.route_segments>();
    for (const segment of path.route_segments) {
      const branchId = segment.branch_id ?? "MAIN";
      const bucket = byBranch.get(branchId) ?? [];
      bucket.push(segment);
      byBranch.set(branchId, bucket);
    }
    const branchTexts = Array.from(byBranch.entries())
      .sort(([left], [right]) => left.localeCompare(right, undefined, { numeric: true }))
      .map(([, segments]) => {
        const ordered = [...segments].sort((left, right) => (left.sequence ?? 0) - (right.sequence ?? 0));
        if (ordered.length === 0) return "";
        const nodes = [ordered[0].from_system_id, ...ordered.map((segment) => segment.to_system_id)];
        return nodes.map(getSystemDisplayName).join(" → ");
      })
      .filter(Boolean);
    if (branchTexts.length > 0) return Array.from(new Set(branchTexts)).join("；");
    return path.system_node_ids.map(getSystemDisplayName).join(" → ");
  }
}
