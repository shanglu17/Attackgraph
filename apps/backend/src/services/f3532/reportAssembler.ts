import type { F353203PathRow, GeneratedBusinessPath, TrustBoundaryFact } from "../../types/domain.js";
import { naturalSortUnique } from "./naturalSort.js";
import { PathExplanationBuilder } from "./pathExplanationBuilder.js";

export class F353203ReportAssembler {
  private readonly explanationBuilder = new PathExplanationBuilder();

  assemblePathRows(paths: GeneratedBusinessPath[], boundaries: TrustBoundaryFact[]): F353203PathRow[] {
    const boundaryById = new Map(boundaries.map((boundary) => [boundary.id, boundary.name]));
    return paths.map((path) => ({
      path_id: path.id,
      path_name: path.name,
      data_flow_types: naturalSortUnique(path.data_types),
      origin: path.origin_boundary_ids.length > 0
        ? path.origin_boundary_ids.map((id) => `${id} ${boundaryById.get(id) ?? ""}`.trim()).join("、")
        : path.origin_type === "INTERNAL_FLOW"
          ? "内部数据流"
          : "规则定义内部路径",
      boundary_interface_ids: naturalSortUnique(path.boundary_interface_ids),
      system_interface_ids: naturalSortUnique(path.system_interface_ids),
      bdf_ids: naturalSortUnique(path.bdf_ids),
      sdf_ids: naturalSortUnique(path.sdf_ids),
      function_ids: naturalSortUnique(path.function_ids),
      system_path: this.explanationBuilder.buildSystemPath(path),
      path_description: path.description,
      status: path.status,
      rule_id: path.rule_id,
      route_segments: path.route_segments,
      terminal_system_ids: path.terminal_system_ids,
      evidence: path.evidence,
      warnings: path.warnings
    }));
  }
}
