import type { F353203BoundaryFlowRow, F353203GenerationFacts } from "../../types/domain.js";
import { compareNaturalBusinessIds, naturalSortUnique, toDisplayBusinessId } from "./naturalSort.js";

/** First 03 sheet: a deterministic one-BDF-per-row join. No grouping or graph traversal occurs here. */
export class BoundaryFlowReportService {
  build(facts: F353203GenerationFacts): F353203BoundaryFlowRow[] {
    const boundaryById = new Map(facts.trust_boundaries.map((boundary) => [boundary.id, boundary]));
    const interfaceById = new Map(facts.boundary_interfaces.map((item) => [item.id, item]));

    return [...facts.boundary_data_flows]
      .sort((left, right) => compareNaturalBusinessIds(left.id, right.id))
      .map((bdf) => {
        const boundaryIds = naturalSortUnique([
          ...bdf.security_boundary_ids,
          ...bdf.boundary_interface_ids
            .map((interfaceId) => interfaceById.get(interfaceId)?.security_boundary_id ?? "")
            .filter(Boolean)
        ]);
        const warnings = [...bdf.warnings];
        if (bdf.boundary_interface_ids.length === 0) warnings.push(`${bdf.id} 缺少边界接口 BI`);
        for (const interfaceId of bdf.boundary_interface_ids) {
          const boundaryInterface = interfaceById.get(interfaceId);
          if (!boundaryInterface) warnings.push(`${bdf.id} 引用不存在的边界接口 ${interfaceId}`);
          else if (!boundaryInterface.security_boundary_id) warnings.push(`${interfaceId} 缺少安保边界 SB 归属`);
        }
        if (boundaryIds.length === 0) warnings.push(`${bdf.id} 无法确定安保边界`);

        const securityBoundary = boundaryIds
          .map((id) => {
            const name = boundaryById.get(id)?.name;
            return name && name !== id ? `${id} ${name}` : id;
          })
          .join("、");

        return {
          security_boundary: securityBoundary,
          security_boundary_ids: boundaryIds,
          data_flow_type: bdf.data_type,
          boundary_interface_ids: naturalSortUnique(bdf.boundary_interface_ids),
          bdf_id: bdf.id,
          bdf_display: toDisplayBusinessId(bdf.id),
          function_ids: naturalSortUnique(bdf.function_ids),
          function_display: bdf.function_text?.trim() || naturalSortUnique(bdf.function_ids).join("、"),
          direction: bdf.direction,
          continuation_policy: bdf.continuation_policy,
          evidence: [
            ...bdf.evidence,
            {
              type: "BOUNDARY_FLOW_JOIN",
              source_id: bdf.id,
              message: `${bdf.id} 通过 ${bdf.boundary_interface_ids.join("、") || "无 BI"} 关联 ${boundaryIds.join("、") || "无 SB"}`
            }
          ],
          warnings: naturalSortUnique(warnings)
        };
      });
  }
}
