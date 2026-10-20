import type { AnalysisConfiguration, SystemModelImportPayload } from "@attackgraph/contracts";

// Inventory conversion and propagation projection are versioned separately.
export const amsPropagationVersion = "do356a-ams-propagation/v2";
export function propagationVersion(mappingVersion: string): string {
  return mappingVersion === "do356a-ams/v1" ? amsPropagationVersion : "core-dps/v1";
}

type Flow = SystemModelImportPayload["entities"]["data_flows"][number];
export function isInferredOwnership(flow: Flow, configuration: AnalysisConfiguration): boolean {
  if (configuration.mapping_version !== "do356a-ams/v1") return false;
  // Only recognize importer-owned records. A similar label on a manually
  // authored flow must never silently disable that flow.
  if (!flow.tags?.includes("auto_generated") || !flow.tags.includes("do356a-ams/v1")) return false;
  if (flow.analysis?.relationship_kind) return flow.analysis.relationship_kind === "data_ownership";
  // Compatibility with persisted v1 imports that predate relationship_kind.
  return (flow.description ?? "").startsWith("Derived data ownership | ");
}

export function propagationProjection(model: Pick<SystemModelImportPayload, "entities">, configuration: AnalysisConfiguration) {
  return {
    version: propagationVersion(configuration.mapping_version),
    excluded_relations: model.entities.data_flows.filter(f => isInferredOwnership(f, configuration)).map(f => ({
      business_id: f.business_id,
      reason: "inferred_ownership_is_not_a_propagation_channel",
    })).sort((a, b) => a.business_id.localeCompare(b.business_id)),
  };
}

export function obsoleteSavedProjection(origin: unknown, mappingVersion: unknown, version: unknown): boolean {
  return origin === "workbench.saved-analysis/v1" && mappingVersion === "do356a-ams/v1" && version !== amsPropagationVersion;
}
