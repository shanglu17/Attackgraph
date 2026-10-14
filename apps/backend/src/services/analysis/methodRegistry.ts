import { createHash } from "node:crypto";
import type { AnalysisMethodDefinition, AnalysisMethodId } from "@attackgraph/contracts";

function digest(manifest: Omit<AnalysisMethodDefinition, "implementation_artifact_digest">) {
  return createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
}

function define(input: Omit<AnalysisMethodDefinition, "implementation_artifact_digest">): AnalysisMethodDefinition {
  return { ...input, implementation_artifact_digest: digest(input) };
}

export const analysisMethods: AnalysisMethodDefinition[] = [
  define({
    method_id: "feature-rule-preview", method_version: "0.1.0", name: "Six-dimension feature rule preview",
    maturity: "experimental", availability: "enabled",
    input_contract_version: "feature-preview-0.1", output_contract_version: "feature-preview-result-0.1",
    canonicalizer_id: "feature-rule-set-canonicalizer", canonicalizer_version: "1.0.0",
    supported_result_kinds: ["feature_decision"],
    completeness_rule: "All validated scope/rule pairs are evaluated; this is not a graph search.",
  }),
  define({
    method_id: "feature-topology-trace", method_version: "0.1.0", name: "Evidence-scoped topology candidate trace",
    maturity: "experimental", availability: "enabled",
    input_contract_version: "feature-path-trace-input-0.1", output_contract_version: "feature-path-trace-0.1",
    canonicalizer_id: "topology-trace-canonicalizer", canonicalizer_version: "1.0.0",
    supported_result_kinds: ["topology_candidate", "search_diagnostic"],
    completeness_rule: "Complete only when allowed adjacency is exhausted without any hop/path/expansion limit.",
  }),
  define({
    method_id: "dfs-dps-attack-path", method_version: "1.0.0", name: "Legacy DFS/DPS attack-path scoring adapter",
    maturity: "qualified", availability: "enabled",
    input_contract_version: "dfs-dps-input-1.0", output_contract_version: "attack-path-candidate-1.0",
    canonicalizer_id: "ordered-attack-path-canonicalizer", canonicalizer_version: "1.0.0",
    supported_result_kinds: ["attack_path_candidate"],
    completeness_rule: "Legacy DFS uses a hop bound; results are partial unless a future adapter proves adjacency exhaustion.",
  }),
  define({
    method_id: "f3532-03-deterministic", method_version: "2.0.0", name: "F3532 03 deterministic generation adapter",
    maturity: "qualified", availability: "enabled",
    input_contract_version: "f3532-03-facts-2.0", output_contract_version: "f3532-03-result-2.0",
    canonicalizer_id: "f3532-business-path-canonicalizer", canonicalizer_version: "1.0.0",
    supported_result_kinds: ["f3532_path_candidate"],
    completeness_rule: "Completeness is method-reported and remains unknown when hop-bound diagnostics are unavailable.",
  }),
];

export function getAnalysisMethod(methodId: AnalysisMethodId, methodVersion: string): AnalysisMethodDefinition {
  const method = analysisMethods.find((item) => item.method_id === methodId && item.method_version === methodVersion);
  if (!method) throw new Error("Unknown analysis method/version: " + methodId + "@" + methodVersion);
  if (method.availability !== "enabled") throw new Error("Analysis method is not enabled: " + methodId);
  return method;
}
