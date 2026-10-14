import type {
  AnalysisCompleteness,
  AnalysisMethodDefinition,
  AnalysisTermination,
} from "@attackgraph/contracts";
import { z } from "zod";
import { AnalysisService, type AnalysisInput } from "../analysisService.js";
import { F353203GenerationService } from "../f3532/f353203GenerationService.js";
import { evaluateFeatureRules } from "../featureRules/evaluate.js";
import { traceFeaturePaths, type ScopeMapping, type Topology } from "../featureRules/pathTrace.js";
import { analysisDigest } from "./canonicalization.js";

export interface ExecutedResult {
  result_kind: string;
  machine_status: "Experimental" | "Candidate";
  topology_only: boolean;
  completeness: AnalysisCompleteness;
  termination_reason: AnalysisTermination;
  truncated: boolean;
  diagnostics: Array<{ code: string; severity: "info" | "warning" | "error"; message: string }>;
  payload: unknown;
  result_hash: string;
}

export interface MethodExecution {
  results: ExecutedResult[];
  result_summary_hash: string;
  extra_snapshots: Array<{ snapshot_type: "graph" | "mapping"; payload: unknown; content_hash: string }>;
}

const topologyInputSchema = z.object({
  feature_input: z.unknown(),
  graph: z.unknown(),
  mappings: z.array(z.unknown()),
  options: z.object({
    max_hops: z.number().int().positive().optional(),
    max_paths_per_decision: z.number().int().positive().optional(),
    max_expansions_per_decision: z.number().int().positive().optional(),
  }).default({}),
});
const dfsInputSchema = z.object({
  analysis_batch_id: z.string().min(1),
  max_hops: z.number().int().min(1).max(8),
  generated_by: z.string().min(1),
  scope_asset_ids: z.array(z.string()).optional(),
  dps_hop_decay: z.number().min(0.8).max(1).optional(),
  asset_nodes: z.array(z.unknown()),
  asset_edges: z.array(z.unknown()),
  threat_points: z.array(z.unknown()),
});
const f3532InputSchema = z.object({
  facts: z.record(z.unknown()),
  options: z.object({ max_hops: z.number().int().min(1).max(20).optional() }).default({}),
});

function withHash(result: Omit<ExecutedResult, "result_hash">): ExecutedResult {
  return { ...result, result_hash: analysisDigest(result.payload, { omit_volatile: true }) };
}

function summary(results: ExecutedResult[]) {
  return analysisDigest(results.map((item) => ({
    result_kind: item.result_kind,
    machine_status: item.machine_status,
    topology_only: item.topology_only,
    completeness: item.completeness,
    termination_reason: item.termination_reason,
    truncated: item.truncated,
    diagnostics: item.diagnostics,
    payload: item.payload,
  })), { omit_volatile: true });
}

export function executeAnalysisMethod(method: AnalysisMethodDefinition, input: unknown): MethodExecution {
  let results: ExecutedResult[] = [];
  const extraSnapshots: MethodExecution["extra_snapshots"] = [];
  if (method.method_id === "feature-rule-preview") {
    const output = evaluateFeatureRules(input);
    results = output.decisions.map((decision) => withHash({
      result_kind: "feature_decision",
      machine_status: decision.decision.startsWith("candidate") ? "Candidate" : "Experimental",
      topology_only: false, completeness: "complete", termination_reason: "completed", truncated: false,
      diagnostics: decision.reasons.map((message) => ({ code: message, severity: "info" as const, message })),
      payload: decision,
    }));
  } else if (method.method_id === "feature-topology-trace") {
    const parsed = topologyInputSchema.parse(input);
    const output = traceFeaturePaths(
      parsed.feature_input,
      parsed.graph as Topology,
      parsed.mappings as ScopeMapping[],
      parsed.options,
    );
    extraSnapshots.push(
      { snapshot_type: "graph", payload: parsed.graph, content_hash: output.graph_sha256 },
      { snapshot_type: "mapping", payload: parsed.mappings, content_hash: output.mapping_sha256 },
    );
    results = output.records.map((record) => withHash({
      result_kind: record.status === "topology_candidate" ? "topology_candidate" : "search_diagnostic",
      machine_status: record.status === "topology_candidate" ? "Candidate" : "Experimental",
      topology_only: true,
      completeness: record.completeness,
      termination_reason: record.termination_reason,
      truncated: record.truncated,
      diagnostics: record.status === "topology_candidate" ? [] : [{
        code: record.status, severity: record.status === "search_incomplete" ? "warning" : "info", message: record.status,
      }],
      payload: record,
    }));
  } else if (method.method_id === "dfs-dps-attack-path") {
    const parsed = dfsInputSchema.parse(input);
    const output = new AnalysisService().run(parsed as AnalysisInput);
    results = output.map((path) => withHash({
      result_kind: "attack_path_candidate", machine_status: "Candidate", topology_only: false,
      completeness: "partial", termination_reason: "hop_limit", truncated: true,
      diagnostics: [{ code: "legacy_hop_bound", severity: "warning", message: "Legacy DFS cannot yet prove search-space exhaustion." }],
      payload: path,
    }));
  } else if (method.method_id === "f3532-03-deterministic") {
    const parsed = f3532InputSchema.parse(input);
    const output = new F353203GenerationService().generate(parsed.facts as never, { ...parsed.options, mode: "preview" });
    results = output.propagation_paths.paths.map((path) => withHash({
      result_kind: "f3532_path_candidate",
      machine_status: path.status === "CONFIRMED" ? "Candidate" : "Experimental",
      topology_only: false, completeness: "unknown", termination_reason: "completed", truncated: false,
      diagnostics: path.warnings.map((message) => ({ code: "method_warning", severity: "warning" as const, message })),
      payload: path,
    }));
  }
  return { results, result_summary_hash: summary(results), extra_snapshots: extraSnapshots };
}
