import type {
  AnalysisConfiguration,
  SavedAnalysisCommand,
  StoredAnalysisRun,
  SystemModelImportPayload,
  WorkbenchSnapshot,
} from "@attackgraph/contracts";
import type { GraphData, AttackPath } from "../../types";
export type Workspace = "imports" | "analysis" | "changes" | "reports";
export interface Draft {
  project_id: string;
  revision_id: string;
  base_version: number;
  entities: SystemModelImportPayload["entities"];
  configuration: AnalysisConfiguration;
}
export interface RunMetadata {
  model_hash: string;
  mapping_version: string;
  parameters: SavedAnalysisCommand["parameters"];
  calculation_ms: number;
  path_count: number;
  target_ids: string[];
  disclaimer: string;
  scope: "bounded" | "failed";
  error?: string;
}
export const disclaimer = "用于相对排序的启发式评分，不代表实际攻击成功概率。";
export function runMetadata(run?: StoredAnalysisRun): RunMetadata | undefined {
  if (run?.method_config_version !== "saved-model-analysis.v1" || run.input_origin!=="saved-model")
    return undefined;
  return run.snapshots.find((s) => s.snapshot_type === "method_config")
    ?.payload as RunMetadata | undefined;
}
export function runPaths(run?: StoredAnalysisRun): AttackPath[] {
  return (
    run?.results
      .filter((r) => r.result_kind === "attack_path_candidate")
      .map((r) => r.payload as AttackPath) ?? []
  ).sort((a, b) =>
    a.path_id.localeCompare(b.path_id, undefined, { numeric: true }),
  );
}
export function currentRun(
  run: StoredAnalysisRun | undefined,
  snapshot: WorkbenchSnapshot | null,
  parameters: SavedAnalysisCommand["parameters"],
) {
  const meta = runMetadata(run);
  return (
    !!run &&
    run.status === "Completed" &&
    !run.stale &&
    !!snapshot &&
    meta?.model_hash === snapshot.model_hash &&
    JSON.stringify(meta.parameters) === JSON.stringify(parameters)
  );
}
export function graphData(snapshot: WorkbenchSnapshot): GraphData {
  return {
    ...snapshot.graph,
    graph_version: String(snapshot.model.revision_version),
    do326a_links: [],
  } as GraphData;
}
