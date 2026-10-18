import type {
  StoredAnalysisRun,
  WorkbenchSnapshot,
} from "@attackgraph/contracts";
import {
  runMetadata,
  runPaths,
  disclaimer,
} from "../../shared/model/workbench";
export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export async function exportResult(
  format: "json" | "xlsx",
  snapshot: WorkbenchSnapshot,
  run: StoredAnalysisRun,
) {
  const metadata = runMetadata(run)!;
  const paths = runPaths(run);
  const filename = `ASTRA-${snapshot.model.project_id}-v${run.input_revision_version}-${run.id}`;
  const bundle = {
    contract_version: "workbench-report.v1",
    status: "current",
    disclaimer,
    model: snapshot.model,
    model_hash: snapshot.model_hash,
    configuration: snapshot.configuration,
    run,
    metadata,
  };
  if (format === "json") {
    downloadBlob(
      new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" }),
      filename + ".json",
    );
    return;
  }
  const xlsx = await import("xlsx");
  const workbook = xlsx.utils.book_new();
  const summary = paths.map((p) => ({
    路径: p.path_id,
    入口: p.entry_point_id,
    目标: p.target_asset_id,
    路径序列: p.hop_sequence,
    跳数: p.hop_count,
    相对分数: p.normalized_score,
    原始分数: p.raw_score,
    入口启发值: p.heuristic_score,
    结构分数: p.dps_score,
    说明: disclaimer,
  }));
  const hops = paths.flatMap((p) =>
    p.traverses.map((t) => ({
      路径: p.path_id,
      跳: t.hop,
      连接: t.edge_id,
      资产: t.asset_id,
      边因子: t.edge_factor,
      跳数衰减: metadata.parameters.dps_hop_decay,
    })),
  );
  const explanations = paths.flatMap((p) =>
    p.explanations.map((e) => ({
      路径: p.path_id,
      评分版本: p.score_config_version,
      解释: e,
      说明: disclaimer,
    })),
  );
  const info = Object.entries({
    状态: "当前结果",
    项目: snapshot.model.project_id,
    修订: snapshot.model.revision_id,
    输入版本: run.input_revision_version,
    当前事务版本: snapshot.model.revision_version,
    模型摘要: snapshot.model_hash,
    运行编号: run.id,
    开始时间: run.started_at,
    完成时间: run.completed_at,
    计算毫秒: metadata.calculation_ms,
    映射版本: metadata.mapping_version,
    参数: JSON.stringify(metadata.parameters),
    目标: metadata.target_ids.join("、"),
    搜索范围: "配置跳数范围内；不证明全图穷尽",
    评分说明: disclaimer,
  }).map(([字段, 值]) => ({ 字段, 值 }));
  for (const [name, rows] of [
    ["路径汇总", summary],
    ["逐跳明细", hops],
    ["评分解释", explanations],
    ["运行信息", info],
  ] as Array<[string, Record<string, unknown>[]]>)
    xlsx.utils.book_append_sheet(
      workbook,
      xlsx.utils.json_to_sheet(
        rows.length ? rows : [{ 说明: "配置范围内没有路径；参见运行信息" }],
      ),
      name,
    );
  xlsx.writeFile(workbook, filename + ".xlsx");
}
