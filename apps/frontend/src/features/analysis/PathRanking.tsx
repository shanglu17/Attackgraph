import { useEffect, useState } from "react";
import type { AttackPath, GraphData } from "../../types";
import { disclaimer } from "../../shared/model/workbench";
export function PathRanking({
  paths,
  graph,
  selected,
  onSelect,
  decay,
  current,
  ran,
  failure,
}: {
  paths: AttackPath[];
  graph: GraphData;
  selected: string;
  onSelect: (id: string) => void;
  decay: number;
  current: boolean;
  ran: boolean;
  failure?: string;
}) {
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [paths[0]?.analysis_batch_id]);
  const item = paths.find((p) => p.path_id === selected) ?? paths[0];
  const name = (id: string) =>
    graph.asset_nodes.find((a) => a.asset_id === id)?.asset_name ??
    graph.threat_points.find((t) => t.threatpoint_id === id)?.name ??
    id;
  if (failure)
    return (
      <aside className="panel">
        <h3>攻击路径运行失败</h3>
        <p role="alert">{failure}</p>
        <p>搜索未完成，本次运行不能用于“无路径”判断或当前成果导出。</p>
      </aside>
    );
  return (
    <aside className="panel">
      <h3>攻击路径排名</h3>
      <p>{disclaimer}</p>
      {!ran ? (
        <p>先检查目标，再运行分析。</p>
      ) : (
        <>
          <p>
            {paths.length} 条路径 · {current ? "当前结果" : "历史结果 / 已过期"}
          </p>
          <p>已完成配置跳数范围内的搜索；未证明全图搜索穷尽。</p>
          {!paths.length ? (
            <p>
              配置跳数与资产范围内未发现路径。请检查连接方向、候选威胁、目标和跳数；这不表示系统不存在攻击路径。
            </p>
          ) : (
            <>
              <div className="workbench-path-list scroll-panel">
                {paths.slice(page * 50, (page + 1) * 50).map((p, i) => (
                  <button
                    key={p.path_id}
                    className={`button ${item?.path_id === p.path_id ? "active" : ""}`}
                    onClick={() => onSelect(p.path_id)}
                  >
                    <strong>
                      #{page * 50 + i + 1} {name(p.target_asset_id)}
                    </strong>
                    <span>
                      {p.hop_count} 跳 · 相对分数{" "}
                      {p.normalized_score.toFixed(3)}
                    </span>
                  </button>
                ))}
              </div>
              <div className="toolbar wrap">
                <button
                  className="button"
                  disabled={!page}
                  onClick={() => setPage(page - 1)}
                >
                  上一页
                </button>
                <span>
                  {page + 1} / {Math.ceil(paths.length / 50)}
                </span>
                <button
                  className="button"
                  disabled={(page + 1) * 50 >= paths.length}
                  onClick={() => setPage(page + 1)}
                >
                  下一页
                </button>
              </div>
              {item && (
                <div className="preview-card">
                  <h4>路径与评分解释</h4>
                  <p>{item.hop_sequence.split(">").map(name).join(" → ")}</p>
                  <p>
                    入口启发值 {item.heuristic_score} × 结构分数{" "}
                    {item.dps_score} = 原始分数 {item.raw_score}
                  </p>
                  <p>
                    逐边因子乘积 × {decay}
                    <sup>跳数 − 1</sup>；按本批次最大原始分数归一化为{" "}
                    {item.normalized_score}。
                  </p>
                  {item.traverses.map((t) => (
                    <p key={t.hop}>
                      第 {t.hop} 跳 → {name(t.asset_id)} · 边因子{" "}
                      {t.edge_factor}
                    </p>
                  ))}
                  <details>
                    <summary>入口因素、逐跳解释与公式版本</summary>
                    <p>{item.score_config_version}</p>
                    {item.explanations.map((e, i) => (
                      <p key={i}>{e}</p>
                    ))}
                  </details>
                </div>
              )}
            </>
          )}
        </>
      )}
    </aside>
  );
}
