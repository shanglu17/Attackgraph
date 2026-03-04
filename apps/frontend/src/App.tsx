import { useMemo, useState } from "react";
import { commitChangeSet, getGraph, persistPaths, runAnalysis, validateChangeSet } from "./api";
import type { AttackPath, GraphChangeSet, GraphData } from "./types";

const emptyChangeSet = (version: string): GraphChangeSet => ({
  graphVersion: version,
  assets: { add: [], update: [], delete: [] },
  edges: { add: [], update: [], delete: [] },
  threats: { add: [], update: [], delete: [] }
});

export function App() {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [message, setMessage] = useState("点击“加载图数据”开始");

  const draft = useMemo(() => (graph ? emptyChangeSet(graph.version) : null), [graph]);

  async function handleLoadGraph() {
    try {
      const data = await getGraph();
      setGraph(data);
      setMessage(`已加载图数据，版本 ${data.version}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "加载失败");
    }
  }

  async function handleValidate() {
    if (!draft) {
      return;
    }
    const result = await validateChangeSet(draft);
    setMessage(result.valid ? "Draft 校验通过" : `Draft 校验失败：${result.errors.join("; ")}`);
  }

  async function handleCommit() {
    if (!draft) {
      return;
    }
    const result = await commitChangeSet(draft);
    if (result.committed) {
      setMessage(`提交成功，commitId=${result.commitId}，新版本=${result.newVersion}`);
      await handleLoadGraph();
    } else {
      setMessage(`提交失败：${(result.errors ?? []).join("; ")}`);
    }
  }

  async function handleRunAnalysis() {
    try {
      const result = await runAnalysis();
      setPaths(result.paths);
      setMessage(`分析完成，生成 ${result.count} 条路径`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "分析失败");
    }
  }

  async function handlePersistPaths() {
    if (paths.length === 0) {
      setMessage("没有可持久化的路径");
      return;
    }
    const result = await persistPaths(paths);
    setMessage(`已持久化 ${result.persisted} 条路径`);
  }

  return (
    <div className="layout">
      <aside className="panel left">
        <h3>对象导航与过滤</h3>
        <p>AssetNode: {graph?.assets.length ?? 0}</p>
        <p>ThreatPoint: {graph?.threats.length ?? 0}</p>
        <p>AttackPath: {paths.length}</p>
      </aside>

      <main className="panel center">
        <h3>主图画布（资产拓扑）</h3>
        <div className="toolbar">
          <button onClick={handleLoadGraph}>加载图数据</button>
          <button onClick={handleRunAnalysis}>运行路径推演</button>
          <button onClick={handlePersistPaths}>持久化路径</button>
        </div>
        <div className="list">
          {(graph?.assets ?? []).map((asset) => (
            <div key={asset.assetId} className="item">
              <strong>{asset.name}</strong>
              <span>{asset.assetId}</span>
              <span>{asset.assetType}</span>
            </div>
          ))}
        </div>
      </main>

      <aside className="panel right">
        <h3>审查详情面板</h3>
        <p>{message}</p>
        <div className="list">
          {paths.slice(0, 8).map((path) => (
            <div key={path.pathId} className="item">
              <strong>
                {path.priority} | Score {path.score}
              </strong>
              <span>hop={path.hopCount}</span>
            </div>
          ))}
        </div>
      </aside>

      <footer className="panel bottom">
        <h3>变更与提交面板（Draft ChangeSet）</h3>
        <div className="toolbar">
          <button onClick={handleValidate} disabled={!draft}>
            校验 Draft
          </button>
          <button onClick={handleCommit} disabled={!draft}>
            显式保存提交
          </button>
        </div>
      </footer>
    </div>
  );
}
