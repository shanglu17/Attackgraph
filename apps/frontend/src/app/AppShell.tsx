import { lazy, Suspense } from "react";
import { useWorkbench } from "./WorkspaceProvider";
import { ProjectRevisionSelector } from "./ProjectRevisionSelector";
import { useWorkspaceContext } from "./WorkspaceContext";
const Imports = lazy(() => import("../features/imports/InventoryWorkspace"));
const Analysis = lazy(() => import("../features/analysis/GraphWorkspace"));
const Changes = lazy(() => import("../features/changes/ModelChangesWorkspace"));
const Reports = lazy(() => import("../features/reports/ResultWorkspace"));
const workspaces = [
  { key: "imports", title: "数据导入", step: "01 · 准备清单" },
  { key: "analysis", title: "图谱分析", step: "02 · 检查与分析" },
  { key: "changes", title: "变更管理", step: "03 · 编辑与保存" },
  { key: "reports", title: "报告中心", step: "04 · 解释与导出" },
] as const;
export function AppShell() {
  const { workspace, navigate, state } = useWorkbench();
  const context=useWorkspaceContext();
  return (
    <main className="page">
      <header className="header">
        <div className="brand-block">
          <h1>ASTRA 航空威胁建模</h1>
          <p>选择项目与修订 → 导入清单 → 检查模型 → 编辑保存 → 分析与导出</p>
        </div>
        <span className="pill">正式工作台 · Neo4j 持久化</span>
      </header>
      <ProjectRevisionSelector />
      <nav className="workspace-nav" role="tablist" aria-label="工作区">
        {workspaces.map((w) => (
          <button
            key={w.key}
            role="tab"
            aria-selected={workspace === w.key}
            className={`workspace-tab ${workspace === w.key ? "active" : ""}`}
            onClick={() => navigate(w.key)}
          >
            <strong>{w.title}</strong>
            <small>{w.step}</small>
          </button>
        ))}
      </nav>
      <p role="status" className="status">
        {state.busy ? "正在处理，请稍候…" : state.message}
      </p>
      {state.error && (
        <p className="status workbench-error" role="alert">
          {state.error}
        </p>
      )}
      {state.conflict && (
        <p className="status workbench-warning">
          恢复的草稿基于旧修订版本，已停止保存。请在变更管理比较并处理冲突。
        </p>
      )}
      <div className="workspace-content" key={`${context.projectId}:${context.revisionId}`}>
        <Suspense
          fallback={
            <p className="panel" role="status">
              加载工作区…
            </p>
          }
        >
          {workspace === "imports" && <Imports />}
          {workspace === "analysis" && <Analysis />}
          {workspace === "changes" && <Changes />}
          {workspace === "reports" && <Reports />}
        </Suspense>
      </div>
    </main>
  );
}
