export type AppWorkspace = "analysis" | "imports" | "reports" | "changes";

interface AppWorkspaceNavProps {
  activeWorkspace: AppWorkspace;
  status: string;
  onChange: (workspace: AppWorkspace) => void;
}

const workspaces: Array<{ id: AppWorkspace; label: string; description: string }> = [
  { id: "analysis", label: "图谱分析", description: "查看安全域拓扑并运行攻击路径分析" },
  { id: "imports", label: "数据导入", description: "解析、预览并提交 F3532、CXF 与 FHA 数据" },
  { id: "reports", label: "报告中心", description: "生成、审查并导出合规分析报告" },
  { id: "changes", label: "变更管理", description: "集中编辑、校验并原子提交图谱变更" }
];

export function AppWorkspaceNav({ activeWorkspace, status, onChange }: AppWorkspaceNavProps) {
  return (
    <nav className="workspace-nav" aria-label="主要工作区">
      <div className="workspace-tabs" role="tablist" aria-label="ASTRA 工作区">
        {workspaces.map((workspace) => (
          <button
            key={workspace.id}
            type="button"
            role="tab"
            aria-selected={activeWorkspace === workspace.id}
            className={`workspace-tab ${activeWorkspace === workspace.id ? "active" : ""}`}
            onClick={() => onChange(workspace.id)}
          >
            <span>{workspace.label}</span>
            <small>{workspace.description}</small>
          </button>
        ))}
      </div>
      <div className="workspace-context" aria-live="polite">
        <span className="status-dot" aria-hidden="true" />
        <span>{status}</span>
      </div>
    </nav>
  );
}
