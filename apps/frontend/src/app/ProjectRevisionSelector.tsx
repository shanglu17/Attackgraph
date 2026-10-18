import { useRef, useState } from "react";
import { useWorkbench } from "./WorkspaceProvider";
import { useWorkspaceContext } from "./WorkspaceContext";
import { workbenchApi } from "../api";
export function ProjectRevisionSelector() {
  const { choices, state, perform, refreshChoices, refresh } = useWorkbench();
  const scope = useWorkspaceContext();
  const [name, setName] = useState("");
  const [id, setId] = useState("");
  const command = useRef({ key: "", id: "" });
  const projects = choices.filter(
    (c, i) => choices.findIndex((v) => v.project_id === c.project_id) === i,
  );
  return (
    <section className="panel" aria-label="项目与修订">
      <div className="toolbar wrap">
        <label className="field-stack">
          项目
          <select
            aria-label="项目"
            className="input-field"
            value={scope.projectId}
            onChange={(e) => {
              const c = choices.find((c) => c.project_id === e.target.value);
              scope.update({
                projectId: c?.project_id ?? "",
                revisionId: c?.revision_id ?? "",
                baselineId: "",
                profileId: "",
              });
            }}
          >
            <option value="">请选择项目</option>
            {projects.map((c) => (
              <option key={c.project_id} value={c.project_id}>
                {c.project_name}
              </option>
            ))}
          </select>
        </label>
        <label className="field-stack">
          修订
          <select
            aria-label="修订"
            className="input-field"
            value={scope.revisionId}
            onChange={(e) =>
              scope.update({ revisionId: e.target.value, baselineId: "" })
            }
          >
            <option value="">请选择修订</option>
            {choices
              .filter((c) => c.project_id === scope.projectId)
              .map((c) => (
                <option key={c.revision_id} value={c.revision_id}>
                  {c.revision_business_id} · {c.status}
                </option>
              ))}
          </select>
        </label>
        <span className="pill">
          {state.snapshot
            ? `${state.snapshot.status === "Draft" ? "可编辑" : "只读"} · 修订 v${state.snapshot.model.revision_version}`
            : "尚未加载模型"}
        </span>
        <button
          className="button"
          disabled={state.busy}
          onClick={() =>
            void perform(async () => {
              await refreshChoices();
              await refresh();
            })
          }
        >
          刷新服务端数据
        </button>
      </div>
      <details>
        <summary>创建项目与初始修订</summary>
        <div className="toolbar wrap">
          <label className="field-stack">
            项目编号
            <input
              className="input-field"
              value={id}
              onChange={(e) => setId(e.target.value)}
              placeholder="PROJECT-001"
            />
          </label>
          <label className="field-stack">
            项目名称
            <input
              className="input-field"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <button
            className="button"
            disabled={state.busy || !name.trim() || !id.trim()}
            onClick={() =>
              void perform(async () => {
                const key = JSON.stringify([id, name]);
                if (command.current.key !== key)
                  command.current = { key, id: crypto.randomUUID() };
                const result = await workbenchApi.createWorkspace(
                  name,
                  id,
                  command.current.id,
                );
                await refreshChoices();
                scope.update({
                  projectId: result.project.id,
                  revisionId: result.revision.id,
                  profileId: "",
                  baselineId: "",
                });
              })
            }
          >
            创建项目
          </button>
        </div>
      </details>
    </section>
  );
}
