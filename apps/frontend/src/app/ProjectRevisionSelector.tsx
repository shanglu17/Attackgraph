import { ProjectManagement } from "./ProjectManagement";
import { matchesProjectFilter, projectLabel, type ProjectFilter } from "../shared/model/projectChoices";
import { useRef, useState } from "react";
import { useWorkbench } from "./WorkspaceProvider";
import { useWorkspaceContext } from "./WorkspaceContext";
import { workbenchApi } from "../api";
export function ProjectRevisionSelector() {
  const { choices, state, perform, refreshChoices, refresh } = useWorkbench();
  const scope = useWorkspaceContext();
  const [filter,setFilter]=useState<ProjectFilter>(()=>{try{const v=sessionStorage.getItem("astra.production.project-filter");return ["user","example","archived","deleted","all"].includes(v??"")?v as ProjectFilter:"user";}catch{return "user";}});
  const [name, setName] = useState("");
  const [id, setId] = useState("");
  const command = useRef({ key: "", id: "" });
  const projects = choices.filter(
    (c, i) => choices.findIndex((v) => v.project_id === c.project_id) === i,
  );
  const selectedProject=choices.find(p=>p.project_id===scope.projectId&&p.revision_id===scope.revisionId)??projects.find(p=>p.project_id===scope.projectId);
  const visible=projects.filter(p=>matchesProjectFilter(p,filter)||p.project_id===scope.projectId);
  return (
    <section className="panel" aria-label="项目与修订">
      <div className="toolbar wrap">
        <label className="field-stack">项目列表<select aria-label="项目列表筛选" className="input-field" value={filter} onChange={e=>{setFilter(e.target.value as ProjectFilter);try{sessionStorage.setItem("astra.production.project-filter",e.target.value);}catch{/* optional preference */}}}>
          <option value="user">活动业务项目</option><option value="example">历史演示 / 测试项目</option><option value="archived">已归档项目</option><option value="deleted">回收站</option><option value="all">全部项目</option>
        </select></label>
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
                revisionId: c?.project_state==="Deleted"?"":c?.revision_id ?? "",
                baselineId: "",
                profileId: "",
              });
            }}
          >
            <option value="">请选择项目</option>
            {visible.map((c) => (
              <option key={c.project_id} value={c.project_id}>
                {projectLabel(c)}
              </option>
            ))}
          </select>
        </label>
        <label className="field-stack">
          修订
          <select
            aria-label="修订"
            disabled={selectedProject?.project_state==="Deleted"}
            className="input-field"
            value={scope.revisionId}
            onChange={(e) =>
              scope.update({ revisionId: e.target.value, baselineId: "" })
            }
          >
            <option value="">请选择修订</option>
            {choices
              .filter((c) => c.project_id === scope.projectId && c.project_state!=="Deleted")
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
      {selectedProject&&!matchesProjectFilter(selectedProject,filter)&&<p>当前选中项目不属于此筛选范围，已保留选择以免丢失草稿。</p>}
      <ProjectManagement project={selectedProject}/>
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
