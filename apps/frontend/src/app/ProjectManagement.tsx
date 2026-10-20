import { useEffect, useRef, useState } from "react";
import type { ProjectOverview, ProjectLifecycleCommand, WorkspaceChoice } from "@attackgraph/contracts";
import { workbenchApi } from "../api";
import { useWorkbench } from "./WorkspaceProvider";

export function ProjectManagement({ project }: { project?: WorkspaceChoice }) {
  const { state, perform, refresh, refreshChoices, forgetProject } = useWorkbench();
  const [open, setOpen] = useState(false);
  const [overview, setOverview] = useState<ProjectOverview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [confirmation, setConfirmation] = useState("");
  const [reason, setReason] = useState("");
  const currentId = useRef(project?.project_id); currentId.current = project?.project_id;
  const command = useRef({key:"",id:""});
  useEffect(() => {
    let active = true;
    setOverview(null); setConfirmation(""); setReason(""); setError("");
    if (!open || !project) return;
    setLoading(true);
    void workbenchApi.projectOverview(project.project_id).then(value => { if(active)setOverview(value); })
      .catch(e => {if(active)setError((e as Error).message);}).finally(()=>{if(active)setLoading(false);});
    return () => {active=false;};
  },[open,project?.project_id,project?.project_version,attempt]);
  async function change(action: ProjectLifecycleCommand["action"]) {
    if (!overview) return;
    const id=overview.project_id;
    const payload={project_id:id,expected_project_version:overview.version,actor:"workbench-user",action,confirmation,reason};
    const key=JSON.stringify(payload);
    if(command.current.key!==key)command.current={key,id:crypto.randomUUID()};
    await workbenchApi.projectLifecycle({...payload,command_id:command.current.id});
    if(action==="delete")forgetProject(id);
    await refreshChoices();
    if(currentId.current===id && action!=="delete")await refresh();
    setAttempt(a=>a+1);
  }
  const disabled=state.busy||loading||!overview||confirmation!==overview.business_id||reason.trim().length<3;
  return <details onToggle={e=>setOpen(e.currentTarget.open)}>
    <summary>项目管理（归档、回收站与恢复）</summary>
    {!project?<p>先从项目列表选择一个项目。</p>:<>
      <p>项目编号：{project.project_business_id} · 状态：{project.project_state??"Active"}</p>
      <p className="workbench-identity">项目 UUID：{project.project_id}<br/>修订 UUID：{project.revision_id}</p>
      {loading&&<p role="status">读取项目范围…</p>}
      {error&&<p role="alert">{error} <button className="button" onClick={()=>setAttempt(a=>a+1)}>重试读取项目</button></p>}
      {overview&&<>
        <button className="button" disabled={state.busy||loading} onClick={()=>setAttempt(a=>a+1)}>刷新项目范围</button>
        <p>范围：{overview.revisions} 个修订、{overview.assets} 个资产、{overview.runs} 次分析运行 · 项目版本 v{overview.version}</p>
        <p>归档后只读；删除会移入回收站并清除本地未保存草稿。模型、来源、冻结基线和审计继续保留，可恢复。归档前请先保存需要保留的草稿。</p>
        <div className="workbench-form-grid">
          <label className="field-stack">输入项目编号确认<input aria-label="输入项目编号确认" className="input-field" disabled={state.busy} value={confirmation} onChange={e=>setConfirmation(e.target.value)}/></label>
          <label className="field-stack">操作原因（至少三个字）<input aria-label="项目操作原因" className="input-field" disabled={state.busy} value={reason} onChange={e=>setReason(e.target.value)}/></label>
        </div>
        <div className="toolbar wrap">
          {overview.state==="Active"&&<button className="button" disabled={disabled} onClick={()=>void perform(()=>change("archive"))}>归档项目</button>}
          {overview.state!=="Deleted"&&<button className="button" disabled={disabled} onClick={()=>void perform(()=>change("delete"))}>删除项目（移入回收站）</button>}
          {overview.state!=="Active"&&<button className="button" disabled={disabled} onClick={()=>void perform(()=>change("restore"))}>{overview.state==="Deleted"?"从回收站恢复":"恢复为活动项目"}</button>}
        </div>
        {overview.state==="Deleted"&&<p>恢复会回到删除前的活动或归档状态。归档项目恢复后仍需单独解除归档才能编辑。</p>}
      </>}
    </>}
  </details>;
}
