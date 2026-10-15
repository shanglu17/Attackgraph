import { useWorkspaceContext } from "./WorkspaceContext";

export function WorkspaceContextBar() {
  const context = useWorkspaceContext();
  return <section className="project-context-bar" aria-label="当前项目上下文">
    <label className="field-stack"><span className="field-label">Project UUID</span><input className="input-field" aria-label="Project UUID" value={context.projectId} onChange={(event) => context.update({ projectId: event.target.value })} /></label>
    <label className="field-stack"><span className="field-label">Revision UUID</span><input className="input-field" aria-label="Revision UUID" value={context.revisionId} onChange={(event) => context.update({ revisionId: event.target.value })} /></label>
    <label className="field-stack"><span className="field-label">Profile UUID</span><input className="input-field" aria-label="Profile UUID" value={context.profileId} onChange={(event) => context.update({ profileId: event.target.value })} /></label>
    <label className="field-stack"><span className="field-label">Baseline UUID</span><input className="input-field" aria-label="Baseline UUID" value={context.baselineId} onChange={(event) => context.update({ baselineId: event.target.value })} /></label>
    <label className="field-stack"><span className="field-label">评审 API Key（仅本页）</span><input className="input-field" type="password" autoComplete="off" aria-label="评审 API Key" value={context.apiKey} onChange={(event) => context.update({ apiKey: event.target.value })} /></label>
  </section>;
}
