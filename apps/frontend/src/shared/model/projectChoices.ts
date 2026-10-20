import type { WorkspaceChoice } from "@attackgraph/contracts";
export type ProjectFilter="user"|"example"|"archived"|"deleted"|"all";
export function matchesProjectFilter(p:WorkspaceChoice,filter:ProjectFilter){
  const state=p.project_state??"Active";
  if(filter==="all")return true;
  if(filter==="archived")return state==="Archived";
  if(filter==="deleted")return state==="Deleted";
  return state==="Active"&&(p.project_kind??"user")===filter;
}
export function projectLabel(p:WorkspaceChoice){
  const state={Active:"活动",Archived:"已归档",Deleted:"回收站"}[p.project_state??"Active"];
  return `${p.project_name} · ${p.project_business_id} · ${p.project_id.slice(0,8)} · ${state}`;
}
