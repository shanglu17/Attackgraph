import { randomUUID } from "node:crypto";
import type { ProjectLifecycleCommand, ProjectOverview } from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";
import { fingerprintCommandPayload } from "../services/governance/commandFingerprint.js";
import { assertCommandReceipt, findCommandReceipt } from "../services/governance/commandReceipt.js";

export class ProjectLifecycleError extends Error {
  constructor(message: string, readonly statusCode = 409) { super(message); }
}
const number = (n: unknown) => Number(n);
export class ProjectLifecycleRepository {
  async overview(id: string): Promise<ProjectOverview> {
    const s = getDriver().session();
    try {
      const r = await s.executeRead(tx => tx.run(`MATCH(p:Project {id:$id})
        RETURN p, COUNT { MATCH(n:Revision {project_id:$id}) } AS revisions,
        COUNT { MATCH(n:Asset {project_id:$id}) } AS assets,
        COUNT { MATCH(n:AnalysisRun {project_id:$id}) } AS runs`, { id }));
      if (!r.records.length) throw new ProjectLifecycleError("项目不存在", 404);
      const row = r.records[0], p = row.get("p").properties;
      return { project_id:id, business_id:p.business_id, name:p.name, version:number(p.version),
        state:p.deleted_at ? "Deleted" : p.status === "Archived" ? "Archived" : "Active",
        revisions:number(row.get("revisions")), assets:number(row.get("assets")), runs:number(row.get("runs")) };
    } finally { await s.close(); }
  }
  async execute(input: ProjectLifecycleCommand) {
    const eventType = "PROJECT_" + ({archive:"ARCHIVED",delete:"RECYCLED",restore:"RESTORED"}[input.action]);
    const fingerprint = fingerprintCommandPayload("workbench.project-lifecycle/v1", input);
    const s = getDriver().session();
    try {
      return await s.executeWrite(async tx => {
        const replay = async () => {
          const receipt = await findCommandReceipt(tx,input.command_id);
          if (!receipt) return undefined;
          assertCommandReceipt(input.command_id,receipt,eventType,fingerprint);
          return {...JSON.parse(String(receipt.result_json)),replayed:true};
        };
        const prior = await replay(); if (prior) return prior;
        const locked = await tx.run(`MATCH(p:Project {id:$id})
          SET p._project_write_lock=coalesce(p._project_write_lock,0)+1 RETURN p`,{id:input.project_id});
        if (!locked.records.length) throw new ProjectLifecycleError("项目不存在",404);
        const concurrent = await replay(); if (concurrent) { await tx.run("MATCH(p:Project {id:$id}) REMOVE p._project_write_lock",{id:input.project_id}); return concurrent; }
        const p=locked.records[0].get("p").properties;
        if (number(p.version)!==input.expected_project_version) throw new ProjectLifecycleError("项目版本已变化，请刷新后重新确认");
        if (p.business_id!==input.confirmation) throw new ProjectLifecycleError("请输入完整项目编号确认操作");
        const before=p.deleted_at?"Deleted":p.status==="Archived"?"Archived":"Active";
        if ((input.action==="archive" && before!=="Active") || (input.action==="delete" && before==="Deleted") || (input.action==="restore" && before==="Active"))
          throw new ProjectLifecycleError("项目状态已变化，当前操作不适用");
        // Recycling preserves every revision, frozen baseline, source and audit event.
        const state=input.action==="delete"?"Deleted":input.action==="archive"?"Archived":(before==="Deleted"&&p.pre_delete_status==="Archived"?"Archived":"Active");
        const result={project_id:input.project_id,state,project_version:number(p.version)+1,audit_event_id:randomUUID(),replayed:false};
        await tx.run(`MATCH(p:Project {id:$id}) SET p.version=$version,p.status=$status,p.updated_at=datetime(),p.updated_by=$actor
          FOREACH(_ IN CASE WHEN $action='delete' THEN [1] ELSE [] END | SET p.deleted_at=datetime(),p.pre_delete_status=$old_status)
          FOREACH(_ IN CASE WHEN $action='restore' THEN [1] ELSE [] END | REMOVE p.deleted_at,p.pre_delete_status)
          REMOVE p._project_write_lock
          CREATE(e:AuditEvent {id:$audit_id,command_id:$command_id,project_id:$id,subject_id:$id,subject_type:'Project',
            event_type:$event_type,actor:$actor,occurred_at:datetime(),subject_version_before:$old_version,subject_version_after:$version,
            request_hash:$request_hash,request_hash_algorithm:$request_hash_algorithm,request_canonicalizer:$request_canonicalizer,
            summary:$reason,result_json:$result}) CREATE(e)-[:AFFECTS]->(p)`,{
          id:input.project_id, version:result.project_version,old_version:input.expected_project_version,status:state==="Active"?"Active":"Archived",
          action:input.action,old_status:p.status??"Active",actor:input.actor,audit_id:result.audit_event_id,command_id:input.command_id,
          event_type:eventType,reason:input.reason,result:JSON.stringify(result),...fingerprint,
        });
        return result;
      });
    } finally { await s.close(); }
  }
}
