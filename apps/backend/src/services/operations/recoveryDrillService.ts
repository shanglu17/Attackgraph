import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { GovernanceService } from "../governance/governanceService.js";
import { ProjectRecoveryService, type ProjectRecoverySnapshot } from "./projectRecoveryService.js";

export interface RecoveryDrillResult {
  ok: true;
  project_id: string;
  deleted_nodes: number;
  restored_nodes: number;
  restored_relationships: number;
  semantic_hash: string;
}

export async function runRecoveryDrill(label = "phase7"): Promise<RecoveryDrillResult> {
  const suffix = randomUUID();
  const governance = new GovernanceService();
  const recovery = new ProjectRecoveryService();
  let projectId: string | undefined;
  let directory: string | undefined;

  try {
    const workspace = await governance.createProjectWorkspace({
      actor: `${label}-recovery-drill`, command_id: `${label}:${suffix}:workspace`,
      project: { business_id: `${label.toUpperCase()}-RECOVERY-${suffix}`, name: `${label} recovery drill` },
      model: { business_id: "MODEL-1", name: "Recovery drill model", level: "system" },
      revision: { business_id: "REV-1" },
      standard_profile: {
        business_id: "PROFILE-326A-356A", name: "DO-326A / DO-356A",
        profile_version: label, standard_references: ["DO-326A", "DO-356A"],
      },
    });
    projectId = workspace.project.id;
    const before = await recovery.capture(projectId);
    directory = await mkdtemp(path.join(tmpdir(), `astra-${label}-recovery-`));
    const backupPath = path.join(directory, "project-backup.json");
    await writeFile(backupPath, JSON.stringify(before, null, 2), "utf8");
    const persisted = JSON.parse(await readFile(backupPath, "utf8")) as ProjectRecoverySnapshot;
    const deleted = await recovery.deleteProject(projectId);
    await recovery.restore(persisted);
    const after = await recovery.capture(projectId);
    if (before.semantic_hash !== after.semantic_hash) {
      throw new Error(`restored project differs: ${before.semantic_hash} != ${after.semantic_hash}`);
    }
    return {
      ok: true, project_id: projectId, deleted_nodes: deleted,
      restored_nodes: after.nodes.length, restored_relationships: after.relationships.length,
      semantic_hash: after.semantic_hash,
    };
  } finally {
    if (projectId) await recovery.deleteProject(projectId).catch(() => undefined);
    if (directory) await rm(directory, { recursive: true, force: true }).catch(() => undefined);
  }
}
