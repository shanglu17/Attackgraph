import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { closeDriver } from "../db/neo4j.js";
import { GraphRepository } from "../repositories/graphRepository.js";
import { Phase7AcceptanceRepository } from "../repositories/phase7AcceptanceRepository.js";
import { ProjectRecoveryService } from "../services/operations/projectRecoveryService.js";
import { runRecoveryDrill } from "../services/operations/recoveryDrillService.js";
import { createPhase7ReleaseEvidence } from "../services/release/phase7Acceptance.js";

type Command = "verify" | "record";

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function command(): Command {
  const value = process.argv[2] ?? "verify";
  if (value === "verify" || value === "record") return value;
  throw new Error(`Unknown Phase 7 command '${value}'. Expected verify or record.`);
}

const requested = command();
const actor = option("--actor")?.trim() || "phase7-verifier";
const releaseId = option("--release-id")?.trim() || "ASTRA-PHASE7-2026-10-15";
const commandId = option("--command-id")?.trim();
const output = option("--output")?.trim();

async function emit(result: unknown) {
  if (output) {
    const resolved = path.resolve(output);
    await mkdir(path.dirname(resolved), { recursive: true });
    await writeFile(resolved, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }
  console.log(JSON.stringify(result, null, 2));
}

async function main() {
  if (requested === "record" && !commandId) throw new Error("record requires --command-id <id>");
  const repository = new Phase7AcceptanceRepository();
  if (requested === "record") {
    const prior = await repository.readRecorded(commandId!, releaseId);
    if (prior) {
      await emit({ command: requested, recorded: { id: prior.id, replayed: true }, evidence: prior.evidence });
      return;
    }
  }
  const raw = await repository.collect();
  const { context, ...collected } = raw;
  const graphRepository = new GraphRepository();
  const graph = await graphRepository.getGraph({ project_id: context.project_id, model_id: context.model_id, revision_id: context.revision_id });
  const audits = await graphRepository.getAuditCommits({ project_id: context.project_id, model_id: context.model_id, revision_id: context.revision_id });
  const snapshot = await new ProjectRecoveryService().capture(context.project_id);
  const recovery = await runRecoveryDrill("phase7");
  const evidence = createPhase7ReleaseEvidence({
    release_id: releaseId, generated_at: new Date().toISOString(), generated_by: actor, recovery_drill: recovery,
    observations: {
      ...collected,
      scope: context,
      compatibility_counts: {
        asset_nodes: graph.asset_nodes.length, asset_edges: graph.asset_edges.length,
        threat_points: graph.threat_points.length, do326a_links: graph.do326a_links.length,
        commit_audits: audits.length,
      },
      backup: { node_count: snapshot.nodes.length, relationship_count: snapshot.relationships.length, semantic_hash: snapshot.semantic_hash },
    },
  });
  const recorded = requested === "record" && evidence.overall_status === "passed"
    ? await repository.record(evidence, actor, commandId!)
    : undefined;
  const result = { command: requested, recorded, evidence };
  await emit(result);
  if (evidence.overall_status !== "passed") process.exitCode = 1;
}

main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(closeDriver);
