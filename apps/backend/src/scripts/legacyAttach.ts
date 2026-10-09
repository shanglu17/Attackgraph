import { closeDriver } from "../db/neo4j.js";
import { LegacyAttachmentBlockedError } from "../repositories/legacyAttachmentRepository.js";
import type { LegacyDatasetKind } from "../services/legacyMigration/legacyAttachment.js";
import { LegacyAttachmentService } from "../services/legacyMigration/legacyAttachmentService.js";

type Command = "dry-run" | "apply" | "verify";

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function command(): Command {
  const value = process.argv[2] ?? "dry-run";
  if (["dry-run", "apply", "verify"].includes(value)) return value as Command;
  throw new Error(`Unknown legacy attachment command: ${value}. Expected dry-run, apply or verify.`);
}

function datasetKind(required: boolean): LegacyDatasetKind {
  const value = option("--dataset");
  if (!value && required) {
    throw new Error(
      "apply requires an explicit --dataset <generic-legacy|do356a-appendix-d>",
    );
  }
  const resolved = value ?? "generic-legacy";
  if (!["generic-legacy", "do356a-appendix-d"].includes(resolved)) {
    throw new Error(`Unsupported dataset '${resolved}'`);
  }
  return resolved as LegacyDatasetKind;
}

async function main(): Promise<void> {
  const service = new LegacyAttachmentService();
  const requested = command();
  const dataset = datasetKind(requested === "apply");

  if (requested === "dry-run") {
    const plan = await service.inspect(dataset);
    console.log(JSON.stringify({ command: requested, plan }, null, 2));
    if (plan.blocked) process.exitCode = 2;
    return;
  }

  if (requested === "verify") {
    const verification = await service.verify(dataset);
    console.log(JSON.stringify({ command: requested, dataset, verification }, null, 2));
    if (!verification.ok) process.exitCode = 1;
    return;
  }

  const actor = option("--actor");
  const commandId = option("--command-id");
  if (!actor) throw new Error("apply requires --actor <actor-id>");
  if (!commandId) throw new Error("apply requires --command-id <id>");
  const result = await service.apply({
    dataset_kind: dataset,
    actor,
    command_id: commandId,
  });
  console.log(JSON.stringify({ command: requested, result }, null, 2));
}

main()
  .catch((error) => {
    if (error instanceof LegacyAttachmentBlockedError) {
      console.error(JSON.stringify({ error: error.message, plan: error.plan }, null, 2));
    } else {
      console.error(error instanceof Error ? error.message : error);
    }
    process.exitCode = 1;
  })
  .finally(closeDriver);
