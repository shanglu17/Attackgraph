import { LegacyAttachmentRepository } from "../../repositories/legacyAttachmentRepository.js";
import {
  resolveLegacyContext,
  type LegacyDatasetKind,
} from "./legacyAttachment.js";

export class LegacyAttachmentService {
  constructor(private readonly repository = new LegacyAttachmentRepository()) {}

  inspect(datasetKind: LegacyDatasetKind) {
    return this.repository.inspect(resolveLegacyContext(datasetKind));
  }

  apply(input: { dataset_kind: LegacyDatasetKind; actor: string; command_id: string }) {
    const actor = input.actor.trim();
    const commandId = input.command_id.trim();
    if (!actor) throw new Error("Legacy attachment apply requires a non-empty actor");
    if (!commandId) throw new Error("Legacy attachment apply requires a command/idempotency id");
    return this.repository.apply({
      config: resolveLegacyContext(input.dataset_kind),
      actor,
      command_id: commandId,
    });
  }

  verify(datasetKind: LegacyDatasetKind) {
    return this.repository.verify(resolveLegacyContext(datasetKind));
  }
}
