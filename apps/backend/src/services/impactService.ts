import {
  impactAssessmentCommandSchema,
  impactContractVersion,
  impactDispositionCommandSchema,
  impactPreviewQuerySchema,
  type ImpactAssessmentCommand,
  type ImpactAssessmentResult,
  type ImpactDispositionCommand,
  type ImpactDispositionResult,
  type ImpactPreview,
  type ImpactPreviewQuery,
} from "@attackgraph/contracts";
import { ImpactRepository } from "../repositories/impactRepository.js";
import { RevisionUnitOfWork } from "../repositories/revisionUnitOfWork.js";
import { compareImpactSnapshots } from "./impact/impactEngine.js";

export class ImpactService {
  constructor(
    private readonly repository = new ImpactRepository(),
    private readonly unitOfWork = new RevisionUnitOfWork(),
  ) {}

  async preview(raw: ImpactPreviewQuery): Promise<ImpactPreview> {
    const input = impactPreviewQuerySchema.parse(raw);
    const [from, to] = await Promise.all([
      this.repository.resolveContext(input.project_id, input.from),
      this.repository.resolveContext(input.project_id, input.to),
    ]);
    const [before, after] = await Promise.all([
      this.repository.readSnapshot(input.project_id, from.revision_id),
      this.repository.readSnapshot(input.project_id, to.revision_id),
    ]);
    const comparison = compareImpactSnapshots(before, after);
    return {
      contract_version: impactContractVersion,
      project_id: input.project_id,
      from,
      to,
      ...comparison,
      diagnostics: ["TraceLink propagation is conservative in both directions; explicit provenance and generated-result dependencies follow their engineering direction."],
    };
  }

  async create(raw: ImpactAssessmentCommand): Promise<ImpactAssessmentResult> {
    const input = impactAssessmentCommandSchema.parse(raw);
    const preview = await this.preview({ project_id: input.project_id, from: input.assessment.from, to: input.assessment.to });
    if (preview.to.revision_id !== input.revision_id) throw new Error("Impact assessment target must match revision_id");
    const write = await this.unitOfWork.execute(
      {
        actor: input.actor, command_id: input.command_id, project_id: input.project_id, revision_id: input.revision_id,
        expected_revision_version: input.expected_revision_version, event_type: "CHANGE_IMPACT_ASSESSED",
        request_canonicalizer: "change-impact.assessment/v1",
        payload: JSON.parse(JSON.stringify({ ...input.assessment, preview_hash: preview.preview_hash })),
        summary: "Create a deterministic change impact assessment",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) => this.repository.createAssessment(transaction, {
        project_id, revision_id, actor: input.actor, revision_version: new_revision_version,
        business_id: input.assessment.business_id, title: input.assessment.title, rationale: input.assessment.rationale,
        from: preview.from, to: preview.to, preview_hash: preview.preview_hash, differences: preview.differences, impacted: preview.impacted,
      }),
    );
    return { contract_version: impactContractVersion, ...write.value, audit_event_id: write.audit_event_id, new_revision_version: write.new_revision_version, replayed: write.replayed };
  }

  async dispose(raw: ImpactDispositionCommand): Promise<ImpactDispositionResult> {
    const input = impactDispositionCommandSchema.parse(raw);
    const write = await this.unitOfWork.execute(
      {
        actor: input.actor, command_id: input.command_id, project_id: input.project_id, revision_id: input.revision_id,
        expected_revision_version: input.expected_revision_version, event_type: "CHANGE_IMPACT_DISPOSITION_RECORDED",
        request_canonicalizer: "change-impact.disposition/v1", payload: JSON.parse(JSON.stringify(input.disposition)),
        summary: "Record human disposition for a change impact item",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) => this.repository.recordDisposition(transaction, {
        project_id, revision_id, actor: input.actor, revision_version: new_revision_version, disposition: input.disposition,
      }),
    );
    return { ...write.value, audit_event_id: write.audit_event_id, new_revision_version: write.new_revision_version, replayed: write.replayed };
  }
}
