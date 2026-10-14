import {
  analysisContractVersion,
  type AnalysisRunCommand,
  type AnalysisRunResult,
  type DerivedResultReviewCommand,
  type DerivedResultReviewResult,
  type PromotionCommand,
  type PromotionResult,
} from "@attackgraph/contracts";
import { AnalysisRepository } from "../repositories/analysisRepository.js";
import { EngineeringCaseRepository } from "../repositories/engineeringCaseRepository.js";
import { GraphRepository } from "../repositories/graphRepository.js";
import { RevisionUnitOfWork } from "../repositories/revisionUnitOfWork.js";
import { analysisDigest } from "./analysis/canonicalization.js";
import { executeAnalysisMethod } from "./analysis/methodExecutor.js";
import { getAnalysisMethod } from "./analysis/methodRegistry.js";

export class AnalysisServiceV2 {
  constructor(
    private readonly repository = new AnalysisRepository(),
    private readonly unitOfWork = new RevisionUnitOfWork(),
    private readonly engineeringRepository = new EngineeringCaseRepository(),
    private readonly graphRepository = new GraphRepository(),
  ) {}

  private async prepareScopedInput(input: AnalysisRunCommand): Promise<unknown> {
    const raw = input.method_input as Record<string, unknown> | null;
    const assets: string[] = [];
    if (raw && typeof raw === "object") {
      if (input.method_id === "feature-rule-preview" || input.method_id === "feature-topology-trace") {
        const featureInput = input.method_id === "feature-topology-trace"
          ? (raw.feature_input as Record<string, unknown> | undefined)
          : raw;
        const featureAssets = Array.isArray(featureInput?.assets) ? featureInput.assets : [];
        for (const value of featureAssets) {
          if (value && typeof value === "object" && typeof (value as Record<string, unknown>).prototype_asset_id === "string") {
            assets.push(String((value as Record<string, unknown>).prototype_asset_id));
          }
        }
        if (input.method_id === "feature-topology-trace") {
          const graph = raw.graph as Record<string, unknown> | undefined;
          const nodes = Array.isArray(graph?.asset_nodes) ? graph.asset_nodes : [];
          for (const value of nodes) if (value && typeof value === "object" && typeof (value as Record<string, unknown>).asset_id === "string") assets.push(String((value as Record<string, unknown>).asset_id));
        }
      } else if (input.method_id === "dfs-dps-attack-path") {
        const nodes = Array.isArray(raw.asset_nodes) ? raw.asset_nodes : [];
        for (const value of nodes) if (value && typeof value === "object" && typeof (value as Record<string, unknown>).asset_id === "string") assets.push(String((value as Record<string, unknown>).asset_id));
      }
    }
    const unresolved = await this.repository.inspectAssetScope(input.project_id, input.revision_id, assets.filter(Boolean));
    if (unresolved.length > 0) throw new Error("Analysis input references assets outside the current project/revision: " + unresolved.join(", "));

    if (input.method_id === "f3532-03-deterministic") {
      const engineering = await this.engineeringRepository.read(input.project_id, input.revision_id);
      const enabled = engineering?.profile_configuration.adapters.some((adapter) => adapter.adapter_id === "f3532" && adapter.enabled);
      if (!enabled) throw new Error("F3532 analysis method is not enabled by the current ProfileConfiguration");
      const scope = await this.repository.resolveProjectRevisionScope(input.project_id, input.revision_id);
      const facts = await this.graphRepository.getF353203GenerationFacts(scope);
      const options = raw && typeof raw.options === "object" && raw.options !== null ? raw.options : {};
      return { facts, options };
    }
    return input.method_input;
  }

  async run(input: AnalysisRunCommand): Promise<AnalysisRunResult> {
    const method = getAnalysisMethod(input.method_id, input.method_version);
    const scopedMethodInput = await this.prepareScopedInput(input);
    const execution = executeAnalysisMethod(method, scopedMethodInput);
    const setArrays = input.method_id === "feature-rule-preview" || input.method_id === "feature-topology-trace";
    const inputHash = analysisDigest(scopedMethodInput, { set_arrays: setArrays });
    const configHash = analysisDigest(input.method_config, { set_arrays: true });
    const canonicalPayload = JSON.parse(JSON.stringify({
      source_record_business_id: input.source_record_business_id,
      method_id: input.method_id,
      method_version: input.method_version,
      method_config_version: input.method_config_version,
      rule_pack_version: input.rule_pack_version ?? null,
      execution_limits: input.execution_limits,
      method_config: input.method_config,
      method_input: scopedMethodInput,
    }));
    const write = await this.unitOfWork.execute(
      {
        actor: input.actor, command_id: input.command_id, project_id: input.project_id,
        revision_id: input.revision_id, expected_revision_version: input.expected_revision_version,
        event_type: "ANALYSIS_RUN_COMPLETED", request_canonicalizer: "analysis-run.command/v1",
        payload: canonicalPayload, summary: "Execute " + input.method_id + "@" + input.method_version,
      },
      ({ transaction, project_id, revision_id, previous_revision_version, new_revision_version }) =>
        this.repository.createRun(transaction, {
          project_id, revision_id, actor: input.actor, command_id: input.command_id,
          revision_version: new_revision_version, input_revision_version: previous_revision_version,
          source_record_business_id: input.source_record_business_id, method,
          method_config_version: input.method_config_version, rule_pack_version: input.rule_pack_version,
          execution_limits: input.execution_limits, input_snapshot: { payload: scopedMethodInput, content_hash: inputHash },
          config_snapshot: { payload: input.method_config, content_hash: configHash },
          extra_snapshots: execution.extra_snapshots, results: execution.results,
          result_summary_hash: execution.result_summary_hash,
        }),
    );
    return {
      contract_version: analysisContractVersion, run_id: write.value.run_id,
      run_business_id: write.value.run_business_id, audit_event_id: write.audit_event_id,
      new_revision_version: write.new_revision_version, replayed: write.replayed,
      result_summary_hash: write.value.result_summary_hash, result_ids: write.value.result_ids,
    };
  }

  async review(input: DerivedResultReviewCommand): Promise<DerivedResultReviewResult> {
    const write = await this.unitOfWork.execute(
      {
        actor: input.actor, command_id: input.command_id, project_id: input.project_id,
        revision_id: input.revision_id, expected_revision_version: input.expected_revision_version,
        event_type: "DERIVED_RESULT_REVIEWED", request_canonicalizer: "analysis-run.derived-result-review/v1",
        payload: JSON.parse(JSON.stringify(input.review)), summary: "Record human ReviewDecision A for DerivedResult",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) =>
        this.repository.reviewResult(transaction, {
          project_id, revision_id, actor: input.actor, revision_version: new_revision_version, review: input.review,
        }),
    );
    return {
      audit_event_id: write.audit_event_id, new_revision_version: write.new_revision_version,
      replayed: write.replayed, derived_result_id: write.value.derived_result_id,
      machine_status: write.value.machine_status,
    };
  }

  async promote(input: PromotionCommand): Promise<PromotionResult> {
    const write = await this.unitOfWork.execute(
      {
        actor: input.actor, command_id: input.command_id, project_id: input.project_id,
        revision_id: input.revision_id, expected_revision_version: input.expected_revision_version,
        event_type: "DERIVED_RESULT_PROMOTED", request_canonicalizer: "analysis-run.promotion/v1",
        payload: JSON.parse(JSON.stringify(input.promotion)), summary: "Promote reviewed DerivedResult to a Core Draft",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) =>
        this.repository.promote(transaction, {
          project_id, revision_id, actor: input.actor, revision_version: new_revision_version, promotion: input.promotion,
        }),
    );
    return {
      audit_event_id: write.audit_event_id, new_revision_version: write.new_revision_version,
      replayed: write.replayed, ...write.value,
    };
  }
}
