import { Worker } from "node:worker_threads";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  analysisContractVersion,
  systemModelImportPayloadSchema,
  analysisConfigurationSchema,
  type EditCommand,
  type EditPreview,
  type FieldDifference,
  type InventoryCommit,
  type InventoryPreview,
  type SavedAnalysisCommand,
  type WorkbenchScope,
  type WorkbenchSnapshot,
  type SystemModelImportPayload,
  type WorkbenchExportRequest,
} from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";
import {
  SystemModelRepository,
  SystemModelConflictError,
} from "../repositories/systemModelRepository.js";
import { WorkbenchRepository } from "../repositories/workbenchRepository.js";
import {
  RevisionUnitOfWork,
  RevisionNotWritableError,
  RevisionWriteConflictError,
} from "../repositories/revisionUnitOfWork.js";
import { AnalysisRepository } from "../repositories/analysisRepository.js";
import { validateSystemModelImport } from "./systemModelImportService.js";
import {
  prepareInventory,
  mapCoreModel,
  modelDigest,
  analysisTargets,
  makeAnalysisInput,
  scoringDisclaimer,
} from "./workbenchMapping.js";
import { analysisDigest } from "./analysis/canonicalization.js";
import { getAnalysisMethod } from "./analysis/methodRegistry.js";
import type { AnalysisInput } from "./analysisService.js";
import type { AttackPath } from "../types/domain.js";
import type { ExecutedResult } from "./analysis/methodExecutor.js";
import { propagationProjection } from "./analysis/propagationPolicy.js";

function candidate(entities: unknown): SystemModelImportPayload {
  return systemModelImportPayloadSchema.parse({
    contract_version: "system-model.v2",
    source: {
      business_id: "EDIT",
      source_type: "manual",
      name: "修订编辑",
      content_hash: "0".repeat(64),
      parser_name: "workbench",
      parser_version: "1",
    },
    entities,
  });
}
export function differences(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): FieldDifference[] {
  const result: FieldDifference[] = [];
  for (const collection of new Set([
    ...Object.keys(before),
    ...Object.keys(after),
  ])) {
    const previous = (before[collection] ?? []) as Record<string, unknown>[];
    const next = (after[collection] ?? []) as Record<string, unknown>[];
    for (const id of new Set(
      [...previous, ...next].map((r) => String(r.business_id)),
    )) {
      const a = previous.find((r) => r.business_id === id);
      const b = next.find((r) => r.business_id === id);
      for (const field of new Set([
        ...Object.keys(a ?? {}),
        ...Object.keys(b ?? {}),
      ])) {
        if (
          ["id", "revision_version", "created_by", "updated_by"].includes(field)
        )
          continue;
        if (JSON.stringify(a?.[field]) !== JSON.stringify(b?.[field]))
          result.push({
            collection,
            business_id: id,
            field,
            before: a?.[field],
            after: b?.[field],
          });
      }
    }
  }
  return result;
}
export async function executeSavedDps(
  input: AnalysisInput,
  timeoutMs = 10000,
): Promise<AttackPath[]> {
  const js = new URL("./analysisService.js", import.meta.url);
  const moduleUrl = existsSync(fileURLToPath(js))
    ? js.href
    : new URL("./analysisService.ts", import.meta.url).href;
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      `const {parentPort,workerData}=require('node:worker_threads');
      (async()=>{ const mod=workerData.url.endsWith('.ts') ? await (await import('tsx/esm/api')).tsImport(workerData.url,workerData.url) : await import(workerData.url);
      parentPort.postMessage(new mod.AnalysisService().run(workerData.input)); })().catch(e=>{throw e});`,
      {
        eval: true,
        workerData: { url: moduleUrl, input },
        resourceLimits: { maxOldGenerationSizeMb: 256 },
      },
    );
    const timer = setTimeout(() => {
      void worker.terminate();
      reject(
        Object.assign(
          new Error(
            "分析超时，搜索已中止；没有生成当前结果，请缩小范围后重试。",
          ),
          { statusCode: 504, code: "ANALYSIS_TIMEOUT" },
        ),
      );
    }, timeoutMs);
    worker.once("message", (value) => {
      clearTimeout(timer);
      void worker.terminate();
      resolve(value);
    });
    worker.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    worker.once("exit", (code) => {
      if (code !== 0) {
        clearTimeout(timer);
        reject(new Error("分析工作线程中止，未生成完整结果"));
      }
    });
  });
}
export class WorkbenchService {
  constructor(private readonly execute:(input:AnalysisInput)=>Promise<AttackPath[]>=executeSavedDps){}
  readonly models = new SystemModelRepository();
  readonly repository = new WorkbenchRepository();
  readonly uow = new RevisionUnitOfWork();
  async read(scope: WorkbenchScope): Promise<WorkbenchSnapshot> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (tx) => {
        const model = await this.models.read(
          scope.project_id,
          scope.revision_id,
          tx,
        );
        const configuration = await this.repository.configuration(
          scope.project_id,
          scope.revision_id,
          tx,
        );
        const graph = mapCoreModel(model, configuration);
        const status = await this.repository.status(
          scope.project_id,
          scope.revision_id,
          tx,
        );
        const version = await tx.run(
          "MATCH(r:Revision {id:$revision_id,project_id:$project_id}) RETURN r.version AS version",
          { project_id: scope.project_id, revision_id: scope.revision_id },
        );
        if (
          Number(version.records[0].get("version")) !== model.revision_version
        )
          throw new RevisionWriteConflictError(
            scope.revision_id,
            model.revision_version,
            Number(version.records[0].get("version")),
          );
        return {
          model,
          configuration,
          graph,
          model_hash: modelDigest(model, configuration),
          target_ids: [...analysisTargets(graph)],
          status,
        };
      });
    } finally {
      await session.close();
    }
  }
  async export(input: WorkbenchExportRequest) {
    const snapshot = await this.read(input);
    const run = (
      await new AnalysisRepository().readRuns(
        input.project_id,
        input.revision_id,
        input.run_id,
        true,
      )
    )[0];
    const metadata = run?.snapshots.find(
      (s) => s.snapshot_type === "method_config",
    )?.payload as { model_hash?: string; parameters?: unknown } | undefined;
    if (
      !run ||
      run.status !== "Completed" ||
      run.input_origin !== "saved-model" ||
      run.stale ||
      run.method_config_version !== "saved-model-analysis.v1" ||
      metadata?.model_hash !== snapshot.model_hash ||
      analysisDigest(metadata?.parameters) !== analysisDigest(input.parameters)
    )
      throw new SystemModelConflictError(
        "结果与当前模型、分析配置或参数不一致，不能导出为当前成果",
      );
    const latest = await this.read(input);
    if (
      latest.model.revision_version !== snapshot.model.revision_version ||
      latest.model_hash !== snapshot.model_hash
    )
      throw new SystemModelConflictError(
        "导出读取期间修订发生变化，请刷新后重试",
      );
    return { snapshot, run };
  }
  async previewInventory(input: InventoryPreview) {
    const prepared = prepareInventory(input);
    if (prepared.model) {
      const scope = await this.models.inspectScope(
        input.project_id,
        input.revision_id,
      );
      if (!scope.exists) throw new SystemModelConflictError("项目或修订不存在");
      prepared.errors.push(
        ...validateSystemModelImport(prepared.model, scope.identities),
      );
      prepared.ok = prepared.errors.length === 0;
    }
    return prepared;
  }
  async commitInventory(input: InventoryCommit) {
    const prepared = prepareInventory(input);
    if (!prepared.ok || !prepared.model || !prepared.configuration)
      throw new SystemModelConflictError(prepared.errors.join("；"));
    const payload = prepared.model;
    const configuration = prepared.configuration;
    return this.uow.execute(
      {
        ...input,
        event_type: "SYSTEM_MODEL_IMPORTED",
        request_canonicalizer: "workbench.inventory/v1",
        payload: JSON.parse(JSON.stringify(input)),
        summary: "导入系统资产清单（AMS 规则 v1）",
      },
      async (context) => {
        const ids = await this.models.createImport(context.transaction, {
          ...context,
          actor: input.actor,
          revision_version: context.new_revision_version,
          payload,
        });
        const previous = await this.repository.configuration(
          input.project_id,
          input.revision_id,
          context.transaction,
        );
        await this.repository.saveConfiguration(
          context.transaction,
          context,
          {
            ...configuration,
            threat_overrides: {
              ...previous.threat_overrides,
              ...configuration.threat_overrides,
            },
          },
          input.inventory,
        );
        return ids;
      },
    );
  }
  async previewEdit(input: EditCommand): Promise<EditPreview> {
    const current = await this.read(input);
    if (current.status !== "Draft")
      throw new RevisionNotWritableError(input.revision_id, current.status);
    if (current.model.revision_version !== input.expected_revision_version)
      throw new RevisionWriteConflictError(
        input.revision_id,
        input.expected_revision_version,
        current.model.revision_version,
      );
    return this.validateEdit(current, input);
  }
  validateEdit(current: WorkbenchSnapshot, input: EditCommand): EditPreview {
    const payload = candidate(input.entities);
    const errors = validateSystemModelImport(payload);
    if(input.configuration.mapping_version!==current.configuration.mapping_version)errors.push("转换版本由导入及服务端管理，不能通过编辑草稿更改");
    if (!payload.entities.assets.length) errors.push("模型至少保留一个资产");
    for (const id of Object.keys(input.configuration.threat_overrides))
      if (!payload.entities.draft_threats.some((t) => t.business_id === id))
        errors.push(`分析配置引用已删除或不存在的威胁 ${id}`);
    for(const [id,parameters] of Object.entries(input.configuration.threat_overrides)){
      if(parameters.expert_modifier!==undefined&&parameters.expert_modifier!==1&&!parameters.expert_adjustment_note)errors.push(`${id}: 专家修正因子非 1 时必须提供修正依据`);
      if(parameters.expert_adjustment_note&&parameters.expert_adjustment_note.trim().length<10)errors.push(`${id}: 专家修正依据至少需要 10 个字符`);
    }
    try {
      mapCoreModel(
        payload,
        analysisConfigurationSchema.parse(input.configuration),
      );
    } catch (e) {
      errors.push((e as Error).message);
    }
    const diff = differences(current.model.entities, payload.entities);
    if (
      JSON.stringify(current.configuration) !==
      JSON.stringify(input.configuration)
    )
      diff.push({
        collection: "configuration",
        business_id: input.revision_id,
        field: "threat_overrides",
        before: current.configuration,
        after: input.configuration,
      });
    return { ok: !errors.length, errors, differences: diff };
  }
  async commitEdit(input: EditCommand) {
    const payload = candidate(input.entities);
    return this.uow.execute(
      {
        ...input,
        event_type: "SYSTEM_MODEL_EDITED",
        request_canonicalizer: "workbench.edit/v1",
        payload: JSON.parse(
          JSON.stringify({
            entities: payload.entities,
            configuration: input.configuration,
          }),
        ),
        summary: "保存核心模型与威胁参数变更",
      },
      async (context) => {
        const model = await this.models.read(
          input.project_id,
          input.revision_id,
          context.transaction,
        );
        const configuration = await this.repository.configuration(
          input.project_id,
          input.revision_id,
          context.transaction,
        );
        const preview = this.validateEdit(
          { model, configuration } as WorkbenchSnapshot,
          { ...input, entities: payload.entities },
        );
        if (!preview.ok)
          throw new SystemModelConflictError(preview.errors.join("；"));
        await this.repository.applyEntities(
          context.transaction,
          context,
          payload.entities,
          input.actor,
        );
        await this.repository.saveConfiguration(
          context.transaction,
          context,
          input.configuration,
        );
        return { saved: true, difference_count: preview.differences.length, differences: JSON.parse(JSON.stringify(preview.differences)) };
      },
    );
  }
  async run(input: SavedAnalysisCommand) {
    const write = await this.uow.execute(
      {
        ...input,
        event_type: "ANALYSIS_RUN_COMPLETED",
        request_canonicalizer: "workbench.saved-analysis/v1",
        payload: JSON.parse(JSON.stringify(input.parameters)),
        summary: "从已保存修订构造 DPS 输入并分析",
      },
      async (context) => {
        const model = await this.models.read(
          input.project_id,
          input.revision_id,
          context.transaction,
        );
        const configuration = await this.repository.configuration(
          input.project_id,
          input.revision_id,
          context.transaction,
        );
        const graph = makeAnalysisInput(
          model,
          configuration,
          input.parameters,
          input.command_id,
          input.actor,
        );
        if (!graph.asset_nodes.length || !model.sources.length)
          throw new SystemModelConflictError("请先导入并保存模型");
        const started_at = new Date().toISOString(),
          start = performance.now();
        let paths: AttackPath[] = [];
        let failure: string | undefined;
        try {
          paths = await this.execute(graph);
        } catch (error) {
          failure = (error as Error).message;
        }
        const calculation_ms = Math.round(performance.now() - start),
          completed_at = new Date().toISOString();
        const propagation = propagationProjection(model, configuration);
        const inputPayload = { ...graph, mapping_version: configuration.mapping_version, propagation };
        const mappingPayload = { configuration, sources: model.sources, propagation };
        const metadata = {
          model_hash: modelDigest(model, configuration),
          mapping_version: configuration.mapping_version,
          propagation,
          parameters: input.parameters,
          calculation_ms,
          disclaimer: scoringDisclaimer,
          scope: failure ? "failed" : "bounded",
          error: failure ?? null,
          path_count: paths.length,
          target_ids: [
            ...analysisTargets(graph, input.parameters.scope_asset_ids),
          ],
        };
        const results: ExecutedResult[] = paths.map((path) => ({
          result_kind: "attack_path_candidate",
          machine_status: "Candidate",
          topology_only: false,
          completeness: "partial",
          termination_reason: "hop_limit",
          truncated: true,
          diagnostics: [],
          payload: path,
          result_hash: analysisDigest(path, { omit_volatile: true }),
        }));
        results.push({
          result_kind: "search_summary",
          machine_status: "Experimental",
          topology_only: false,
          completeness: failure ? "unknown" : "partial",
          termination_reason: failure ? "execution_error" : "hop_limit",
          truncated: true,
          diagnostics: [
            failure
              ? {
                  code: failure.includes("超时")
                    ? "ANALYSIS_TIMEOUT"
                    : "ANALYSIS_EXECUTION_ERROR",
                  severity: "error",
                  message: failure,
                }
              : {
                  code: "bounded_search",
                  severity: "info",
                  message: "已完成配置跳数范围内的搜索；不证明全图无攻击路径。",
                },
          ],
          payload: metadata,
          result_hash: analysisDigest(metadata),
        });
        const stored = await new AnalysisRepository().createRun(
          context.transaction,
          {
            project_id: context.project_id,
            revision_id: context.revision_id,
            actor: input.actor,
            command_id: input.command_id,
            revision_version: context.new_revision_version,
            input_revision_version: context.previous_revision_version,
            source_record_business_id: model.sources[0].business_id,
            method: getAnalysisMethod("dfs-dps-attack-path", "1.0.0"),
            method_config_version: "saved-model-analysis.v1",
            rule_pack_version: configuration.mapping_version,
            projection_version: propagation.version,
            execution_limits: {
              max_hops: input.parameters.max_hops,
              timeout_ms: 10000,
            },
            input_snapshot: {
              payload: inputPayload,
              content_hash: analysisDigest(inputPayload),
            },
            config_snapshot: {
              payload: metadata,
              content_hash: analysisDigest(metadata),
            },
            extra_snapshots: [
              {
                snapshot_type: "mapping",
                payload: mappingPayload,
                content_hash: analysisDigest(mappingPayload),
              },
            ],
            results,
            result_summary_hash: analysisDigest(paths, { omit_volatile: true }),
            status: failure ? "Failed" : "Completed",
            started_at,
            completed_at,
          },
        );
        return {
          ...stored,
          status: failure ? "Failed" : "Completed",
          error: failure ?? null,
        };
      },
    );
    return {
      ...write,
      ...write.value,
      contract_version: analysisContractVersion,
    };
  }
}
