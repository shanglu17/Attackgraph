import { createHash } from "node:crypto";
import {
  systemModelImportPayloadSchema,
  analysisConfigurationSchema,
  threatParametersSchema,
  businessIdSchema,
  validateInventoryRecords,
  inventoryFields,
  sheetNames,
  type AnalysisConfiguration,
  type InventoryPreview,
  type InventoryPreviewResult,
  type StoredSystemModel,
  type SystemModelImportPayload,
} from "@attackgraph/contracts";
import { CxfImportService } from "./cxfImportService.js";
import { AnalysisService, type AnalysisInput } from "./analysisService.js";
import { assetNodeSchema, assetEdgeSchema } from "../types/api.js";
import type { AssetNode, AssetEdge, ThreatPoint } from "../types/domain.js";
import { analysisDigest } from "./analysis/canonicalization.js";
import { z } from "zod";

export const scoringDisclaimer =
  "用于相对排序的启发式评分，不代表实际攻击成功概率。";
const defaults = threatParametersSchema.parse({
  entry_likelihood_level: "Medium",
  attack_complexity_level: "Medium",
  threat_source: "external",
  stride_category: "Tampering",
  attack_vector: "Network",
});
const mappedAssetSchema = assetNodeSchema
  .innerType()
  .extend({
    asset_id: businessIdSchema,
    asset_name: z.string().min(1).max(300),
    description: z.string().max(2000).optional(),
  });
const mappedEdgeSchema = assetEdgeSchema
  .innerType()
  .extend({
    edge_id: businessIdSchema,
    source_asset_id: businessIdSchema,
    target_asset_id: businessIdSchema,
    description: z.string().max(2000).optional(),
  });
const ordered = <T extends { analysis?: Record<string, unknown> }>(rows: T[]) =>
  [...rows].sort(
    (a, b) =>
      Number(a.analysis?.mapping_order ?? 0) -
      Number(b.analysis?.mapping_order ?? 0),
  );
export function mapCoreModel(
  model: Pick<SystemModelImportPayload, "entities">,
  configuration: AnalysisConfiguration,
) {
  const assets = ordered(model.entities.assets).map((a) =>
    mappedAssetSchema.parse({
      ...a.analysis,
      asset_id: a.business_id,
      asset_name: a.name,
      asset_type: ["Terminal", "Interface", "Link", "Data"].includes(a.category)
        ? a.category
        : (a.analysis?.asset_type ?? "Terminal"),
      data_classification:
        a.analysis?.data_classification ??
        a.classification ??
        (a.category === "Data" ? "Internal" : undefined),
      criticality:
        a.criticality === "Catastrophic" ? "High" : (a.criticality ?? "Medium"),
      description: a.description,
      tags: a.tags,
      source_sheet: a.source_locator?.sheet,
      source_row: a.source_locator?.row,
    }),
  ) as AssetNode[];
  const edges = ordered(model.entities.data_flows)
    .filter((f) => f.analysis?.dps_enabled !== false)
    .map((f) =>
      mappedEdgeSchema.parse({
        link_type: "DataFlow",
        direction: "Unidirectional",
        ...f.analysis,
        edge_id: f.business_id,
        source_asset_id: f.producer_asset_business_id,
        target_asset_id: f.consumer_asset_business_id,
        description: f.description ?? f.content,
      }),
    ) as AssetEdge[];
  for (const i of model.entities.interfaces)
    if (
      i.analysis?.dps_enabled !== false &&
      (i.direction === "Bidirectional" || i.analysis?.direction === "Unidirectional") &&
      i.asset_business_ids.length === 2 &&
      !model.entities.data_flows.some(
        (f) => f.interface_business_id === i.business_id,
      )
    )
      edges.push(
        mappedEdgeSchema.parse({
          edge_id: "IFEDGE-" + i.business_id,
          source_asset_id: i.asset_business_ids[0],
          target_asset_id: i.asset_business_ids[1],
          link_type: "Logical",
          direction:
            i.direction === "Bidirectional"
              ? "Bidirectional"
              : "Unidirectional",
          protocol_or_medium: i.protocol_or_medium,
          description: "由核心接口推导：" + i.business_id,
        }),
      );
  const threats: ThreatPoint[] = ordered(model.entities.draft_threats).map(
    (t) => ({
      ...defaults,
      ...configuration.threat_overrides[t.business_id],
      threatpoint_id: t.business_id,
      related_asset_id: t.target_asset_business_id,
      name: t.name,
      preconditions:t.description,
    }),
  );
  return { asset_nodes: assets, asset_edges: edges, threat_points: threats };
}
export function modelDigest(
  model: Pick<SystemModelImportPayload, "entities">,
  configuration: AnalysisConfiguration,
) {
  // Storage IDs, revision counters and actors do not change the logical model.
  const entities = Object.fromEntries(
    Object.entries(model.entities).map(([collection, rows]) => [
      collection,
      rows
        .map((row) => {
          const { id, revision_version, created_by, updated_by, ...semantic } =
            row as unknown as Record<string, unknown>;
          return semantic;
        })
        .sort((a, b) =>
          String(a.business_id).localeCompare(String(b.business_id)),
        ),
    ]),
  );
  return analysisDigest({ entities, configuration });
}
export function analysisTargets(
  graph: ReturnType<typeof mapCoreModel>,
  scope?: string[],
) {
  return new AnalysisService().resolveAnalysisTargetIds(
    graph.asset_nodes,
    scope ? new Set(scope) : null,
  );
}
export function prepareInventory(
  input: InventoryPreview,
): InventoryPreviewResult & { configuration?: AnalysisConfiguration } {
  const original_counts = Object.fromEntries(
    Object.entries(input.inventory.workbook).map(([k, v]) => [k, v.length]),
  );
  const empty = { assets: 0, edges: 0, threats: 0 };
  const fail = (message: string): InventoryPreviewResult => ({
    ok: false,
    errors: [message],
    error_details: [{ message }],
    warnings: [],
    original_counts,
    generated_counts: empty,
    target_ids: [],
  });
  if (input.inventory.source.aircraft_model !== "DO356A-AMS")
    return fail(
      "do356a-ams/v1 仅适用于经核对的 DO356A-AMS 清单；当前机型未确认适用性。",
    );
  const diagnostics = validateInventoryRecords(input.inventory);
  if (diagnostics.length)
    return {
      ok: false,
      errors: diagnostics.map(
        (d) =>
          `${d.sheet} ${d.row ?? "—"} 行 ${d.record_id} ${d.field}：${d.message}`,
      ),
      error_details: diagnostics,
      warnings: [],
      original_counts,
      generated_counts: empty,
      target_ids: [],
    };
  if (
    !input.inventory.workbook.functional_assets.length ||
    !input.inventory.workbook.interface_assets.length ||
    !input.inventory.workbook.data_assets.length
  )
    return fail(
      "功能资产、边界数据流和数据资产至少各包含一条记录，空模板不能提交。",
    );
  const prepared = new CxfImportService().prepareChangeSet(
    input.inventory,
    "inventory-conversion-v1",
  );
  const details = prepared.error_details.map((e) => ({
    ...e,
    sheet: e.sheet ? input.inventory.workbook[e.sheet].find(r=>r.excel_row===e.row)?.source_sheet ?? sheetNames[e.sheet] : "转换规则 do356a-ams/v1",
    record_id: e.sheet
      ? input.inventory.workbook[e.sheet].find((r) => r.excel_row === e.row)?.id
      : undefined,
  }));
  if (!prepared.ok || !prepared.change_set)
    return {
      ok: false,
      errors: prepared.errors,
      error_details: details,
      warnings: prepared.summary.warnings,
      original_counts,
      generated_counts: empty,
      target_ids: [],
    };
  const graph = prepared.change_set;
  const origin = (id?: string) => {
    for (const [sheet, rows] of Object.entries(input.inventory.workbook)) {
      const row = rows.find((r) => r.id === id);
      if (!row) continue;
      const fields = inventoryFields[sheet as keyof typeof inventoryFields];
      return {
        sheet: row.source_sheet ?? sheetNames[sheet as keyof typeof sheetNames],
        row: row.excel_row,
          field_locators: row.field_locators ?? Object.fromEntries(
          fields.map((f, i) => [
            f.key,
            `${String.fromCharCode(65 + i)}${row.excel_row ?? "?"}`,
          ]),
        ),
      };
    }
    return {
      sheet: "转换规则 do356a-ams/v1",
      field_locators: { rule: "do356a-ams/v1" },
    };
  };
  const resolve = (value: string | undefined) =>
    graph.asset_nodes.add.filter(
      (a) =>
        !!value &&
        [a.asset_id, a.business_id, a.asset_name].some(
          (id) => id?.toUpperCase() === value.toUpperCase(),
        ),
    );
  const coreInterfaces = input.inventory.workbook.boundary_interfaces.map(
    (row) => {
      const candidates = graph.asset_nodes.add.filter(
        (a) =>
          a.business_id === row.id ||
          a.boundary_interface_id === row.id ||
          a.boundary_interface_ids?.includes(row.id),
      );
      const bound = [
        ...new Set(
          [...candidates, ...resolve(row.access_object)].map((a) => a.asset_id),
        ),
      ];
      if (!bound.length || bound.length > 2)
        details.push({
          type: "binding",
        sheet: "边界接口表",
          row: row.excel_row,
          field: "access_object",
          record_id: row.id,
          message:
            "边界接口必须通过接入对象或所属边界接口引用唯一绑定到 1–2 个已转换资产，不能猜测端点。",
        });
      return {
        business_id: row.id,
        name: row.name ?? row.id,
        interface_type: row.interface_class ?? "Boundary",
        direction:
          row.direction &&
          [
            "Inbound",
            "Outbound",
            "Bidirectional",
            "Internal",
            "Unknown",
          ].includes(row.direction)
            ? row.direction
            : "Unknown",
        asset_business_ids: bound,
        boundary_business_id: row.boundary_id,
        protocol_or_medium: row.logical_protocol ?? row.physical_interconnect,
        description: row.description,
        analysis: { dps_enabled: false },
        source_locator: {
          sheet: "边界接口表",
          row: row.excel_row,
          field_locators: {},
        },
      };
    },
  );
  const coreSystemFlows = input.inventory.workbook.system_data_flows.map(
    (row) => {
      const producer = resolve(row.producer),
        consumer = resolve(row.consumer);
      for (const [field, values] of [
        ["producer", producer],
        ["consumer", consumer],
      ] as const)
        if (values.length !== 1)
          details.push({
            type: "binding",
        sheet: "系统数据流表",
            row: row.excel_row,
            field,
            record_id: row.id,
            message:
              "系统数据流端点必须唯一匹配转换后的资产编号或名称，不能猜测。",
          });
      return {
        business_id: row.id,
        name: row.content?.slice(0, 300) || row.id,
        producer_asset_business_id: producer[0]?.asset_id ?? "MISSING",
        consumer_asset_business_id: consumer[0]?.asset_id ?? "MISSING",
        content: row.content,
        analysis: { dps_enabled: false },
        source_locator: {
          sheet: "系统数据流表",
          row: row.excel_row,
          field_locators: {},
        },
      };
    },
  );
  if (details.length)
    return {
      ok: false,
      errors: details.map((d) => d.message),
      error_details: details,
      original_counts,
      warnings: prepared.summary.warnings,
      generated_counts: empty,
      target_ids: [],
    };
  const configuration = analysisConfigurationSchema.parse({
    mapping_version: "do356a-ams/v1",
    threat_overrides: Object.fromEntries(
      graph.threat_points.add.map((t) => [
        t.threatpoint_id,
        threatParametersSchema.strip().parse(t),
      ]),
    ),
  });
  const sourceId =
    "SRC-" +
    createHash("sha256").update(input.file_sha256).digest("hex").slice(0, 24);
  const model = systemModelImportPayloadSchema.parse({
    contract_version: "system-model.v2",
    source: {
      business_id: sourceId,
      source_type: "xlsx",
      name: input.inventory.source.file_name ?? "系统资产清单",
      content_hash: input.file_sha256,
      media_type:
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      parser_name: "cxf_asset_inventory_v1/do356a-ams",
      parser_version: "1",
    },
    entities: {
      functions: (graph.function_nodes?.add ?? []).map((f) => ({
        business_id: f.function_id,
        name: f.name,
        description: f.description,
      })),
      interfaces: coreInterfaces,
      external_entities: input.inventory.workbook.threat_actors.map((t) => ({
        business_id: t.id,
        name: t.name,
        entity_type: t.actor_type ?? "ThreatActor",
        description: t.description,
        source_locator: {
          sheet: "威胁主体表",
          row: t.excel_row,
          field_locators: {},
        },
      })),
      assets: graph.asset_nodes.add.map((a, index) => ({
        business_id: a.asset_id,
        name: a.asset_name,
        category: a.asset_type,
        criticality: a.criticality,
        description: a.description,
        tags: a.tags ?? [],
        analysis: Object.fromEntries(
          Object.entries({ ...a, mapping_order: index }).filter(
            ([, v]) => v !== undefined,
          ),
        ),
        source_locator: origin(a.business_id),
      })),
      data_flows: [
        ...graph.asset_edges.add.map((e, index) => ({
          business_id: e.edge_id,
          name: e.description?.slice(0, 300) || e.edge_id,
          description: e.description,
          producer_asset_business_id: e.source_asset_id,
          consumer_asset_business_id: e.target_asset_id,
          analysis: Object.fromEntries(
            Object.entries({ ...e, mapping_order: index }).filter(
              ([, v]) => v !== undefined,
            ),
          ),
          tags: ["auto_generated", "do356a-ams/v1"],
        })),
        ...coreSystemFlows,
      ],
      draft_threats: graph.threat_points.add.map((t, index) => ({
        business_id: t.threatpoint_id,
        name: t.name,
          threat_type: t.stride_category,
          description:t.preconditions,
        target_asset_business_id: t.related_asset_id,
        standard_reference: "DO-356A",
        rationale: "自动威胁候选，未经人工确认；do356a-ams/v1",
        tags: ["auto_generated"],
        analysis: { mapping_order: index },
        source_locator: origin(
          graph.asset_nodes.add.find((a) => a.asset_id === t.related_asset_id)
            ?.business_id,
        ),
      })),
      security_boundaries: input.inventory.workbook.trust_boundaries.map(
        (b) => ({
          business_id: b.id,
          name: b.name,
          boundary_type: "Trust",
          description: b.description,
          member_asset_business_ids: [
            ...new Set([
              ...(graph.trust_boundaries?.add.find(
                (g) => g.boundary_id === b.id,
              )?.domain_asset_ids ?? []),
              ...(graph.trust_boundaries?.add.find(
                (g) => g.boundary_id === b.id,
              )?.interface_asset_ids ?? []),
            ]),
          ],
          source_locator: {
            sheet: "信任边界表",
            row: b.excel_row,
            field_locators: {},
          },
        }),
      ),
    },
  });
  const mapped = mapCoreModel(model, configuration);
  return {
    ok: true,
    errors: [],
    error_details: [],
    original_counts,
    warnings: [
      ...prepared.summary.warnings,
      "AMS 规则仅适用于 DO356A-AMS；自动连接、威胁与目标均需人工核对。",
      ...(coreInterfaces.length || coreSystemFlows.length
        ? [
            "边界接口与系统数据流保存在核心模型；原 DPS 的连接集合保持不变。这些补充清单记录标记 dps_enabled=false，不能当作已经参与 DPS 的连接。",
          ]
        : []),
    ],
    generated_counts: {
      assets: mapped.asset_nodes.length,
      edges: mapped.asset_edges.length,
      threats: mapped.threat_points.length,
    },
    target_ids: [...analysisTargets(mapped)],
    model,
    configuration,
  };
}
export function makeAnalysisInput(
  model: StoredSystemModel,
  configuration: AnalysisConfiguration,
  params: {
    max_hops: number;
    dps_hop_decay: number;
    scope_asset_ids?: string[];
  },
  commandId: string,
  actor: string,
): AnalysisInput {
  const graph = mapCoreModel(model, configuration);
  if (
    params.scope_asset_ids?.some(
      (id) => !graph.asset_nodes.some((a) => a.asset_id === id),
    )
  )
    throw Object.assign(new Error("目标筛选引用了当前修订之外的资产"), {
      statusCode: 409,
    });
  return {
    ...graph,
    ...params,
    analysis_batch_id: commandId,
    generated_by: actor,
  };
}
