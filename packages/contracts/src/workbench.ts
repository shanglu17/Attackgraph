import { z } from "zod";
import { cxfImportRequestSchema } from "./inventory.js";
import type { StoredSystemModel, SystemModelImportPayload } from "./index.js";

export const workbenchScopeSchema = z.object({
  project_id: z.string().uuid(),
  revision_id: z.string().uuid(),
});
export const workbenchCommandSchema = workbenchScopeSchema.extend({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  expected_revision_version: z.number().int().positive(),
});
export const threatParametersSchema = z
  .object({
    entry_likelihood_level: z.enum(["High", "Medium", "Low"]),
    attack_complexity_level: z.enum(["Low", "Medium", "High"]),
    threat_source: z.enum(["internal", "external", "third-party"]),
    stride_category: z.enum([
      "Spoofing",
      "Tampering",
      "Repudiation",
      "InformationDisclosure",
      "DenialOfService",
      "ElevationOfPrivilege",
    ]),
    attack_vector: z.enum([
      "Network",
      "Wireless",
      "Physical",
      "Maintenance",
      "SupplyChain",
    ]),
    expert_modifier: z.number().min(0.5).max(1.5).optional(),
    expert_adjustment_note: z.string().max(2000).optional(),
  })
  .strict();
export const analysisConfigurationSchema = z
  .object({
    mapping_version: z
      .enum(["core-dps/v1", "do356a-ams/v1"])
      .default("core-dps/v1"),
    threat_overrides: z.record(threatParametersSchema).default({}),
  })
  .strict();
export const inventoryPreviewSchema = workbenchScopeSchema.extend({
  contract_version: z.literal("inventory-import.v1"),
  conversion_profile: z.literal("do356a-ams/v1"),
  file_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  inventory: cxfImportRequestSchema,
});
export const inventoryCommitSchema = inventoryPreviewSchema.merge(
  workbenchCommandSchema,
);
export const editPreviewSchema = workbenchCommandSchema
  .extend({
    contract_version: z.literal("model-edit.v1"),
    entities: z.record(z.array(z.unknown())),
    configuration: analysisConfigurationSchema,
  })
  .strict();
export const savedAnalysisSchema = workbenchCommandSchema
  .extend({
    contract_version: z.literal("saved-model-analysis.v1"),
    parameters: z
      .object({
        max_hops: z.number().int().min(1).max(8),
        dps_hop_decay: z.number().min(0.8).max(1),
        scope_asset_ids: z.array(z.string().min(1)).optional(),
      })
      .strict(),
  })
  .strict();
export const workbenchExportSchema = workbenchScopeSchema
  .extend({
    run_id: z.string().uuid(),
    parameters: savedAnalysisSchema.shape.parameters,
  })
  .strict();
export type WorkbenchExportRequest = z.infer<typeof workbenchExportSchema>;
export type WorkbenchScope = z.infer<typeof workbenchScopeSchema>;
export type WorkbenchCommand = z.infer<typeof workbenchCommandSchema>;
export type AnalysisConfiguration = z.infer<typeof analysisConfigurationSchema>;
export type ThreatParameters = z.infer<typeof threatParametersSchema>;
export type InventoryPreview = z.infer<typeof inventoryPreviewSchema>;
export type InventoryCommit = z.infer<typeof inventoryCommitSchema>;
export type SavedAnalysisCommand = z.infer<typeof savedAnalysisSchema>;
export type EditCommand = Omit<
  z.infer<typeof editPreviewSchema>,
  "entities"
> & { entities: SystemModelImportPayload["entities"] };
export interface WorkspaceChoice {
  project_id: string;
  project_name: string;
  project_business_id: string;
  model_id: string;
  model_name: string;
  revision_id: string;
  revision_business_id: string;
  revision_version: number;
  status: string;
}
export interface FieldDifference {
  collection: string;
  business_id: string;
  field: string;
  before?: unknown;
  after?: unknown;
}
export interface EditPreview {
  ok: boolean;
  errors: string[];
  differences: FieldDifference[];
}
export interface WorkbenchSnapshot {
  model: StoredSystemModel;
  configuration: AnalysisConfiguration;
  model_hash: string;
  graph: {
    asset_nodes: unknown[];
    asset_edges: unknown[];
    threat_points: unknown[];
  };
  target_ids: string[];
  status: string;
}
export interface InventoryPreviewResult {
  ok: boolean;
  errors: string[];
  error_details: Array<{
    sheet?: string;
    row?: number;
    field?: string;
    record_id?: string;
    message: string;
  }>;
  warnings: string[];
  original_counts: Record<string, number>;
  generated_counts: { assets: number; edges: number; threats: number };
  target_ids: string[];
  model?: SystemModelImportPayload;
}
