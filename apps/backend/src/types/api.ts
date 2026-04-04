import { z } from "zod";

const assetIdPattern = /^(IS|IF|SYS|EXT)-[A-Z0-9]{2,24}(?:-[A-Z0-9]{2,8})?$/;
const threatIdPattern = /^TP-[A-Z0-9-]+-\d{2}$/;

export const assetNodeSchema = z
  .object({
    asset_id: z.string().regex(assetIdPattern),
    asset_name: z.string().min(2).max(48).regex(/^[A-Za-z\u4e00-\u9fa5][A-Za-z0-9\u4e00-\u9fa5\s\-_\/]{1,47}$/),
    asset_type: z.enum(["Terminal", "Interface", "Link", "Data"]),
    criticality: z.enum(["High", "Medium", "Low"]),
    security_domain: z.enum(["Internal", "External", "DMZ", "Shared"]).optional(),
    description: z.string().max(200).optional(),
    data_classification: z.enum(["Public", "Internal", "Sensitive", "Restricted"]).optional(),
    tags: z.array(z.string().min(1)).optional(),
    is_placeholder: z.boolean().optional(),
    source: z.enum(["manual", "excel_import", "auto_generated"]).optional()
  })
  .superRefine((value, ctx) => {
    if (value.asset_type === "Data" && !value.data_classification) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["data_classification"],
        message: "data_classification is required when asset_type is Data"
      });
    }
  });

export const assetEdgeSchema = z
  .object({
    edge_id: z.string().regex(/^E-[A-Z0-9-]+-[A-Z0-9-]+-\d{2}$/),
    source_asset_id: z.string().regex(assetIdPattern),
    target_asset_id: z.string().regex(assetIdPattern),
    link_type: z.enum(["Physical", "Logical", "DataFlow", "Control"]),
    protocol_or_medium: z.string().min(1).max(64).optional(),
    direction: z.enum(["Unidirectional", "Bidirectional"]),
    trust_level: z.enum(["Trusted", "Semi-Trusted", "Untrusted"]).optional(),
    security_mechanism: z.string().min(1).max(64).optional(),
    description: z.string().max(200).optional()
  })
  .superRefine((value, ctx) => {
    if ((value.link_type === "Logical" || value.link_type === "DataFlow") && !value.protocol_or_medium) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["protocol_or_medium"],
        message: "protocol_or_medium is required when link_type is Logical or DataFlow"
      });
    }
  });

export const threatPointSchema = z
  .object({
    threatpoint_id: z.string().regex(threatIdPattern),
    name: z.string().min(4).max(64),
    related_asset_id: z.string().regex(assetIdPattern),
    stride_category: z.enum([
      "Spoofing",
      "Tampering",
      "Repudiation",
      "InformationDisclosure",
      "DenialOfService",
      "ElevationOfPrivilege"
    ]),
    attack_vector: z.enum(["Network", "Wireless", "Physical", "Maintenance", "SupplyChain"]),
    entry_likelihood_level: z.enum(["High", "Medium", "Low"]).default("Medium"),
    attack_complexity_level: z.enum(["Low", "Medium", "High"]).default("Medium"),
    threat_source: z.enum(["internal", "external", "third-party"]).default("internal"),
    preconditions: z.string().max(200).optional(),
    detection_status: z.enum(["None", "Monitoring", "Mitigated"]).optional(),
    cve_reference: z.string().max(200).optional(),
    expert_modifier: z.number().min(0.5).max(1.5).optional(),
    expert_adjustment_note: z.string().max(500).optional(),
    mitigation_reference: z.string().max(200).optional()
  })
  .superRefine((value, ctx) => {
    if (typeof value.expert_modifier === "number" && value.expert_modifier !== 1 && !value.expert_adjustment_note) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expert_adjustment_note"],
        message: "expert_adjustment_note is required when expert_modifier is not 1.0"
      });
    }
    if (value.expert_adjustment_note && value.expert_adjustment_note.trim().length < 10) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expert_adjustment_note"],
        message: "expert_adjustment_note must be at least 10 characters"
      });
    }
  });

export const do326aLinkSchema = z
  .object({
    link_id: z.string().regex(/^DL-\d{3}$/),
    standard_id: z.string().min(1),
    clause_title: z.string().min(1),
    semantic_element_id: z.array(z.string().min(1)).min(1),
    linkage_type: z.enum(["Requirement", "Evidence", "Mitigation"]),
    evidence_reference: z.string().max(1000).optional(),
    review_status: z.enum(["Draft", "Reviewed", "Approved"]).default("Draft"),
    reviewer: z.string().max(64).optional(),
    mapping_version: z.string().max(64).optional()
  })
  .superRefine((value, ctx) => {
    if ((value.review_status === "Reviewed" || value.review_status === "Approved") && !value.reviewer) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reviewer"],
        message: "reviewer is required when review_status is Reviewed or Approved"
      });
    }
  });

const changeSetSchema = <T extends z.ZodTypeAny>(schema: T) =>
  z.object({
    add: z.array(schema),
    update: z.array(schema),
    delete: z.array(z.string())
  });

export const graphChangeSetSchema = z.object({
  graph_version: z.string().min(1),
  asset_nodes: changeSetSchema(assetNodeSchema),
  asset_edges: changeSetSchema(assetEdgeSchema),
  threat_points: changeSetSchema(threatPointSchema),
  do326a_links: changeSetSchema(do326aLinkSchema)
});

export const runAnalysisSchema = z.object({
  analysis_batch_id: z.string().min(1),
  max_hops: z.number().int().min(1).max(8).default(3),
  generated_by: z.string().min(1),
  scope_asset_ids: z.array(z.string().regex(assetIdPattern)).optional(),
  dps_hop_decay: z.number().min(0.8).max(1).optional()
});

export const persistPathsSchema = z.object({
  paths: z.array(
    z.object({
      path_id: z.string().regex(/^AP-\d{4}$/),
      analysis_batch_id: z.string().min(1),
      entry_point_id: z.string().regex(threatIdPattern),
      target_asset_id: z.string().regex(assetIdPattern),
      hop_sequence: z.string().min(1),
      hop_count: z.number().int().min(1),
      path_probability: z.number().min(0),
      raw_score: z.number().min(0),
      dps_score: z.number().min(0),
      heuristic_score: z.number().min(0),
      normalized_score: z.number().min(0),
      priority_label: z.enum(["High", "Medium", "Low"]),
      is_low_priority: z.boolean(),
      score_config_version: z.string().min(1),
      explanations: z.array(z.string()),
      generated_by: z.string().min(1),
      generated_at: z.string().min(1),
      traverses: z.array(
        z.object({
          hop: z.number().int().min(1),
          edge_id: z.string().min(1),
          asset_id: z.string().regex(assetIdPattern),
          edge_factor: z.number().min(0).max(1)
        })
      )
    })
  )
});

export const do326aReviewSchema = z
  .object({
    review_status: z.enum(["Draft", "Reviewed", "Approved"]),
    reviewer: z.string().max(64).optional()
  })
  .superRefine((value, ctx) => {
    if ((value.review_status === "Reviewed" || value.review_status === "Approved") && !value.reviewer) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reviewer"],
        message: "reviewer is required when review_status is Reviewed or Approved"
      });
    }
  });

export const singleSheetImportRequestSchema = z.object({
  headers: z.array(z.string().min(1)).optional(),
  rows: z.array(z.record(z.unknown()))
});

const cxfRowBaseSchema = {
  id: z.string().min(1),
  excel_row: z.number().int().min(2).optional()
} as const;

export const cxfSourceSchema = z.object({
  aircraft_model: z.string().min(1),
  file_name: z.string().min(1).optional(),
  submitted_by: z.string().min(1),
  submitted_at: z.string().datetime()
});

export const cxfFunctionalAssetSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  description: z.string().optional()
});

export const cxfInterfaceAssetSchema = z.object({
  ...cxfRowBaseSchema,
  producer: z.string().min(1),
  producer_ref: z.string().min(1).optional(),
  consumer: z.string().min(1),
  consumer_ref: z.string().min(1).optional(),
  data_flow_description: z.string().optional(),
  physical_interface: z.string().optional(),
  logical_interface: z.string().optional(),
  network_domain: z.string().optional(),
  zone: z.string().optional(),
  purpose: z.string().optional()
});

export const cxfSupportAssetSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  linked_interfaces: z.array(z.string().min(1)).optional()
});

export const cxfDataAssetSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  data_type: z.string().optional(),
  load_description: z.string().optional(),
  description: z.string().optional()
});

export const cxfImportRequestSchema = z.object({
  template_version: z.literal("cxf_asset_inventory_v1"),
  source: cxfSourceSchema,
  workbook: z.object({
    functional_assets: z.array(cxfFunctionalAssetSchema),
    interface_assets: z.array(cxfInterfaceAssetSchema),
    support_assets: z.array(cxfSupportAssetSchema),
    data_assets: z.array(cxfDataAssetSchema)
  })
});

export const modelingExportQuerySchema = z.object({
  analysis_batch_id: z.preprocess((value) => {
    if (typeof value !== "string") {
      return undefined;
    }
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }, z.string().min(1).optional())
});

export type SingleSheetImportRequest = z.infer<typeof singleSheetImportRequestSchema>;
export type CxfImportRequest = z.infer<typeof cxfImportRequestSchema>;
export type ModelingExportQuery = z.infer<typeof modelingExportQuerySchema>;
