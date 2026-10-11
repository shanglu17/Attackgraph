import { z } from "zod";

export const systemModelContractVersion = "system-model.v2" as const;

export const businessIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(160)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);

const optionalText = z.string().trim().min(1).max(2_000).optional();
const tagList = z.array(z.string().trim().min(1).max(120)).max(100).default([]);

export const sourceLocatorSchema = z.object({
  sheet: z.string().trim().min(1).max(200).optional(),
  row: z.number().int().positive().optional(),
  column: z.string().trim().min(1).max(80).optional(),
  json_pointer: z.string().trim().min(1).max(500).optional(),
  field_locators: z.record(z.string().trim().min(1).max(500)).default({}),
});

const baseEntitySchema = z.object({
  business_id: businessIdSchema,
  name: z.string().trim().min(1).max(300),
  description: optionalText,
  tags: tagList,
  source_locator: sourceLocatorSchema.optional(),
});

export const assetSchema = baseEntitySchema.extend({
  category: z.string().trim().min(1).max(120),
  subtype: z.string().trim().min(1).max(120).optional(),
  criticality: z.enum(["Low", "Medium", "High", "Catastrophic"]).optional(),
  classification: z.string().trim().min(1).max(120).optional(),
  lifecycle_status: z.enum(["Proposed", "Active", "Retired"]).default("Active"),
});

export const functionSchema = baseEntitySchema.extend({
  function_type: z.string().trim().min(1).max(120).optional(),
  parent_function_business_id: businessIdSchema.optional(),
});

export const externalEntitySchema = baseEntitySchema.extend({
  entity_type: z.string().trim().min(1).max(120),
  trust_classification: z.string().trim().min(1).max(120).optional(),
});

export const securityBoundarySchema = baseEntitySchema.extend({
  boundary_type: z.string().trim().min(1).max(120),
  trust_level: z.string().trim().min(1).max(120).optional(),
  member_asset_business_ids: z.array(businessIdSchema).default([]),
});

export const interfaceSchema = baseEntitySchema.extend({
  interface_type: z.string().trim().min(1).max(120),
  direction: z.enum(["Inbound", "Outbound", "Bidirectional", "Internal", "Unknown"]),
  protocol_or_medium: z.string().trim().min(1).max(200).optional(),
  asset_business_ids: z.array(businessIdSchema).min(1).max(2),
  boundary_business_id: businessIdSchema.optional(),
  external_entity_business_id: businessIdSchema.optional(),
});

export const dataFlowSchema = baseEntitySchema.extend({
  producer_asset_business_id: businessIdSchema,
  consumer_asset_business_id: businessIdSchema,
  interface_business_id: businessIdSchema.optional(),
  content: optionalText,
  classification: z.string().trim().min(1).max(120).optional(),
  supported_function_business_ids: z.array(businessIdSchema).default([]),
});

export const draftThreatSchema = baseEntitySchema.extend({
  status: z.literal("Draft").default("Draft"),
  threat_type: z.string().trim().min(1).max(160),
  target_asset_business_id: businessIdSchema,
  standard_reference: z.string().trim().min(1).max(200),
  rationale: optionalText,
});

export const evidenceRecordSchema = z.object({
  business_id: businessIdSchema,
  evidence_type: z.string().trim().min(1).max(120),
  title: z.string().trim().min(1).max(300),
  reference: z.string().trim().min(1).max(1_000),
  content_hash: z.string().trim().regex(/^[a-fA-F0-9]{64}$/).transform((value) => value.toLowerCase()).optional(),
  source_locator: sourceLocatorSchema.optional(),
});

export const traceEndpointTypeSchema = z.enum([
  "Asset", "Function", "Interface", "DataFlow", "SecurityBoundary", "ExternalEntity", "EvidenceRecord", "DraftThreat",
]);

export const traceLinkSchema = z.object({
  business_id: businessIdSchema,
  link_type: z.enum(["DERIVED_FROM", "SATISFIES", "SUPPORTS", "ALLOCATED_TO", "RELATED_TO"]),
  source: z.object({ type: traceEndpointTypeSchema, business_id: businessIdSchema }),
  target: z.object({ type: traceEndpointTypeSchema, business_id: businessIdSchema }),
  rationale: optionalText,
  source_locator: sourceLocatorSchema.optional(),
});

export const sourceRecordSchema = z.object({
  business_id: businessIdSchema,
  source_type: z.string().trim().min(1).max(120),
  name: z.string().trim().min(1).max(500),
  content_hash: z.string().trim().regex(/^[a-fA-F0-9]{64}$/).transform((value) => value.toLowerCase()),
  media_type: z.string().trim().min(1).max(160).optional(),
  parser_name: z.string().trim().min(1).max(160),
  parser_version: z.string().trim().min(1).max(80),
});

export const systemModelImportPayloadSchema = z.object({
  contract_version: z.literal(systemModelContractVersion),
  source: sourceRecordSchema,
  entities: z.object({
    assets: z.array(assetSchema).default([]),
    functions: z.array(functionSchema).default([]),
    interfaces: z.array(interfaceSchema).default([]),
    data_flows: z.array(dataFlowSchema).default([]),
    security_boundaries: z.array(securityBoundarySchema).default([]),
    external_entities: z.array(externalEntitySchema).default([]),
    evidence_records: z.array(evidenceRecordSchema).default([]),
    draft_threats: z.array(draftThreatSchema).default([]),
    trace_links: z.array(traceLinkSchema).default([]),
  }),
});

export const systemModelPreviewRequestSchema = z.object({
  project_id: z.string().uuid().transform((value) => value.toLowerCase()),
  revision_id: z.string().uuid().transform((value) => value.toLowerCase()),
  import: systemModelImportPayloadSchema,
});

export const systemModelCommitRequestSchema = systemModelPreviewRequestSchema.extend({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  expected_revision_version: z.number().int().positive(),
});

export const systemModelQuerySchema = z.object({
  project_id: z.string().uuid().transform((value) => value.toLowerCase()),
  revision_id: z.string().uuid().transform((value) => value.toLowerCase()),
});

export type SourceLocator = z.infer<typeof sourceLocatorSchema>;
export type Asset = z.infer<typeof assetSchema>;
export type SystemFunction = z.infer<typeof functionSchema>;
export type SystemInterface = z.infer<typeof interfaceSchema>;
export type DataFlow = z.infer<typeof dataFlowSchema>;
export type SecurityBoundary = z.infer<typeof securityBoundarySchema>;
export type ExternalEntity = z.infer<typeof externalEntitySchema>;
export type EvidenceRecord = z.infer<typeof evidenceRecordSchema>;
export type DraftThreat = z.infer<typeof draftThreatSchema>;
export type TraceLink = z.infer<typeof traceLinkSchema>;
export type SourceRecord = z.infer<typeof sourceRecordSchema>;
export type SystemModelImportPayload = z.infer<typeof systemModelImportPayloadSchema>;
export type SystemModelPreviewRequest = z.infer<typeof systemModelPreviewRequestSchema>;
export type SystemModelCommitRequest = z.infer<typeof systemModelCommitRequestSchema>;
export type SystemModelQuery = z.infer<typeof systemModelQuerySchema>;

export interface SystemModelCounts {
  assets: number;
  functions: number;
  interfaces: number;
  data_flows: number;
  security_boundaries: number;
  external_entities: number;
  evidence_records: number;
  draft_threats: number;
  trace_links: number;
}

export interface SystemModelPreviewResult {
  contract_version: typeof systemModelContractVersion;
  ok: boolean;
  import_hash: string;
  counts: SystemModelCounts;
  errors: string[];
  warnings: string[];
}

export interface SystemModelCommitResult extends SystemModelPreviewResult {
  committed: boolean;
  replayed: boolean;
  audit_event_id: string;
  new_revision_version: number;
  created_ids: Record<string, string[]>;
}

export interface StoredSystemModel {
  contract_version: typeof systemModelContractVersion;
  project_id: string;
  revision_id: string;
  revision_version: number;
  sources: Array<SourceRecord & { id: string; created_by: string }>;
  entities: {
    assets: Array<Asset & { id: string }>;
    functions: Array<SystemFunction & { id: string }>;
    interfaces: Array<SystemInterface & { id: string }>;
    data_flows: Array<DataFlow & { id: string }>;
    security_boundaries: Array<SecurityBoundary & { id: string }>;
    external_entities: Array<ExternalEntity & { id: string }>;
    evidence_records: Array<EvidenceRecord & { id: string }>;
    draft_threats: Array<DraftThreat & { id: string }>;
    trace_links: Array<TraceLink & { id: string }>;
  };
}

export const traceabilityReportContractVersion = "traceability-report.v1" as const;

export const traceabilityReportQuerySchema = z.object({
  project_id: z.string().uuid().transform((value) => value.toLowerCase()),
  revision_id: z.string().uuid().transform((value) => value.toLowerCase()).optional(),
  baseline_id: z.string().uuid().transform((value) => value.toLowerCase()).optional(),
}).superRefine((value, context) => {
  if ((value.revision_id ? 1 : 0) + (value.baseline_id ? 1 : 0) !== 1) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["revision_id"],
      message: "provide exactly one of revision_id or baseline_id",
    });
  }
});

export const freezeRevisionCommandSchema = z.object({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  project_id: z.string().uuid().transform((value) => value.toLowerCase()),
  revision_id: z.string().uuid().transform((value) => value.toLowerCase()),
  expected_revision_version: z.number().int().positive(),
  baseline: z.object({
    business_id: businessIdSchema,
    content_hash: z.string().trim().regex(/^[a-fA-F0-9]{64}$/).transform((value) => value.toLowerCase()),
  }),
});

export type TraceabilityReportQuery = z.infer<typeof traceabilityReportQuerySchema>;
export type FreezeRevisionCommand = z.infer<typeof freezeRevisionCommandSchema>;

export interface TraceabilityReportEndpoint {
  type: z.infer<typeof traceEndpointTypeSchema>;
  business_id: string;
  name: string;
  status?: string;
}

export interface TraceabilityReportChain {
  trace_link_business_id: string;
  link_type: z.infer<typeof traceLinkSchema>["link_type"];
  source: TraceabilityReportEndpoint;
  target: TraceabilityReportEndpoint;
  standard_reference?: string;
  source_record_business_id?: string;
}

export interface TraceabilityReport {
  metadata: {
    contract_version: typeof traceabilityReportContractVersion;
    generator_version: string;
    generated_at: string;
    generated_by: string;
    content_hash: string;
    integrity_status: "not_frozen" | "matched" | "mismatch";
    disclaimer: string;
  };
  context: {
    project: { id: string; business_id: string; name: string };
    model: { id: string; business_id: string; name: string };
    revision: { id: string; business_id: string; status: string; version: number };
    baseline?: { id: string; business_id: string; status: string; version: number; content_hash: string; frozen_at: string; frozen_by: string };
    standard_profile_version: {
      id: string;
      business_id: string;
      name: string;
      profile_version: string;
      maturity: string;
      standard_references: string[];
    };
  };
  sources: Array<SourceRecord & { id: string; created_by: string }>;
  assets: Array<Asset & { id: string }>;
  draft_threats: Array<DraftThreat & { id: string }>;
  evidence_records: Array<EvidenceRecord & { id: string }>;
  trace_links: Array<TraceLink & { id: string }>;
  chains: TraceabilityReportChain[];
  audit: Array<{ event_type: string; actor: string; occurred_at: string; command_id: string }>;
}
