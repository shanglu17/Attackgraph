import { z } from "zod";
const cxfRowBaseSchema = {
  id: z.string().min(1),
  excel_row: z.number().int().min(2).optional(),
  source_sheet: z.string().min(1).optional(),
  field_locators: z.record(z.string()).optional(),
} as const;

export const cxfSourceSchema = z.object({
  aircraft_model: z.string().min(1),
  file_name: z.string().min(1).optional(),
  submitted_by: z.string().min(1),
  submitted_at: z.string().datetime(),
});

export const cxfFunctionalAssetSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  description: z.string().optional(),
});

export const cxfInterfaceAssetSchema = z.object({
  ...cxfRowBaseSchema,
  producer: z.string().min(1),
  producer_ref: z.string().min(1).optional(),
  consumer: z.string().min(1),
  consumer_ref: z.string().min(1).optional(),
  data_flow_description: z.string().optional(),
  data_flow_type: z.string().optional(),
  physical_interface: z.string().optional(),
  logical_interface: z.string().optional(),
  network_domain: z.string().optional(),
  zone: z.string().optional(),
  purpose: z.string().optional(),
  target_function: z.string().optional(),
  boundary_id: z.string().optional(),
  bdf_ids: z.array(z.string().min(1)).optional(),
  enters_internal_propagation: z.boolean().optional(),
  boundary_interface_id: z.string().optional(),
});

export const cxfBoundaryInterfaceSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().optional(),
  interface_class: z.string().optional(),
  external_entity: z.string().optional(),
  access_object: z.string().optional(),
  physical_interconnect: z.string().optional(),
  logical_protocol: z.string().optional(),
  direction: z.string().optional(),
  boundary_id: z.string().optional(),
  description: z.string().optional(),
});

export const cxfTrustBoundarySchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  description: z.string().optional(),
  covered_domain_ids: z.array(z.string().min(1)).optional(),
  threat_actor_ids: z.array(z.string().min(1)).optional(),
  enters_internal_propagation: z.boolean().optional(),
});

export const cxfThreatActorSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  actor_type: z.string().optional(),
  description: z.string().optional(),
});

export const cxfSupportAssetSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  linked_interfaces: z.array(z.string().min(1)).optional(),
  security_domain: z.string().optional(),
  criticality: z.string().optional(),
});

export const cxfDomainPropertySchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  trust_level: z.string().min(1),
  security_domain: z.string().min(1),
  description: z.string().optional(),
});

export const cxfSystemDataFlowSchema = z.object({
  ...cxfRowBaseSchema,
  producer: z.string().optional(),
  consumer: z.string().optional(),
  content: z.string().optional(),
  data_flow_type: z.string().optional(),
  target_function: z.string().optional(),
});

export const cxfDataAssetSchema = z.object({
  ...cxfRowBaseSchema,
  name: z.string().min(1),
  data_type: z.string().optional(),
  data_flow_type: z.string().optional(),
  linked_interfaces: z.string().optional(),
  domain_id: z.string().optional(),
  load_description: z.string().optional(),
  description: z.string().optional(),
  target_function: z.string().optional(),
});

export const cxfImportRequestSchema = z.object({
  template_version: z.literal("cxf_asset_inventory_v1"),
  source: cxfSourceSchema,
  workbook: z.object({
    functional_assets: z.array(cxfFunctionalAssetSchema),
    interface_assets: z.array(cxfInterfaceAssetSchema),
    support_assets: z.array(cxfSupportAssetSchema),
    data_assets: z.array(cxfDataAssetSchema),
    domain_properties: z.array(cxfDomainPropertySchema).default([]),
    trust_boundaries: z.array(cxfTrustBoundarySchema).default([]),
    threat_actors: z.array(cxfThreatActorSchema).default([]),
    boundary_interfaces: z.array(cxfBoundaryInterfaceSchema).default([]),
    system_data_flows: z.array(cxfSystemDataFlowSchema).default([]),
  }),
});

export type Inventory = z.infer<typeof cxfImportRequestSchema>;
