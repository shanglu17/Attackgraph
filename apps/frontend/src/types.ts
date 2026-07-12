export type PriorityLabel = "High" | "Medium" | "Low";
export type ReviewStatus = "Draft" | "Reviewed" | "Approved";
export type FhaSeverity = "Catastrophic" | "Hazardous" | "Major" | "Minor" | "NoSafetyEffect" | "Unknown";
export type CiaAttribute = "C" | "I" | "A";
export type CxfSheetName =
  | "functional_assets"
  | "interface_assets"
  | "support_assets"
  | "data_assets"
  | "domain_properties"
  | "trust_boundaries"
  | "threat_actors"
  | "boundary_interfaces"
  | "system_data_flows";

export interface AssetNode {
  asset_id: string;
  asset_name: string;
  asset_type: "Terminal" | "Interface" | "Link" | "Data";
  criticality: "High" | "Medium" | "Low";
  security_domain?: "Internal" | "External" | "DMZ" | "Shared";
  description?: string;
  data_classification?: "Public" | "Internal" | "Sensitive" | "Restricted";
  tags?: string[];
  is_placeholder?: boolean;
  source?: "manual" | "excel_import" | "auto_generated";
  business_id?: string;
  data_flow_type?: string;
  bdf_ids?: string[];
  enters_internal_propagation?: boolean;
  boundary_interface_id?: string;
  boundary_interface_ids?: string[];
}

export interface BoundaryInterface {
  interface_id: string;
  name?: string;
  interface_class?: string;
  external_entity?: string;
  access_object?: string;
  physical_interconnect?: string;
  logical_protocol?: string;
  direction?: string;
  boundary_id?: string;
  description?: string;
}

export interface FunctionNode {
  function_id: string;
  name: string;
  description?: string;
}

export interface TrustBoundary {
  boundary_id: string;
  name: string;
  description?: string;
  enters_internal_propagation?: boolean;
  interface_asset_ids?: string[];
  domain_asset_ids?: string[];
}

export interface ThreatActor {
  actor_id: string;
  name: string;
  actor_type: "external" | "internal" | "third-party";
  description?: string;
  boundary_ids?: string[];
}

export interface SystemDataFlow {
  sdf_id: string;
  producer?: string;
  consumer?: string;
  content?: string;
  data_flow_type?: string;
  function_ids?: string[];
  failure_condition_ids?: string[];
  system_interface_id?: string;
  description?: string;
}

export interface FailureCondition {
  failure_condition_id: string;
  name: string;
  flight_phases: string[];
  hazard_class: string;
  severity: FhaSeverity;
  max_failure_probability?: string;
  source_ref?: string;
  notes?: string;
  sdf_ids?: string[];
  function_ids?: string[];
  path_ids?: string[];
}

export interface ThreatCondition {
  tc_id: string;
  function_id?: string;
  failure_condition_ids: string[];
  flight_phases?: string[];
  affected_assets?: string[];
  cia_attributes: CiaAttribute[];
  description?: string;
  aircraft_effect?: string;
  system_effect?: string;
  crew_effect?: string;
  occupant_effect?: string;
  severity: FhaSeverity;
  severity_source: "FHA" | "manual" | "default";
  path_ids: string[];
  coverage_status: "linked" | "unlinked";
  review_status: ReviewStatus;
  is_default?: boolean;
}

export interface ThreatScenario {
  ts_id: string;
  threat_actor_id?: string;
  tc_ids: string[];
  attack_vector?: "Network" | "Wireless" | "Physical" | "Maintenance" | "SupplyChain";
  attack_path: string;
  existing_security_measures?: string;
  review_status: ReviewStatus;
  is_default?: boolean;
}

export interface FhaImportRequest {
  source: {
    file_name: string;
    submitted_by: string;
    submitted_at: string;
  };
  failure_conditions: FailureCondition[];
}

export interface F353204Defaults {
  cia_modes: Array<{ value: "single" | "all_non_empty"; label: string }>;
  aircraft_effect_options: string[];
  system_effect_options: string[];
  crew_effect_options: string[];
  occupant_effect_options: string[];
  reference_notes: string[];
}

export interface F353204GenerationResult {
  generated: boolean;
  defaults: F353204Defaults;
  threat_conditions: ThreatCondition[];
  threat_scenarios: ThreatScenario[];
  coverage: {
    total_failure_conditions: number;
    linked_failure_conditions: number;
    unlinked_failure_condition_ids: string[];
    generated_tc_count: number;
    generated_ts_count: number;
  };
}

export interface FunctionPropagationPath {
  fp_id: string;
  data_type_label?: string;
  system_path_text?: string;
  sdf_note?: string;
  bdf_ids?: string[];
  sdf_ids?: string[];
  description?: string;
}

export interface AssetEdge {
  edge_id: string;
  source_asset_id: string;
  target_asset_id: string;
  link_type: "Physical" | "Logical" | "DataFlow" | "Control";
  protocol_or_medium?: string;
  direction: "Unidirectional" | "Bidirectional";
  trust_level?: "Trusted" | "Semi-Trusted" | "Untrusted";
  security_mechanism?: string;
  description?: string;
}

export interface ThreatPoint {
  threatpoint_id: string;
  name: string;
  related_asset_id: string;
  stride_category:
    | "Spoofing"
    | "Tampering"
    | "Repudiation"
    | "InformationDisclosure"
    | "DenialOfService"
    | "ElevationOfPrivilege";
  attack_vector: "Network" | "Wireless" | "Physical" | "Maintenance" | "SupplyChain";
  entry_likelihood_level: "High" | "Medium" | "Low";
  attack_complexity_level: "Low" | "Medium" | "High";
  threat_source: "internal" | "external" | "third-party";
  preconditions?: string;
  detection_status?: "None" | "Monitoring" | "Mitigated";
  cve_reference?: string;
  expert_modifier?: number;
  expert_adjustment_note?: string;
  mitigation_reference?: string;
}

export interface AttackPath {
  path_id: string;
  analysis_batch_id: string;
  entry_point_id: string;
  target_asset_id: string;
  hop_sequence: string;
  hop_count: number;
  path_probability: number;
  raw_score: number;
  dps_score: number;
  heuristic_score: number;
  normalized_score: number;
  priority_label: PriorityLabel;
  is_low_priority: boolean;
  score_config_version: string;
  explanations: string[];
  generated_by: string;
  generated_at: string;
  traverses: Array<{ hop: number; edge_id: string; asset_id: string; edge_factor: number }>;
}

export interface DO326ALink {
  link_id: string;
  standard_id: string;
  clause_title: string;
  semantic_element_id: string[];
  linkage_type: "Requirement" | "Evidence" | "Mitigation";
  evidence_reference?: string;
  review_status: ReviewStatus;
  reviewer?: string;
  mapping_version?: string;
}

export interface StandardClause {
  clause_id: string;
  std: string;
  parent_id?: string;
  level?: number;
  number?: string;
  section?: string;
  title_zh?: string;
  title_en?: string;
  clause_type?: string;
  normative?: string;
  keywords?: string[];
  pdf_page?: number;
  text_zh?: string;
  text_en?: string;
  notes?: string;
}

export interface StandardArtifactField {
  field_id: string;
  artifact_id: string;
  artifact_name?: string;
  seq: number;
  field_name_zh: string;
  required: boolean;
  data_type: string;
  enum_or_ref?: string;
  fill_guidance?: string;
  example?: string;
  clause_ref?: string;
  clause_title?: string;
  source?: string;
  trace_role?: string;
}

export interface StandardArtifactType {
  artifact_id: string;
  name_zh: string;
  name_en?: string;
  io_role: "input" | "output" | "intermediate";
  pipeline_slot: string;
  primary_clause_id?: string;
  primary_clause_title?: string;
  scope_status?: "active" | "placeholder" | "deprecated";
  source_ref?: string;
  description?: string;
  fields?: StandardArtifactField[];
}

export interface StandardKnowledgeSummary {
  standard_id: string;
  counts: {
    clauses: number;
    clause_relations: number;
    artifact_types: number;
    artifact_fields: number;
    pipeline_stages: number;
  };
  imported_at?: string;
}

export interface StandardMapping {
  mapping_id: string;
  standard_id: string;
  clause_id: string;
  semantic_element_type: string;
  semantic_element_id: string;
  linkage_type: "Requirement" | "Evidence" | "Mitigation" | "Input" | "Output";
  evidence_reference?: string;
  review_status: ReviewStatus;
}

export interface GraphData {
  graph_version: string;
  asset_nodes: AssetNode[];
  asset_edges: AssetEdge[];
  threat_points: ThreatPoint[];
  do326a_links: DO326ALink[];
  function_nodes?: FunctionNode[];
  trust_boundaries?: TrustBoundary[];
  threat_actors?: ThreatActor[];
  boundary_interfaces?: BoundaryInterface[];
  system_data_flows?: SystemDataFlow[];
  function_propagation_paths?: FunctionPropagationPath[];
}

export interface ChangeSet<T> {
  add: T[];
  update: T[];
  delete: string[];
}

export interface GraphChangeSet {
  graph_version: string;
  asset_nodes: ChangeSet<AssetNode>;
  asset_edges: ChangeSet<AssetEdge>;
  threat_points: ChangeSet<ThreatPoint>;
  do326a_links: ChangeSet<DO326ALink>;
  function_nodes?: ChangeSet<FunctionNode>;
  trust_boundaries?: ChangeSet<TrustBoundary>;
  threat_actors?: ChangeSet<ThreatActor>;
  boundary_interfaces?: ChangeSet<BoundaryInterface>;
  system_data_flows?: ChangeSet<SystemDataFlow>;
  function_propagation_paths?: ChangeSet<FunctionPropagationPath>;
  function_links?: Array<{ asset_id: string; function_id: string }>;
}

export interface ModelingExportMetadata {
  exported_at: string;
  filter: {
    analysis_batch_id?: string;
  };
  graph_version: string;
  counts: {
    asset_nodes: number;
    asset_edges: number;
    threat_points: number;
    do326a_links: number;
    analysis_paths: number;
  };
}

export interface ModelingExportData {
  metadata: ModelingExportMetadata;
  payload: {
    graph: GraphData;
    analysis_paths: AttackPath[];
    do326a_links: DO326ALink[];
  };
}

export interface CxfFunctionalAssetRow {
  id: string;
  name: string;
  description?: string;
  excel_row?: number;
}

export interface CxfInterfaceAssetRow {
  id: string;
  producer: string;
  producer_ref?: string;
  consumer: string;
  consumer_ref?: string;
  data_flow_description?: string;
  data_flow_type?: string;
  physical_interface?: string;
  logical_interface?: string;
  network_domain?: string;
  zone?: string;
  purpose?: string;
  target_function?: string;
  boundary_id?: string;
  bdf_ids?: string[];
  enters_internal_propagation?: boolean;
  boundary_interface_id?: string;
  excel_row?: number;
}

export interface CxfBoundaryInterfaceRow {
  id: string;
  name?: string;
  interface_class?: string;
  external_entity?: string;
  access_object?: string;
  physical_interconnect?: string;
  logical_protocol?: string;
  direction?: string;
  boundary_id?: string;
  description?: string;
  excel_row?: number;
}

export interface CxfTrustBoundaryRow {
  id: string;
  name: string;
  description?: string;
  covered_domain_ids?: string[];
  threat_actor_ids?: string[];
  enters_internal_propagation?: boolean;
  excel_row?: number;
}

export interface CxfThreatActorRow {
  id: string;
  name: string;
  actor_type?: string;
  description?: string;
  excel_row?: number;
}

export interface CxfSystemDataFlowRow {
  id: string;
  producer?: string;
  consumer?: string;
  content?: string;
  data_flow_type?: string;
  target_function?: string;
  excel_row?: number;
}

export interface CxfSupportAssetRow {
  id: string;
  name: string;
  linked_interfaces?: string[];
  security_domain?: string;
  criticality?: string;
  excel_row?: number;
}

export interface CxfDataAssetRow {
  id: string;
  name: string;
  data_type?: string;
  data_flow_type?: string;
  linked_interfaces?: string;
  domain_id?: string;
  load_description?: string;
  description?: string;
  target_function?: string;
  excel_row?: number;
}

export interface CxfDomainPropertyRow {
  id: string;
  name: string;
  trust_level: string;
  security_domain: string;
  description?: string;
  excel_row?: number;
}

export interface CxfImportRequest {
  template_version: "cxf_asset_inventory_v1";
  source: {
    aircraft_model: string;
    file_name?: string;
    submitted_by: string;
    submitted_at: string;
  };
  workbook: {
    functional_assets: CxfFunctionalAssetRow[];
    interface_assets: CxfInterfaceAssetRow[];
    support_assets: CxfSupportAssetRow[];
    data_assets: CxfDataAssetRow[];
    domain_properties: CxfDomainPropertyRow[];
    trust_boundaries: CxfTrustBoundaryRow[];
    threat_actors: CxfThreatActorRow[];
    boundary_interfaces: CxfBoundaryInterfaceRow[];
    system_data_flows: CxfSystemDataFlowRow[];
  };
}

export interface CxfImportErrorDetail {
  type: "field" | "binding";
  sheet?: CxfSheetName;
  row?: number;
  field?: string;
  message: string;
}

export interface CxfAutoThreatSummary {
  threatpoint_id: string;
  related_asset_id: string;
  asset_name: string;
  threat_kind: "ingress" | "integrity" | "control_misuse";
  attack_vector: ThreatPoint["attack_vector"];
  stride_category: ThreatPoint["stride_category"];
}

export interface CxfImportSummary {
  asset_nodes_to_add: number;
  asset_edges_to_add: number;
  threat_points_to_add: number;
  auto_placeholder_assets_to_add: number;
  warnings: string[];
  auto_generated_threats: CxfAutoThreatSummary[];
}

export interface CxfImportPreviewResult {
  ok: boolean;
  accepted: {
    functional_assets: number;
    interface_assets: number;
    support_assets: number;
    data_assets: number;
    domain_properties: number;
  };
  errors: string[];
  error_details: CxfImportErrorDetail[];
  summary: CxfImportSummary;
}

export interface CxfImportCommitResult extends CxfImportPreviewResult {
  committed: boolean;
  commit_id?: string;
  new_version?: string;
}

export interface F3532BoundaryInterfaceRow {
  id: string;
  interface_class?: string;
  external_entity?: string;
  access_object?: string;
  access_device?: string;
  physical_interconnect?: string;
  logical_protocol?: string;
  direction?: string;
  description?: string;
  notes?: string;
  excel_row?: number;
}

export interface F3532BoundaryDataFlowRow {
  id: string;
  producer?: string;
  consumer?: string;
  destination?: string;
  description?: string;
  data_flow_type?: string;
  target_function?: string;
  failure_condition?: string;
  notes?: string;
  boundary_interface_id?: string;
  excel_row?: number;
}

export interface F3532SystemInterfaceRow {
  id: string;
  producer?: string;
  consumer?: string;
  interface_type?: string;
  protocol?: string;
  direction?: string;
  content?: string;
  notes?: string;
  excel_row?: number;
}

export interface F3532SystemDataFlowRow {
  id: string;
  producer?: string;
  consumer?: string;
  destination?: string;
  content?: string;
  data_flow_type?: string;
  target_function?: string;
  failure_condition?: string;
  notes?: string;
  system_interface_id?: string;
  excel_row?: number;
}

export interface F3532ThreatActorRow {
  id: string;
  name?: string;
  actor_type?: string;
  description?: string;
  excel_row?: number;
}

export interface F3532TrustBoundaryRow {
  boundary_id: string;
  name?: string;
  description?: string;
  covered_scope?: string;
  threat_actor_refs?: string;
  excel_row?: number;
}

export interface F3532InputImportRequest {
  template_version: "f3532_input_01_02_v1";
  source: {
    aircraft_model: string;
    file_names?: string[];
    submitted_by: string;
    submitted_at: string;
  };
  workbook: {
    boundary_interfaces: F3532BoundaryInterfaceRow[];
    boundary_data_flows: F3532BoundaryDataFlowRow[];
    system_interfaces: F3532SystemInterfaceRow[];
    system_data_flows: F3532SystemDataFlowRow[];
    threat_actors: F3532ThreatActorRow[];
    trust_boundaries: F3532TrustBoundaryRow[];
  };
}

export interface F3532InputImportErrorDetail {
  type: "field" | "binding";
  sheet?: keyof F3532InputImportRequest["workbook"];
  row?: number;
  field?: string;
  message: string;
}

export interface F3532InputImportSummary {
  asset_nodes_to_add: number;
  asset_edges_to_add: number;
  boundary_interfaces_to_add: number;
  trust_boundaries_to_add: number;
  threat_actors_to_add: number;
  system_data_flows_to_add: number;
  function_nodes_to_add: number;
  function_links_to_add: number;
  warnings: string[];
}

export interface F3532InputImportPreviewResult {
  ok: boolean;
  accepted: {
    boundary_interfaces: number;
    boundary_data_flows: number;
    system_interfaces: number;
    system_data_flows: number;
    threat_actors: number;
    trust_boundaries: number;
  };
  errors: string[];
  error_details: F3532InputImportErrorDetail[];
  summary: F3532InputImportSummary;
}

export interface F3532InputImportCommitResult extends F3532InputImportPreviewResult {
  committed: boolean;
  commit_id?: string;
  new_version?: string;
}

export interface TrustBoundaryReportRow {
  boundary_id: string;
  name: string;
  description?: string;
  interfaces: string[];
  threat_actors: string[];
}

export interface BoundaryDataFlowReportRow {
  boundary_id: string;
  boundary_name: string;
  data_flow_type: string;
  interfaces: string[];
  bdf_ids: string[];
  function_ids: string[];
  enters_internal_propagation: boolean;
}

export interface FunctionPropagationReportRow {
  fp_id: string;
  data_type: string;
  entry_bis: string[];
  bdf_ids: string[];
  sdf_ids: string[];
  sdf_note?: string;
  system_path: string;
  function_ids: string[];
}

export interface InternalDataFlowReportRow {
  sdf_id: string;
  producer: string;
  consumer: string;
  data_flow_type: string;
  content?: string;
  function_ids: string[];
  origin_class: string;
  boundary_reachable: boolean;
}

export interface F3532Report03Data {
  metadata: {
    generated_at?: string;
    loaded_at?: string;
    graph_version: string;
    fp_count?: number;
  };
  boundary_data_flows: {
    count: number;
    rows: BoundaryDataFlowReportRow[];
  };
  function_propagation: {
    count: number;
    rows: FunctionPropagationReportRow[];
  };
  generated?: boolean;
}
