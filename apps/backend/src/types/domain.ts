export type AssetType = "Terminal" | "Interface" | "Link" | "Data";
export type CriticalityLevel = "High" | "Medium" | "Low";
export type SecurityDomain = "Internal" | "External" | "DMZ" | "Shared";
export type DataClassification = "Public" | "Internal" | "Sensitive" | "Restricted";
export type AssetSource = "manual" | "excel_import" | "auto_generated";

export type LinkType = "Physical" | "Logical" | "DataFlow" | "Control";
export type Direction = "Unidirectional" | "Bidirectional";
export type TrustLevel = "Trusted" | "Semi-Trusted" | "Untrusted";

export type StrideCategory =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "InformationDisclosure"
  | "DenialOfService"
  | "ElevationOfPrivilege";
export type AttackVector = "Network" | "Wireless" | "Physical" | "Maintenance" | "SupplyChain";
export type DetectionStatus = "None" | "Monitoring" | "Mitigated";

export type EntryLikelihoodLevel = "High" | "Medium" | "Low";
export type AttackComplexityLevel = "Low" | "Medium" | "High";
export type ThreatSource = "internal" | "external" | "third-party";

export type PriorityLabel = "High" | "Medium" | "Low";

export type LinkageType = "Requirement" | "Evidence" | "Mitigation";
export type StandardLinkageType = LinkageType | "Input" | "Output";
export type ReviewStatus = "Draft" | "Reviewed" | "Approved";
export type FhaSeverity = "Catastrophic" | "Hazardous" | "Major" | "Minor" | "NoSafetyEffect" | "Unknown";
export type CiaAttribute = "C" | "I" | "A";

export interface AssetNode {
  asset_id: string;
  asset_name: string;
  asset_type: AssetType;
  criticality: CriticalityLevel;
  security_domain?: SecurityDomain;
  description?: string;
  data_classification?: DataClassification;
  tags?: string[];
  is_placeholder?: boolean;
  source?: AssetSource;
  /** Original business identifier from import (e.g. BI01, SD01, F2, D.1) — enables reverse-mapping to report tables. */
  business_id?: string;
  /** Data flow type for interface/data assets (CMD/CONFIG/STATE/DATA/LOAD/ALERT/SENSOR). */
  data_flow_type?: string;
  /** Boundary data flow ids carried by this interface asset (e.g. BDF08, BDF12). */
  bdf_ids?: string[];
  /** Whether this interface's data flows enter internal propagation analysis. */
  enters_internal_propagation?: boolean;
  /** For a BDF interface asset: the boundary interface (BI) it flows over (e.g. BI02). */
  boundary_interface_id?: string;
  /** For a BDF interface asset carried by multiple BIs. */
  boundary_interface_ids?: string[];
  /** Exact AFHA/FHA failure-condition ids referenced by a boundary data flow row. */
  failure_condition_ids?: string[];
}

export interface AssetEdge {
  edge_id: string;
  source_asset_id: string;
  target_asset_id: string;
  link_type: LinkType;
  protocol_or_medium?: string;
  direction: Direction;
  trust_level?: TrustLevel;
  security_mechanism?: string;
  description?: string;
}

export interface ThreatPoint {
  threatpoint_id: string;
  name: string;
  related_asset_id: string;
  stride_category: StrideCategory;
  attack_vector: AttackVector;
  entry_likelihood_level: EntryLikelihoodLevel;
  attack_complexity_level: AttackComplexityLevel;
  threat_source: ThreatSource;
  preconditions?: string;
  detection_status?: DetectionStatus;
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
  linkage_type: LinkageType;
  evidence_reference?: string;
  review_status: ReviewStatus;
  reviewer?: string;
  mapping_version?: string;
}

export type StandardIoRole = "input" | "output" | "intermediate";
export type StandardScopeStatus = "active" | "placeholder" | "deprecated";
export type StandardRelationType =
  | "PARENT_OF"
  | "REFERENCES"
  | "TRIGGERS"
  | "ITERATES_WITH"
  | "DEPENDS_ON"
  | "TAILORS"
  | "DEFINES"
  | "CHECKS"
  | "PRODUCES";

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

export interface StandardClauseRelation {
  relation_id: string;
  source_clause_id: string;
  target_clause_id: string;
  relation_type: StandardRelationType;
  description?: string;
}

export interface StandardArtifactType {
  artifact_id: string;
  name_zh: string;
  name_en?: string;
  io_role: StandardIoRole;
  pipeline_slot: string;
  primary_clause_id?: string;
  primary_clause_title?: string;
  scope_status?: StandardScopeStatus;
  source_ref?: string;
  description?: string;
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

export interface StandardPipelineStage {
  stage_id: string;
  stage_name?: string;
  key_question?: string;
  inputs?: string[];
  activities?: string;
  outputs?: string[];
  termination_condition?: string;
}

export interface StandardMapping {
  mapping_id: string;
  standard_id: string;
  clause_id: string;
  semantic_element_type: string;
  semantic_element_id: string;
  linkage_type: StandardLinkageType;
  evidence_reference?: string;
  review_status: ReviewStatus;
}

export interface StandardKnowledgeBase {
  clauses: StandardClause[];
  clause_relations: StandardClauseRelation[];
  artifact_types: StandardArtifactType[];
  artifact_fields: StandardArtifactField[];
  pipeline_stages: StandardPipelineStage[];
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

export type ThreatActorType = "external" | "internal" | "third-party";

/** Functional asset (F1..Fn) — promoted to a first-class node so report tables can reference it. */
export interface FunctionNode {
  function_id: string;
  name: string;
  description?: string;
}

/** Trust boundary (SB-01..) from vol3 §4.2. Many-to-many with D.x security domains. */
export interface TrustBoundary {
  boundary_id: string;
  name: string;
  description?: string;
  enters_internal_propagation?: boolean;
  /** Resolved asset_ids of interface assets (BI) inside this boundary. */
  interface_asset_ids?: string[];
  /** Resolved asset_ids of domain-property assets (D.x) covered by this boundary. */
  domain_asset_ids?: string[];
}

/** Boundary interface (BI01..) from vol1 表7-1 — the security-boundary crossing point (aircraft ↔ external). */
export interface BoundaryInterface {
  interface_id: string;
  name?: string;
  interface_class?: string;
  external_entity?: string;
  access_object?: string;
  physical_interconnect?: string;
  logical_protocol?: string;
  direction?: string;
  /** boundary_id of the TrustBoundary (SB) this interface belongs to. */
  boundary_id?: string;
  description?: string;
}

/** Threat actor/source (TA-E-xx / TA-I-xx) associated with trust boundaries. */
export interface ThreatActor {
  actor_id: string;
  name: string;
  actor_type: ThreatActorType;
  description?: string;
  /** boundary_ids of TrustBoundary nodes this actor threatens. */
  boundary_ids?: string[];
}

/** Asset → Function relationship (SUPPORTS_FUNCTION). */
export interface FunctionLink {
  asset_id: string;
  function_id: string;
}

/** System data flow (SDF01..) from vol3 附录E — an internal flow between two onboard subsystems. */
export interface SystemDataFlow {
  sdf_id: string;
  producer?: string;
  consumer?: string;
  content?: string;
  data_flow_type?: string;
  /** function_ids (F1..) this SDF supports — drives the 影响功能 derivation in table 4-5. */
  function_ids?: string[];
  /** Exact AFHA/FHA failure-condition ids referenced by the source 01 workbook. */
  failure_condition_ids?: string[];
  /** Source system-interface id from the 01 workbook. */
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
  attack_vector?: AttackVector;
  attack_path: string;
  existing_security_measures?: string;
  review_status: ReviewStatus;
  is_default?: boolean;
}

/** Function propagation path (FP01..) from vol3 表4-5 — expert grouping of BDFs into a propagation chain. */
export interface FunctionPropagationPath {
  fp_id: string;
  /** Data-type label with semantic suffix, e.g. "CMD（飞行控制）". */
  data_type_label?: string;
  /** Subsystem-level propagation chain text, e.g. "RCS → DLS → IMS → FMS → FCS". */
  system_path_text?: string;
  /** Free-text shown in the 关联SDF column when no SDF ids apply (e.g. "无直接对应SDF"). */
  sdf_note?: string;
  /** BDF business_ids included in this path (INCLUDES_BDF). */
  bdf_ids?: string[];
  /** SDF ids included in this path (INCLUDES_SDF). */
  sdf_ids?: string[];
  description?: string;
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
  /** SUPPORTS_FUNCTION links to (re)create; old ones cleared when assets are DETACH DELETEd on re-import. */
  function_links?: FunctionLink[];
}

export interface GraphSnapshot {
  graph_version: string;
  asset_nodes: AssetNode[];
  asset_edges: AssetEdge[];
  threat_points: ThreatPoint[];
  do326a_links: DO326ALink[];
  function_nodes: FunctionNode[];
  trust_boundaries: TrustBoundary[];
  threat_actors: ThreatActor[];
  boundary_interfaces: BoundaryInterface[];
  system_data_flows: SystemDataFlow[];
  function_propagation_paths: FunctionPropagationPath[];
}

export interface ModelingExportBundle {
  graph: GraphSnapshot;
  analysis_paths: AttackPath[];
  do326a_links: DO326ALink[];
}

/** vol3 §4.2 信任边界汇总表 — one row per trust boundary. */
export interface TrustBoundaryReportRow {
  boundary_id: string;
  name: string;
  description?: string;
  /** 对应接口(BI) business_ids. */
  interfaces: string[];
  /** 相关威胁主体(TA) actor_ids. */
  threat_actors: string[];
}

/** vol3 §4.3.x 边界数据流分析表 — one row per (boundary, data_flow_type). */
export interface BoundaryDataFlowReportRow {
  boundary_id: string;
  boundary_name: string;
  data_flow_type: string;
  /** 典型接口(BI) business_ids. */
  interfaces: string[];
  /** 关联BDF ids. */
  bdf_ids: string[];
  /** 关联功能(F) function_ids. */
  function_ids: string[];
  /** 是否进入内部传播分析. */
  enters_internal_propagation: boolean;
}

/** vol3 表4-5 功能传播路径（FP）识别结果 — one row per FP. */
export interface FunctionPropagationReportRow {
  fp_id: string;
  /** 数据类型 label, e.g. "CMD（飞行控制）". */
  data_type: string;
  /** 入口BI — derived from each BDF's boundary interface. */
  entry_bis: string[];
  /** 关联BDF business_ids. */
  bdf_ids: string[];
  /** 关联SDF ids (empty when sdf_note is used instead). */
  sdf_ids: string[];
  /** Free-text fallback for the 关联SDF column when no SDF ids apply. */
  sdf_note?: string;
  /** 系统传播路径 chain text. */
  system_path: string;
  /** 影响功能 — derived from the union of BDF and SDF SUPPORTS_FUNCTION links. */
  function_ids: string[];
}

/**
 * Internal data flow analysis row — one per SystemDataFlow (SDF), organized IMS-centric.
 * Surfaces flows that do NOT enter from a boundary: `boundary_reachable=false` marks a
 * "pure internal" flow that no boundary entry can reach via type-channel propagation.
 */
export interface InternalDataFlowReportRow {
  sdf_id: string;
  producer: string;
  consumer: string;
  data_flow_type: string;
  content?: string;
  /** 影响功能 — F-ids this SDF supports. */
  function_ids: string[];
  /** 以 IMS 为核心的归类: "IMS发起" | "汇入IMS" | "其他内部". */
  origin_class: string;
  /** false = 纯内部流（任何边界入口都到不了）. */
  boundary_reachable: boolean;
}

export interface AuditRecord {
  commit_id: string;
  user_id: string;
  created_at: string;
  summary: string;
  new_version: string;
}
