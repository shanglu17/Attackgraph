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
export type ReviewStatus = "Draft" | "Reviewed" | "Approved";

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

export interface AuditRecord {
  commit_id: string;
  user_id: string;
  created_at: string;
  summary: string;
  new_version: string;
}
