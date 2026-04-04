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
}

export interface GraphSnapshot {
  graph_version: string;
  asset_nodes: AssetNode[];
  asset_edges: AssetEdge[];
  threat_points: ThreatPoint[];
  do326a_links: DO326ALink[];
}

export interface ModelingExportBundle {
  graph: GraphSnapshot;
  analysis_paths: AttackPath[];
  do326a_links: DO326ALink[];
}

export interface AuditRecord {
  commit_id: string;
  user_id: string;
  created_at: string;
  summary: string;
  new_version: string;
}
