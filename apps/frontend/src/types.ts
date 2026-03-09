export type PriorityLabel = "High" | "Medium" | "Low";
export type ReviewStatus = "Draft" | "Reviewed" | "Approved";

export interface AssetNode {
  asset_id: string;
  asset_name: string;
  asset_type: "Terminal" | "Interface" | "Link" | "Data";
  criticality: "High" | "Medium" | "Low";
  security_domain?: "Internal" | "External" | "DMZ" | "Shared";
  description?: string;
  data_classification?: "Public" | "Internal" | "Sensitive" | "Restricted";
  tags?: string[];
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

export interface GraphData {
  graph_version: string;
  asset_nodes: AssetNode[];
  asset_edges: AssetEdge[];
  threat_points: ThreatPoint[];
  do326a_links: DO326ALink[];
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
