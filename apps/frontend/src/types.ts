export interface AssetNode {
  assetId: string;
  name: string;
  assetType: string;
  criticality: number;
  owner?: string;
  tags?: string[];
}

export interface AssetEdge {
  edgeId: string;
  sourceAssetId: string;
  targetAssetId: string;
  relationType: string;
  trustBoundary: boolean;
  directionality: "UNI" | "BI";
}

export interface ThreatPoint {
  threatId: string;
  name: string;
  category: string;
  severityBase: number;
  preconditionText?: string;
  assetId: string;
}

export interface AttackPath {
  pathId: string;
  analysisBatchId: string;
  hopCount: number;
  score: number;
  priority: "P1" | "P2" | "P3";
  explanations: string[];
  generatedBy: string;
  generatedAt: string;
}

export interface GraphData {
  version: string;
  assets: AssetNode[];
  edges: AssetEdge[];
  threats: ThreatPoint[];
}

export interface ChangeSet<T> {
  add: T[];
  update: T[];
  delete: string[];
}

export interface GraphChangeSet {
  graphVersion: string;
  assets: ChangeSet<AssetNode>;
  edges: ChangeSet<AssetEdge>;
  threats: ChangeSet<ThreatPoint>;
}
