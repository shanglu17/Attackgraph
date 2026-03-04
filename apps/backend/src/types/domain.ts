export type Priority = "P1" | "P2" | "P3";
export type EntryLikelihoodLevel = "High" | "Medium" | "Low";
export type AttackComplexityLevel = "Low" | "Medium" | "High";
export type AttackSourceType = "internal" | "external" | "third-party";

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
  entryLikelihoodLevel?: EntryLikelihoodLevel;
  attackComplexityLevel?: AttackComplexityLevel;
  sourceType?: AttackSourceType;
  expertModifier?: number;
  expertAdjustmentNote?: string;
}

export interface AttackPath {
  pathId: string;
  analysisBatchId: string;
  hopCount: number;
  rawScore: number;
  normalizedScore: number;
  isLowPriority: boolean;
  scoreConfigVersion: string;
  score: number;
  priority: Priority;
  explanations: string[];
  generatedBy: string;
  generatedAt: string;
  startsFromThreatId: string;
  hits: Array<{ hop: number; assetId: string }>;
  traverses: Array<{ hop: number; edgeId: string; assetId: string }>;
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

export interface AuditRecord {
  commitId: string;
  userId: string;
  createdAt: string;
  summary: string;
}
