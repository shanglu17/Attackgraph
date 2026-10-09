export type ProjectStatus = "Active" | "Archived";
export type ModelStatus = "Active" | "Archived";
export type RevisionStatus = "Draft" | "InReview" | "Closed";
export type BaselineStatus = "Frozen" | "Approved" | "Retired";
export type StandardProfileMaturity = "Draft" | "Active" | "Deprecated";

export interface Project {
  id: string;
  business_id: string;
  name: string;
  description?: string;
  status: ProjectStatus;
  version: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

export interface Model {
  id: string;
  project_id: string;
  business_id: string;
  name: string;
  level: string;
  status: ModelStatus;
  version: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

export interface Revision {
  id: string;
  project_id: string;
  model_id: string;
  standard_profile_version_id: string;
  business_id: string;
  status: RevisionStatus;
  version: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

export interface StandardProfileVersion {
  id: string;
  project_id: string;
  business_id: string;
  name: string;
  profile_version: string;
  standard_references: string[];
  maturity: StandardProfileMaturity;
  version: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

export interface Baseline {
  id: string;
  project_id: string;
  model_id: string;
  source_revision_id: string;
  standard_profile_version_id: string;
  business_id: string;
  content_hash: string;
  status: BaselineStatus;
  version: number;
  created_at: string;
  created_by: string;
  frozen_at: string;
  frozen_by: string;
  updated_at: string;
  updated_by: string;
  approved_at?: string;
  approved_by?: string;
  approval_rationale?: string;
}

export interface ProjectWorkspace {
  project: Project;
  model: Model;
  revision: Revision;
  standard_profile_version: StandardProfileVersion;
  replayed: boolean;
}

export interface CommandResult<T> {
  value: T;
  replayed: boolean;
}
