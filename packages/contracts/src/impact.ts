import { z } from "zod";

export const impactContractVersion = "change-impact.v1" as const;
export const assuranceWorkProductContractVersion = "assurance-work-product.v1" as const;

const businessId = z.string().trim().min(1).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const uuid = z.string().uuid().transform((value) => value.toLowerCase());
const context = z.object({
  revision_id: uuid.optional(),
  baseline_id: uuid.optional(),
}).superRefine((value, refinement) => {
  if ((value.revision_id ? 1 : 0) + (value.baseline_id ? 1 : 0) !== 1) {
    refinement.addIssue({ code: z.ZodIssueCode.custom, path: ["revision_id"], message: "provide exactly one of revision_id or baseline_id" });
  }
});

export const impactPreviewQuerySchema = z.object({
  project_id: uuid,
  from: context,
  to: context,
});

export const impactAssessmentCommandSchema = z.object({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  project_id: uuid,
  revision_id: uuid,
  expected_revision_version: z.number().int().positive(),
  assessment: z.object({
    business_id: businessId,
    title: z.string().trim().min(1).max(300),
    from: context,
    to: context,
    rationale: z.string().trim().min(1).max(2_000),
  }),
});

export const impactDispositionCommandSchema = z.object({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
  project_id: uuid,
  revision_id: uuid,
  expected_revision_version: z.number().int().positive(),
  disposition: z.object({
    business_id: businessId,
    assessment_id: uuid,
    impact_item_id: uuid,
    decision: z.enum(["Accept", "Reanalyze", "Waive", "Defer"]),
    rationale: z.string().trim().min(1).max(2_000),
    reviewer_role: z.string().trim().min(1).max(160),
    due_at: z.string().datetime().optional(),
    waiver_basis: z.string().trim().min(1).max(2_000).optional(),
    supersedes_business_id: businessId.optional(),
  }).superRefine((value, refinement) => {
    if (value.decision === "Defer" && !value.due_at) {
      refinement.addIssue({ code: z.ZodIssueCode.custom, path: ["due_at"], message: "Defer requires due_at" });
    }
    if (value.decision === "Waive" && !value.waiver_basis) {
      refinement.addIssue({ code: z.ZodIssueCode.custom, path: ["waiver_basis"], message: "Waive requires waiver_basis" });
    }
  }),
});

export const impactQuerySchema = z.object({
  project_id: uuid,
  revision_id: uuid,
  assessment_id: uuid.optional(),
});

export const workProductQuerySchema = z.object({
  project_id: uuid,
  revision_id: uuid.optional(),
  baseline_id: uuid.optional(),
  actor: z.string().trim().min(1).max(200).default("work-product-generator"),
}).superRefine((value, refinement) => {
  if ((value.revision_id ? 1 : 0) + (value.baseline_id ? 1 : 0) !== 1) {
    refinement.addIssue({ code: z.ZodIssueCode.custom, path: ["revision_id"], message: "provide exactly one of revision_id or baseline_id" });
  }
});

export type ImpactContext = z.infer<typeof context>;
export type ImpactPreviewQuery = z.infer<typeof impactPreviewQuerySchema>;
export type ImpactAssessmentCommand = z.infer<typeof impactAssessmentCommandSchema>;
export type ImpactDispositionCommand = z.infer<typeof impactDispositionCommandSchema>;
export type ImpactQuery = z.infer<typeof impactQuerySchema>;
export type WorkProductQuery = z.infer<typeof workProductQuerySchema>;

export interface ImpactEntityRef {
  type: string;
  business_id: string;
  name: string;
  status?: string;
}

export interface ImpactDifference {
  change_kind: "Added" | "Removed" | "Modified";
  entity: ImpactEntityRef;
  before_hash?: string;
  after_hash?: string;
  changed_fields: string[];
}

export interface ImpactCandidate {
  entity: ImpactEntityRef;
  impact_kind: "Direct" | "Propagated";
  distance: number;
  trigger_business_ids: string[];
  via_trace_link_business_ids: string[];
}

export interface ImpactPreview {
  contract_version: typeof impactContractVersion;
  project_id: string;
  from: ResolvedImpactContext;
  to: ResolvedImpactContext;
  preview_hash: string;
  differences: ImpactDifference[];
  impacted: ImpactCandidate[];
  diagnostics: string[];
}

export interface ResolvedImpactContext {
  revision_id: string;
  revision_business_id: string;
  revision_version: number;
  baseline_id?: string;
  baseline_business_id?: string;
  baseline_status?: string;
}

export interface StoredImpactDisposition {
  id: string;
  business_id: string;
  decision: "Accept" | "Reanalyze" | "Waive" | "Defer";
  rationale: string;
  reviewer: string;
  reviewer_role: string;
  due_at?: string;
  waiver_basis?: string;
  supersedes_business_id?: string;
  decided_at: string;
  revision_version: number;
}

export interface StoredImpactItem extends ImpactCandidate {
  id: string;
  business_id: string;
  status: "Open" | "Dispositioned";
  disposition?: StoredImpactDisposition;
}

export interface StoredImpactAssessment {
  id: string;
  business_id: string;
  title: string;
  rationale: string;
  project_id: string;
  revision_id: string;
  status: "Open" | "Resolved";
  preview_hash: string;
  from: ResolvedImpactContext;
  to: ResolvedImpactContext;
  differences: ImpactDifference[];
  items: StoredImpactItem[];
  created_at: string;
  created_by: string;
  revision_version: number;
}

export interface ImpactAssessmentResult {
  contract_version: typeof impactContractVersion;
  assessment_id: string;
  audit_event_id: string;
  new_revision_version: number;
  replayed: boolean;
  item_count: number;
  preview_hash: string;
}

export interface ImpactDispositionResult {
  disposition_id: string;
  assessment_status: "Open" | "Resolved";
  audit_event_id: string;
  new_revision_version: number;
  replayed: boolean;
}

export interface TraceabilityMatrixRow {
  trace_link_business_id: string;
  link_type: string;
  source: ImpactEntityRef;
  target: ImpactEntityRef;
  source_record_business_id?: string;
  provenance_status: "Linked" | "Missing";
  review_status: "Approved" | "Reviewed" | "Draft" | "Stale" | "Rejected" | "Unknown";
  coverage_status: "Covered" | "Partial" | "Gap";
}

export interface TraceabilityGap {
  gap_type: "UntracedEntity" | "MissingProvenance" | "UnreviewedConclusion" | "StaleAnalysis" | "OpenImpact";
  entity_type: string;
  business_id: string;
  message: string;
}

export interface AssuranceWorkProduct {
  contract_version: typeof assuranceWorkProductContractVersion;
  metadata: {
    generator_version: string;
    generated_at: string;
    generated_by: string;
    content_hash: string;
    package_status: "Draft" | "Reviewable";
    disclaimer: string;
  };
  context: {
    project_id: string;
    revision_id: string;
    baseline_id?: string;
    baseline_status?: string;
    profile_business_id: string;
    profile_version: string;
    standard_references: string[];
  };
  coverage: {
    covered: number;
    partial: number;
    gaps: number;
    percentage: number;
  };
  matrix: TraceabilityMatrixRow[];
  gaps: TraceabilityGap[];
  impact_assessments: StoredImpactAssessment[];
  sections: Array<{
    section_id: string;
    title: string;
    profile_basis: string[];
    status: "Draft" | "Reviewable";
    conclusions: Array<{ statement: string; basis_trace_link_business_ids: string[] }>;
  }>;
}
