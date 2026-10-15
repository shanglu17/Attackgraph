import { z } from "zod";

const uuid = z.string().uuid().transform((value) => value.toLowerCase());
const businessId = z.string().trim().min(1).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const text = z.string().trim().min(1).max(4_000);

export const reviewWorkspaceContractVersion = "review-workspace.v1" as const;

export const reviewRoleSchema = z.enum([
  "ProjectAdmin",
  "SecurityEngineer",
  "AnalysisReviewer",
  "EngineeringApprover",
  "Auditor",
]);

export const reviewSubjectTypeSchema = z.enum([
  "ThreatCondition",
  "ThreatScenario",
  "RiskAssessment",
  "SecurityObjective",
  "SecurityRequirement",
  "Control",
  "VerificationCase",
  "DerivedResult",
]);

const commandEnvelope = z.object({
  command_id: z.string().trim().min(1).max(200),
  project_id: uuid,
  revision_id: uuid,
  expected_revision_version: z.number().int().positive(),
});

export const createReviewSessionCommandSchema = commandEnvelope.extend({
  session: z.object({
    business_id: businessId,
    title: z.string().trim().min(1).max(300),
    subject: z.object({
      type: reviewSubjectTypeSchema,
      business_id: businessId,
      version: z.number().int().positive(),
    }),
    candidate_business_ids: z.array(businessId).max(2).default([]),
  }),
});

export const addReviewCommentCommandSchema = commandEnvelope.extend({
  session_id: uuid,
  comment: z.object({
    business_id: businessId,
    body: text,
  }),
});

export const decideReviewSessionCommandSchema = commandEnvelope.extend({
  session_id: uuid,
  review: z.object({
    business_id: businessId,
    decision: z.enum(["Accept", "Approve", "Reject", "Return"]),
    rationale: text,
    supersedes_business_id: businessId.optional(),
  }),
});

export const reviewWorkspaceQuerySchema = z.object({
  project_id: uuid,
  revision_id: uuid,
});

export type ReviewRole = z.infer<typeof reviewRoleSchema>;
export type ReviewSubjectType = z.infer<typeof reviewSubjectTypeSchema>;
export type CreateReviewSessionCommand = z.infer<typeof createReviewSessionCommandSchema>;
export type AddReviewCommentCommand = z.infer<typeof addReviewCommentCommandSchema>;
export type DecideReviewSessionCommand = z.infer<typeof decideReviewSessionCommandSchema>;
export type ReviewWorkspaceQuery = z.infer<typeof reviewWorkspaceQuerySchema>;

export interface AuthenticatedPrincipal {
  actor_id: string;
  display_name: string;
  roles: ReviewRole[];
}

export interface StoredReviewComment {
  id: string;
  business_id: string;
  body: string;
  author_actor_id: string;
  author_display_name: string;
  author_role: ReviewRole;
  created_at: string;
  revision_version: number;
}

export interface ReviewEvidenceSummary {
  business_id: string;
  name: string;
  evidence_type?: string;
  status?: string;
  location?: string;
}

export interface StoredReviewSession {
  id: string;
  business_id: string;
  title: string;
  project_id: string;
  revision_id: string;
  subject: { type: ReviewSubjectType; business_id: string; version: number };
  candidate_business_ids: string[];
  status: "Open" | "Reviewed" | "Approved" | "Rejected" | "Returned";
  opened_by: string;
  opened_by_display_name: string;
  opened_by_role: ReviewRole;
  opened_at: string;
  revision_version: number;
  subject_payload?: Record<string, unknown>;
  candidate_payloads: Array<{ business_id: string; payload: Record<string, unknown> }>;
  evidence: ReviewEvidenceSummary[];
  comments: StoredReviewComment[];
  decision?: {
    id: string;
    business_id: string;
    decision: "Accept" | "Approve" | "Reject" | "Return";
    rationale: string;
    reviewer: string;
    reviewer_display_name: string;
    reviewer_role: ReviewRole;
    decided_at: string;
    subject_version: number;
  };
}

export interface ReviewWorkspace {
  contract_version: typeof reviewWorkspaceContractVersion;
  project_id: string;
  revision_id: string;
  revision_version: number;
  sessions: StoredReviewSession[];
}

export interface ReviewWriteResult {
  recorded: boolean;
  replayed: boolean;
  audit_event_id: string;
  new_revision_version: number;
  session_id: string;
  session_status: StoredReviewSession["status"];
  decision_id?: string;
  comment_id?: string;
}
