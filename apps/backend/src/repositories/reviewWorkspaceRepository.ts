import { randomUUID } from "node:crypto";
import type { ManagedTransaction } from "neo4j-driver";
import {
  reviewWorkspaceContractVersion,
  type ReviewRole,
  type ReviewWorkspace,
  type StoredReviewComment,
  type StoredReviewSession,
} from "@attackgraph/contracts";
import { getDriver } from "../db/neo4j.js";

type Properties = Record<string, unknown>;

export class ReviewWorkspaceConflictError extends Error {
  readonly statusCode = 409;
  constructor(message: string) {
    super(message);
    this.name = "ReviewWorkspaceConflictError";
  }
}

export class ReviewWorkspaceNotFoundError extends Error {
  readonly statusCode = 404;
  constructor(message: string) {
    super(message);
    this.name = "ReviewWorkspaceNotFoundError";
  }
}

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") {
    return value.toNumber();
  }
  return Number(value);
}

function properties(record: { get(key: string): unknown }, key: string): Properties {
  const node = record.get(key);
  if (typeof node !== "object" || node === null || !("properties" in node)) throw new TypeError(`Expected Neo4j node '${key}'`);
  return (node as { properties: Properties }).properties;
}

function payloadOf(input: Properties): Record<string, unknown> | undefined {
  if (input.payload_json == null) return undefined;
  try {
    return JSON.parse(String(input.payload_json)) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

export interface ReviewSessionInspection {
  id: string;
  status: StoredReviewSession["status"];
  opened_by: string;
  subject: StoredReviewSession["subject"];
}

export class ReviewWorkspaceRepository {
  async createSession(transaction: ManagedTransaction, input: {
    project_id: string;
    revision_id: string;
    revision_version: number;
    actor_id: string;
    actor_display_name: string;
    actor_role: ReviewRole;
    session: { business_id: string; title: string; subject: StoredReviewSession["subject"]; candidate_business_ids: string[] };
  }): Promise<{ session_id: string; session_status: "Open" }> {
    const sessionId = randomUUID();
    const result = await transaction.run(
      `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})
       MATCH (subject {project_id: $project_id, revision_id: $revision_id, business_id: $subject_business_id, revision_version: $subject_version})
       WHERE subject.entity_type = $subject_type
       CREATE (session:ReviewSession {
         id: $session_id, business_id: $business_id, project_id: $project_id, revision_id: $revision_id,
         title: $title, subject_type: $subject_type, subject_business_id: $subject_business_id,
         subject_version: $subject_version, candidate_business_ids: $candidate_business_ids,
         status: 'Open', opened_by: $actor_id, opened_by_display_name: $actor_display_name,
         opened_by_role: $actor_role, opened_at: datetime(), revision_version: $revision_version
       })
       CREATE (revision)-[:CONTAINS]->(session)
       CREATE (session)-[:REVIEWS]->(subject)
       RETURN session.id AS id`,
      {
        project_id: input.project_id,
        revision_id: input.revision_id,
        revision_version: input.revision_version,
        actor_id: input.actor_id,
        actor_display_name: input.actor_display_name,
        actor_role: input.actor_role,
        session_id: sessionId,
        business_id: input.session.business_id,
        title: input.session.title,
        subject_type: input.session.subject.type,
        subject_business_id: input.session.subject.business_id,
        subject_version: input.session.subject.version,
        candidate_business_ids: input.session.candidate_business_ids,
      },
    );
    if (result.records.length === 0) throw new ReviewWorkspaceConflictError("review subject/version is not present in this revision");
    return { session_id: sessionId, session_status: "Open" };
  }

  async addComment(transaction: ManagedTransaction, input: {
    project_id: string;
    revision_id: string;
    revision_version: number;
    session_id: string;
    actor_id: string;
    actor_display_name: string;
    actor_role: ReviewRole;
    comment: { business_id: string; body: string };
  }): Promise<{ session_id: string; session_status: StoredReviewSession["status"]; comment_id: string }> {
    const commentId = randomUUID();
    const result = await transaction.run(
      `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})-[:CONTAINS]->(session:ReviewSession {id: $session_id})
       WHERE session.status = 'Open'
       CREATE (comment:ReviewComment {
         id: $comment_id, business_id: $business_id, project_id: $project_id, revision_id: $revision_id,
         body: $body, author_actor_id: $actor_id, author_display_name: $actor_display_name,
         author_role: $actor_role, created_at: datetime(), revision_version: $revision_version
       })
       CREATE (session)-[:HAS_COMMENT]->(comment)
       CREATE (revision)-[:CONTAINS]->(comment)
       RETURN session.status AS status`,
      { ...input, comment_id: commentId, business_id: input.comment.business_id, body: input.comment.body },
    );
    if (result.records.length === 0) throw new ReviewWorkspaceConflictError("review session is missing, out of scope, or no longer open");
    return { session_id: input.session_id, session_status: String(result.records[0].get("status")) as "Open", comment_id: commentId };
  }

  async decide(transaction: ManagedTransaction, input: {
    project_id: string;
    revision_id: string;
    revision_version: number;
    session_id: string;
    actor_id: string;
    actor_display_name: string;
    actor_role: ReviewRole;
    review: { business_id: string; decision: "Accept" | "Approve" | "Reject" | "Return"; rationale: string; supersedes_business_id?: string };
  }): Promise<{ session_id: string; session_status: StoredReviewSession["status"]; decision_id: string }> {
    const status = ({ Accept: "Reviewed", Approve: "Approved", Reject: "Rejected", Return: "Returned" } as const)[input.review.decision];
    const subjectStatus = input.review.decision === "Return" ? "Draft" : status;
    const decisionId = randomUUID();
    const result = await transaction.run(
      `MATCH (revision:Revision {id: $revision_id, project_id: $project_id})-[:CONTAINS]->(session:ReviewSession {id: $session_id, status: 'Open'})
       MATCH (session)-[:REVIEWS]->(subject)
       OPTIONAL MATCH (prior:ReviewDecision {project_id: $project_id, revision_id: $revision_id, business_id: $supersedes_business_id})
       CREATE (decision:ReviewDecision {
         id: $decision_id, business_id: $business_id, project_id: $project_id, revision_id: $revision_id,
         subject_type: session.subject_type, subject_business_id: session.subject_business_id,
         subject_version: session.subject_version, decision: $decision, rationale: $rationale,
         reviewer: $actor_id, reviewer_display_name: $actor_display_name, reviewer_role: $actor_role,
         revision_version: $revision_version, decided_at: datetime()
       })
       SET session.status = $session_status, session.closed_at = datetime(), session.closed_by = $actor_id,
           session.revision_version = $revision_version,
           subject.status = $subject_status, subject.reviewed_at = datetime(), subject.reviewed_by = $actor_id
       CREATE (revision)-[:CONTAINS]->(decision)
       CREATE (decision)-[:DECIDES]->(subject)
       CREATE (session)-[:HAS_DECISION]->(decision)
       FOREACH (_ IN CASE WHEN prior IS NULL THEN [] ELSE [1] END | CREATE (decision)-[:SUPERSEDES]->(prior))
       RETURN decision.id AS id`,
      {
        project_id: input.project_id,
        revision_id: input.revision_id,
        revision_version: input.revision_version,
        session_id: input.session_id,
        decision_id: decisionId,
        business_id: input.review.business_id,
        decision: input.review.decision,
        rationale: input.review.rationale,
        supersedes_business_id: input.review.supersedes_business_id ?? null,
        actor_id: input.actor_id,
        actor_display_name: input.actor_display_name,
        actor_role: input.actor_role,
        session_status: status,
        subject_status: subjectStatus,
      },
    );
    if (result.records.length === 0) throw new ReviewWorkspaceConflictError("review session is missing, out of scope, or already closed");
    return { session_id: input.session_id, session_status: status, decision_id: decisionId };
  }

  async inspectSession(projectId: string, revisionId: string, sessionId: string): Promise<ReviewSessionInspection> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((transaction) => transaction.run(
        `MATCH (review:ReviewSession {id: $session_id, project_id: $project_id, revision_id: $revision_id})
         RETURN review`,
        { project_id: projectId, revision_id: revisionId, session_id: sessionId },
      ));
      if (result.records.length === 0) throw new ReviewWorkspaceNotFoundError(`review session '${sessionId}' was not found`);
      const item = properties(result.records[0], "review");
      return {
        id: String(item.id),
        status: String(item.status) as StoredReviewSession["status"],
        opened_by: String(item.opened_by),
        subject: { type: item.subject_type as StoredReviewSession["subject"]["type"], business_id: String(item.subject_business_id), version: numeric(item.subject_version) },
      };
    } finally {
      await session.close();
    }
  }

  async read(projectId: string, revisionId: string): Promise<ReviewWorkspace | undefined> {
    const session = getDriver().session();
    try {
      return await session.executeRead(async (transaction) => {
        const revisionResult = await transaction.run(
          `MATCH (:Project {id: $project_id})-[:HAS_MODEL]->(:Model)-[:HAS_REVISION]->(revision:Revision {id: $revision_id})
           RETURN revision.version AS version`,
          { project_id: projectId, revision_id: revisionId },
        );
        if (revisionResult.records.length === 0) return undefined;
        const sessionsResult = await transaction.run(
          `MATCH (review:ReviewSession {project_id: $project_id, revision_id: $revision_id})
           OPTIONAL MATCH (review)-[:REVIEWS]->(subject)
           RETURN review, subject ORDER BY review.opened_at DESC`,
          { project_id: projectId, revision_id: revisionId },
        );
        const stored: StoredReviewSession[] = [];
        for (const row of sessionsResult.records) {
          const item = properties(row, "review");
          const subjectNode = row.get("subject");
          const subjectProperties = typeof subjectNode === "object" && subjectNode !== null && "properties" in subjectNode
            ? (subjectNode as { properties: Properties }).properties : {};
          const commentsResult = await transaction.run(
            `MATCH (:ReviewSession {id: $session_id})-[:HAS_COMMENT]->(comment:ReviewComment)
             RETURN comment ORDER BY comment.created_at`, { session_id: String(item.id) },
          );
          const comments: StoredReviewComment[] = commentsResult.records.map((commentRow) => {
            const comment = properties(commentRow, "comment");
            return {
              id: String(comment.id), business_id: String(comment.business_id), body: String(comment.body),
              author_actor_id: String(comment.author_actor_id), author_display_name: String(comment.author_display_name),
              author_role: String(comment.author_role) as ReviewRole, created_at: String(comment.created_at),
              revision_version: numeric(comment.revision_version),
            };
          });
          const candidateBusinessIds = stringList(item.candidate_business_ids);
          const candidatesResult = candidateBusinessIds.length === 0 ? undefined : await transaction.run(
            `MATCH (candidate {project_id: $project_id, revision_id: $revision_id})
             WHERE candidate.business_id IN $business_ids
             RETURN candidate ORDER BY candidate.business_id`,
            { project_id: projectId, revision_id: revisionId, business_ids: candidateBusinessIds },
          );
          const evidenceResult = await transaction.run(
            `MATCH (evidence:CoreEntity {project_id: $project_id, revision_id: $revision_id, entity_type: 'EvidenceRecord'})
             MATCH (link:TraceLink {project_id: $project_id, revision_id: $revision_id})
             WHERE (link.source_type = $subject_type AND link.source_business_id = $subject_business_id AND link.target_type = 'EvidenceRecord' AND link.target_business_id = evidence.business_id)
                OR (link.target_type = $subject_type AND link.target_business_id = $subject_business_id AND link.source_type = 'EvidenceRecord' AND link.source_business_id = evidence.business_id)
             RETURN DISTINCT evidence ORDER BY evidence.business_id`,
            { project_id: projectId, revision_id: revisionId, subject_type: String(item.subject_type), subject_business_id: String(item.subject_business_id) },
          );
          const decisionResult = await transaction.run(
            `MATCH (:ReviewSession {id: $session_id})-[:HAS_DECISION]->(decision:ReviewDecision)
             RETURN decision ORDER BY decision.decided_at DESC LIMIT 1`, { session_id: String(item.id) },
          );
          const decision = decisionResult.records.length === 0 ? undefined : (() => {
            const value = properties(decisionResult.records[0], "decision");
            return {
              id: String(value.id), business_id: String(value.business_id),
              decision: String(value.decision) as "Accept" | "Approve" | "Reject" | "Return",
              rationale: String(value.rationale), reviewer: String(value.reviewer),
              reviewer_display_name: String(value.reviewer_display_name ?? value.reviewer),
              reviewer_role: String(value.reviewer_role) as ReviewRole, decided_at: String(value.decided_at),
              subject_version: numeric(value.subject_version),
            };
          })();
          stored.push({
            id: String(item.id), business_id: String(item.business_id), title: String(item.title),
            project_id: projectId, revision_id: revisionId,
            subject: { type: item.subject_type as StoredReviewSession["subject"]["type"], business_id: String(item.subject_business_id), version: numeric(item.subject_version) },
            candidate_business_ids: candidateBusinessIds,
            status: String(item.status) as StoredReviewSession["status"], opened_by: String(item.opened_by),
            opened_by_display_name: String(item.opened_by_display_name), opened_by_role: String(item.opened_by_role) as ReviewRole,
            opened_at: String(item.opened_at), revision_version: numeric(item.revision_version),
            subject_payload: payloadOf(subjectProperties),
            candidate_payloads: (candidatesResult?.records ?? []).map((candidateRow) => {
              const candidate = properties(candidateRow, "candidate");
              return { business_id: String(candidate.business_id), payload: payloadOf(candidate) ?? candidate };
            }),
            evidence: evidenceResult.records.map((evidenceRow) => {
              const evidence = properties(evidenceRow, "evidence");
              const payload = payloadOf(evidence) ?? {};
              return {
                business_id: String(evidence.business_id), name: String(payload.name ?? evidence.business_id),
                evidence_type: payload.evidence_type == null ? undefined : String(payload.evidence_type),
                status: payload.status == null ? undefined : String(payload.status),
                location: payload.location == null ? undefined : String(payload.location),
              };
            }),
            comments,
            decision,
          });
        }
        return {
          contract_version: reviewWorkspaceContractVersion,
          project_id: projectId,
          revision_id: revisionId,
          revision_version: numeric(revisionResult.records[0].get("version")),
          sessions: stored,
        };
      });
    } finally {
      await session.close();
    }
  }
}
