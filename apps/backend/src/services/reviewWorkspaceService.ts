import type {
  AddReviewCommentCommand,
  AuthenticatedPrincipal,
  CreateReviewSessionCommand,
  DecideReviewSessionCommand,
  ReviewWriteResult,
} from "@attackgraph/contracts";
import { ReviewWorkspaceRepository } from "../repositories/reviewWorkspaceRepository.js";
import { RevisionUnitOfWork } from "../repositories/revisionUnitOfWork.js";
import { AuthorizationDeniedError, requireRole } from "./auth/apiKeyIdentity.js";

export class ReviewWorkspaceService {
  constructor(
    private readonly repository = new ReviewWorkspaceRepository(),
    private readonly unitOfWork = new RevisionUnitOfWork(),
  ) {}

  async createSession(principal: AuthenticatedPrincipal, command: CreateReviewSessionCommand): Promise<ReviewWriteResult> {
    const role = requireRole(principal, ["SecurityEngineer", "AnalysisReviewer", "EngineeringApprover", "ProjectAdmin"]);
    const result = await this.unitOfWork.execute(
      {
        actor: principal.actor_id, command_id: command.command_id, project_id: command.project_id,
        revision_id: command.revision_id, expected_revision_version: command.expected_revision_version,
        event_type: "REVIEW_SESSION_CREATED", request_canonicalizer: "review-workspace.create-session/v1",
        payload: command.session, summary: "Open a governed review session for a versioned engineering subject",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) => this.repository.createSession(transaction, {
        project_id, revision_id, revision_version: new_revision_version,
        actor_id: principal.actor_id, actor_display_name: principal.display_name, actor_role: role, session: command.session,
      }),
    );
    return { recorded: true, replayed: result.replayed, audit_event_id: result.audit_event_id, new_revision_version: result.new_revision_version, ...result.value };
  }

  async addComment(principal: AuthenticatedPrincipal, command: AddReviewCommentCommand): Promise<ReviewWriteResult> {
    const role = requireRole(principal, ["SecurityEngineer", "AnalysisReviewer", "EngineeringApprover", "ProjectAdmin", "Auditor"]);
    const result = await this.unitOfWork.execute(
      {
        actor: principal.actor_id, command_id: command.command_id, project_id: command.project_id,
        revision_id: command.revision_id, expected_revision_version: command.expected_revision_version,
        event_type: "REVIEW_COMMENT_ADDED", request_canonicalizer: "review-workspace.add-comment/v1",
        payload: { session_id: command.session_id, comment: command.comment }, summary: "Append an attributed comment to a review session",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) => this.repository.addComment(transaction, {
        project_id, revision_id, revision_version: new_revision_version, session_id: command.session_id,
        actor_id: principal.actor_id, actor_display_name: principal.display_name, actor_role: role, comment: command.comment,
      }),
    );
    return { recorded: true, replayed: result.replayed, audit_event_id: result.audit_event_id, new_revision_version: result.new_revision_version, ...result.value };
  }

  async decide(principal: AuthenticatedPrincipal, command: DecideReviewSessionCommand): Promise<ReviewWriteResult> {
    const role = requireRole(principal, command.review.decision === "Approve"
      ? ["EngineeringApprover", "ProjectAdmin"]
      : ["SecurityEngineer", "AnalysisReviewer", "EngineeringApprover", "ProjectAdmin"]);
    const session = await this.repository.inspectSession(command.project_id, command.revision_id, command.session_id);
    if (session.status === "Open" && session.opened_by === principal.actor_id) {
      throw new AuthorizationDeniedError("separation of duties requires the deciding actor to differ from the session opener");
    }
    const result = await this.unitOfWork.execute(
      {
        actor: principal.actor_id, command_id: command.command_id, project_id: command.project_id,
        revision_id: command.revision_id, expected_revision_version: command.expected_revision_version,
        event_type: "REVIEW_DECISION_RECORDED", request_canonicalizer: "review-workspace.decide-session/v1",
        payload: { session_id: command.session_id, review: command.review }, summary: "Record an authenticated human decision and close its review session",
      },
      ({ transaction, project_id, revision_id, new_revision_version }) => this.repository.decide(transaction, {
        project_id, revision_id, revision_version: new_revision_version, session_id: command.session_id,
        actor_id: principal.actor_id, actor_display_name: principal.display_name, actor_role: role, review: command.review,
      }),
    );
    return { recorded: true, replayed: result.replayed, audit_event_id: result.audit_event_id, new_revision_version: result.new_revision_version, ...result.value };
  }

  async read(principal: AuthenticatedPrincipal, projectId: string, revisionId: string) {
    requireRole(principal, ["SecurityEngineer", "AnalysisReviewer", "EngineeringApprover", "ProjectAdmin", "Auditor"]);
    return this.repository.read(projectId, revisionId);
  }
}
