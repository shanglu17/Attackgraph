import { Router } from "express";
import {
  addReviewCommentCommandSchema,
  createReviewSessionCommandSchema,
  decideReviewSessionCommandSchema,
  reviewWorkspaceQuerySchema,
} from "@attackgraph/contracts";
import { authenticateRequest, AuthenticationRequiredError, AuthorizationDeniedError } from "../services/auth/apiKeyIdentity.js";
import { ReviewWorkspaceService } from "../services/reviewWorkspaceService.js";

const router = Router();
const service = new ReviewWorkspaceService();

function invalid(issues: Array<{ path: Array<string | number>; message: string }>) {
  return { code: "INVALID_REVIEW_WORKSPACE_REQUEST", errors: issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })) };
}

function authFailure(error: unknown) {
  if (error instanceof AuthenticationRequiredError) return { status: 401, code: "AUTHENTICATION_REQUIRED" };
  if (error instanceof AuthorizationDeniedError) return { status: 403, code: "AUTHORIZATION_DENIED" };
  return undefined;
}

router.get("/", async (req, res, next) => {
  try {
    const principal = authenticateRequest(req);
    const parsed = reviewWorkspaceQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    const workspace = await service.read(principal, parsed.data.project_id, parsed.data.revision_id);
    return workspace ? res.json(workspace) : res.status(404).json({ code: "REVIEW_SCOPE_NOT_FOUND", message: "project/revision scope not found" });
  } catch (error) {
    const failure = authFailure(error);
    if (failure) return res.status(failure.status).json({ code: failure.code, message: (error as Error).message });
    return next(error);
  }
});

router.post("/sessions", async (req, res, next) => {
  try {
    const principal = authenticateRequest(req);
    const parsed = createReviewSessionCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.createSession(principal, parsed.data));
  } catch (error) {
    const failure = authFailure(error);
    if (failure) return res.status(failure.status).json({ code: failure.code, message: (error as Error).message });
    return next(error);
  }
});

router.post("/comments", async (req, res, next) => {
  try {
    const principal = authenticateRequest(req);
    const parsed = addReviewCommentCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.addComment(principal, parsed.data));
  } catch (error) {
    const failure = authFailure(error);
    if (failure) return res.status(failure.status).json({ code: failure.code, message: (error as Error).message });
    return next(error);
  }
});

router.post("/decisions", async (req, res, next) => {
  try {
    const principal = authenticateRequest(req);
    const parsed = decideReviewSessionCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.decide(principal, parsed.data));
  } catch (error) {
    const failure = authFailure(error);
    if (failure) return res.status(failure.status).json({ code: failure.code, message: (error as Error).message });
    return next(error);
  }
});

export default router;
