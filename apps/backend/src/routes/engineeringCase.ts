import { Router, type NextFunction, type Response } from "express";
import {
  engineeringCaseCommitRequestSchema,
  engineeringCaseQuerySchema,
  reviewDecisionCommandSchema,
} from "@attackgraph/contracts";
import { EngineeringCaseConflictError, EngineeringCaseRepository } from "../repositories/engineeringCaseRepository.js";
import {
  RevisionNotWritableError,
  RevisionWriteConflictError,
  RevisionWriteScopeError,
} from "../repositories/revisionUnitOfWork.js";
import {
  CommandPayloadMismatchError,
  CommandReceiptUnverifiableError,
  CommandReuseError,
} from "../services/governance/commandReceipt.js";
import { EngineeringCaseService } from "../services/engineeringCaseService.js";

const router = Router();
const repository = new EngineeringCaseRepository();
const service = new EngineeringCaseService(repository);

function invalid(issues: Array<{ path: Array<string | number>; message: string }>) {
  return { code: "INVALID_ENGINEERING_CASE_REQUEST", errors: issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })) };
}

function forwardKnown(error: unknown, res: Response, next: NextFunction) {
  if (error instanceof RevisionWriteScopeError) return res.status(404).json({ code: "ENGINEERING_SCOPE_NOT_FOUND", message: error.message });
  if (error instanceof RevisionWriteConflictError) return res.status(409).json({ code: "REVISION_VERSION_CONFLICT", message: error.message });
  if (error instanceof RevisionNotWritableError) return res.status(409).json({ code: "REVISION_NOT_WRITABLE", message: error.message });
  if (error instanceof EngineeringCaseConflictError) return res.status(409).json({ code: "ENGINEERING_CASE_CONFLICT", message: error.message });
  if (error instanceof CommandPayloadMismatchError) return res.status(409).json({ code: "COMMAND_PAYLOAD_MISMATCH", message: error.message });
  if (error instanceof CommandReuseError) return res.status(409).json({ code: "COMMAND_REUSE_CONFLICT", message: error.message });
  if (error instanceof CommandReceiptUnverifiableError) return res.status(409).json({ code: "COMMAND_RECEIPT_UNVERIFIABLE", message: error.message });
  return next(error);
}

router.post("/commit", async (req, res, next) => {
  try {
    const parsed = engineeringCaseCommitRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.commit(parsed.data));
  } catch (error) {
    return forwardKnown(error, res, next);
  }
});

router.post("/review-decisions", async (req, res, next) => {
  try {
    const parsed = reviewDecisionCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.review(parsed.data));
  } catch (error) {
    return forwardKnown(error, res, next);
  }
});

router.get("/", async (req, res, next) => {
  try {
    const parsed = engineeringCaseQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    const value = await repository.read(parsed.data.project_id, parsed.data.revision_id);
    if (!value) return res.status(404).json({ code: "ENGINEERING_CASE_NOT_FOUND", message: "No Phase 3 engineering case exists in this revision" });
    return res.json(value);
  } catch (error) {
    return next(error);
  }
});

export default router;
