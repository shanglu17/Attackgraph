import { Router, type NextFunction, type Response } from "express";
import {
  systemModelCommitRequestSchema,
  systemModelPreviewRequestSchema,
  systemModelQuerySchema,
} from "@attackgraph/contracts";
import { SystemModelRepository } from "../repositories/systemModelRepository.js";
import {
  RevisionNotWritableError,
  RevisionWriteConflictError,
  RevisionWriteScopeError,
} from "../repositories/revisionUnitOfWork.js";
import {
  SystemModelConflictError,
  SystemModelScopeNotFoundError,
} from "../repositories/systemModelRepository.js";
import {
  CommandPayloadMismatchError,
  CommandReceiptUnverifiableError,
  CommandReuseError,
} from "../services/governance/commandReceipt.js";
import { SystemModelImportService } from "../services/systemModelImportService.js";

const router = Router();
const repository = new SystemModelRepository();
const importService = new SystemModelImportService(repository);

function invalid(issues: Array<{ path: Array<string | number>; message: string }>) {
  return {
    code: "INVALID_SYSTEM_MODEL_V2_REQUEST",
    errors: issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })),
  };
}

function knownError(error: unknown): { status: number; code: string; message: string } | undefined {
  if (error instanceof SystemModelScopeNotFoundError || error instanceof RevisionWriteScopeError) {
    return { status: 404, code: "SYSTEM_MODEL_SCOPE_NOT_FOUND", message: error.message };
  }
  if (error instanceof RevisionWriteConflictError) {
    return { status: 409, code: "REVISION_VERSION_CONFLICT", message: error.message };
  }
  if (error instanceof RevisionNotWritableError) {
    return { status: 409, code: "REVISION_NOT_WRITABLE", message: error.message };
  }
  if (error instanceof SystemModelConflictError) {
    return { status: 409, code: "SYSTEM_MODEL_IMPORT_CONFLICT", message: error.message };
  }
  if (error instanceof CommandPayloadMismatchError) {
    return { status: 409, code: "COMMAND_PAYLOAD_MISMATCH", message: error.message };
  }
  if (error instanceof CommandReuseError) {
    return { status: 409, code: "COMMAND_REUSE_CONFLICT", message: error.message };
  }
  if (error instanceof CommandReceiptUnverifiableError) {
    return { status: 409, code: "COMMAND_RECEIPT_UNVERIFIABLE", message: error.message };
  }
  return undefined;
}

function forwardKnown(error: unknown, res: Response, next: NextFunction) {
  const mapped = knownError(error);
  if (mapped) return res.status(mapped.status).json({ code: mapped.code, message: mapped.message });
  return next(error);
}

router.post("/import/preview", async (req, res, next) => {
  try {
    const parsed = systemModelPreviewRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    const result = await importService.preview(parsed.data);
    return res.status(result.ok ? 200 : 409).json(result);
  } catch (error) {
    return forwardKnown(error, res, next);
  }
});

router.post("/import/commit", async (req, res, next) => {
  try {
    const parsed = systemModelCommitRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await importService.commit(parsed.data));
  } catch (error) {
    return forwardKnown(error, res, next);
  }
});

router.get("/", async (req, res, next) => {
  try {
    const parsed = systemModelQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.json(await repository.read(parsed.data.project_id, parsed.data.revision_id));
  } catch (error) {
    return forwardKnown(error, res, next);
  }
});

export default router;
