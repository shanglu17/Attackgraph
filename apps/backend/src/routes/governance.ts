import { z } from "zod";
import { projectLifecycleCommandSchema } from "@attackgraph/contracts";
import { ProjectLifecycleRepository, ProjectLifecycleError } from "../repositories/projectLifecycleRepository.js";
import { RevisionNotWritableError } from "../repositories/revisionUnitOfWork.js";
import { Router } from "express";
import { freezeRevisionCommandSchema } from "@attackgraph/contracts";
import {
  CommandPayloadMismatchError,
  CommandReceiptUnverifiableError,
  CommandReuseError,
  GovernanceConflictError,
  GovernanceNotFoundError,
} from "../repositories/governanceRepository.js";
import { createProjectWorkspaceSchema } from "../services/governance/contracts.js";
import { GovernanceService } from "../services/governance/governanceService.js";
import { WorkbenchRepository } from "../repositories/workbenchRepository.js";

const router = Router();
const service = new GovernanceService();
router.get("/workspaces", async (_req,res,next)=>{try {res.json({workspaces:await new WorkbenchRepository().list(_req.query.view==="management.v1")});} catch(error){next(error);} });

function invalid(issues: Array<{ path: Array<string | number>; message: string }>) {
  return {
    code: "INVALID_GOVERNANCE_V2_REQUEST",
    errors: issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })),
  };
}

function conflict(error: unknown) {
  if(error instanceof RevisionNotWritableError) return "PROJECT_READ_ONLY";
  if (error instanceof CommandPayloadMismatchError) return "COMMAND_PAYLOAD_MISMATCH";
  if (error instanceof CommandReuseError) return "COMMAND_REUSE_CONFLICT";
  if (error instanceof CommandReceiptUnverifiableError) return "COMMAND_RECEIPT_UNVERIFIABLE";
  if (error instanceof GovernanceConflictError) return "GOVERNANCE_CONFLICT";
  return undefined;
}

router.post("/workspaces", async (req, res, next) => {
  try {
    const parsed = createProjectWorkspaceSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.createProjectWorkspace(parsed.data));
  } catch (error) {
    const code = conflict(error);
    if (code) return res.status(409).json({ code, message: (error as Error).message });
    return next(error);
  }
});

router.post("/revisions/freeze", async (req, res, next) => {
  try {
    const parsed = freezeRevisionCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.freezeRevision(parsed.data));
  } catch (error) {
    if (error instanceof GovernanceNotFoundError) {
      return res.status(404).json({ code: "GOVERNANCE_SCOPE_NOT_FOUND", message: error.message });
    }
    const code = conflict(error);
    if (code) return res.status(409).json({ code, message: (error as Error).message });
    return next(error);
  }
});

export default router;

router.get("/projects/:id/overview",async(req,res,next)=>{try{const id=z.string().uuid().parse(req.params.id);res.json(await new ProjectLifecycleRepository().overview(id));}catch(e){if(e instanceof z.ZodError)return res.status(400).json(invalid(e.issues));if(e instanceof ProjectLifecycleError)return res.status(e.statusCode).json({code:"PROJECT_LIFECYCLE_ERROR",message:e.message});next(e);}});
router.post("/projects/lifecycle",async(req,res,next)=>{try{const input=projectLifecycleCommandSchema.parse(req.body);res.json(await new ProjectLifecycleRepository().execute(input));}catch(e){if(e instanceof z.ZodError)return res.status(400).json(invalid(e.issues));if(e instanceof ProjectLifecycleError)return res.status(e.statusCode).json({code:"PROJECT_LIFECYCLE_ERROR",message:e.message});const code=conflict(e);if(code)return res.status(409).json({code,message:(e as Error).message});next(e);}});
