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

const router = Router();
const service = new GovernanceService();

function invalid(issues: Array<{ path: Array<string | number>; message: string }>) {
  return {
    code: "INVALID_GOVERNANCE_V2_REQUEST",
    errors: issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })),
  };
}

function conflict(error: unknown) {
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
