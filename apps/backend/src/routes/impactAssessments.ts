import { Router, type NextFunction, type Response } from "express";
import {
  impactAssessmentCommandSchema,
  impactDispositionCommandSchema,
  impactPreviewQuerySchema,
  impactQuerySchema,
  workProductQuerySchema,
} from "@attackgraph/contracts";
import { ZodError } from "zod";
import { ImpactRepository, ImpactScopeError } from "../repositories/impactRepository.js";
import { RevisionNotWritableError, RevisionWriteConflictError, RevisionWriteScopeError } from "../repositories/revisionUnitOfWork.js";
import { CommandPayloadMismatchError, CommandReceiptUnverifiableError, CommandReuseError } from "../services/governance/commandReceipt.js";
import { AssuranceWorkProductService } from "../services/assuranceWorkProductService.js";
import { ImpactService } from "../services/impactService.js";

const router = Router();
const repository = new ImpactRepository();
const service = new ImpactService(repository);
const workProducts = new AssuranceWorkProductService();

function invalid(error: ZodError) {
  return { code: "INVALID_IMPACT_REQUEST", errors: error.issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })) };
}

function forward(error: unknown, res: Response, next: NextFunction) {
  if (error instanceof ZodError) return res.status(400).json(invalid(error));
  if (error instanceof ImpactScopeError || error instanceof RevisionWriteScopeError) return res.status(409).json({ code: "IMPACT_SCOPE_ERROR", message: error.message });
  if (error instanceof RevisionWriteConflictError) return res.status(409).json({ code: "REVISION_VERSION_CONFLICT", message: error.message });
  if (error instanceof RevisionNotWritableError) return res.status(409).json({ code: "REVISION_NOT_WRITABLE", message: error.message });
  if (error instanceof CommandPayloadMismatchError) return res.status(409).json({ code: "COMMAND_PAYLOAD_MISMATCH", message: error.message });
  if (error instanceof CommandReuseError) return res.status(409).json({ code: "COMMAND_REUSE_CONFLICT", message: error.message });
  if (error instanceof CommandReceiptUnverifiableError) return res.status(409).json({ code: "COMMAND_RECEIPT_UNVERIFIABLE", message: error.message });
  return next(error);
}

router.post("/preview", async (req, res, next) => {
  try {
    const parsed = impactPreviewQuerySchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error));
    return res.json(await service.preview(parsed.data));
  } catch (error) { return forward(error, res, next); }
});

router.post("/", async (req, res, next) => {
  try {
    const parsed = impactAssessmentCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error));
    return res.status(201).json(await service.create(parsed.data));
  } catch (error) { return forward(error, res, next); }
});

router.get("/", async (req, res, next) => {
  try {
    const parsed = impactQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error));
    return res.json({ assessments: await repository.readAssessments(parsed.data.project_id, parsed.data.revision_id, parsed.data.assessment_id) });
  } catch (error) { return forward(error, res, next); }
});

router.post("/dispositions", async (req, res, next) => {
  try {
    const parsed = impactDispositionCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error));
    return res.status(201).json(await service.dispose(parsed.data));
  } catch (error) { return forward(error, res, next); }
});

router.get("/work-product", async (req, res, next) => {
  try {
    const parsed = workProductQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error));
    return res.json(await workProducts.generate(parsed.data));
  } catch (error) { return forward(error, res, next); }
});

router.get("/work-product/export", async (req, res, next) => {
  try {
    const parsed = workProductQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error));
    const report = await workProducts.generate(parsed.data);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="astra-assurance-work-product-${report.context.revision_id}.json"`);
    return res.send(JSON.stringify(report, null, 2));
  } catch (error) { return forward(error, res, next); }
});

export default router;
