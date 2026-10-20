import { Router, type NextFunction, type Response } from "express";
import {
  analysisQuerySchema, analysisHistoryQuerySchema, analysisDetailQuerySchema,
  analysisRunCommandSchema,
  derivedResultReviewCommandSchema,
  promotionCommandSchema,
  savedAnalysisSchema, workbenchExportSchema,
} from "@attackgraph/contracts";
import { WorkbenchService } from "../services/workbenchService.js";
import { ZodError } from "zod";
import { AnalysisRepository, AnalysisScopeError } from "../repositories/analysisRepository.js";
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
import { analysisMethods } from "../services/analysis/methodRegistry.js";
import { AnalysisServiceV2 } from "../services/analysisServiceV2.js";

const router = Router();
const repository = new AnalysisRepository();
const service = new AnalysisServiceV2(repository);

function invalid(issues: Array<{ path: Array<string | number>; message: string }>) {
  return { code: "INVALID_ANALYSIS_REQUEST", errors: issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })) };
}

function forward(error: unknown, res: Response, next: NextFunction) {
  if (error instanceof ZodError) return res.status(400).json(invalid(error.issues));
  if (error instanceof RevisionWriteScopeError || error instanceof AnalysisScopeError) return res.status(409).json({ code: "ANALYSIS_SCOPE_ERROR", message: error.message });
  if (error instanceof RevisionWriteConflictError) return res.status(409).json({ code: "REVISION_VERSION_CONFLICT", message: error.message });
  if (error instanceof RevisionNotWritableError) return res.status(409).json({ code: "REVISION_NOT_WRITABLE", message: error.message });
  if (error instanceof CommandPayloadMismatchError) return res.status(409).json({ code: "COMMAND_PAYLOAD_MISMATCH", message: error.message });
  if (error instanceof CommandReuseError) return res.status(409).json({ code: "COMMAND_REUSE_CONFLICT", message: error.message });
  if (error instanceof CommandReceiptUnverifiableError) return res.status(409).json({ code: "COMMAND_RECEIPT_UNVERIFIABLE", message: error.message });
  if (error instanceof Error && /Unknown analysis method|not enabled/.test(error.message)) return res.status(409).json({ code: "ANALYSIS_METHOD_UNAVAILABLE", message: error.message });
  if (error instanceof Error && /outside the current project\/revision/.test(error.message)) return res.status(409).json({ code: "ANALYSIS_SCOPE_ERROR", message: error.message });
  return next(error);
}

router.get("/methods", (_req, res) => res.json({ methods: analysisMethods }));
router.post("/runs/export",async(req,res,next)=>{try{return res.json(await new WorkbenchService().export(workbenchExportSchema.parse(req.body)));}catch(error){return forward(error,res,next);}});

router.post("/runs", async (req, res, next) => {
  try {
    if (req.body.contract_version === "saved-model-analysis.v1") return res.status(201).json(await new WorkbenchService().run(savedAnalysisSchema.parse(req.body)));
    const parsed = analysisRunCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.run(parsed.data));
  } catch (error) {
    return forward(error, res, next);
  }
});

router.get("/runs/summaries",async(req,res,next)=>{try{const q=analysisHistoryQuerySchema.parse(req.query);res.json(await repository.readSummaries(q.project_id,q.revision_id,q.limit,q.cursor,q.run_id));}catch(e){forward(e,res,next);}});
router.get("/runs/detail",async(req,res,next)=>{try{const q=analysisDetailQuerySchema.parse(req.query);await repository.resolveProjectRevisionScope(q.project_id,q.revision_id);const run=(await repository.readRuns(q.project_id,q.revision_id,q.run_id,true,q.include_inputs==="true"))[0];if(!run)return res.status(404).json({code:"ANALYSIS_RUN_NOT_FOUND",message:"所选修订中不存在该运行"});res.json({run});}catch(e){forward(e,res,next);}});

router.get("/runs", async (req, res, next) => {
  try {
    const parsed = analysisQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.json({ runs: await repository.readRuns(parsed.data.project_id, parsed.data.revision_id, parsed.data.run_id,parsed.data.view === "workbench.v1") });
  } catch (error) {
    return forward(error, res, next);
  }
});

router.post("/derived-results/review-decisions", async (req, res, next) => {
  try {
    const parsed = derivedResultReviewCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.review(parsed.data));
  } catch (error) {
    return forward(error, res, next);
  }
});

router.post("/promotions", async (req, res, next) => {
  try {
    const parsed = promotionCommandSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await service.promote(parsed.data));
  } catch (error) {
    return forward(error, res, next);
  }
});

router.get("/promotions", async (req, res, next) => {
  try {
    const parsed = analysisQuerySchema.omit({ run_id: true }).safeParse(req.query);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.json({ promotions: await repository.readPromotions(parsed.data.project_id, parsed.data.revision_id) });
  } catch (error) {
    return forward(error, res, next);
  }
});

export default router;
