import { Router, type NextFunction, type Response } from "express";
import {
  systemModelCommitRequestSchema,
  systemModelPreviewRequestSchema,
  systemModelQuerySchema,
  inventoryPreviewSchema, inventoryCommitSchema, editPreviewSchema,
  type EditCommand,
  sheetNames,
} from "@attackgraph/contracts";
import { ZodError } from "zod";
import { WorkbenchService } from "../services/workbenchService.js";
import { readFile } from "node:fs/promises";
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
const workbench = new WorkbenchService();
router.get("/import/example",async(_req,res,next)=>{try{
  res.type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet").send(await readFile(new URL("../../../../docs/DO356A_example_filled.xlsx",import.meta.url)));
}catch(error){next(error);}});

function invalid(issues: Array<{ path: Array<string | number>; message: string }>, body?:{inventory?:{workbook?:Record<string,Array<{id?:string;excel_row?:number;source_sheet?:string}>>}}) {
  return {
    code: "INVALID_SYSTEM_MODEL_V2_REQUEST",
    errors: issues.map((issue) => {
      const sheet=issue.path[2],index=issue.path[3];const row=typeof sheet==="string"&&typeof index==="number"?body?.inventory?.workbook?.[sheet]?.[index]:undefined;
      return { field: issue.path.join("."), message: issue.message, ...(row?{sheet:row.source_sheet??sheetNames[sheet as keyof typeof sheetNames],row:row.excel_row,record_id:row.id}: {}) };
    }),
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
  if (error instanceof ZodError) return res.status(400).json(invalid(error.issues));
  const mapped = knownError(error);
  if (mapped) return res.status(mapped.status).json({ code: mapped.code, message: mapped.message });
  return next(error);
}

router.post("/import/preview", async (req, res, next) => {
  try {
    if (req.body.contract_version === "inventory-import.v1") return res.json(await workbench.previewInventory(inventoryPreviewSchema.parse(req.body)));
    const parsed = systemModelPreviewRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    const result = await importService.preview(parsed.data);
    return res.status(result.ok ? 200 : 409).json(result);
  } catch (error) {
    if(error instanceof ZodError)return res.status(400).json(invalid(error.issues,req.body));
    return forwardKnown(error, res, next);
  }
});

router.post("/import/commit", async (req, res, next) => {
  try {
    if (req.body.contract_version === "inventory-import.v1") return res.status(201).json(await workbench.commitInventory(inventoryCommitSchema.parse(req.body)));
    const parsed = systemModelCommitRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(invalid(parsed.error.issues));
    return res.status(201).json(await importService.commit(parsed.data));
  } catch (error) {
    if(error instanceof ZodError)return res.status(400).json(invalid(error.issues,req.body));
    return forwardKnown(error, res, next);
  }
});

router.get("/workbench", async (req,res,next)=>{
  try { return res.json(await workbench.read(systemModelQuerySchema.parse(req.query))); }
  catch(error){return forwardKnown(error,res,next);}
});
for (const operation of ["preview","commit"] as const) router.post(`/changes/${operation}`,async(req,res,next)=>{
  try {
    const input=editPreviewSchema.parse(req.body) as EditCommand;
    return res.json(operation === "preview" ? await workbench.previewEdit(input) : await workbench.commitEdit(input));
  } catch(error){return forwardKnown(error,res,next);}
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
