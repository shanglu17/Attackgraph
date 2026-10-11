import { Router } from "express";
import { traceabilityReportQuerySchema } from "@attackgraph/contracts";
import { TraceabilityContextNotFoundError } from "../repositories/traceabilityReportRepository.js";
import { TraceabilityReportService } from "../services/traceabilityReportService.js";

const router = Router();
const service = new TraceabilityReportService();

function invalid(issues: Array<{ path: Array<string | number>; message: string }>) {
  return {
    code: "INVALID_TRACEABILITY_REPORT_REQUEST",
    errors: issues.map((issue) => ({ field: issue.path.join("."), message: issue.message })),
  };
}

async function generate(req: unknown, actor: string) {
  const parsed = traceabilityReportQuerySchema.safeParse(req);
  if (!parsed.success) return { parsed, report: undefined };
  return { parsed, report: await service.generate(parsed.data, actor) };
}

router.get("/report", async (req, res, next) => {
  try {
    const result = await generate(req.query, String(req.headers["x-user-id"] ?? "traceability-viewer"));
    if (!result.parsed.success) return res.status(400).json(invalid(result.parsed.error.issues));
    return res.json(result.report);
  } catch (error) {
    if (error instanceof TraceabilityContextNotFoundError) {
      return res.status(404).json({ code: "TRACEABILITY_CONTEXT_NOT_FOUND", message: error.message });
    }
    return next(error);
  }
});

router.get("/report/export", async (req, res, next) => {
  try {
    const actor = String(req.headers["x-user-id"] ?? "traceability-exporter");
    const result = await generate(req.query, actor);
    if (!result.parsed.success) return res.status(400).json(invalid(result.parsed.error.issues));
    const contextId = result.report?.context.baseline?.business_id ?? result.report?.context.revision.business_id ?? "traceability";
    const filename = `astra-traceability-${contextId.replace(/[^A-Za-z0-9._-]/g, "-")}.json`;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(JSON.stringify(result.report, null, 2));
  } catch (error) {
    if (error instanceof TraceabilityContextNotFoundError) {
      return res.status(404).json({ code: "TRACEABILITY_CONTEXT_NOT_FOUND", message: error.message });
    }
    return next(error);
  }
});

export default router;
