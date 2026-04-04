import { Router } from "express";
import { GraphChangeSetValidationError, GraphRepository } from "../repositories/graphRepository.js";
import { AnalysisService } from "../services/analysisService.js";
import { CxfImportService, type CxfImportSummary } from "../services/cxfImportService.js";
import { ImportService } from "../services/importService.js";
import {
  cxfImportRequestSchema,
  do326aLinkSchema,
  do326aReviewSchema,
  graphChangeSetSchema,
  modelingExportQuerySchema,
  persistPathsSchema,
  runAnalysisSchema,
  singleSheetImportRequestSchema
} from "../types/api.js";

const router = Router();
const graphRepo = new GraphRepository();
const analysisService = new AnalysisService();
const importService = new ImportService();
const cxfImportService = new CxfImportService();

const emptyImportSummary = {
  asset_nodes: 0,
  asset_edges: 0,
  threat_points: 0,
  do326a_links: 0
};

const emptyCxfAccepted = {
  functional_assets: 0,
  interface_assets: 0,
  support_assets: 0,
  data_assets: 0
};

const emptyCxfSummary: CxfImportSummary = {
  asset_nodes_to_add: 0,
  asset_edges_to_add: 0,
  threat_points_to_add: 0,
  auto_placeholder_assets_to_add: 0,
  warnings: [],
  auto_generated_threats: []
};

function toImportRequestErrorResponse(issues: Array<{ path: Array<string | number>; message: string }>) {
  const error_details = issues.map((issue) => ({
    type: "field" as const,
    field: issue.path.join(".") || undefined,
    message: issue.message
  }));

  return {
    accepted: 0,
    rejected: 0,
    errors: error_details.map((detail) => (detail.field ? `field / ${detail.field}: ${detail.message}` : detail.message)),
    error_details,
    summary: emptyImportSummary
  };
}

function toCxfImportRequestErrorResponse(issues: Array<{ path: Array<string | number>; message: string }>) {
  const error_details = issues.map((issue) => ({
    type: "field" as const,
    field: issue.path.join(".") || undefined,
    message: issue.message
  }));

  return {
    ok: false,
    accepted: emptyCxfAccepted,
    errors: error_details.map((detail) => (detail.field ? `field / ${detail.field}: ${detail.message}` : detail.message)),
    error_details,
    summary: emptyCxfSummary
  };
}

router.get("/health", async (_req, res) => {
  res.json({ ok: true });
});

router.post("/admin/seed/sample", async (req, res, next) => {
  try {
    const userId = String(req.headers["x-user-id"] ?? "admin-seed");
    const result = await graphRepo.seedSampleData(userId);
    res.json({ seeded: true, ...result });
  } catch (error) {
    next(error);
  }
});

router.post("/admin/seed/generic", async (req, res, next) => {
  try {
    const userId = String(req.headers["x-user-id"] ?? "admin-generic-seed");
    const result = await graphRepo.seedGenericExample(userId);
    res.json({ seeded: true, ...result });
  } catch (error) {
    next(error);
  }
});

router.post("/imports/excel/single-sheet/preview", (req, res) => {
  const parsed = singleSheetImportRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json(toImportRequestErrorResponse(parsed.error.issues));
  }

  const preview = importService.preview(parsed.data);
  return res.json(preview);
});

router.post("/imports/excel/single-sheet/commit", async (req, res, next) => {
  let accepted = 0;
  let rejected = 0;
  let summary = emptyImportSummary;

  try {
    const parsed = singleSheetImportRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ committed: false, ...toImportRequestErrorResponse(parsed.error.issues) });
    }

    const graphVersion = await graphRepo.getGraphVersion();
    const prepared = importService.prepareChangeSet(parsed.data, graphVersion);
    accepted = prepared.accepted;
    rejected = prepared.rejected;
    summary = prepared.summary;
    if (prepared.error_details.length > 0 || !prepared.change_set) {
      return res.status(400).json({ committed: false, ...prepared });
    }

    const userId = String(req.headers["x-user-id"] ?? "excel-import");
    const commit = await graphRepo.commitChangeSet(prepared.change_set, userId);
    return res.json({ committed: true, ...prepared, ...commit });
  } catch (error) {
    if (error instanceof GraphChangeSetValidationError) {
      const error_details = importService.createBindingErrors(error.errors);
      return res.status(409).json({
        committed: false,
        accepted,
        rejected,
        errors: error_details.map((detail) => detail.message),
        error_details,
        summary
      });
    }
    return next(error);
  }
});

router.post("/imports/cxf-asset-inventory/preview", (req, res) => {
  const parsed = cxfImportRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json(toCxfImportRequestErrorResponse(parsed.error.issues));
  }

  const preview = cxfImportService.preview(parsed.data);
  return res.json(preview);
});

router.post("/imports/cxf-asset-inventory/commit", async (req, res, next) => {
  let accepted = emptyCxfAccepted;
  let summary = emptyCxfSummary;

  try {
    const parsed = cxfImportRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ committed: false, ...toCxfImportRequestErrorResponse(parsed.error.issues) });
    }

    const graphVersion = await graphRepo.getGraphVersion();
    const prepared = cxfImportService.prepareChangeSet(parsed.data, graphVersion);
    accepted = prepared.accepted;
    summary = prepared.summary;
    if (prepared.error_details.length > 0 || !prepared.change_set) {
      return res.status(400).json({ committed: false, ...prepared });
    }

    const userId = String(req.headers["x-user-id"] ?? "cxf-import");
    const commit = await graphRepo.commitChangeSet(prepared.change_set, userId);
    return res.json({ committed: true, ...prepared, ...commit });
  } catch (error) {
    if (error instanceof GraphChangeSetValidationError) {
      const error_details = cxfImportService.createBindingErrors(error.errors);
      return res.status(409).json({
        committed: false,
        ok: false,
        accepted,
        errors: error_details.map((detail) => detail.message),
        error_details,
        summary
      });
    }
    return next(error);
  }
});

router.get("/graph", async (_req, res, next) => {
  try {
    const data = await graphRepo.getGraph();
    res.json(data);
  } catch (error) {
    next(error);
  }
});

router.post("/graph/changeset/validate", async (req, res, next) => {
  try {
    const parsed = graphChangeSetSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ valid: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const result = await graphRepo.validateChangeSet(parsed.data);
    return res.json(result);
  } catch (error) {
    return next(error);
  }
});

router.post("/graph/changeset/commit", async (req, res, next) => {
  try {
    const parsed = graphChangeSetSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ committed: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }

    const valid = await graphRepo.validateChangeSet(parsed.data);
    if (!valid.valid) {
      return res.status(409).json({ committed: false, errors: valid.errors });
    }

    const userId = String(req.headers["x-user-id"] ?? "anonymous");
    try {
      const commit = await graphRepo.commitChangeSet(parsed.data, userId);
      return res.json({ committed: true, ...commit });
    } catch (error) {
      if (error instanceof GraphChangeSetValidationError) {
        return res.status(409).json({ committed: false, errors: error.errors });
      }
      throw error;
    }
  } catch (error) {
    return next(error);
  }
});

router.post("/analysis/attack-paths/run", async (req, res, next) => {
  try {
    const parsed = runAnalysisSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: "invalid params", errors: parsed.error.issues.map((issue) => issue.message) });
    }

    const graph = await graphRepo.getGraph();
    const paths = analysisService.run({
      analysis_batch_id: parsed.data.analysis_batch_id,
      max_hops: parsed.data.max_hops,
      generated_by: parsed.data.generated_by,
      scope_asset_ids: parsed.data.scope_asset_ids,
      dps_hop_decay: parsed.data.dps_hop_decay,
      asset_nodes: graph.asset_nodes,
      asset_edges: graph.asset_edges,
      threat_points: graph.threat_points
    });
    return res.json({ count: paths.length, paths });
  } catch (error) {
    return next(error);
  }
});

router.post("/analysis/attack-paths/persist", async (req, res, next) => {
  try {
    const parsed = persistPathsSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: "invalid params", errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const count = await graphRepo.persistAttackPaths(parsed.data.paths);
    return res.json({ persisted: count });
  } catch (error) {
    return next(error);
  }
});

router.get("/analysis/attack-paths", async (req, res, next) => {
  try {
    const analysisBatchId = req.query.analysis_batch_id ? String(req.query.analysis_batch_id) : undefined;
    const paths = await graphRepo.getAttackPaths(analysisBatchId);
    return res.json({ count: paths.length, paths });
  } catch (error) {
    return next(error);
  }
});

router.get("/exports/modeling-result", async (req, res, next) => {
  try {
    const parsed = modelingExportQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({
        message: "invalid params",
        errors: parsed.error.issues.map((issue) => issue.message)
      });
    }

    const bundle = await graphRepo.getModelingExportBundle(parsed.data.analysis_batch_id);
    return res.json({
      metadata: {
        exported_at: new Date().toISOString(),
        filter: parsed.data.analysis_batch_id ? { analysis_batch_id: parsed.data.analysis_batch_id } : {},
        graph_version: bundle.graph.graph_version,
        counts: {
          asset_nodes: bundle.graph.asset_nodes.length,
          asset_edges: bundle.graph.asset_edges.length,
          threat_points: bundle.graph.threat_points.length,
          do326a_links: bundle.do326a_links.length,
          analysis_paths: bundle.analysis_paths.length
        }
      },
      payload: bundle
    });
  } catch (error) {
    return next(error);
  }
});

router.get("/compliance/do326a-links", async (_req, res, next) => {
  try {
    const links = await graphRepo.getDo326ALinks();
    return res.json({ count: links.length, links });
  } catch (error) {
    return next(error);
  }
});

router.post("/compliance/do326a-links", async (req, res, next) => {
  try {
    const parsed = do326aLinkSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ created: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const link = await graphRepo.upsertDo326ALink(parsed.data);
    return res.status(201).json({ created: true, link });
  } catch (error) {
    return next(error);
  }
});

router.patch("/compliance/do326a-links/:link_id/review", async (req, res, next) => {
  try {
    const parsed = do326aReviewSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ updated: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const updated = await graphRepo.reviewDo326ALink(
      String(req.params.link_id),
      parsed.data.review_status,
      parsed.data.reviewer
    );
    if (!updated) {
      return res.status(404).json({ updated: false, message: "link not found" });
    }
    return res.json({ updated: true, link: updated });
  } catch (error) {
    return next(error);
  }
});

router.get("/audit/commits", async (_req, res, next) => {
  try {
    const commits = await graphRepo.getAuditCommits();
    return res.json({ count: commits.length, commits });
  } catch (error) {
    return next(error);
  }
});

export default router;
