import { Router } from "express";
import { GraphChangeSetValidationError, GraphRepository } from "../repositories/graphRepository.js";
import { F3532AnalysisRepository } from "../repositories/f3532AnalysisRepository.js";
import { StandardRepository } from "../repositories/standardRepository.js";
import { AnalysisService } from "../services/analysisService.js";
import { FpAnalysisService } from "../services/fpAnalysisService.js";
import { CxfImportService, type CxfImportSummary } from "../services/cxfImportService.js";
import { F3532InputImportService, type F3532InputImportSummary } from "../services/f3532InputImportService.js";
import { F353204Service, f353204Defaults } from "../services/f353204Service.js";
import { ImportService } from "../services/importService.js";
import {
  cxfImportRequestSchema,
  do326aLinkSchema,
  do326aReviewSchema,
  f3532InputImportRequestSchema,
  f3532StandardImportRequestSchema,
  fhaImportRequestSchema,
  generateF353204Schema,
  commitF353204Schema,
  graphChangeSetSchema,
  modelingExportQuerySchema,
  persistPathsSchema,
  runAnalysisSchema,
  runFpAnalysisSchema,
  singleSheetImportRequestSchema,
  standardMappingRequestSchema
} from "../types/api.js";

const router = Router();
const graphRepo = new GraphRepository();
const f3532AnalysisRepo = new F3532AnalysisRepository();
const standardRepo = new StandardRepository();
const analysisService = new AnalysisService();
const fpAnalysisService = new FpAnalysisService();
const importService = new ImportService();
const cxfImportService = new CxfImportService();
const f3532InputImportService = new F3532InputImportService();
const f353204Service = new F353204Service();

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
  data_assets: 0,
  domain_properties: 0
};

const emptyCxfSummary: CxfImportSummary = {
  asset_nodes_to_add: 0,
  asset_edges_to_add: 0,
  threat_points_to_add: 0,
  auto_placeholder_assets_to_add: 0,
  warnings: [],
  auto_generated_threats: []
};

const emptyF3532Accepted = {
  boundary_interfaces: 0,
  boundary_data_flows: 0,
  system_interfaces: 0,
  system_data_flows: 0,
  threat_actors: 0,
  trust_boundaries: 0
};

const emptyF3532Summary: F3532InputImportSummary = {
  asset_nodes_to_add: 0,
  asset_edges_to_add: 0,
  boundary_interfaces_to_add: 0,
  trust_boundaries_to_add: 0,
  threat_actors_to_add: 0,
  system_data_flows_to_add: 0,
  function_nodes_to_add: 0,
  function_links_to_add: 0,
  warnings: []
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

function toF3532InputImportRequestErrorResponse(issues: Array<{ path: Array<string | number>; message: string }>) {
  const error_details = issues.map((issue) => ({
    type: "field" as const,
    field: issue.path.join(".") || undefined,
    message: issue.message
  }));

  return {
    ok: false,
    accepted: emptyF3532Accepted,
    errors: error_details.map((detail) => (detail.field ? `field / ${detail.field}: ${detail.message}` : detail.message)),
    error_details,
    summary: emptyF3532Summary
  };
}

router.get("/health", async (_req, res) => {
  res.json({ ok: true });
});

router.post("/standard/f3532/import", async (req, res, next) => {
  try {
    const parsed = f3532StandardImportRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ imported: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const summary = await standardRepo.importF3532KnowledgeBase({
      ...parsed.data,
      source: {
        ...parsed.data.source,
        imported_by: parsed.data.source?.imported_by ?? String(req.headers["x-user-id"] ?? "standard-import")
      }
    });
    return res.status(201).json({ imported: true, summary });
  } catch (error) {
    return next(error);
  }
});

router.get("/standard/f3532/summary", async (_req, res, next) => {
  try {
    const summary = await standardRepo.getKnowledgeSummary();
    return res.json(summary);
  } catch (error) {
    return next(error);
  }
});

router.get("/standard/f3532/clauses", async (req, res, next) => {
  try {
    const clauses = await standardRepo.getClauses("ASTM-F3532-23", req.query.section ? String(req.query.section) : undefined);
    return res.json({ count: clauses.length, clauses });
  } catch (error) {
    return next(error);
  }
});

router.get("/standard/f3532/artifacts", async (_req, res, next) => {
  try {
    const artifacts = await standardRepo.getArtifacts();
    return res.json({ count: artifacts.length, artifacts });
  } catch (error) {
    return next(error);
  }
});

router.get("/standard/f3532/mappings", async (_req, res, next) => {
  try {
    const mappings = await standardRepo.getMappings();
    return res.json({ count: mappings.length, mappings });
  } catch (error) {
    return next(error);
  }
});

router.post("/standard/f3532/mappings", async (req, res, next) => {
  try {
    const parsed = standardMappingRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ created: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const mapping = await standardRepo.upsertMapping(parsed.data);
    return res.status(201).json({ created: true, mapping });
  } catch (error) {
    return next(error);
  }
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

router.post("/imports/f3532-input/preview", (req, res) => {
  const parsed = f3532InputImportRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json(toF3532InputImportRequestErrorResponse(parsed.error.issues));
  }

  const preview = f3532InputImportService.preview(parsed.data);
  return res.json(preview);
});

router.post("/imports/f3532-input/commit", async (req, res, next) => {
  let accepted = emptyF3532Accepted;
  let summary = emptyF3532Summary;

  try {
    const parsed = f3532InputImportRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ committed: false, ...toF3532InputImportRequestErrorResponse(parsed.error.issues) });
    }

    const graphVersion = await graphRepo.getGraphVersion();
    const prepared = f3532InputImportService.prepareChangeSet(parsed.data, graphVersion);
    accepted = prepared.accepted;
    summary = prepared.summary;
    if (prepared.error_details.length > 0 || !prepared.change_set) {
      return res.status(400).json({ committed: false, ...prepared });
    }

    const userId = String(req.headers["x-user-id"] ?? "f3532-input-import");
    const commit = await graphRepo.commitChangeSet(prepared.change_set, userId);
    return res.json({ committed: true, ...prepared, ...commit });
  } catch (error) {
    if (error instanceof GraphChangeSetValidationError) {
      const error_details = f3532InputImportService.createBindingErrors(error.errors);
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

router.post("/imports/fha/preview", (req, res) => {
  const parsed = fhaImportRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      ok: false,
      errors: parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    });
  }
  const ids = parsed.data.failure_conditions.map((item) => item.failure_condition_id);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length > 0) {
    return res.status(400).json({ ok: false, errors: [`duplicate failure condition ids: ${Array.from(new Set(duplicates)).join(", ")}`] });
  }
  const severity_counts = parsed.data.failure_conditions.reduce<Record<string, number>>((counts, item) => {
    counts[item.severity] = (counts[item.severity] ?? 0) + 1;
    return counts;
  }, {});
  return res.json({ ok: true, count: parsed.data.failure_conditions.length, severity_counts, errors: [] });
});

router.post("/imports/fha/commit", async (req, res, next) => {
  try {
    const parsed = fhaImportRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ committed: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const result = await f3532AnalysisRepo.importFailureConditions(parsed.data);
    return res.json({ committed: true, ...result });
  } catch (error) {
    return next(error);
  }
});

router.get("/fha/failure-conditions", async (_req, res, next) => {
  try {
    const rows = await f3532AnalysisRepo.getFailureConditionContexts();
    return res.json({ count: rows.length, rows });
  } catch (error) {
    return next(error);
  }
});

router.get("/analysis/f3532/04/defaults", (_req, res) => {
  return res.json(f353204Defaults);
});

router.post("/analysis/f3532/generate-04", async (req, res, next) => {
  try {
    const parsed = generateF353204Schema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ generated: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const inputs = await graphRepo.getFunctionPropagationInputs();
    const refreshedPaths = fpAnalysisService.run({ ...inputs, group_by: "function" });
    await graphRepo.replaceFunctionPropagationPaths(refreshedPaths);
    const [failureConditions, paths] = await Promise.all([
      f3532AnalysisRepo.getFailureConditionContexts(),
      f3532AnalysisRepo.getThreatPathContexts()
    ]);
    const result = f353204Service.generate(parsed.data, failureConditions, paths);
    return res.json({ generated: true, refreshed_path_count: refreshedPaths.length, ...result });
  } catch (error) {
    return next(error);
  }
});

router.post("/analysis/f3532/commit-04", async (req, res, next) => {
  try {
    const parsed = commitF353204Schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ committed: false, errors: parsed.error.issues.map((issue) => issue.message) });
    }
    await f3532AnalysisRepo.replaceF353204(parsed.data.threat_conditions, parsed.data.threat_scenarios);
    return res.json({
      committed: true,
      threat_condition_count: parsed.data.threat_conditions.length,
      threat_scenario_count: parsed.data.threat_scenarios.length
    });
  } catch (error) {
    return next(error);
  }
});

router.get("/reports/f3532/04", async (_req, res, next) => {
  try {
    const report = await f3532AnalysisRepo.getF353204();
    return res.json({
      threat_condition_count: report.threat_conditions.length,
      threat_scenario_count: report.threat_scenarios.length,
      ...report
    });
  } catch (error) {
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

router.get("/reports/chapter4/trust-boundaries", async (_req, res, next) => {
  try {
    const rows = await graphRepo.getTrustBoundaryReport();
    return res.json({ count: rows.length, rows });
  } catch (error) {
    return next(error);
  }
});

router.get("/reports/chapter4/boundary-data-flows", async (_req, res, next) => {
  try {
    const rows = await graphRepo.getBoundaryDataFlowReport();
    return res.json({ count: rows.length, rows });
  } catch (error) {
    return next(error);
  }
});

router.get("/reports/chapter4/function-propagation", async (_req, res, next) => {
  try {
    const rows = await graphRepo.getFunctionPropagationReport();
    return res.json({ count: rows.length, rows });
  } catch (error) {
    return next(error);
  }
});

router.get("/reports/chapter4/internal-data-flows", async (_req, res, next) => {
  try {
    const rows = await graphRepo.getInternalDataFlowReport();
    return res.json({ count: rows.length, rows });
  } catch (error) {
    return next(error);
  }
});

router.post("/analysis/function-propagation/run", async (req, res, next) => {
  try {
    const parsed = runFpAnalysisSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ message: "invalid params", errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const inputs = await graphRepo.getFunctionPropagationInputs();
    const fps = fpAnalysisService.run({ ...inputs, max_hops: parsed.data.max_hops, group_by: parsed.data.group_by });
    await graphRepo.replaceFunctionPropagationPaths(fps);
    const rows = await graphRepo.getFunctionPropagationReport();
    return res.json({ count: rows.length, fp_count: fps.length, rows });
  } catch (error) {
    return next(error);
  }
});

router.post("/analysis/f3532/generate-03", async (req, res, next) => {
  try {
    const parsed = runFpAnalysisSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ message: "invalid params", errors: parsed.error.issues.map((issue) => issue.message) });
    }
    const inputs = await graphRepo.getFunctionPropagationInputs();
    const fps = fpAnalysisService.run({ ...inputs, max_hops: parsed.data.max_hops, group_by: parsed.data.group_by });
    await graphRepo.replaceFunctionPropagationPaths(fps);
    const [boundaryDataFlows, functionPropagation] = await Promise.all([
      graphRepo.getBoundaryDataFlowReport(),
      graphRepo.getFunctionPropagationReport()
    ]);
    return res.json({
      generated: true,
      metadata: {
        generated_at: new Date().toISOString(),
        graph_version: await graphRepo.getGraphVersion(),
        fp_count: fps.length
      },
      boundary_data_flows: { count: boundaryDataFlows.length, rows: boundaryDataFlows },
      function_propagation: { count: functionPropagation.length, rows: functionPropagation }
    });
  } catch (error) {
    return next(error);
  }
});

router.get("/reports/f3532/03", async (_req, res, next) => {
  try {
    const [boundaryDataFlows, functionPropagation] = await Promise.all([
      graphRepo.getBoundaryDataFlowReport(),
      graphRepo.getFunctionPropagationReport()
    ]);
    return res.json({
      metadata: {
        loaded_at: new Date().toISOString(),
        graph_version: await graphRepo.getGraphVersion()
      },
      boundary_data_flows: { count: boundaryDataFlows.length, rows: boundaryDataFlows },
      function_propagation: { count: functionPropagation.length, rows: functionPropagation }
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
