import { Router } from "express";
import { GraphRepository } from "../repositories/graphRepository.js";
import { AnalysisService } from "../services/analysisService.js";
import { ImportService } from "../services/importService.js";
import {
  do326aLinkSchema,
  do326aReviewSchema,
  graphChangeSetSchema,
  persistPathsSchema,
  runAnalysisSchema
} from "../types/api.js";

const router = Router();
const graphRepo = new GraphRepository();
const analysisService = new AnalysisService();
const importService = new ImportService();

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

router.post("/imports/excel/single-sheet/preview", (req, res) => {
  const preview = importService.preview(req.body?.rows ?? []);
  res.json(preview);
});

router.post("/imports/excel/single-sheet/commit", async (_req, res) => {
  res.status(501).json({ message: "MVP 阶段暂不提供导入写入，请使用 /graph/changeset/commit" });
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
      return res.status(400).json({ valid: false, errors: parsed.error.issues.map((i) => i.message) });
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
      return res.status(400).json({ committed: false, errors: parsed.error.issues.map((i) => i.message) });
    }
    const valid = await graphRepo.validateChangeSet(parsed.data);
    if (!valid.valid) {
      return res.status(409).json({ committed: false, errors: valid.errors });
    }
    const userId = String(req.headers["x-user-id"] ?? "anonymous");
    const commit = await graphRepo.commitChangeSet(parsed.data, userId);
    return res.json({ committed: true, ...commit });
  } catch (error) {
    return next(error);
  }
});

router.post("/analysis/attack-paths/run", async (req, res, next) => {
  try {
    const parsed = runAnalysisSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: "invalid params", errors: parsed.error.issues.map((i) => i.message) });
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
      return res.status(400).json({ message: "invalid params", errors: parsed.error.issues.map((i) => i.message) });
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
      return res.status(400).json({ created: false, errors: parsed.error.issues.map((i) => i.message) });
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
      return res.status(400).json({ updated: false, errors: parsed.error.issues.map((i) => i.message) });
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
