import { Router } from "express";
import { getDriver } from "../db/neo4j.js";
import { Neo4jMigrationStore } from "../migrations/neo4jMigrationStore.js";
import { migrationRegistry } from "../migrations/registry.js";
import { migrationChecksum } from "../migrations/runner.js";
import { requestMetricsSnapshot } from "../operations/requestMetrics.js";

const router = Router();

router.get("/health", async (_request, response) => {
  const checkedAt = new Date().toISOString();
  const session = getDriver().session();
  try {
    await getDriver().verifyConnectivity();
    const records = await new Neo4jMigrationStore(session).listRecords();
    const byId = new Map(records.map((record) => [record.migration_id, record]));
    const migrationIssues = migrationRegistry.flatMap((migration) => {
      const record = byId.get(migration.id);
      if (!record) return [`${migration.id}:missing`];
      if (record.status !== "applied") return [`${migration.id}:${record.status}`];
      if (record.checksum !== migrationChecksum(migration)) return [`${migration.id}:checksum_mismatch`];
      return [];
    });
    const ready = migrationIssues.length === 0;
    return response.status(ready ? 200 : 503).json({
      ok: ready,
      status: ready ? "ready" : "degraded",
      checked_at: checkedAt,
      checks: { neo4j: "available", migrations: ready ? "current" : "attention_required" },
      diagnostics: migrationIssues,
    });
  } catch (error) {
    return response.status(503).json({
      ok: false,
      status: "unavailable",
      checked_at: checkedAt,
      checks: { neo4j: "unavailable", migrations: "unknown" },
      diagnostics: [error instanceof Error ? error.message : String(error)],
    });
  } finally {
    await session.close();
  }
});

router.get("/metrics", (_request, response) => response.json(requestMetricsSnapshot()));

export default router;
