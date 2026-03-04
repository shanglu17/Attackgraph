import crypto from "node:crypto";
import { getDriver } from "../db/neo4j.js";
import type { AttackPath, GraphChangeSet } from "../types/domain.js";
import type { AssetEdge, AssetNode, ThreatPoint } from "../types/domain.js";

const graphVersionNodeId = "GRAPH_VERSION";

export class GraphRepository {
  async ensureConstraints(): Promise<void> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run("CREATE CONSTRAINT asset_unique IF NOT EXISTS FOR (a:AssetNode) REQUIRE a.assetId IS UNIQUE");
        await tx.run("CREATE CONSTRAINT edge_unique IF NOT EXISTS FOR ()-[r:ASSET_EDGE]-() REQUIRE r.edgeId IS UNIQUE");
        await tx.run("CREATE CONSTRAINT threat_unique IF NOT EXISTS FOR (t:ThreatPoint) REQUIRE t.threatId IS UNIQUE");
        await tx.run("CREATE CONSTRAINT path_unique IF NOT EXISTS FOR (p:AttackPath) REQUIRE p.pathId IS UNIQUE");
        await tx.run("CREATE CONSTRAINT graph_version_unique IF NOT EXISTS FOR (v:GraphVersion) REQUIRE v.id IS UNIQUE");
        await tx.run(
          "MERGE (v:GraphVersion {id: $id}) ON CREATE SET v.value = $version ON MATCH SET v.value = coalesce(v.value, $version)",
          { id: graphVersionNodeId, version: "v1" }
        );
      });
    } finally {
      await session.close();
    }
  }

  async getGraph(): Promise<{
    version: string;
    assets: AssetNode[];
    edges: AssetEdge[];
    threats: ThreatPoint[];
  }> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead(async (tx) => {
        const [versionRes, assetsRes, edgesRes, threatsRes] = await Promise.all([
          tx.run("MATCH (v:GraphVersion {id: $id}) RETURN v.value AS version", { id: graphVersionNodeId }),
          tx.run("MATCH (a:AssetNode) RETURN a ORDER BY a.assetId"),
          tx.run(
            "MATCH (s:AssetNode)-[r:ASSET_EDGE]->(t:AssetNode) RETURN r.edgeId AS edgeId, s.assetId AS sourceAssetId, t.assetId AS targetAssetId, r.relationType AS relationType, r.trustBoundary AS trustBoundary, r.directionality AS directionality ORDER BY edgeId"
          ),
          tx.run(
            "MATCH (th:ThreatPoint)-[:OVERLAY_ON]->(a:AssetNode) RETURN th.threatId AS threatId, th.name AS name, th.category AS category, th.severityBase AS severityBase, th.preconditionText AS preconditionText, a.assetId AS assetId ORDER BY threatId"
          )
        ]);
        return { versionRes, assetsRes, edgesRes, threatsRes };
      });

      return {
        version: (result.versionRes.records[0]?.get("version") as string) ?? "v1",
        assets: result.assetsRes.records.map((r) => ({
          assetId: r.get("a").properties.assetId,
          name: r.get("a").properties.name,
          assetType: r.get("a").properties.assetType,
          criticality: Number(r.get("a").properties.criticality),
          owner: r.get("a").properties.owner,
          tags: r.get("a").properties.tags
        })),
        edges: result.edgesRes.records.map((r) => ({
          edgeId: r.get("edgeId"),
          sourceAssetId: r.get("sourceAssetId"),
          targetAssetId: r.get("targetAssetId"),
          relationType: r.get("relationType"),
          trustBoundary: r.get("trustBoundary"),
          directionality: r.get("directionality")
        })),
        threats: result.threatsRes.records.map((r) => ({
          threatId: r.get("threatId"),
          name: r.get("name"),
          category: r.get("category"),
          severityBase: r.get("severityBase"),
          preconditionText: r.get("preconditionText"),
          assetId: r.get("assetId")
        }))
      };
    } finally {
      await session.close();
    }
  }

  async validateChangeSet(changeSet: GraphChangeSet): Promise<{ valid: boolean; errors: string[] }> {
    const session = getDriver().session();
    const errors: string[] = [];
    try {
      const dbVersionResult = await session.run("MATCH (v:GraphVersion {id: $id}) RETURN v.value AS version", {
        id: graphVersionNodeId
      });
      const dbVersion = (dbVersionResult.records[0]?.get("version") as string) ?? "v1";
      if (dbVersion !== changeSet.graphVersion) {
        errors.push(`图版本冲突：当前版本 ${dbVersion}，提交版本 ${changeSet.graphVersion}`);
      }

      const referencedAssetIds = new Set<string>();
      for (const edge of [...changeSet.edges.add, ...changeSet.edges.update]) {
        referencedAssetIds.add(edge.sourceAssetId);
        referencedAssetIds.add(edge.targetAssetId);
      }
      for (const threat of [...changeSet.threats.add, ...changeSet.threats.update]) {
        referencedAssetIds.add(threat.assetId);
      }

      if (referencedAssetIds.size > 0) {
        const existingAssetsResult = await session.run(
          "MATCH (a:AssetNode) WHERE a.assetId IN $assetIds RETURN collect(a.assetId) AS ids",
          { assetIds: Array.from(referencedAssetIds) }
        );
        const existing = new Set<string>((existingAssetsResult.records[0]?.get("ids") as string[]) ?? []);
        const adding = new Set(changeSet.assets.add.map((a) => a.assetId));
        for (const refId of referencedAssetIds) {
          if (!existing.has(refId) && !adding.has(refId)) {
            errors.push(`引用资产不存在：${refId}`);
          }
        }
      }

      return { valid: errors.length === 0, errors };
    } finally {
      await session.close();
    }
  }

  async commitChangeSet(changeSet: GraphChangeSet, userId: string): Promise<{ newVersion: string; commitId: string }> {
    const session = getDriver().session();
    const commitId = crypto.randomUUID();
    const newVersion = `v_${Date.now()}`;

    try {
      await session.executeWrite(async (tx) => {
        for (const assetId of changeSet.threats.delete) {
          await tx.run("MATCH (th:ThreatPoint {threatId: $threatId}) DETACH DELETE th", { threatId: assetId });
        }
        for (const edgeId of changeSet.edges.delete) {
          await tx.run("MATCH ()-[r:ASSET_EDGE {edgeId: $edgeId}]-() DELETE r", { edgeId });
        }
        for (const assetId of changeSet.assets.delete) {
          await tx.run("MATCH (a:AssetNode {assetId: $assetId}) DETACH DELETE a", { assetId });
        }

        for (const asset of [...changeSet.assets.add, ...changeSet.assets.update]) {
          await tx.run(
            "MERGE (a:AssetNode {assetId: $assetId}) SET a.name = $name, a.assetType = $assetType, a.criticality = $criticality, a.owner = $owner, a.tags = $tags",
            { ...asset, tags: asset.tags ?? [] }
          );
        }

        for (const edge of [...changeSet.edges.add, ...changeSet.edges.update]) {
          await tx.run(
            "MATCH (s:AssetNode {assetId: $sourceAssetId}), (t:AssetNode {assetId: $targetAssetId}) MERGE (s)-[r:ASSET_EDGE {edgeId: $edgeId}]->(t) SET r.relationType = $relationType, r.trustBoundary = $trustBoundary, r.directionality = $directionality",
            edge
          );
        }

        for (const threat of [...changeSet.threats.add, ...changeSet.threats.update]) {
          await tx.run(
            "MERGE (th:ThreatPoint {threatId: $threatId}) SET th.name = $name, th.category = $category, th.severityBase = $severityBase, th.preconditionText = $preconditionText WITH th MATCH (a:AssetNode {assetId: $assetId}) MERGE (th)-[:OVERLAY_ON]->(a)",
            threat
          );
        }

        await tx.run("MATCH (v:GraphVersion {id: $id}) SET v.value = $newVersion", {
          id: graphVersionNodeId,
          newVersion
        });

        await tx.run(
          "CREATE (c:CommitAudit {commitId: $commitId, userId: $userId, createdAt: datetime(), summary: $summary, newVersion: $newVersion})",
          {
            commitId,
            userId,
            newVersion,
            summary: `assets(+${changeSet.assets.add.length}/~${changeSet.assets.update.length}/-${changeSet.assets.delete.length}), edges(+${changeSet.edges.add.length}/~${changeSet.edges.update.length}/-${changeSet.edges.delete.length}), threats(+${changeSet.threats.add.length}/~${changeSet.threats.update.length}/-${changeSet.threats.delete.length})`
          }
        );
      });
      return { newVersion, commitId };
    } finally {
      await session.close();
    }
  }

  async persistAttackPaths(paths: AttackPath[]): Promise<number> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        for (const path of paths) {
          await tx.run(
            "MERGE (p:AttackPath {pathId: $pathId}) SET p.analysisBatchId = $analysisBatchId, p.hopCount = $hopCount, p.score = $score, p.priority = $priority, p.explanations = $explanations, p.generatedBy = $generatedBy, p.generatedAt = datetime($generatedAt)",
            {
              pathId: path.pathId,
              analysisBatchId: path.analysisBatchId,
              hopCount: path.hopCount,
              score: path.score,
              priority: path.priority,
              explanations: path.explanations,
              generatedBy: path.generatedBy,
              generatedAt: path.generatedAt
            }
          );

          await tx.run(
            "MATCH (p:AttackPath {pathId: $pathId}), (t:ThreatPoint {threatId: $threatId}) MERGE (p)-[:STARTS_FROM]->(t)",
            { pathId: path.pathId, threatId: path.startsFromThreatId }
          );

          for (const hit of path.hits) {
            await tx.run(
              "MATCH (p:AttackPath {pathId: $pathId}), (a:AssetNode {assetId: $assetId}) MERGE (p)-[r:HITS {hop: $hop}]->(a)",
              { pathId: path.pathId, assetId: hit.assetId, hop: hit.hop }
            );
          }

          for (const traversed of path.traverses) {
            await tx.run(
              "MATCH (p:AttackPath {pathId: $pathId}), (a:AssetNode {assetId: $assetId}) MERGE (p)-[r:TRAVERSES {hop: $hop, edgeId: $edgeId}]->(a)",
              {
                pathId: path.pathId,
                assetId: traversed.assetId,
                hop: traversed.hop,
                edgeId: traversed.edgeId
              }
            );
          }
        }
      });
      return paths.length;
    } finally {
      await session.close();
    }
  }

  async getAttackPaths(analysisBatchId?: string): Promise<Array<Record<string, unknown>>> {
    const session = getDriver().session();
    try {
      const where = analysisBatchId ? "WHERE p.analysisBatchId = $analysisBatchId" : "";
      const result = await session.run(
        `MATCH (p:AttackPath) ${where} RETURN p.pathId AS pathId, p.analysisBatchId AS analysisBatchId, p.hopCount AS hopCount, p.score AS score, p.priority AS priority, p.explanations AS explanations, p.generatedBy AS generatedBy, toString(p.generatedAt) AS generatedAt ORDER BY p.score DESC`,
        { analysisBatchId }
      );
      return result.records.map((r) => ({
        pathId: r.get("pathId"),
        analysisBatchId: r.get("analysisBatchId"),
        hopCount: r.get("hopCount"),
        score: r.get("score"),
        priority: r.get("priority"),
        explanations: r.get("explanations"),
        generatedBy: r.get("generatedBy"),
        generatedAt: r.get("generatedAt")
      }));
    } finally {
      await session.close();
    }
  }

  async getAuditCommits(): Promise<Array<Record<string, unknown>>> {
    const session = getDriver().session();
    try {
      const result = await session.run(
        "MATCH (c:CommitAudit) RETURN c.commitId AS commitId, c.userId AS userId, toString(c.createdAt) AS createdAt, c.summary AS summary, c.newVersion AS newVersion ORDER BY c.createdAt DESC LIMIT 100"
      );
      return result.records.map((r) => ({
        commitId: r.get("commitId"),
        userId: r.get("userId"),
        createdAt: r.get("createdAt"),
        summary: r.get("summary"),
        newVersion: r.get("newVersion")
      }));
    } finally {
      await session.close();
    }
  }
}
