import crypto from "node:crypto";
import type { AttackPath, AssetEdge, AssetNode, Priority, ThreatPoint } from "../types/domain.js";

interface AnalysisInput {
  analysisBatchId: string;
  maxHops: number;
  generatedBy: string;
  scopeAssetIds?: string[];
  assets: AssetNode[];
  edges: AssetEdge[];
  threats: ThreatPoint[];
}

export class AnalysisService {
  run(input: AnalysisInput): AttackPath[] {
    const adjacency = new Map<string, AssetEdge[]>();
    for (const edge of input.edges) {
      const list = adjacency.get(edge.sourceAssetId) ?? [];
      list.push(edge);
      adjacency.set(edge.sourceAssetId, list);
      if (edge.directionality === "BI") {
        const reverse: AssetEdge = {
          ...edge,
          sourceAssetId: edge.targetAssetId,
          targetAssetId: edge.sourceAssetId,
          edgeId: `${edge.edgeId}#rev`
        };
        const revList = adjacency.get(reverse.sourceAssetId) ?? [];
        revList.push(reverse);
        adjacency.set(reverse.sourceAssetId, revList);
      }
    }

    const assetsById = new Map(input.assets.map((asset) => [asset.assetId, asset]));
    const scopeSet = input.scopeAssetIds ? new Set(input.scopeAssetIds) : null;
    const dedupe = new Set<string>();
    const paths: AttackPath[] = [];

    for (const threat of input.threats) {
      if (scopeSet && !scopeSet.has(threat.assetId)) {
        continue;
      }

      type QueueState = { assetId: string; hops: number; traverses: Array<{ hop: number; edgeId: string; assetId: string }> };
      const queue: QueueState[] = [{ assetId: threat.assetId, hops: 0, traverses: [] }];

      while (queue.length > 0) {
        const current = queue.shift() as QueueState;
        if (current.hops >= input.maxHops) {
          continue;
        }

        const outgoing = adjacency.get(current.assetId) ?? [];
        for (const edge of outgoing) {
          if (scopeSet && !scopeSet.has(edge.targetAssetId)) {
            continue;
          }
          const nextHops = current.hops + 1;
          const traverses = [...current.traverses, { hop: nextHops, edgeId: edge.edgeId, assetId: edge.targetAssetId }];
          const signature = `${threat.threatId}::${traverses.map((t) => `${t.hop}:${t.edgeId}->${t.assetId}`).join("|")}`;
          if (dedupe.has(signature)) {
            continue;
          }
          dedupe.add(signature);

          const targetAsset = assetsById.get(edge.targetAssetId);
          if (!targetAsset) {
            continue;
          }
          const { score, priority, explanations } = this.scorePath({
            threatSeverity: threat.severityBase,
            hopCount: nextHops,
            trustBoundaryCrossings: traverses.filter((t) => t.edgeId.includes("#rev")).length,
            targetCriticality: targetAsset.criticality,
            relationTypes: outgoing.map((e) => e.relationType)
          });

          paths.push({
            pathId: crypto.randomUUID(),
            analysisBatchId: input.analysisBatchId,
            hopCount: nextHops,
            score,
            priority,
            explanations,
            generatedBy: input.generatedBy,
            generatedAt: new Date().toISOString(),
            startsFromThreatId: threat.threatId,
            hits: [
              { hop: 0, assetId: threat.assetId },
              { hop: nextHops, assetId: targetAsset.assetId }
            ],
            traverses
          });

          queue.push({
            assetId: edge.targetAssetId,
            hops: nextHops,
            traverses
          });
        }
      }
    }

    return paths.sort((a, b) => b.score - a.score);
  }

  private scorePath(input: {
    threatSeverity: number;
    hopCount: number;
    trustBoundaryCrossings: number;
    targetCriticality: number;
    relationTypes: string[];
  }): { score: number; priority: Priority; explanations: string[] } {
    const threatComponent = input.threatSeverity * 20;
    const hopPenalty = Math.max(0, (input.hopCount - 1) * 5);
    const trustComponent = input.trustBoundaryCrossings * 8;
    const criticalityComponent = input.targetCriticality * 10;
    const relationComponent = input.relationTypes.some((type) => /control|manage/i.test(type)) ? 12 : 5;

    const raw = threatComponent + trustComponent + criticalityComponent + relationComponent - hopPenalty;
    const score = Math.max(0, Math.min(100, raw));
    const priority: Priority = score >= 80 ? "P1" : score >= 60 ? "P2" : "P3";

    return {
      score,
      priority,
      explanations: [
        `威胁基线严重度贡献 ${threatComponent}`,
        `路径长度折减 ${hopPenalty}`,
        `信任边界穿越贡献 ${trustComponent}`,
        `目标资产关键性贡献 ${criticalityComponent}`,
        `关系类型权重贡献 ${relationComponent}`
      ]
    };
  }
}
