import crypto from "node:crypto";
import type {
  AttackComplexityLevel,
  AttackPath,
  AttackSourceType,
  AssetEdge,
  AssetNode,
  EntryLikelihoodLevel,
  Priority,
  ThreatPoint
} from "../types/domain.js";

interface AnalysisInput {
  analysisBatchId: string;
  maxHops: number;
  generatedBy: string;
  scopeAssetIds?: string[];
  assets: AssetNode[];
  edges: AssetEdge[];
  threats: ThreatPoint[];
}

interface CandidatePath {
  pathId: string;
  analysisBatchId: string;
  hopCount: number;
  rawScore: number;
  generatedBy: string;
  generatedAt: string;
  startsFromThreatId: string;
  hits: Array<{ hop: number; assetId: string }>;
  traverses: Array<{ hop: number; edgeId: string; assetId: string }>;
  entryLikelihoodLevel: EntryLikelihoodLevel;
  attackComplexityLevel: AttackComplexityLevel;
  sourceType: AttackSourceType;
  entryLikelihoodValue: number;
  attackSuccessFactor: number;
  sourceWeight: number;
  expertModifier: number;
  expertAdjustmentNote?: string;
}

const entryLikelihoodMap: Record<EntryLikelihoodLevel, number> = {
  High: 0.7,
  Medium: 0.5,
  Low: 0.3
};

const attackComplexityMap: Record<AttackComplexityLevel, number> = {
  Low: 1.0,
  Medium: 0.7,
  High: 0.4
};

const sourceWeightMap: Record<AttackSourceType, number> = {
  internal: 0.9,
  external: 0.7,
  "third-party": 0.5
};

const lowPriorityThreshold = 0.15;
const scoreConfigVersion = "heuristic-v2-2026-03-04";

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
    const candidates: CandidatePath[] = [];

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
          const entryLikelihoodLevel = this.resolveEntryLikelihoodLevel(threat);
          const attackComplexityLevel = this.resolveAttackComplexityLevel(threat);
          const sourceType = this.resolveSourceType(threat);
          const entryLikelihoodValue = entryLikelihoodMap[entryLikelihoodLevel];
          const attackSuccessFactor = attackComplexityMap[attackComplexityLevel];
          const sourceWeight = sourceWeightMap[sourceType];
          const expertModifier = this.normalizeExpertModifier(threat.expertModifier);
          const rawScore = entryLikelihoodValue * attackSuccessFactor * sourceWeight * expertModifier;

          candidates.push({
            pathId: crypto.randomUUID(),
            analysisBatchId: input.analysisBatchId,
            hopCount: nextHops,
            rawScore,
            generatedBy: input.generatedBy,
            generatedAt: new Date().toISOString(),
            startsFromThreatId: threat.threatId,
            hits: [
              { hop: 0, assetId: threat.assetId },
              { hop: nextHops, assetId: targetAsset.assetId }
            ],
            traverses,
            entryLikelihoodLevel,
            attackComplexityLevel,
            sourceType,
            entryLikelihoodValue,
            attackSuccessFactor,
            sourceWeight,
            expertModifier,
            expertAdjustmentNote: threat.expertAdjustmentNote
          });

          queue.push({
            assetId: edge.targetAssetId,
            hops: nextHops,
            traverses
          });
        }
      }
    }

    const maxRawScore = Math.max(...candidates.map((item) => item.rawScore), 0);
    const paths: AttackPath[] = candidates.map((item) => {
      const normalizedScore = maxRawScore > 0 ? item.rawScore / maxRawScore : 0;
      const isLowPriority = normalizedScore < lowPriorityThreshold;
      const { score, priority } = this.rankPath(normalizedScore, isLowPriority);

      return {
        pathId: item.pathId,
        analysisBatchId: item.analysisBatchId,
        hopCount: item.hopCount,
        rawScore: Number(item.rawScore.toFixed(6)),
        normalizedScore: Number(normalizedScore.toFixed(6)),
        isLowPriority,
        scoreConfigVersion,
        score,
        priority,
        explanations: [
          `entry_likelihood_value(${item.entryLikelihoodLevel})=${item.entryLikelihoodValue}`,
          `attack_success_factor(${item.attackComplexityLevel})=${item.attackSuccessFactor}`,
          `source_weight(${item.sourceType})=${item.sourceWeight}`,
          `expert_modifier=${item.expertModifier}${item.expertAdjustmentNote ? `, note=${item.expertAdjustmentNote}` : ""}`,
          `raw_score=${item.rawScore.toFixed(6)}, normalized_score=${normalizedScore.toFixed(6)}`,
          isLowPriority
            ? `normalized_score < ${lowPriorityThreshold}，标记为低优先级，默认不进入进一步缓解分析`
            : `normalized_score >= ${lowPriorityThreshold}，进入后续缓解分析队列`
        ],
        generatedBy: item.generatedBy,
        generatedAt: item.generatedAt,
        startsFromThreatId: item.startsFromThreatId,
        hits: item.hits,
        traverses: item.traverses
      };
    });

    return paths.sort((a, b) => b.score - a.score);
  }

  private normalizeExpertModifier(value: number | undefined): number {
    if (typeof value !== "number" || Number.isNaN(value)) {
      return 1.0;
    }
    return Math.max(0.5, Math.min(1.5, value));
  }

  private resolveEntryLikelihoodLevel(threat: ThreatPoint): EntryLikelihoodLevel {
    if (threat.entryLikelihoodLevel) {
      return threat.entryLikelihoodLevel;
    }
    if (threat.severityBase >= 4) {
      return "High";
    }
    if (threat.severityBase <= 2) {
      return "Low";
    }
    return "Medium";
  }

  private resolveAttackComplexityLevel(threat: ThreatPoint): AttackComplexityLevel {
    if (threat.attackComplexityLevel) {
      return threat.attackComplexityLevel;
    }
    if (/rce|credentialaccess|credentialattack/i.test(threat.category)) {
      return "Medium";
    }
    if (/misconfiguration/i.test(threat.category)) {
      return "Low";
    }
    return "High";
  }

  private resolveSourceType(threat: ThreatPoint): AttackSourceType {
    if (threat.sourceType) {
      return threat.sourceType;
    }
    if (/公网|external|internet/i.test(`${threat.name} ${threat.preconditionText ?? ""}`)) {
      return "external";
    }
    if (/third|第三方|供应商/i.test(`${threat.name} ${threat.preconditionText ?? ""}`)) {
      return "third-party";
    }
    return "internal";
  }

  private rankPath(normalizedScore: number, isLowPriority: boolean): { score: number; priority: Priority } {
    const score = Math.max(0, Math.min(100, Math.round(normalizedScore * 100)));
    if (isLowPriority) {
      return { score, priority: "P3" };
    }
    const priority: Priority = normalizedScore >= 0.66 ? "P1" : normalizedScore >= 0.33 ? "P2" : "P3";
    return { score, priority };
  }
}
