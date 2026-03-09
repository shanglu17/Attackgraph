import type {
  AttackComplexityLevel,
  AttackPath,
  AssetEdge,
  AssetNode,
  EntryLikelihoodLevel,
  ThreatPoint,
  ThreatSource
} from "../types/domain.js";

interface AnalysisInput {
  analysis_batch_id: string;
  max_hops: number;
  generated_by: string;
  scope_asset_ids?: string[];
  dps_hop_decay?: number;
  asset_nodes: AssetNode[];
  asset_edges: AssetEdge[];
  threat_points: ThreatPoint[];
}

interface CandidatePath {
  analysis_batch_id: string;
  entry_point_id: string;
  target_asset_id: string;
  hop_sequence: string;
  hop_count: number;
  path_probability: number;
  raw_score: number;
  dps_score: number;
  heuristic_score: number;
  generated_by: string;
  generated_at: string;
  traverses: Array<{ hop: number; edge_id: string; asset_id: string; edge_factor: number }>;
  entry_likelihood_level: EntryLikelihoodLevel;
  attack_complexity_level: AttackComplexityLevel;
  threat_source: ThreatSource;
  entry_likelihood_value: number;
  attack_success_factor: number;
  source_weight: number;
  expert_modifier: number;
  expert_adjustment_note?: string;
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

const sourceWeightMap: Record<ThreatSource, number> = {
  internal: 0.9,
  external: 0.7,
  "third-party": 0.5
};

const lowPriorityThreshold = 0.15;
const scoreConfigVersion = "dps-heuristic-v1-2026-03-09";
const defaultDpsHopDecay = 0.95;

interface DfsState {
  current_asset_id: string;
  traverses: Array<{ hop: number; edge_id: string; asset_id: string; edge_factor: number }>;
  structural_score: number;
  visited: Set<string>;
}

interface DfsContext {
  threat: ThreatPoint;
  input: AnalysisInput;
  adjacency: Map<string, AssetEdge[]>;
  scope_set: Set<string> | null;
  asset_ids: Set<string>;
  candidates: CandidatePath[];
}

export class AnalysisService {
  run(input: AnalysisInput): AttackPath[] {
    const adjacency = this.buildAdjacency(input.asset_edges);
    const assetIds = new Set(input.asset_nodes.map((asset) => asset.asset_id));
    const scopeSet = input.scope_asset_ids ? new Set(input.scope_asset_ids) : null;
    const candidates: CandidatePath[] = [];

    for (const threat of input.threat_points) {
      if (scopeSet && !scopeSet.has(threat.related_asset_id)) {
        continue;
      }
      if (!assetIds.has(threat.related_asset_id)) {
        continue;
      }

      this.dps(
        {
          threat,
          input,
          adjacency,
          scope_set: scopeSet,
          asset_ids: assetIds,
          candidates
        },
        {
          current_asset_id: threat.related_asset_id,
          traverses: [],
          structural_score: 1,
          visited: new Set([threat.related_asset_id])
        }
      );
    }

    const maxRawScore = Math.max(...candidates.map((item) => item.raw_score), 0);
    const ranked = candidates
      .map((item) => {
        const normalizedScore = maxRawScore > 0 ? item.raw_score / maxRawScore : 0;
        const isLowPriority = normalizedScore < lowPriorityThreshold;
        return {
          ...item,
          normalized_score: Number(normalizedScore.toFixed(6)),
          is_low_priority: isLowPriority,
          priority_label: this.resolvePriorityLabel(normalizedScore)
        };
      })
      .sort((a, b) => b.raw_score - a.raw_score);

    return ranked.map((item, index) => {
      const pathId = `AP-${String(index + 1).padStart(4, "0")}`;
      return {
        path_id: pathId,
        analysis_batch_id: item.analysis_batch_id,
        entry_point_id: item.entry_point_id,
        target_asset_id: item.target_asset_id,
        hop_sequence: item.hop_sequence,
        hop_count: item.hop_count,
        path_probability: Number(item.path_probability.toFixed(6)),
        raw_score: Number(item.raw_score.toFixed(6)),
        dps_score: Number(item.dps_score.toFixed(6)),
        heuristic_score: Number(item.heuristic_score.toFixed(6)),
        normalized_score: item.normalized_score,
        priority_label: item.priority_label,
        is_low_priority: item.is_low_priority,
        score_config_version: scoreConfigVersion,
        explanations: [
          `entry_likelihood_value(${item.entry_likelihood_level})=${item.entry_likelihood_value}`,
          `attack_success_factor(${item.attack_complexity_level})=${item.attack_success_factor}`,
          `source_weight(${item.threat_source})=${item.source_weight}`,
          `expert_modifier=${item.expert_modifier}${item.expert_adjustment_note ? `, note=${item.expert_adjustment_note}` : ""}`,
          `dps_score=${item.dps_score.toFixed(6)} (edge_factor_product x hop_decay)`,
          `raw_score=${item.raw_score.toFixed(6)}, normalized_score=${item.normalized_score.toFixed(6)}`,
          item.is_low_priority
            ? `normalized_score < ${lowPriorityThreshold}, marked as low priority`
            : `normalized_score >= ${lowPriorityThreshold}, move to mitigation queue`
        ],
        generated_by: item.generated_by,
        generated_at: item.generated_at,
        traverses: item.traverses
      } satisfies AttackPath;
    });
  }

  private dps(context: DfsContext, state: DfsState): void {
    if (state.traverses.length >= context.input.max_hops) {
      return;
    }

    const outgoing = context.adjacency.get(state.current_asset_id) ?? [];
    for (const edge of outgoing) {
      if (context.scope_set && !context.scope_set.has(edge.target_asset_id)) {
        continue;
      }
      if (!context.asset_ids.has(edge.target_asset_id)) {
        continue;
      }
      if (state.visited.has(edge.target_asset_id)) {
        continue;
      }

      const nextHop = state.traverses.length + 1;
      const edgeFactor = this.resolveEdgeFactor(edge);
      const nextStructuralScore = state.structural_score * edgeFactor;
      const nextTraverses = [
        ...state.traverses,
        {
          hop: nextHop,
          edge_id: edge.edge_id,
          asset_id: edge.target_asset_id,
          edge_factor: Number(edgeFactor.toFixed(6))
        }
      ];

      const heuristicScore = this.resolveHeuristicScore(context.threat);
      const hopDecay = Math.pow(context.input.dps_hop_decay ?? defaultDpsHopDecay, Math.max(nextHop - 1, 0));
      const dpsScore = nextStructuralScore * hopDecay;
      const rawScore = heuristicScore * dpsScore;
      const hopSequence = [
        context.threat.threatpoint_id,
        context.threat.related_asset_id,
        ...nextTraverses.map((traverse) => traverse.asset_id)
      ].join(">");

      context.candidates.push({
        analysis_batch_id: context.input.analysis_batch_id,
        entry_point_id: context.threat.threatpoint_id,
        target_asset_id: edge.target_asset_id,
        hop_sequence: hopSequence,
        hop_count: nextHop,
        path_probability: rawScore,
        raw_score: rawScore,
        dps_score: dpsScore,
        heuristic_score: heuristicScore,
        generated_by: context.input.generated_by,
        generated_at: new Date().toISOString(),
        traverses: nextTraverses,
        entry_likelihood_level: context.threat.entry_likelihood_level,
        attack_complexity_level: context.threat.attack_complexity_level,
        threat_source: context.threat.threat_source,
        entry_likelihood_value: entryLikelihoodMap[context.threat.entry_likelihood_level],
        attack_success_factor: attackComplexityMap[context.threat.attack_complexity_level],
        source_weight: sourceWeightMap[context.threat.threat_source],
        expert_modifier: this.normalizeExpertModifier(context.threat.expert_modifier),
        expert_adjustment_note: context.threat.expert_adjustment_note
      });

      const nextVisited = new Set(state.visited);
      nextVisited.add(edge.target_asset_id);
      this.dps(context, {
        current_asset_id: edge.target_asset_id,
        traverses: nextTraverses,
        structural_score: nextStructuralScore,
        visited: nextVisited
      });
    }
  }

  private buildAdjacency(edges: AssetEdge[]): Map<string, AssetEdge[]> {
    const adjacency = new Map<string, AssetEdge[]>();
    for (const edge of edges) {
      const outgoing = adjacency.get(edge.source_asset_id) ?? [];
      outgoing.push(edge);
      adjacency.set(edge.source_asset_id, outgoing);

      if (edge.direction === "Bidirectional") {
        const reverse: AssetEdge = {
          ...edge,
          edge_id: `${edge.edge_id}#rev`,
          source_asset_id: edge.target_asset_id,
          target_asset_id: edge.source_asset_id
        };
        const reverseOutgoing = adjacency.get(reverse.source_asset_id) ?? [];
        reverseOutgoing.push(reverse);
        adjacency.set(reverse.source_asset_id, reverseOutgoing);
      }
    }
    return adjacency;
  }

  private resolveHeuristicScore(threat: ThreatPoint): number {
    const entryLikelihoodValue = entryLikelihoodMap[threat.entry_likelihood_level];
    const attackSuccessFactor = attackComplexityMap[threat.attack_complexity_level];
    const sourceWeight = sourceWeightMap[threat.threat_source];
    const expertModifier = this.normalizeExpertModifier(threat.expert_modifier);
    return entryLikelihoodValue * attackSuccessFactor * sourceWeight * expertModifier;
  }

  private resolveEdgeFactor(edge: AssetEdge): number {
    const trustFactorMap = {
      Trusted: 1,
      "Semi-Trusted": 0.85,
      Untrusted: 0.7
    } satisfies Record<NonNullable<AssetEdge["trust_level"]>, number>;
    const trustFactor = edge.trust_level ? trustFactorMap[edge.trust_level] : 0.9;

    if (!edge.security_mechanism) {
      return trustFactor;
    }

    const value = edge.security_mechanism.toLowerCase();
    let securityFactor = 0.9;
    if (/tls|ssl|ipsec|vpn|wpa2|wpa3|macsec|802\.1x/.test(value)) {
      securityFactor = 0.8;
    } else if (/certificate|token|mfa|signature/.test(value)) {
      securityFactor = 0.85;
    }

    return Math.max(0.3, Number((trustFactor * securityFactor).toFixed(6)));
  }

  private normalizeExpertModifier(value: number | undefined): number {
    if (typeof value !== "number" || Number.isNaN(value)) {
      return 1.0;
    }
    return Math.max(0.5, Math.min(1.5, value));
  }

  private resolvePriorityLabel(normalizedScore: number): AttackPath["priority_label"] {
    if (normalizedScore >= 0.5) {
      return "High";
    }
    if (normalizedScore >= lowPriorityThreshold) {
      return "Medium";
    }
    return "Low";
  }
}
