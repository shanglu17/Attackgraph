import type { F3532PathRule } from "../../config/f3532/pathRules.js";
import { findTypeTransition } from "../../config/f3532/typeTransitions.js";
import type { F3532DataTopic, F3532GenerationEvidence } from "../../types/domain.js";
import type { PropagationGraph, PropagationGraphEdge } from "./propagationGraphBuilder.js";

export interface CandidateRouteSeed {
  seed_id: string;
  start_system_id: string;
  data_type?: string;
  topic_ids: F3532DataTopic[];
}

export interface CandidateRoute {
  seed_id: string;
  edges: PropagationGraphEdge[];
  terminal_system_id: string;
  stop_reason: string;
  evidence: F3532GenerationEvidence[];
  warnings: string[];
}

interface SearchState {
  node_id: string;
  current_type?: string;
  current_topics: F3532DataTopic[];
  edges: PropagationGraphEdge[];
  visited_nodes: Set<string>;
  visited_sdf_ids: Set<string>;
  evidence: F3532GenerationEvidence[];
  warnings: string[];
}

function intersects<T>(left: T[], right: T[]): boolean {
  return left.some((item) => right.includes(item));
}

function isExplicitTransitionAllowed(rule: F3532PathRule, from: string, to: string): boolean {
  if (rule.allowed_transitions) {
    return rule.allowed_transitions.some(
      (transition) => transition.from.toUpperCase() === from.toUpperCase() && transition.to.toUpperCase() === to.toUpperCase()
    );
  }
  return Boolean(findTypeTransition(from, to));
}

function toFilteredEvidence(rule: F3532PathRule, filtered: string[]): F3532GenerationEvidence[] {
  return filtered.map((message) => ({
    type: "FILTERED_CANDIDATE",
    rule_id: rule.id,
    message
  }));
}

/**
 * Finds topology candidates only. Every returned edge is a real SDF; filtering and stop decisions
 * are carried as evidence so the rule engine never has to reconstruct why a route exists.
 */
export class CandidateRouteFinder {
  find(graph: PropagationGraph, rule: F3532PathRule, seed: CandidateRouteSeed, maxHops: number): CandidateRoute[] {
    const routes: CandidateRoute[] = [];
    const defensiveMaxHops = Math.min(maxHops, rule.max_hops);

    const visit = (state: SearchState): void => {
      const isConfiguredTerminal = (rule.terminal_conditions.system_ids ?? []).includes(state.node_id) && state.edges.length > 0;
      if (isConfiguredTerminal) {
        routes.push(this.toRoute(seed.seed_id, state, `到达规则终止系统 ${state.node_id}`));
        return;
      }
      if (state.edges.length >= defensiveMaxHops) {
        routes.push(this.toRoute(seed.seed_id, state, `达到防御性最大跳数 ${defensiveMaxHops}`));
        return;
      }

      const compatible: Array<{ edge: PropagationGraphEdge; evidence: F3532GenerationEvidence[] }> = [];
      const filtered: string[] = [];
      for (const edge of graph.outgoing.get(state.node_id) ?? []) {
        if (state.visited_sdf_ids.has(edge.sdf_id)) {
          filtered.push(`${edge.sdf_id}: SDF 已在当前分支使用`);
          continue;
        }
        if (state.visited_nodes.has(edge.to_system_id)) {
          filtered.push(`${edge.sdf_id}: 检测到环 ${state.node_id} → ${edge.to_system_id}`);
          continue;
        }
        if (!rule.allowed_system_ids.includes(edge.to_system_id)) {
          filtered.push(`${edge.sdf_id}: 目标系统 ${edge.to_system_id} 不在规则允许范围`);
          continue;
        }
        if (!intersects(edge.topic_ids, rule.allowed_topic_ids)) {
          filtered.push(`${edge.sdf_id}: 主题 ${edge.topic_ids.join("/")} 不在规则允许范围`);
          continue;
        }
        if (state.current_topics.length > 0 && !intersects(state.current_topics, edge.topic_ids)) {
          filtered.push(`${edge.sdf_id}: 与当前业务主题 ${state.current_topics.join("/")} 不兼容`);
          continue;
        }
        const transition = state.current_type
          ? isExplicitTransitionAllowed(rule, state.current_type, edge.data_type)
          : true;
        if (!transition) {
          filtered.push(`${edge.sdf_id}: 未配置类型转换 ${state.current_type} → ${edge.data_type}`);
          continue;
        }
        const transitionRule = state.current_type ? findTypeTransition(state.current_type, edge.data_type)?.rule_id : undefined;
        compatible.push({
          edge,
          evidence: [
            {
              type: "ROUTE_SEGMENT",
              source_id: edge.sdf_id,
              rule_id: rule.id,
              message: `${edge.from_system_id} → ${edge.to_system_id} 使用 ${edge.sdf_id}`
            },
            {
              type: "TYPE_TRANSITION",
              source_id: edge.sdf_id,
              rule_id: transitionRule ?? rule.id,
              message: `${state.current_type ?? "起始"} → ${edge.data_type} 被允许`
            },
            {
              type: "TOPIC_COMPATIBILITY",
              source_id: edge.sdf_id,
              rule_id: rule.id,
              message: `主题 ${edge.topic_ids.join("/")} 与规则及当前路径兼容`
            }
          ]
        });
      }

      const filteredEvidence = toFilteredEvidence(rule, filtered);

      if (compatible.length === 0) {
        const reason = filtered.length > 0 ? `无兼容后继；已过滤 ${filtered.join("；")}` : "无后继 SDF";
        if (state.edges.length > 0 || rule.terminal_conditions.no_compatible_successor) {
          routes.push(this.toRoute(seed.seed_id, { ...state, evidence: [...state.evidence, ...filteredEvidence] }, reason));
        }
        return;
      }

      for (const { edge, evidence } of compatible) {
        const nextTopics = state.current_topics.length > 0
          ? state.current_topics.filter((topic) => edge.topic_ids.includes(topic))
          : edge.topic_ids.filter((topic) => rule.allowed_topic_ids.includes(topic));
        visit({
          node_id: edge.to_system_id,
          current_type: edge.data_type,
          current_topics: nextTopics,
          edges: [...state.edges, edge],
          visited_nodes: new Set([...state.visited_nodes, edge.to_system_id]),
          visited_sdf_ids: new Set([...state.visited_sdf_ids, edge.sdf_id]),
          evidence: [...state.evidence, ...filteredEvidence, ...evidence],
          warnings: state.warnings
        });
      }
    };

    visit({
      node_id: seed.start_system_id,
      current_type: seed.data_type,
      current_topics: seed.topic_ids.filter((topic) => rule.allowed_topic_ids.includes(topic)),
      edges: [],
      visited_nodes: new Set([seed.start_system_id]),
      visited_sdf_ids: new Set(),
      evidence: [],
      warnings: []
    });
    return routes;
  }

  private toRoute(seedId: string, state: SearchState, stopReason: string): CandidateRoute {
    return {
      seed_id: seedId,
      edges: state.edges,
      terminal_system_id: state.node_id,
      stop_reason: stopReason,
      evidence: state.evidence,
      warnings: state.warnings
    };
  }
}
