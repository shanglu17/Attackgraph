import { f3532PathRules, type F3532PathRule, type F3532PathSeedSelector } from "../../config/f3532/pathRules.js";
import { getSystemDisplayName } from "../../config/f3532/systemAliases.js";
import type {
  BoundaryDataFlowFact,
  F353203GenerationFacts,
  F3532DataTopic,
  GeneratedBusinessPath,
  GeneratedRouteSegment
} from "../../types/domain.js";
import { CandidateRouteFinder, type CandidateRoute, type CandidateRouteSeed } from "./candidateRouteFinder.js";
import { naturalSortUnique } from "./naturalSort.js";
import type { PropagationGraph } from "./propagationGraphBuilder.js";

function hasIntersection<T>(actual: T[], expected: T[] | undefined): boolean {
  return !expected || expected.length === 0 || actual.some((item) => expected.includes(item));
}

function matchesSeed(bdf: BoundaryDataFlowFact, selector: F3532PathSeedSelector | undefined): boolean {
  if (!selector) return false;
  return (
    hasIntersection(bdf.security_boundary_ids, selector.security_boundary_ids) &&
    hasIntersection(bdf.boundary_interface_ids, selector.boundary_interface_ids) &&
    (!selector.producer_system_ids || (bdf.producer_id ? selector.producer_system_ids.includes(bdf.producer_id) : false)) &&
    (!selector.consumer_system_ids || (bdf.consumer_id ? selector.consumer_system_ids.includes(bdf.consumer_id) : false)) &&
    (!selector.data_types || selector.data_types.includes(bdf.data_type)) &&
    hasIntersection(bdf.function_ids, selector.function_ids) &&
    hasIntersection(bdf.topic_ids, selector.topic_ids) &&
    (!selector.directions || selector.directions.includes(bdf.direction))
  );
}

function stableReviewId(sourceId: string): string {
  let hash = 2166136261;
  for (const char of sourceId) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return `R-${(hash >>> 0).toString(36).toUpperCase()}`;
}

function template(value: string, replacements: Record<string, string>): string {
  return value.replace(/\{([A-Z]+)\}/g, (_match, key: string) => replacements[key] ?? `{${key}}`);
}

/** Selects business paths from graph candidates. Rules contain semantics; this service contains no BDF/SDF number lists. */
export class BusinessPathRuleEngine {
  private readonly finder = new CandidateRouteFinder();

  generate(facts: F353203GenerationFacts, graph: PropagationGraph, maxHops: number): GeneratedBusinessPath[] {
    const claimedBdfIds = new Set<string>();
    const paths: GeneratedBusinessPath[] = [];
    const orderedRules = f3532PathRules.filter((rule) => rule.enabled).sort((left, right) => left.priority - right.priority);

    for (const rule of orderedRules) {
      const selectedBdfs = facts.boundary_data_flows.filter(
        (bdf) => !claimedBdfIds.has(bdf.id) && matchesSeed(bdf, rule.seed_selector)
      );
      const hasInternalSeed = (rule.internal_seed_system_ids?.length ?? 0) > 0;
      if (selectedBdfs.length === 0 && !hasInternalSeed) continue;

      for (const bdf of selectedBdfs) claimedBdfIds.add(bdf.id);
      const seeds = this.buildSeeds(rule, selectedBdfs);
      const routes = rule.terminal_conditions.stop_at_seed_consumer
        ? seeds.map((seed) => ({
            seed_id: seed.seed_id,
            edges: [],
            terminal_system_id: seed.start_system_id,
            stop_reason: "规则指定在 BDF Consumer 停止",
            evidence: [],
            warnings: []
          } satisfies CandidateRoute))
        : seeds.flatMap((seed) => this.finder.find(graph, rule, seed, maxHops));

      if (selectedBdfs.length === 0 && routes.every((route) => route.edges.length === 0)) {
        continue;
      }
      paths.push(this.assembleRulePath(rule, selectedBdfs, seeds, routes));
    }

    for (const bdf of facts.boundary_data_flows.filter(
      (candidate) => !claimedBdfIds.has(candidate.id) && candidate.direction !== "INTERNAL"
    )) {
      paths.push(this.assembleUnmatchedPath(bdf));
    }
    return paths.sort((left, right) => left.id.localeCompare(right.id, undefined, { numeric: true }));
  }

  private buildSeeds(rule: F3532PathRule, bdfs: BoundaryDataFlowFact[]): CandidateRouteSeed[] {
    const seeds: CandidateRouteSeed[] = bdfs.flatMap((bdf) => {
      const start = bdf.direction === "OUTBOUND" ? bdf.producer_id : bdf.consumer_id;
      return start
        ? [{ seed_id: bdf.id, start_system_id: start, data_type: bdf.data_type, topic_ids: bdf.topic_ids }]
        : [];
    });
    for (const systemId of rule.internal_seed_system_ids ?? []) {
      if (!seeds.some((seed) => seed.start_system_id === systemId)) {
        seeds.push({ seed_id: `${rule.id}:${systemId}`, start_system_id: systemId, topic_ids: [] });
      }
    }
    return seeds.sort((left, right) => left.seed_id.localeCompare(right.seed_id, undefined, { numeric: true }));
  }

  private assembleRulePath(
    rule: F3532PathRule,
    bdfs: BoundaryDataFlowFact[],
    seeds: CandidateRouteSeed[],
    routes: CandidateRoute[]
  ): GeneratedBusinessPath {
    const routeSegments: GeneratedRouteSegment[] = [];
    routes.forEach((route, routeIndex) => {
      route.edges.forEach((edge, edgeIndex) => {
        routeSegments.push({
          from_system_id: edge.from_system_id,
          to_system_id: edge.to_system_id,
          sdf_ids: [edge.sdf_id],
          sequence: edgeIndex + 1,
          branch_id: `${rule.path_code}-B${String(routeIndex + 1).padStart(2, "0")}`,
          system_interface_ids: edge.system_interface_id ? [edge.system_interface_id] : [],
          data_types: [edge.data_type],
          topic_ids: edge.topic_ids
        });
      });
    });
    const sdfIds = naturalSortUnique(routeSegments.flatMap((segment) => segment.sdf_ids));
    const boundaryInterfaceIds = naturalSortUnique(bdfs.flatMap((bdf) => bdf.boundary_interface_ids));
    const topicIds = Array.from(
      new Set<F3532DataTopic>([
        ...bdfs.flatMap((bdf) => bdf.topic_ids),
        ...routeSegments.flatMap((segment) => segment.topic_ids ?? [])
      ])
    );
    const systemNodeIds = naturalSortUnique([
      ...seeds.map((seed) => seed.start_system_id),
      ...bdfs.flatMap((bdf) => [bdf.producer_id ?? "", bdf.consumer_id ?? ""]).filter(Boolean),
      ...routeSegments.flatMap((segment) => [segment.from_system_id, segment.to_system_id])
    ]);
    const replacements = {
      BI: boundaryInterfaceIds.join("、") || "无外部 BI",
      SYSTEMS: systemNodeIds.map(getSystemDisplayName).join(" → ") || "未识别系统",
      TOPICS: topicIds.join("、") || "UNKNOWN"
    };
    const warnings = naturalSortUnique([
      ...bdfs.flatMap((bdf) => bdf.warnings),
      ...routes.flatMap((route) => route.warnings),
      ...(routes.length === 0 ? [`${rule.id} 未找到候选路由`] : [])
    ]);
    return {
      id: rule.path_code,
      compatibility_fp_id: `FP${rule.path_code.slice(1)}`,
      rule_id: rule.id,
      status: warnings.length > 0 && rule.status === "CONFIRMED" ? "NEEDS_REVIEW" : rule.status,
      name: template(rule.output.name_template, replacements),
      description: template(rule.output.description_template, replacements),
      origin_type: rule.origin_type,
      origin_boundary_ids: naturalSortUnique(bdfs.flatMap((bdf) => bdf.security_boundary_ids)),
      seed_bdf_ids: naturalSortUnique(bdfs.map((bdf) => bdf.id)),
      boundary_interface_ids: boundaryInterfaceIds,
      system_interface_ids: naturalSortUnique(routeSegments.flatMap((segment) => segment.system_interface_ids ?? [])),
      bdf_ids: naturalSortUnique(bdfs.map((bdf) => bdf.id)),
      sdf_ids: sdfIds,
      function_ids: naturalSortUnique([
        ...bdfs.flatMap((bdf) => bdf.function_ids),
        ...routes.flatMap((route) => route.edges.flatMap((edge) => edge.function_ids))
      ]),
      data_types: naturalSortUnique([
        ...bdfs.map((bdf) => bdf.data_type),
        ...routeSegments.flatMap((segment) => segment.data_types ?? [])
      ]),
      topic_ids: topicIds,
      system_node_ids: systemNodeIds,
      route_segments: routeSegments,
      terminal_system_ids: naturalSortUnique(routes.map((route) => route.terminal_system_id)),
      stop_reasons: naturalSortUnique(routes.map((route) => route.stop_reason)),
      evidence: [
        {
          type: "PATH_RULE",
          rule_id: rule.id,
          message: `命中 ${rule.id}，稳定编号 ${rule.path_code}`
        },
        ...bdfs.flatMap((bdf) => bdf.evidence),
        ...routes.flatMap((route) => route.evidence)
      ],
      warnings
    };
  }

  private assembleUnmatchedPath(bdf: BoundaryDataFlowFact): GeneratedBusinessPath {
    const systemNodes = naturalSortUnique([bdf.producer_id ?? "", bdf.consumer_id ?? ""].filter(Boolean));
    return {
      id: stableReviewId(`${bdf.id}|${bdf.direction}|${bdf.topic_ids.join(",")}`),
      rule_id: "UNMATCHED_BOUNDARY_FLOW",
      status: "UNMATCHED",
      name: `${bdf.id} 未匹配业务路径`,
      description: `${bdf.producer_name} → ${bdf.consumer_name} 未命中已配置业务规则，保留结构化事实待审核。`,
      origin_type: "BOUNDARY_FLOW",
      origin_boundary_ids: bdf.security_boundary_ids,
      seed_bdf_ids: [bdf.id],
      boundary_interface_ids: bdf.boundary_interface_ids,
      system_interface_ids: [],
      bdf_ids: [bdf.id],
      sdf_ids: [],
      function_ids: bdf.function_ids,
      data_types: [bdf.data_type],
      topic_ids: bdf.topic_ids,
      system_node_ids: systemNodes,
      route_segments: [],
      terminal_system_ids: bdf.consumer_id ? [bdf.consumer_id] : [],
      stop_reasons: ["未命中业务规则"],
      evidence: bdf.evidence,
      warnings: naturalSortUnique([...bdf.warnings, `${bdf.id} 未命中路径规则`])
    };
  }
}
