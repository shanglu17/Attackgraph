import { z } from "zod";
import { createHash } from "node:crypto";
import { evaluateFeatureRules } from "./evaluate.js";

const topologySchema = z.object({ graph_version: z.string(),
  asset_nodes: z.array(z.object({ asset_id: z.string() }).passthrough()).max(100000),
  asset_edges: z.array(z.object({ edge_id: z.string(), source_asset_id: z.string(), target_asset_id: z.string(),
    direction: z.enum(["Unidirectional", "Bidirectional"]) }).passthrough()).max(200000)
}).passthrough();
const mappingSchema = z.array(z.object({ scope_id: z.string(), allowed_edge_ids: z.array(z.string()).max(200000),
  target_asset_ids: z.array(z.string()).max(100000), evidence_refs: z.array(z.string()).max(10000) }).strict()).max(1000);
export type Topology = z.input<typeof topologySchema>;
export type ScopeMapping = z.input<typeof mappingSchema>[number];
type Options = { max_hops?: number; max_paths_per_decision?: number; max_expansions_per_decision?: number };
type Hop = { edge_id: string; next_asset_id: string; reverse: boolean };
type TracePath = { asset_ids: string[]; edge_ids: string[]; reverse_edge_ids: string[]; hop_count: number; topology_only: true };

const candidateDecisions = new Set(["candidate", "candidate_scoped", "candidate_protection_unresolved"]);
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const sorted = (xs: string[]) => [...new Set(xs)].sort(compare);
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical).sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b)));
  if (value !== null && typeof value === "object") return Object.fromEntries(
    Object.entries(value).sort(([a], [b]) => compare(a, b)).map(([k, v]) => [k, canonical(v)]));
  return value;
}
const digest = (value: unknown) => createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");

function unique(xs: string[], label: string) {
  if (xs.some(x => !x.trim()) || new Set(xs).size !== xs.length) throw new Error(`Invalid or duplicate ${label}`);
}

/**
 * Evaluate the original input and enumerate topology candidates for machine decisions. The caller explicitly supplies the
 * scope-to-edge and target mapping; graph edges have no provenance field, so these paths
 * cannot establish attack feasibility, edge evidence, or a calibrated likelihood.
 */
export function traceFeaturePaths(rawInput: unknown, rawGraph: Topology, rawMappings: ScopeMapping[], options: Options = {}) {
  const preview = evaluateFeatureRules(rawInput);
  const graph = topologySchema.parse(rawGraph);
  const mappings = mappingSchema.parse(rawMappings);
  const maxHops = options.max_hops ?? 4;
  const maxPaths = options.max_paths_per_decision ?? 50;
  const maxExpansions = options.max_expansions_per_decision ?? 10000;
  if (!Number.isInteger(maxHops) || maxHops < 1 || maxHops > 10) throw new Error("max_hops must be 1..10");
  if (!Number.isInteger(maxPaths) || maxPaths < 1 || maxPaths > 1000) throw new Error("max_paths_per_decision must be 1..1000");
  if (!Number.isInteger(maxExpansions) || maxExpansions < 1 || maxExpansions > 100000) throw new Error("max_expansions_per_decision must be 1..100000");
  if (!graph.graph_version.trim()) throw new Error("graph_version required");
  unique(graph.asset_nodes.map(x => x.asset_id), "asset_id");
  unique(graph.asset_edges.map(x => x.edge_id), "edge_id");
  unique(mappings.map(x => x.scope_id), "scope_id mapping");
  const nodes = new Set(graph.asset_nodes.map(x => x.asset_id));
  const edges = new Map(graph.asset_edges.map(x => [x.edge_id, x]));
  const scopes = new Set(preview.scope_index.map(x => x.scope_id));
  const evidence = new Map(preview.evidence_index.map(x => [x.evidence_id, x]));
  for (const edge of graph.asset_edges) {
    if (!nodes.has(edge.source_asset_id) || !nodes.has(edge.target_asset_id)) throw new Error(`Unknown edge endpoint: ${edge.edge_id}`);
    if (edge.direction !== "Unidirectional" && edge.direction !== "Bidirectional") throw new Error(`Invalid direction: ${edge.edge_id}`);
  }
  for (const mapping of mappings) {
    if (!scopes.has(mapping.scope_id)) throw new Error(`Unknown scope: ${mapping.scope_id}`);
    unique(mapping.allowed_edge_ids, "allowed_edge_ids");
    unique(mapping.target_asset_ids, "target_asset_ids");
    unique(mapping.evidence_refs, "mapping evidence_refs");
    for (const id of mapping.allowed_edge_ids) if (!edges.has(id)) throw new Error(`Unknown edge: ${id}`);
    for (const id of mapping.target_asset_ids) if (!nodes.has(id)) throw new Error(`Unknown target asset: ${id}`);
    for (const id of mapping.evidence_refs) if (!evidence.has(id)) throw new Error(`Unknown mapping evidence: ${id}`);
  }
  const mappingByScope = new Map(mappings.map(x => [x.scope_id, x]));
  // Decisions are emitted in scope order; retain only the current scope's adjacency.
  let cachedAdjacency: { scope_id: string; adjacency: Map<string, Hop[]> } | null = null;
  function adjacencyFor(mapping: ScopeMapping) {
    if (cachedAdjacency?.scope_id === mapping.scope_id) return cachedAdjacency.adjacency;
    const adjacency = new Map<string, Hop[]>();
    function add(from: string, hop: Hop) {
      const hops = adjacency.get(from);
      if (hops) hops.push(hop);
      else adjacency.set(from, [hop]);
    }
    for (const id of mapping.allowed_edge_ids) {
      const edge = edges.get(id)!;
      add(edge.source_asset_id, { edge_id: id, next_asset_id: edge.target_asset_id, reverse: false });
      if (edge.direction === "Bidirectional")
        add(edge.target_asset_id, { edge_id: id, next_asset_id: edge.source_asset_id, reverse: true });
    }
    for (const hops of adjacency.values()) hops.sort((a, b) => compare(a.edge_id, b.edge_id) || compare(a.next_asset_id, b.next_asset_id));
    cachedAdjacency = { scope_id: mapping.scope_id, adjacency };
    return adjacency;
  }
  const records = preview.decisions.map(decision => {
    const mapping = mappingByScope.get(decision.scope_id);
    const base = { scenario_id: decision.scenario_id, scope_id: decision.scope_id,
      rule_id: decision.rule_id, rule_version: decision.rule_version, output_threat_id: decision.output_threat_id,
      decision: decision.decision, prototype_asset_id: decision.prototype_asset_id,
      review_status: "pending_review" as const, evidence_refs: sorted([
        ...decision.evidence_refs, ...(mapping?.evidence_refs ?? [])]),
      paths: [] as TracePath[], truncated: false, edge_evidence_status: "not_supplied_by_graph" as const };
    if (!candidateDecisions.has(decision.decision) || !decision.executed)
      return { ...base, status: "decision_not_candidate" as const };
    if (!decision.prototype_asset_id || !nodes.has(decision.prototype_asset_id))
      return { ...base, status: "asset_unmapped" as const };
    if (!mapping || mapping.allowed_edge_ids.length === 0 || mapping.target_asset_ids.length === 0)
      return { ...base, status: "scope_unmapped" as const };
    if (mapping.evidence_refs.length === 0 || !mapping.evidence_refs.every(id => {
      const item = evidence.get(id)!;
      return item.review_status === "verified" && Object.values(item.source_locator).some(v => v !== null);
    })) return { ...base, status: "mapping_evidence_unverified" as const };

    const adjacency = adjacencyFor(mapping);
    const targets = new Set(mapping.target_asset_ids);
    const paths: TracePath[] = [];
    let truncated = false;
    let expansions = 0;
    function walk(current: string, assetIds: string[], edgeIds: string[], reverseEdgeIds: string[], visited: Set<string>) {
      if (truncated) return;
      if (edgeIds.length >= maxHops) {
        if ((adjacency.get(current) ?? []).some(hop => !visited.has(hop.next_asset_id))) truncated = true;
        return;
      }
      for (const hop of adjacency.get(current) ?? []) {
        if (visited.has(hop.next_asset_id)) continue;
        if (expansions >= maxExpansions) { truncated = true; return; }
        expansions++;
        const nextAssets = [...assetIds, hop.next_asset_id];
        const nextEdges = [...edgeIds, hop.edge_id];
        const nextReverse = hop.reverse ? [...reverseEdgeIds, hop.edge_id] : reverseEdgeIds;
        if (targets.has(hop.next_asset_id)) {
          paths.push({ asset_ids: nextAssets, edge_ids: nextEdges,
            reverse_edge_ids: nextReverse, hop_count: nextEdges.length, topology_only: true });
          if (paths.length === maxPaths) { truncated = true; return; }
        }
        const nextVisited = new Set(visited); nextVisited.add(hop.next_asset_id);
        walk(hop.next_asset_id, nextAssets, nextEdges, nextReverse, nextVisited);
        if (truncated) return;
      }
    }
    walk(decision.prototype_asset_id, [decision.prototype_asset_id], [], [], new Set([decision.prototype_asset_id]));
    return { ...base, paths, truncated,
      status: paths.length ? "topology_candidate" as const :
        truncated ? "search_incomplete" as const : "no_path_in_snapshot" as const };
  });
  return { format: "feature-path-trace-0.1" as const, scenario_id: preview.decisions[0]?.scenario_id ?? null,
    input_sha256: preview.input_sha256, graph_version: graph.graph_version,
    graph_sha256: digest(graph), mapping_sha256: digest(mappings),
    max_hops: maxHops, max_paths_per_decision: maxPaths,
    max_expansions_per_decision: maxExpansions, records };
}
