import type { FunctionPropagationPath } from "../types/domain.js";

/** A boundary data flow as a propagation start point. */
export interface FpBdfInput {
  business_id: string;
  data_flow_type?: string;
  boundary_interface_id?: string;
  /** Entry subsystem = BoundaryInterface.access_object (e.g. RCS, DLS, ICP). */
  entry_subsystem?: string;
  /** External entity = BoundaryInterface.external_entity (e.g. 操控员, 地面维护设备). */
  external_entity?: string;
  /** Entry trust boundary = BoundaryInterface.boundary_id (SB-01..). Used by the "boundary" grouping. */
  entry_boundary?: string;
  function_ids: string[];
}

/** A system data flow as a directed internal edge (producer -> consumer). */
export interface FpSdfInput {
  sdf_id: string;
  producer?: string;
  consumer?: string;
  data_flow_type?: string;
  function_ids: string[];
}

/** Grouping granularity for merging BDFs into representative FPs. */
export type FpGroupBy = "function" | "boundary" | "type";

export interface FpAnalysisInput {
  bdfs: FpBdfInput[];
  sdfs: FpSdfInput[];
  max_hops?: number;
  /** function = type + impacted-function-set (finest); boundary = type + entry SB; type = data type only. */
  group_by?: FpGroupBy;
}

interface SdfEdge {
  sdf_id: string;
  to: string;
  data_flow_type?: string;
  function_ids: string[];
}

interface BdfTraversal {
  bdf: FpBdfInput;
  type: string;
  entry: string;
  external: string;
  entry_boundary: string;
  sdf_ids: string[];
  impacted: string[];
  /** Best (longest) subsystem chain starting at the entry subsystem. */
  chain: string[];
}

const defaultMaxHops = 5;
const defaultGroupBy: FpGroupBy = "boundary";

/**
 * Builds vol3 §4.5 function propagation paths (FP) from boundary data flows (BDF) and
 * system data flows (SDF). Borrows the in-memory adjacency + recursive DFS pattern from
 * AnalysisService, but the graph is directed (no reverse edges), there is no scoring and
 * no target filtering — the goal is reachability + grouping, not attack-path ranking.
 */
export class FpAnalysisService {
  run(input: FpAnalysisInput): FunctionPropagationPath[] {
    const maxHops = input.max_hops ?? defaultMaxHops;
    const groupBy = input.group_by ?? defaultGroupBy;
    const adjacency = this.buildAdjacency(input.sdfs);

    const traversals = input.bdfs.map((bdf) => this.traverse(bdf, adjacency, maxHops));

    // Group by the chosen granularity.
    const groups = new Map<string, BdfTraversal[]>();
    for (const t of traversals) {
      const key = this.groupKey(t, groupBy);
      const bucket = groups.get(key) ?? [];
      bucket.push(t);
      groups.set(key, bucket);
    }

    // Order groups by type then signature for stable FP numbering.
    const orderedKeys = Array.from(groups.keys()).sort((a, b) => a.localeCompare(b));

    return orderedKeys.map((key, index) => {
      const members = groups.get(key)!;
      const fpId = `FP${String(index + 1).padStart(2, "0")}`;
      const type = members[0].type;

      const bdfIds = this.sortByTrailingNumber(members.map((m) => m.bdf.business_id));
      const sdfIds = this.sortByTrailingNumber(members.flatMap((m) => m.sdf_ids));

      // Representative chain = the member with the longest subsystem chain.
      const rep = members.reduce((best, m) => (this.isBetterChain(m.chain, best.chain) ? m : best), members[0]);
      const hasSdf = sdfIds.length > 0;
      const chainBody = rep.chain.join(" → ");
      const systemPath = rep.external && rep.external !== rep.chain[0] ? `${rep.external} → ${chainBody}` : chainBody;

      return {
        fp_id: fpId,
        data_type_label: type,
        system_path_text: systemPath,
        sdf_note: hasSdf ? undefined : "无对应SDF",
        bdf_ids: bdfIds,
        sdf_ids: sdfIds
      } satisfies FunctionPropagationPath;
    });
  }

  private groupKey(t: BdfTraversal, groupBy: FpGroupBy): string {
    switch (groupBy) {
      case "type":
        return t.type;
      case "boundary":
        return `${t.type}||${t.entry_boundary || "?"}`;
      case "function":
      default:
        return `${t.type}||${t.impacted.join(",")}`;
    }
  }

  /**
   * Resolve the entry subsystem. BoundaryInterface.access_object may list several systems
   * (e.g. "IMS、FMS、FCS"); pick the first that exists in the SDF graph so propagation can start.
   */
  private resolveEntry(bdf: FpBdfInput, adjacency: Map<string, SdfEdge[]>): string {
    const candidates = this.splitNames(bdf.entry_subsystem);
    const matched = candidates.find((c) => adjacency.has(c));
    if (matched) {
      return matched;
    }
    if (candidates.length > 0) {
      return candidates[0];
    }
    return this.normalizeName(bdf.external_entity);
  }

  private splitNames(value: string | undefined): string[] {
    return (value ?? "")
      .split(/[、,，/\n\r;；]+/)
      .map((p) => this.normalizeName(p))
      .filter(Boolean);
  }

  private buildAdjacency(sdfs: FpSdfInput[]): Map<string, SdfEdge[]> {
    const adjacency = new Map<string, SdfEdge[]>();
    for (const sdf of sdfs) {
      const from = this.normalizeName(sdf.producer);
      const to = this.normalizeName(sdf.consumer);
      if (!from || !to) {
        continue;
      }
      const outgoing = adjacency.get(from) ?? [];
      outgoing.push({ sdf_id: sdf.sdf_id, to, data_flow_type: sdf.data_flow_type, function_ids: sdf.function_ids });
      adjacency.set(from, outgoing);
    }
    return adjacency;
  }

  private traverse(bdf: FpBdfInput, adjacency: Map<string, SdfEdge[]>, maxHops: number): BdfTraversal {
    const type = this.normalizeType(bdf.data_flow_type);
    const entry = this.resolveEntry(bdf, adjacency);
    const sdfIds = new Set<string>();
    const functions = new Set<string>(bdf.function_ids);
    let bestChain: string[] = entry ? [entry] : [];

    const visited = new Set<string>(entry ? [entry] : []);
    const dfs = (node: string, pathNodes: string[], hops: number): void => {
      if (this.isBetterChain(pathNodes, bestChain)) {
        bestChain = [...pathNodes];
      }
      if (hops >= maxHops) {
        return;
      }
      for (const edge of adjacency.get(node) ?? []) {
        // Type-channel propagation: a CMD input flows along CMD data flows, not unrelated ones.
        // This is the "筛" step — without it the IMS hub makes every BDF reach the whole graph.
        if (this.normalizeType(edge.data_flow_type) !== type) {
          continue;
        }
        // The flow is reachable from the entry within this type channel — record it.
        sdfIds.add(edge.sdf_id);
        for (const fn of edge.function_ids) {
          functions.add(fn);
        }
        if (visited.has(edge.to)) {
          continue;
        }
        visited.add(edge.to);
        dfs(edge.to, [...pathNodes, edge.to], hops + 1);
        visited.delete(edge.to);
      }
    };
    if (entry) {
      dfs(entry, [entry], 0);
    }

    return {
      bdf,
      type,
      entry,
      external: this.normalizeName(bdf.external_entity),
      entry_boundary: (bdf.entry_boundary ?? "").trim().toUpperCase(),
      sdf_ids: Array.from(sdfIds),
      impacted: this.sortByTrailingNumber(Array.from(functions)),
      chain: bestChain
    };
  }

  /** Longer chains win; ties broken lexicographically so the result is deterministic. */
  private isBetterChain(candidate: string[], current: string[]): boolean {
    if (candidate.length !== current.length) {
      return candidate.length > current.length;
    }
    return candidate.join(" → ") < current.join(" → ");
  }

  private normalizeName(value: string | undefined): string {
    return (value ?? "").trim().replace(/\s+/g, " ").toUpperCase();
  }

  private normalizeType(value: string | undefined): string {
    const normalized = (value ?? "").trim().toUpperCase();
    return normalized.length > 0 ? normalized : "UNSPECIFIED";
  }

  private sortByTrailingNumber(ids: string[]): string[] {
    const trailingNumber = (id: string): number => {
      const match = id.match(/(\d+)\s*$/);
      return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
    };
    return Array.from(new Set(ids)).sort((a, b) => {
      const diff = trailingNumber(a) - trailingNumber(b);
      return diff !== 0 ? diff : a.localeCompare(b);
    });
  }
}
