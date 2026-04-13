import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { closeDriver } from "../db/neo4j.js";
import { GraphRepository } from "../repositories/graphRepository.js";
import { AnalysisService } from "../services/analysisService.js";
import type { AssetEdge, AssetNode, ThreatPoint } from "../types/domain.js";

interface BaselinePath {
  entry_point_id: string;
  start_asset_id: string;
  target_asset_id: string;
  hop_sequence: string;
  hop_count: number;
  has_cycle: boolean;
  traverses: Array<{ hop: number; edge_id: string; asset_id: string }>;
}

interface ExperimentOptions {
  maxHops: number;
  seedSample: boolean;
  generatedBy: string;
}

function parseOptions(argv: string[]): ExperimentOptions {
  let maxHops = 6;
  let seedSample = true;
  let generatedBy = "do356a-baseline-experiment";

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--max-hops") {
      const next = argv[index + 1];
      if (!next || Number.isNaN(Number(next))) {
        throw new Error("--max-hops requires a numeric value");
      }
      maxHops = Number(next);
      index += 1;
      continue;
    }

    if (arg === "--no-seed") {
      seedSample = false;
      continue;
    }

    if (arg === "--generated-by") {
      const next = argv[index + 1];
      if (!next) {
        throw new Error("--generated-by requires a value");
      }
      generatedBy = next;
      index += 1;
    }
  }

  return { maxHops, seedSample, generatedBy };
}

function buildAdjacency(edges: AssetEdge[]): Map<string, AssetEdge[]> {
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

function hasCycle(sequenceAssets: string[]): boolean {
  const seen = new Set<string>();
  for (const assetId of sequenceAssets) {
    if (seen.has(assetId)) {
      return true;
    }
    seen.add(assetId);
  }
  return false;
}

function runBaselineDfs(input: {
  maxHops: number;
  assetNodes: AssetNode[];
  assetEdges: AssetEdge[];
  threatPoints: ThreatPoint[];
}): BaselinePath[] {
  const assetIds = new Set(input.assetNodes.map((asset) => asset.asset_id));
  const adjacency = buildAdjacency(input.assetEdges);
  const output: BaselinePath[] = [];

  for (const threat of input.threatPoints) {
    if (!assetIds.has(threat.related_asset_id)) {
      continue;
    }

    const dfs = (currentAssetId: string, traverses: Array<{ hop: number; edge_id: string; asset_id: string }>) => {
      if (traverses.length >= input.maxHops) {
        return;
      }

      const outgoing = adjacency.get(currentAssetId) ?? [];
      for (const edge of outgoing) {
        if (!assetIds.has(edge.target_asset_id)) {
          continue;
        }

        const nextHop = traverses.length + 1;
        const nextTraverses = [
          ...traverses,
          {
            hop: nextHop,
            edge_id: edge.edge_id,
            asset_id: edge.target_asset_id
          }
        ];

        const sequenceAssets = [threat.related_asset_id, ...nextTraverses.map((item) => item.asset_id)];
        output.push({
          entry_point_id: threat.threatpoint_id,
          start_asset_id: threat.related_asset_id,
          target_asset_id: edge.target_asset_id,
          hop_sequence: [threat.threatpoint_id, ...sequenceAssets].join(">"),
          hop_count: nextHop,
          has_cycle: hasCycle(sequenceAssets),
          traverses: nextTraverses
        });

        dfs(edge.target_asset_id, nextTraverses);
      }
    };

    dfs(threat.related_asset_id, []);
  }

  return output;
}

function countByHop<T extends { hop_count: number }>(items: T[]): Record<string, number> {
  return items.reduce<Record<string, number>>((acc, item) => {
    const key = String(item.hop_count);
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
}

function countByEntry<T extends { entry_point_id: string }>(items: T[]): Record<string, number> {
  return items.reduce<Record<string, number>>((acc, item) => {
    acc[item.entry_point_id] = (acc[item.entry_point_id] ?? 0) + 1;
    return acc;
  }, {});
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const graphRepo = new GraphRepository();
  const analysisService = new AnalysisService();

  await graphRepo.ensureConstraints();
  if (options.seedSample) {
    const seed = await graphRepo.seedSampleData(`${options.generatedBy}-seed`);
    console.log("Seeded DO-356A sample dataset", seed);
  }

  const graph = await graphRepo.getGraph();
  const analysisBatchId = `EXP-${Date.now()}`;
  const systemPaths = analysisService.run({
    analysis_batch_id: analysisBatchId,
    max_hops: options.maxHops,
    generated_by: options.generatedBy,
    asset_nodes: graph.asset_nodes,
    asset_edges: graph.asset_edges,
    threat_points: graph.threat_points
  });
  const baselinePaths = runBaselineDfs({
    maxHops: options.maxHops,
    assetNodes: graph.asset_nodes,
    assetEdges: graph.asset_edges,
    threatPoints: graph.threat_points
  });

  const baselineUniqueSequences = new Set(baselinePaths.map((pathItem) => pathItem.hop_sequence)).size;
  const systemUniqueSequences = new Set(systemPaths.map((pathItem) => pathItem.hop_sequence)).size;
  const baselineCyclicCount = baselinePaths.filter((pathItem) => pathItem.has_cycle).length;
  const systemCyclicCount = systemPaths.filter((pathItem) => {
    const assets = pathItem.hop_sequence.split(">").slice(1);
    return hasCycle(assets);
  }).length;

  const report = {
    generated_at: new Date().toISOString(),
    graph_version: graph.graph_version,
    dataset: "DO-356A Appendix D sample",
    options,
    summary: {
      baseline: {
        total_paths: baselinePaths.length,
        unique_hop_sequences: baselineUniqueSequences,
        redundant_paths: baselinePaths.length - baselineUniqueSequences,
        cyclic_paths: baselineCyclicCount,
        by_hop_count: countByHop(baselinePaths),
        by_entry_point: countByEntry(baselinePaths)
      },
      system: {
        total_paths: systemPaths.length,
        unique_hop_sequences: systemUniqueSequences,
        redundant_paths: systemPaths.length - systemUniqueSequences,
        cyclic_paths: systemCyclicCount,
        by_hop_count: countByHop(systemPaths),
        by_entry_point: countByEntry(systemPaths)
      },
      delta: {
        total_paths: baselinePaths.length - systemPaths.length,
        cyclic_paths: baselineCyclicCount - systemCyclicCount,
        redundant_paths: (baselinePaths.length - baselineUniqueSequences) - (systemPaths.length - systemUniqueSequences)
      }
    },
    baseline_paths: baselinePaths,
    system_paths: systemPaths
  };

  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const outputDir = path.resolve(scriptDir, "../../../../docs/experiments");
  await mkdir(outputDir, { recursive: true });
  const outputPath = path.join(outputDir, `do356a-baseline-vs-system-${analysisBatchId}.json`);
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  console.log("Experiment completed");
  console.log(`Graph version: ${graph.graph_version}`);
  console.log(`Baseline paths: ${baselinePaths.length}`);
  console.log(`System paths: ${systemPaths.length}`);
  console.log(`Output report: ${outputPath}`);
}

main()
  .catch((error) => {
    console.error("DO-356A baseline experiment failed", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDriver();
  });
