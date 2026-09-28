import { readFileSync } from "node:fs";
import { traceFeaturePaths } from "../apps/backend/src/services/featureRules/pathTrace.js";

function read(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
}

try {
  if (process.argv.length !== 5) throw new Error(
    "Usage: node --import tsx scripts/trace-feature-paths.ts <bundle.json> <graph.json> <scope-mapping.json>");
  const input = read(process.argv[2]);
  const graph = read(process.argv[3]) as Parameters<typeof traceFeaturePaths>[1];
  const mappings = read(process.argv[4]) as Parameters<typeof traceFeaturePaths>[2];
  process.stdout.write(JSON.stringify(traceFeaturePaths(input, graph, mappings), null, 2) + "\n");
} catch (error) {
  process.stderr.write((error instanceof Error ? error.message : String(error)) + "\n");
  process.exitCode = 1;
}
