import { readFileSync } from "node:fs";
import { evaluateFeatureRules } from "../apps/backend/src/services/featureRules/evaluate.js";

try {
  if (process.argv.length !== 3) throw new Error("Usage: node --import tsx scripts/preview-feature-rules.ts <bundle.json>");
  const input = JSON.parse(readFileSync(process.argv[2], "utf8").replace(/^\uFEFF/, ""));
  process.stdout.write(JSON.stringify(evaluateFeatureRules(input), null, 2) + "\n");
} catch (error) {
  process.stderr.write((error instanceof Error ? error.message : String(error)) + "\n");
  process.exitCode = 1;
}
