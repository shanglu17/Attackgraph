import { createHash } from "node:crypto";

function compare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalize(value: unknown, sortArrays: boolean, omitVolatile: boolean): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("analysis values must contain finite numbers");
    return value;
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => normalize(item, sortArrays, omitVolatile));
    return sortArrays ? items.sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b))) : items;
  }
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([key, item]) => item !== undefined && (!omitVolatile || !["generated_at", "started_at", "completed_at"].includes(key)))
      .sort(([left], [right]) => compare(left, right))
      .map(([key, item]) => [key, normalize(item, sortArrays, omitVolatile)]));
  }
  throw new TypeError("unsupported analysis value: " + typeof value);
}

export function canonicalAnalysisJson(value: unknown, options: { set_arrays?: boolean; omit_volatile?: boolean } = {}) {
  return JSON.stringify(normalize(value, options.set_arrays === true, options.omit_volatile === true));
}

export function analysisDigest(value: unknown, options: { set_arrays?: boolean; omit_volatile?: boolean } = {}) {
  return createHash("sha256").update(canonicalAnalysisJson(value, options), "utf8").digest("hex");
}
