import { createHash } from "node:crypto";
import type { ImpactCandidate, ImpactDifference, ImpactEntityRef } from "@attackgraph/contracts";

export interface ImpactSnapshotEntity extends ImpactEntityRef {
  semantic: Record<string, unknown>;
}

export interface ImpactDependency {
  from: { type: string; business_id: string };
  to: { type: string; business_id: string };
  trace_link_business_id: string;
}

export interface ImpactSnapshot {
  entities: ImpactSnapshotEntity[];
  dependencies: ImpactDependency[];
}

function canonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    return `{${Object.entries(value as Record<string, unknown>).filter(([, item]) => item !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  throw new TypeError("Impact snapshot contains a non-canonical value");
}

export function impactHash(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

function key(value: { type: string; business_id: string }): string {
  return value.type + ":" + value.business_id;
}

function changedFields(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((field) => {
      const beforeHasField = Object.prototype.hasOwnProperty.call(before, field);
      const afterHasField = Object.prototype.hasOwnProperty.call(after, field);
      if (beforeHasField !== afterHasField) return true;
      return canonical(before[field]) !== canonical(after[field]);
    })
    .sort();
}

export function compareImpactSnapshots(before: ImpactSnapshot, after: ImpactSnapshot): {
  differences: ImpactDifference[];
  impacted: ImpactCandidate[];
  preview_hash: string;
} {
  const beforeIndex = new Map(before.entities.map((entity) => [key(entity), entity]));
  const afterIndex = new Map(after.entities.map((entity) => [key(entity), entity]));
  const identities = [...new Set([...beforeIndex.keys(), ...afterIndex.keys()])].sort();
  const differences: ImpactDifference[] = [];
  for (const identity of identities) {
    const left = beforeIndex.get(identity);
    const right = afterIndex.get(identity);
    if (!left && right) {
      differences.push({ change_kind: "Added", entity: right, after_hash: impactHash(right.semantic), changed_fields: Object.keys(right.semantic).sort() });
    } else if (left && !right) {
      differences.push({ change_kind: "Removed", entity: left, before_hash: impactHash(left.semantic), changed_fields: Object.keys(left.semantic).sort() });
    } else if (left && right) {
      const beforeHash = impactHash(left.semantic);
      const afterHash = impactHash(right.semantic);
      if (beforeHash !== afterHash) differences.push({ change_kind: "Modified", entity: right, before_hash: beforeHash, after_hash: afterHash, changed_fields: changedFields(left.semantic, right.semantic) });
    }
  }

  const entityIndex = new Map([...before.entities, ...after.entities].map((entity) => [key(entity), entity]));
  const adjacency = new Map<string, Array<{ neighbor: string; trace: string }>>();
  const add = (from: string, to: string, trace: string) => {
    const values = adjacency.get(from) ?? [];
    if (!values.some((item) => item.neighbor === to && item.trace === trace)) values.push({ neighbor: to, trace });
    adjacency.set(from, values);
  };
  for (const dependency of [...before.dependencies, ...after.dependencies]) {
    const from = key(dependency.from);
    const to = key(dependency.to);
    add(from, to, dependency.trace_link_business_id);
  }
  for (const values of adjacency.values()) values.sort((a, b) => a.neighbor.localeCompare(b.neighbor) || a.trace.localeCompare(b.trace));

  const directKeys = new Set(differences.map((item) => key(item.entity)));
  const best = new Map<string, { distance: number; triggers: Set<string>; traces: Set<string> }>();
  const queue = differences.map((difference) => ({ current: key(difference.entity), trigger: difference.entity.business_id, distance: 0, traces: [] as string[] }));
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const item = queue[cursor];
    for (const edge of adjacency.get(item.current) ?? []) {
      const distance = item.distance + 1;
      const prior = best.get(edge.neighbor);
      if (!prior || distance < prior.distance) {
        best.set(edge.neighbor, { distance, triggers: new Set([item.trigger]), traces: new Set([...item.traces, edge.trace]) });
        queue.push({ current: edge.neighbor, trigger: item.trigger, distance, traces: [...item.traces, edge.trace] });
      } else if (distance === prior.distance) {
        prior.triggers.add(item.trigger);
        for (const trace of [...item.traces, edge.trace]) prior.traces.add(trace);
      }
    }
  }

  const impacted: ImpactCandidate[] = differences.map((difference) => ({
    entity: difference.entity,
    impact_kind: "Direct",
    distance: 0,
    trigger_business_ids: [difference.entity.business_id],
    via_trace_link_business_ids: [],
  }));
  for (const [identity, value] of [...best.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (directKeys.has(identity)) continue;
    const entity = entityIndex.get(identity);
    if (!entity) continue;
    impacted.push({
      entity,
      impact_kind: "Propagated",
      distance: value.distance,
      trigger_business_ids: [...value.triggers].sort(),
      via_trace_link_business_ids: [...value.traces].sort(),
    });
  }
  impacted.sort((a, b) => a.distance - b.distance || key(a.entity).localeCompare(key(b.entity)));
  return { differences, impacted, preview_hash: impactHash({ differences, impacted }) };
}
