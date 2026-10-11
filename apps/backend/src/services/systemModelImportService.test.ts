import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  systemModelCommitRequestSchema,
  systemModelImportPayloadSchema,
  type SystemModelImportPayload,
} from "@attackgraph/contracts";
import { hashSystemModelImport, validateSystemModelImport } from "./systemModelImportService.js";

function payload(): SystemModelImportPayload {
  return systemModelImportPayloadSchema.parse({
    contract_version: "system-model.v2",
    source: {
      business_id: "SRC-001",
      source_type: "json",
      name: "Generic system model",
      content_hash: "a".repeat(64),
      parser_name: "generic-json",
      parser_version: "1.0.0",
    },
    entities: {
      assets: [
        { business_id: "ASSET-A", name: "Producer", category: "System" },
        { business_id: "ASSET-B", name: "Consumer", category: "System" },
      ],
      functions: [{ business_id: "FN-1", name: "Exchange data" }],
      interfaces: [{
        business_id: "IF-1", name: "Generic interface", interface_type: "Logical",
        direction: "Bidirectional", asset_business_ids: ["ASSET-A", "ASSET-B"],
      }],
      data_flows: [{
        business_id: "FLOW-1", name: "Generic flow",
        producer_asset_business_id: "ASSET-A", consumer_asset_business_id: "ASSET-B",
        interface_business_id: "IF-1", supported_function_business_ids: ["FN-1"],
      }],
      security_boundaries: [], external_entities: [], evidence_records: [],
      trace_links: [{
        business_id: "TRACE-1", link_type: "RELATED_TO",
        source: { type: "DataFlow", business_id: "FLOW-1" },
        target: { type: "Function", business_id: "FN-1" },
      }],
    },
  });
}

test("generic system-model contract has no F3532-specific fields and validates references", () => {
  const parsed = payload();
  assert.deepEqual(validateSystemModelImport(parsed), []);
  const serialized = JSON.stringify(parsed).toLowerCase();
  assert.equal(serialized.includes("f3532"), false);
  assert.equal(serialized.includes("boundary_data_flow"), false);
});

test("preview validation rejects duplicates, existing identities and unresolved references", () => {
  const parsed = payload();
  parsed.entities.assets.push({ ...parsed.entities.assets[0] });
  parsed.entities.data_flows[0].consumer_asset_business_id = "MISSING";
  const errors = validateSystemModelImport(parsed, new Set(["Function:FN-1"]));
  assert.ok(errors.some((message) => message.includes("duplicate Asset")));
  assert.ok(errors.some((message) => message.includes("existing Function:FN-1")));
  assert.ok(errors.some((message) => message.includes("unresolved Asset:MISSING")));
});

test("canonical import hash is stable across object key order", () => {
  const first = payload();
  const second = { entities: first.entities, source: first.source, contract_version: first.contract_version } as SystemModelImportPayload;
  assert.equal(hashSystemModelImport(first), hashSystemModelImport(second));
});

test("checked-in generic import example conforms to the shared commit contract", async () => {
  const example = JSON.parse(
    await readFile(fileURLToPath(new URL("../../../../examples/system-model-v2-import.json", import.meta.url)), "utf8"),
  );
  assert.equal(systemModelCommitRequestSchema.safeParse(example).success, true);
});

test("Phase 2 core modules do not depend on F3532 adapters", async () => {
  const files = [
    "../repositories/systemModelRepository.ts",
    "./systemModelImportService.ts",
    "../routes/systemModel.ts",
  ];
  for (const relative of files) {
    const source = await readFile(fileURLToPath(new URL(relative, import.meta.url)), "utf8");
    assert.equal(/from\s+["'][^"']*f3532/i.test(source), false, `${relative} imports an F3532 module`);
  }
});
