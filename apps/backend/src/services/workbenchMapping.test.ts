import { test } from "node:test";
import assert from "node:assert/strict";
import {
  systemModelImportPayloadSchema,
  analysisConfigurationSchema,
  savedAnalysisSchema,
} from "@attackgraph/contracts";
import {
  mapCoreModel,
  makeAnalysisInput,
  modelDigest,
} from "./workbenchMapping.js";
import { AnalysisService } from "./analysisService.js";
import { executeSavedDps, WorkbenchService } from "./workbenchService.js";
import type { StoredSystemModel } from "@attackgraph/contracts";
import { amsPropagationVersion, obsoleteSavedProjection, propagationProjection } from "./analysis/propagationPolicy.js";
import { analysisDigest } from "./analysis/canonicalization.js";
const config = analysisConfigurationSchema.parse({});
const model = () =>
  systemModelImportPayloadSchema.parse({
    contract_version: "system-model.v2",
    source: {
      business_id: "SRC",
      source_type: "test",
      name: "Fixture",
      content_hash: "a".repeat(64),
      parser_name: "test",
      parser_version: "1",
    },
    entities: {
      assets: [
        {
          business_id: "A",
          name: "External terminal",
          category: "Terminal",
          analysis: { security_domain: "External" },
        },
        {
          business_id: "B",
          name: "Controller",
          category: "Terminal",
          criticality: "High",
          tags: ["controller"],
          analysis: { security_domain: "Internal" },
        },
        {
          business_id: "C",
          name: "Auxiliary",
          category: "Terminal",
          analysis: { security_domain: "Internal" },
        },
      ],
      data_flows: [
        {
          business_id: "AB",
          name: "A to B",
          producer_asset_business_id: "A",
          consumer_asset_business_id: "B",
          analysis: {
            link_type: "Logical",
            direction: "Bidirectional",
            trust_level: "Untrusted",
          },
        },
        {
          business_id: "BC",
          name: "B to C",
          producer_asset_business_id: "B",
          consumer_asset_business_id: "C",
        },
        {
          business_id: "CA",
          name: "C to A",
          producer_asset_business_id: "C",
          consumer_asset_business_id: "A",
        },
      ],
      draft_threats: [
        {
          business_id: "T",
          name: "Candidate",
          threat_type: "Tampering",
          target_asset_business_id: "A",
          standard_reference: "DO-356A",
        },
      ],
    },
  });
test("saved-model contract rejects browser graph and unversioned semantics", () => {
  const input = {
    contract_version: "saved-model-analysis.v1",
    actor: "tester",
    command_id: "1",
    project_id: "00000000-0000-4000-8000-000000000001",
    revision_id: "00000000-0000-4000-8000-000000000002",
    expected_revision_version: 1,
    parameters: { max_hops: 3, dps_hop_decay: 0.95 },
  };
  assert.equal(savedAnalysisSchema.safeParse(input).success, true);
  assert.equal(
    savedAnalysisSchema.safeParse({ ...input, graph: {} }).success,
    false,
  );
});
test("core mapping preserves real business IDs, references and default candidate parameters", () => {
  const mapped = mapCoreModel(model(), config);
  assert.equal(mapped.asset_nodes[0].asset_id, "A");
  assert.equal(mapped.asset_edges[0].source_asset_id, "A");
  assert.equal(mapped.threat_points[0].related_asset_id, "A");
  assert.deepEqual(
    [
      ...new AnalysisService().resolveAnalysisTargetIds(
        mapped.asset_nodes,
        null,
      ),
    ],
    ["B"],
  );
});
test("model hash ignores storage IDs/version but detects model and threat configuration changes", () => {
  const a = model();
  const hash = modelDigest(a, config);
  assert.equal(
    modelDigest(
      {
        ...a,
        entities: {
          ...a.entities,
          assets: a.entities.assets.map((v) => ({
            ...v,
            id: "random",
            revision_version: 8,
            created_by: "actor",
          })),
        },
      },
      config,
    ),
    hash,
  );
  a.entities.assets[1].name = "Changed";
  assert.notEqual(modelDigest(a, config), hash);
  assert.notEqual(
    modelDigest(model(), {
      ...config,
      threat_overrides: {
        T: {
          entry_likelihood_level: "Low",
          attack_complexity_level: "High",
          threat_source: "external",
          stride_category: "Tampering",
          attack_vector: "Network",
        },
      },
    }),
    hash,
  );
});
test("worker matches original DPS across cycles, hop bounds, scope, no paths and overrides", async () => {
  for (const max_hops of [1, 2, 4])
    for (const scope_asset_ids of [undefined, ["A", "B"], ["C"]]) {
      const input = makeAnalysisInput(
        model() as unknown as StoredSystemModel,
        config,
        { max_hops, dps_hop_decay: 0.95, scope_asset_ids },
        "batch",
        "tester",
      );
      const expected = new AnalysisService().run(input);
      const actual = await executeSavedDps(input);
      const stable = (rows: typeof actual) =>
        rows.map(({ generated_at, ...row }) => row);
      assert.deepEqual(stable(actual), stable(expected));
    }
  const changed = structuredClone(config);
  changed.threat_overrides.T = {
    entry_likelihood_level: "Low",
    attack_complexity_level: "High",
    threat_source: "external",
    stride_category: "Tampering",
    attack_vector: "Network",
  };
  const input = makeAnalysisInput(
    model() as unknown as StoredSystemModel,
    changed,
    { max_hops: 3, dps_hop_decay: 0.8 },
    "changed",
    "tester",
  );
  assert.deepEqual(
    (await executeSavedDps(input)).map((p) => p.raw_score),
    new AnalysisService().run(input).map((p) => p.raw_score),
  );
});
test("dangling asset deletion and orphaned threat overrides are rejected before mutation", () => {
  const current = { model: model(), configuration: config } as never;
  const entities = model().entities;
  entities.assets = entities.assets.filter((a) => a.business_id !== "A");
  const preview = new WorkbenchService().validateEdit(current, {
    entities,
    configuration: {
      ...config,
      threat_overrides: {
        UNKNOWN: {
          entry_likelihood_level: "Low",
          attack_complexity_level: "High",
          threat_source: "external",
          stride_category: "Tampering",
          attack_vector: "Network",
        },
      },
    },
  } as never);
  assert.equal(preview.ok, false);
  assert.ok(preview.errors.some((e) => e.includes("unresolved")));
  assert.ok(preview.errors.some((e) => e.includes("UNKNOWN")));
  const changedMapping=new WorkbenchService().validateEdit(current,{entities:model().entities,configuration:{...config,mapping_version:"do356a-ams/v1"}} as never);
  assert.equal(changedMapping.ok,false);assert.ok(changedMapping.errors.some(e=>e.includes("转换版本")));
  const missingExpertRationale=new WorkbenchService().validateEdit(current,{entities:model().entities,configuration:{...config,threat_overrides:{T:{entry_likelihood_level:"Medium",attack_complexity_level:"Medium",threat_source:"external",stride_category:"Tampering",attack_vector:"Network",expert_modifier:0.8}}}} as never);
  assert.equal(missingExpertRationale.ok,false);assert.ok(missingExpertRationale.errors.some(e=>e.includes("专家修正")));
});
test("connection modifications preserve baseline scores and timeout is an explicit failure", async () => {
  const core = model();
  core.entities.data_flows[0].analysis = {
    ...core.entities.data_flows[0].analysis,
    trust_level: "Trusted",
    security_mechanism: "Authentication",
    direction: "Unidirectional",
  };
  const input = makeAnalysisInput(
    core as unknown as StoredSystemModel,
    config,
    { max_hops: 3, dps_hop_decay: 0.95 },
    "edges",
    "test",
  );
  assert.deepEqual(
    (await executeSavedDps(input)).map((p) => p.raw_score),
    new AnalysisService().run(input).map((p) => p.raw_score),
  );
  await assert.rejects(executeSavedDps(input, 1), (error: Error) =>
    error.message.includes("超时"),
  );
});

test("AMS ownership is retained as provenance, but only real channels propagate (including persisted v1 imports)", () => {
  const core = model();
  const ams = analysisConfigurationSchema.parse({ mapping_version: "do356a-ams/v1" });
  const channel = { ...core.entities.data_flows[0], business_id: "CHANNEL", description: "Data via | SI.4 | Software",
    analysis: { direction: "Bidirectional", trust_level: "Trusted", relationship_kind: "propagation" },
    tags: ["auto_generated", "do356a-ams/v1"] };
  const ownership = { ...channel, business_id: "OWNER", description: "Derived data ownership | Software | AMS controller",
    analysis: { direction: "Bidirectional", trust_level: "Trusted" } };
  core.entities.data_flows = [ownership, channel];
  const before = structuredClone(core);
  const graph = mapCoreModel(core, ams);
  assert.deepEqual(core, before, "projection must not mutate persisted provenance");
  assert.deepEqual(graph.asset_edges.map(e => e.edge_id), ["CHANNEL"]);
  assert.deepEqual(propagationProjection(core, ams), { version: amsPropagationVersion,
    excluded_relations: [{ business_id: "OWNER", reason: "inferred_ownership_is_not_a_propagation_channel" }] });
  const run = (edges: typeof graph.asset_edges) => new AnalysisService().run({ ...graph, asset_edges: edges,
    analysis_batch_id: "regression", generated_by: "test", max_hops: 1, dps_hop_decay: 0.95 });
  const legacy = run(mapCoreModel(core, config).asset_edges);
  const fixed = run(graph.asset_edges);
  assert.equal(legacy.length, 2);
  assert.equal(fixed.length, 1);
  assert.equal(fixed[0].hop_sequence, legacy[0].hop_sequence);
  assert.equal(fixed[0].raw_score, legacy[0].raw_score, "scoring formula stays unchanged");
  assert.equal(fixed[0].traverses[0].edge_id, "CHANNEL");

  core.entities.data_flows = [{ ...ownership, analysis: { ...ownership.analysis, relationship_kind: "data_ownership" }, description: "Localized ownership" }];
  assert.equal(mapCoreModel(core, ams).asset_edges.length, 0, "new imports use explicit semantics");
  core.entities.data_flows = [channel, { ...channel, business_id: "CHANNEL-2", description: "Data via | SI.5 | Software" }];
  assert.equal(mapCoreModel(core, ams).asset_edges.length, 2, "independent parallel channels must survive");
  core.entities.data_flows = [{ ...ownership, tags: [] }];
  assert.equal(mapCoreModel(core, ams).asset_edges.length, 1, "manual records are never classified by label alone");
  core.entities.data_flows = [{ ...ownership, tags: ["auto_generated"] }];
  assert.equal(mapCoreModel(core, ams).asset_edges.length, 1, "unrelated import rules remain unchanged");
  core.entities.data_flows = [{ ...channel, analysis: { ...channel.analysis, dps_enabled: false } }];
  assert.equal(mapCoreModel(core, ams).asset_edges.length, 0);
});

test("propagation upgrades invalidate AMS current results without changing core mapping or legacy caller inputs", () => {
  const core = model(), ams = { ...config, mapping_version: "do356a-ams/v1" as const };
  const oldHash = analysisDigest({ entities: core.entities, configuration: ams });
  assert.notEqual(modelDigest(core, ams), oldHash);
  assert.equal(modelDigest(core, config), analysisDigest({ entities: core.entities, configuration: config }));
  assert.equal(obsoleteSavedProjection("workbench.saved-analysis/v1", ams.mapping_version, undefined), true);
  assert.equal(obsoleteSavedProjection("workbench.saved-analysis/v1", ams.mapping_version, amsPropagationVersion), false);
  assert.equal(obsoleteSavedProjection("workbench.saved-analysis/v1", "core-dps/v1", undefined), false);
  assert.equal(obsoleteSavedProjection("analysis.execute/v1", ams.mapping_version, undefined), false);
});
