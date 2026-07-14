import assert from "node:assert/strict";
import test from "node:test";
import type { F3532PathRule } from "../../config/f3532/pathRules.js";
import type {
  BoundaryDataFlowFact,
  F353203GenerationFacts,
  F3532DataTopic,
  SystemDataFlowFact
} from "../../types/domain.js";
import { BoundaryFlowReportService } from "./boundaryFlowReportService.js";
import { CandidateRouteFinder } from "./candidateRouteFinder.js";
import { F353203GenerationService } from "./f353203GenerationService.js";
import { determineBoundaryDataFlowDirection } from "./factNormalizer.js";
import { compareNaturalBusinessIds } from "./naturalSort.js";
import { PropagationGraphBuilder } from "./propagationGraphBuilder.js";

const noIds = new Set<string>();

function bdf(overrides: Partial<BoundaryDataFlowFact> & Pick<BoundaryDataFlowFact, "id">): BoundaryDataFlowFact {
  const { id, ...rest } = overrides;
  return {
    id,
    producer_id: "SYS.CCS",
    producer_name: "指挥控制系统",
    consumer_id: "SYS.IMS",
    consumer_name: "IMS",
    destination_ids: [],
    destination_names: [],
    direction: "INBOUND",
    boundary_interface_ids: ["BI01"],
    security_boundary_ids: ["SB01"],
    data_type: "DATA",
    function_ids: ["F1"],
    continuation_policy: "RULE_DEPENDENT",
    topic_ids: ["COMMAND_CONTROL"],
    warnings: [],
    evidence: [],
    ...rest
  };
}

function sdf(
  id: string,
  from: string,
  to: string,
  dataType = "DATA",
  topics: F3532DataTopic[] = ["NAVIGATION"]
): SystemDataFlowFact {
  return {
    id,
    producer_system_id: from,
    consumer_system_id: to,
    producer_name: from,
    consumer_name: to,
    system_interface_id: `SI${id.match(/\d+/)?.[0] ?? id}`,
    data_type: dataType,
    function_ids: ["F1"],
    topic_ids: topics,
    warnings: [],
    evidence: []
  };
}

function facts(overrides: Partial<F353203GenerationFacts> = {}): F353203GenerationFacts {
  return {
    graph_version: "test-v1",
    boundary_data_flows: [],
    system_data_flows: [],
    system_interfaces: [],
    boundary_interfaces: [],
    trust_boundaries: [],
    warnings: [],
    ...overrides
  };
}

function rule(overrides: Partial<F3532PathRule> = {}): F3532PathRule {
  return {
    id: "TEST_RULE",
    path_code: "T01",
    priority: 1,
    enabled: true,
    status: "CONFIRMED",
    origin_type: "RULE_DEFINED",
    internal_seed_system_ids: ["A"],
    allowed_system_ids: ["A", "B", "C", "D"],
    allowed_topic_ids: ["NAVIGATION"],
    terminal_conditions: { no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: false, merge_branches: true },
    max_hops: 8,
    output: { name_template: "test", description_template: "test" },
    ...overrides
  };
}

test("BDF 方向由结构化 Producer/Consumer 的内外属性确定", () => {
  assert.equal(determineBoundaryDataFlowDirection({ producer_name: "地面维护设备", consumer_name: "IMS", known_external_system_ids: noIds, known_internal_system_ids: noIds }), "INBOUND");
  assert.equal(determineBoundaryDataFlowDirection({ producer_name: "PACKS", consumer_name: "地面维护设备", known_external_system_ids: noIds, known_internal_system_ids: noIds }), "OUTBOUND");
  assert.equal(determineBoundaryDataFlowDirection({ producer_name: "IMS", consumer_name: "FMS", known_external_system_ids: noIds, known_internal_system_ids: noIds }), "INTERNAL");
  assert.equal(determineBoundaryDataFlowDirection({ producer_name: "未知对象", consumer_name: "IMS", known_external_system_ids: noIds, known_internal_system_ids: noIds }), "UNKNOWN");
});

test("第一 Sheet 一条 BDF 一行，保留多 BI/功能、缺失 SB warning，并自然排序", () => {
  const input = facts({
    boundary_data_flows: [
      bdf({ id: "BDF10", boundary_interface_ids: ["BI10"], security_boundary_ids: ["SB01"] }),
      bdf({ id: "BDF2", boundary_interface_ids: ["BI02", "BI03"], security_boundary_ids: ["SB01"], function_ids: ["F10", "F2"] }),
      bdf({ id: "BDF1", boundary_interface_ids: ["BI01"], security_boundary_ids: [] })
    ],
    boundary_interfaces: [
      { id: "BI01", access_system_ids: [], access_names: [] },
      { id: "BI02", access_system_ids: [], access_names: [], security_boundary_id: "SB01" },
      { id: "BI03", access_system_ids: [], access_names: [], security_boundary_id: "SB01" },
      { id: "BI10", access_system_ids: [], access_names: [], security_boundary_id: "SB01" }
    ],
    trust_boundaries: [{ id: "SB01", name: "边界一" }]
  });
  const rows = new BoundaryFlowReportService().build(input);
  assert.deepEqual(rows.map((row) => row.bdf_id), ["BDF1", "BDF2", "BDF10"]);
  assert.deepEqual(rows[1].boundary_interface_ids, ["BI02", "BI03"]);
  assert.deepEqual(rows[1].function_ids, ["F2", "F10"]);
  assert.ok(rows[0].warnings.some((warning) => warning.includes("缺少安保边界")));
  assert.equal(rows.length, 3);
  assert.ok(compareNaturalBusinessIds("BDF2", "BDF10") < 0);
});

test("BDF32/33/34 使用真实 Consumer 作为各自入口", () => {
  const input = facts({
    boundary_data_flows: [
      bdf({ id: "BDF32", producer_id: "SYS.GROUND_MAINTENANCE", producer_name: "地面维护设备", consumer_id: "SYS.IMS", consumer_name: "IMS", boundary_interface_ids: ["BI09"], security_boundary_ids: ["SB03"], data_type: "LOAD", topic_ids: ["SOFTWARE_LOAD"] }),
      bdf({ id: "BDF33", producer_id: "SYS.GROUND_MAINTENANCE", producer_name: "地面维护设备", consumer_id: "SYS.FMS", consumer_name: "FMS", boundary_interface_ids: ["BI09"], security_boundary_ids: ["SB03"], data_type: "LOAD", topic_ids: ["SOFTWARE_LOAD"] }),
      bdf({ id: "BDF34", producer_id: "SYS.GROUND_MAINTENANCE", producer_name: "地面维护设备", consumer_id: "SYS.FCS", consumer_name: "FCS", boundary_interface_ids: ["BI09"], security_boundary_ids: ["SB03"], data_type: "LOAD", topic_ids: ["SOFTWARE_LOAD"] })
    ]
  });
  const path = new F353203GenerationService().generate(input).propagation_paths.paths.find((item) => item.id === "P09");
  assert.ok(path);
  assert.deepEqual(path.terminal_system_ids, ["SYS.FCS", "SYS.FMS", "SYS.IMS"]);
});

test("出站 BDF 从内部 Producer 开始且不会反转", () => {
  const input = facts({
    boundary_data_flows: [bdf({
      id: "BDF40", producer_id: "SYS.PACKS", producer_name: "PACKS", consumer_id: "SYS.GROUND_MAINTENANCE",
      consumer_name: "地面维护设备", direction: "OUTBOUND", boundary_interface_ids: ["BI12"], security_boundary_ids: ["SB03"],
      topic_ids: ["MAINTENANCE"]
    })]
  });
  const path = new F353203GenerationService().generate(input).propagation_paths.paths.find((item) => item.id === "P12");
  assert.ok(path);
  assert.deepEqual(path.terminal_system_ids, ["SYS.PACKS"]);
  assert.ok(path.description.includes("地面维护设备"));
});

test("允许导航主题 SENSOR→DATA，拒绝拓扑相连但主题不兼容的 DATA", () => {
  const graph = new PropagationGraphBuilder().build(facts({ system_data_flows: [
    sdf("SDF1", "A", "B", "DATA", ["NAVIGATION"]),
    sdf("SDF2", "A", "C", "DATA", ["VIDEO"])
  ] }));
  const routes = new CandidateRouteFinder().find(graph, rule(), {
    seed_id: "BDF1", start_system_id: "A", data_type: "SENSOR", topic_ids: ["NAVIGATION"]
  }, 8);
  assert.deepEqual(routes.flatMap((route) => route.edges.map((edge) => edge.sdf_id)), ["SDF1"]);
  assert.ok(routes[0].evidence.some((item) => item.type === "FILTERED_CANDIDATE" && item.message.includes("SDF2")));
});

test("新增同类型不同主题边不改变原路径成员", () => {
  const finder = new CandidateRouteFinder();
  const base = facts({ system_data_flows: [sdf("SDF1", "A", "B")] });
  const seed = { seed_id: "BDF1", start_system_id: "A", data_type: "SENSOR", topic_ids: ["NAVIGATION"] as F3532DataTopic[] };
  const before = finder.find(new PropagationGraphBuilder().build(base), rule(), seed, 8).flatMap((route) => route.edges.map((edge) => edge.sdf_id));
  base.system_data_flows.push(sdf("SDF9", "A", "D", "DATA", ["VIDEO"]));
  const after = finder.find(new PropagationGraphBuilder().build(base), rule(), seed, 8).flatMap((route) => route.edges.map((edge) => edge.sdf_id));
  assert.deepEqual(after, before);
});

test("输入行顺序变化不改变结构化生成结果", () => {
  const input = facts({
    boundary_data_flows: [bdf({ id: "BDF2" }), bdf({ id: "BDF1" })],
    boundary_interfaces: [{ id: "BI01", access_system_ids: ["SYS.IMS"], access_names: ["IMS"], security_boundary_id: "SB01" }],
    trust_boundaries: [{ id: "SB01", name: "边界一" }]
  });
  const service = new F353203GenerationService();
  const left = service.generate(input);
  const right = service.generate({ ...input, boundary_data_flows: [...input.boundary_data_flows].reverse() });
  assert.deepEqual(left.boundary_data_flows.rows, right.boundary_data_flows.rows);
  assert.deepEqual(left.propagation_paths.paths, right.propagation_paths.paths);
});

test("所有 path.sdf_ids 都能映射到 routeSegments", () => {
  const input = facts({
    boundary_data_flows: [bdf({ id: "BDF1", consumer_id: "SYS.RCS", consumer_name: "RCS" })],
    system_data_flows: [
      sdf("SDF1", "SYS.RCS", "SYS.DLS", "DATA", ["COMMAND_CONTROL"]),
      sdf("SDF2", "SYS.DLS", "SYS.FMS", "DATA", ["COMMAND_CONTROL"]),
      sdf("SDF3", "SYS.DLS", "SYS.FCS", "DATA", ["COMMAND_CONTROL"])
    ]
  });
  const paths = new F353203GenerationService().generate(input).propagation_paths.paths;
  for (const path of paths) {
    const segmentIds = new Set(path.route_segments.flatMap((segment) => segment.sdf_ids));
    assert.ok(path.sdf_ids.every((id) => segmentIds.has(id)));
  }
});

test("A→B→C→A 环不会递归，并记录环检测", () => {
  const graph = new PropagationGraphBuilder().build(facts({ system_data_flows: [
    sdf("SDF1", "A", "B"), sdf("SDF2", "B", "C"), sdf("SDF3", "C", "A")
  ] }));
  const routes = new CandidateRouteFinder().find(graph, rule(), {
    seed_id: "INTERNAL", start_system_id: "A", data_type: "DATA", topic_ids: ["NAVIGATION"]
  }, 8);
  assert.equal(routes.length, 1);
  assert.deepEqual(routes[0].edges.map((edge) => edge.sdf_id), ["SDF1", "SDF2"]);
  assert.ok(routes[0].evidence.some((item) => item.type === "FILTERED_CANDIDATE" && item.message.includes("SDF3")));
});

test("规则指定的纯内部路径生成，普通内部连通分量不生成", () => {
  const service = new F353203GenerationService();
  const ruled = service.generate(facts({ system_data_flows: [sdf("SDF8", "SYS.IMS", "SYS.PES", "CMD", ["COMMAND_CONTROL"])] }));
  assert.ok(ruled.propagation_paths.paths.some((path) => path.id === "P08" && path.origin_type === "RULE_DEFINED"));
  const unruled = service.generate(facts({ system_data_flows: [sdf("SDF99", "X", "Y")] }));
  assert.equal(unruled.propagation_paths.count, 0);
});

test("新增无关路径不改变已有稳定路径编号", () => {
  const service = new F353203GenerationService();
  const base = facts({ system_data_flows: [sdf("SDF8", "SYS.IMS", "SYS.PES", "CMD", ["COMMAND_CONTROL"])] });
  assert.ok(service.generate(base).propagation_paths.paths.some((path) => path.id === "P08"));
  base.boundary_data_flows.push(bdf({ id: "BDF999", producer_id: "X", consumer_id: "Y", direction: "UNKNOWN", security_boundary_ids: [] }));
  assert.ok(service.generate(base).propagation_paths.paths.some((path) => path.id === "P08"));
});

test("预览生成是纯函数，不修改输入事实或已存在路径状态", () => {
  const input = facts({ boundary_data_flows: [bdf({ id: "BDF1" })] });
  const before = structuredClone(input);
  const result = new F353203GenerationService().generate(input, { mode: "preview" });
  assert.equal(result.metadata.mode, "preview");
  assert.deepEqual(input, before);
});
