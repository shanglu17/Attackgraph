import type {
  BoundaryDataFlowDirection,
  F3532DataTopic,
  GeneratedPathOriginType,
  GeneratedPathStatus
} from "../../types/domain.js";

export interface F3532PathSeedSelector {
  security_boundary_ids?: string[];
  boundary_interface_ids?: string[];
  producer_system_ids?: string[];
  consumer_system_ids?: string[];
  data_types?: string[];
  function_ids?: string[];
  topic_ids?: F3532DataTopic[];
  directions?: BoundaryDataFlowDirection[];
}

export interface F3532PathRule {
  id: string;
  path_code: string;
  priority: number;
  enabled: boolean;
  status: GeneratedPathStatus;
  origin_type: GeneratedPathOriginType;
  seed_selector?: F3532PathSeedSelector;
  internal_seed_system_ids?: string[];
  allowed_system_ids: string[];
  allowed_topic_ids: F3532DataTopic[];
  allowed_transitions?: Array<{ from: string; to: string }>;
  terminal_conditions: {
    system_ids?: string[];
    no_compatible_successor?: boolean;
    stop_at_seed_consumer?: boolean;
  };
  grouping: {
    keys: Array<"RULE" | "BOUNDARY" | "CONSUMER" | "TOPIC">;
    allow_multiple_seeds: boolean;
    merge_branches: boolean;
  };
  max_hops: number;
  output: {
    name_template: string;
    description_template: string;
  };
}

const maintenanceTopics: F3532DataTopic[] = [
  "MAINTENANCE",
  "SOFTWARE_LOAD",
  "PARAMETER_CONFIGURATION",
  "FAULT_DIAGNOSIS",
  "FLIGHT_STATE",
  "RECORDING",
  "ALERT",
  "UNKNOWN"
];

function maintenanceRule(
  pathCode: string,
  id: string,
  interfaceIds: string[],
  systems: string[],
  name: string
): F3532PathRule {
  return {
    id,
    path_code: pathCode,
    priority: Number(pathCode.slice(1)),
    enabled: true,
    status: "CONFIRMED",
    origin_type: "BOUNDARY_FLOW",
    seed_selector: { security_boundary_ids: ["SB03"], boundary_interface_ids: interfaceIds },
    allowed_system_ids: ["SYS.GROUND_MAINTENANCE", ...systems],
    allowed_topic_ids: maintenanceTopics,
    terminal_conditions: { stop_at_seed_consumer: true, no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: true, merge_branches: true },
    max_hops: 1,
    output: {
      name_template: name,
      description_template: "地面维护设备通过 {BI} 与 {SYSTEMS} 交换 {TOPICS} 数据；依据维护规则在目标系统停止。"
    }
  };
}

export const f3532PathRules: F3532PathRule[] = [
  {
    id: "RULE_CC_DOWNLINK",
    path_code: "P01",
    priority: 1,
    enabled: true,
    status: "NEEDS_REVIEW",
    origin_type: "BOUNDARY_FLOW",
    seed_selector: { security_boundary_ids: ["SB01"], producer_system_ids: ["SYS.CCS"], directions: ["INBOUND"] },
    allowed_system_ids: ["SYS.RCS", "SYS.DLS", "SYS.IMS", "SYS.FCS", "SYS.FMS", "SYS.AVCS"],
    allowed_topic_ids: [
      "COMMAND_CONTROL",
      "MISSION_DATA",
      "PARAMETER_CONFIGURATION",
      "FLIGHT_STATE",
      "ALERT",
      "AUDIO",
      "VIDEO",
      "POWER",
      "FAULT_DIAGNOSIS",
      "RECORDING"
    ],
    terminal_conditions: { system_ids: ["SYS.FCS", "SYS.FMS", "SYS.AVCS"], no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: true, merge_branches: true },
    max_hops: 6,
    output: {
      name_template: "指挥控制下行数据路径",
      description_template: "指挥控制系统经 {BI} 进入 {SYSTEMS}，传播主题为 {TOPICS}。"
    }
  },
  {
    id: "RULE_CC_UPLINK",
    path_code: "P02",
    priority: 2,
    enabled: true,
    status: "NEEDS_REVIEW",
    origin_type: "INTERNAL_FLOW",
    seed_selector: { security_boundary_ids: ["SB01"], consumer_system_ids: ["SYS.CCS"], directions: ["OUTBOUND"] },
    internal_seed_system_ids: ["SYS.IMS", "SYS.FCS", "SYS.FMS"],
    allowed_system_ids: ["SYS.IMS", "SYS.FCS", "SYS.FMS", "SYS.DLS", "SYS.RCS"],
    allowed_topic_ids: ["FLIGHT_STATE", "ALERT", "RECORDING", "FAULT_DIAGNOSIS", "POSITION", "POWER"],
    terminal_conditions: { system_ids: ["SYS.RCS"], no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: true, merge_branches: true },
    max_hops: 6,
    output: {
      name_template: "机载状态与告警上行路径",
      description_template: "内部系统状态、告警和记录数据经 {SYSTEMS} 到达外部通信边界。"
    }
  },
  {
    id: "RULE_AUDIO_VIDEO_UPLINK",
    path_code: "P03",
    priority: 3,
    enabled: true,
    status: "NEEDS_REVIEW",
    origin_type: "INTERNAL_FLOW",
    internal_seed_system_ids: ["SYS.AVCS", "SYS.DAAS"],
    allowed_system_ids: ["SYS.AVCS", "SYS.DAAS", "SYS.DLS", "SYS.RCS"],
    allowed_topic_ids: ["AUDIO", "VIDEO", "ALERT", "FLIGHT_STATE", "RECORDING"],
    terminal_conditions: { system_ids: ["SYS.RCS"], no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: false, merge_branches: true },
    max_hops: 5,
    output: {
      name_template: "音视频与探测数据上行路径",
      description_template: "音视频或探测数据从 {SYSTEMS} 汇聚至外部通信边界。"
    }
  },
  {
    id: "RULE_OPEN_ENVIRONMENT",
    path_code: "P04",
    priority: 4,
    enabled: true,
    status: "NEEDS_REVIEW",
    origin_type: "BOUNDARY_FLOW",
    seed_selector: {
      security_boundary_ids: ["SB02"],
      boundary_interface_ids: ["BI05", "BI06", "BI07", "BI08"],
      directions: ["INBOUND"]
    },
    allowed_system_ids: ["SYS.DAAS", "SYS.AVCS", "SYS.IMS", "SYS.DLS", "SYS.RCS"],
    allowed_topic_ids: ["POSITION", "VIDEO", "AUDIO", "ALERT", "FLIGHT_STATE", "NAVIGATION", "UNKNOWN"],
    terminal_conditions: { system_ids: ["SYS.IMS", "SYS.RCS"], no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: true, merge_branches: true },
    max_hops: 5,
    output: {
      name_template: "开放环境感知输入路径",
      description_template: "开放环境感知数据经 {BI} 进入 {SYSTEMS}。"
    }
  },
  {
    id: "RULE_GNSS_RTK",
    path_code: "P05",
    priority: 5,
    enabled: true,
    status: "CONFIRMED",
    origin_type: "BOUNDARY_FLOW",
    seed_selector: {
      security_boundary_ids: ["SB02"],
      boundary_interface_ids: ["BI03", "BI04"],
      directions: ["INBOUND"]
    },
    allowed_system_ids: ["SYS.RCS", "SYS.DLS", "SYS.NAVS", "SYS.IMS"],
    allowed_topic_ids: ["NAVIGATION", "RTK_CORRECTION", "POSITION", "FLIGHT_STATE"],
    terminal_conditions: { system_ids: ["SYS.IMS"], no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: true, merge_branches: true },
    max_hops: 5,
    output: {
      name_template: "GNSS 导航定位与 RTK 修正路径",
      description_template: "GNSS/RTK 数据经 {BI} 沿 {SYSTEMS} 传播，主题为 {TOPICS}。"
    }
  },
  {
    id: "RULE_INTERNAL_FLIGHT_CORE",
    path_code: "P06",
    priority: 6,
    enabled: true,
    status: "NEEDS_REVIEW",
    origin_type: "RULE_DEFINED",
    internal_seed_system_ids: ["SYS.IMS", "SYS.FMS", "SYS.FCS"],
    allowed_system_ids: ["SYS.IMS", "SYS.FMS", "SYS.FCS"],
    allowed_topic_ids: ["COMMAND_CONTROL", "NAVIGATION", "POSITION", "MISSION_DATA", "PARAMETER_CONFIGURATION", "FLIGHT_STATE", "ALERT"],
    terminal_conditions: { no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: false, merge_branches: true },
    max_hops: 5,
    output: {
      name_template: "飞控/飞管核心数据交互路径",
      description_template: "IMS、FMS、FCS 之间按配置规则识别出的关键内部交互。"
    }
  },
  {
    id: "RULE_INTERNAL_POWER",
    path_code: "P07",
    priority: 7,
    enabled: true,
    status: "NEEDS_REVIEW",
    origin_type: "RULE_DEFINED",
    internal_seed_system_ids: ["SYS.EPS", "SYS.ES", "SYS.HVDS", "SYS.PACKS", "SYS.IMS"],
    allowed_system_ids: ["SYS.EPS", "SYS.ES", "SYS.HVDS", "SYS.PACKS", "SYS.IMS"],
    allowed_topic_ids: ["POWER", "FLIGHT_STATE", "ALERT", "COMMAND_CONTROL", "FAULT_DIAGNOSIS"],
    terminal_conditions: { no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: false, merge_branches: true },
    max_hops: 5,
    output: {
      name_template: "动力与电气系统状态/控制交互路径",
      description_template: "动力和电气系统之间按 POWER 主题识别出的关键内部交互。"
    }
  },
  {
    id: "RULE_INTERNAL_PARACHUTE",
    path_code: "P08",
    priority: 8,
    enabled: true,
    status: "CONFIRMED",
    origin_type: "RULE_DEFINED",
    internal_seed_system_ids: ["SYS.IMS", "SYS.PES"],
    allowed_system_ids: ["SYS.IMS", "SYS.PES"],
    allowed_topic_ids: ["COMMAND_CONTROL", "FLIGHT_STATE", "ALERT", "FAULT_DIAGNOSIS"],
    terminal_conditions: { no_compatible_successor: true },
    grouping: { keys: ["RULE"], allow_multiple_seeds: false, merge_branches: true },
    max_hops: 3,
    output: {
      name_template: "伞降应急路径",
      description_template: "IMS 与 PES 之间按应急控制和状态主题识别出的内部交互。"
    }
  },
  maintenanceRule("P09", "RULE_MAINTENANCE_FLIGHT_CORE", ["BI09"], ["SYS.IMS", "SYS.FMS", "SYS.FCS"], "IMS/FMS/FCS 维护路径"),
  maintenanceRule("P10", "RULE_MAINTENANCE_DLS", ["BI10"], ["SYS.DLS"], "DLS 维护路径"),
  maintenanceRule("P11", "RULE_MAINTENANCE_EPS", ["BI11"], ["SYS.EPS"], "EPS 维护路径"),
  maintenanceRule("P12", "RULE_MAINTENANCE_PACKS", ["BI12"], ["SYS.PACKS"], "PACKS 维护路径"),
  maintenanceRule("P13", "RULE_MAINTENANCE_HVDS", ["BI13"], ["SYS.HVDS"], "HVDS 维护路径（建议删除项）"),
  maintenanceRule("P14", "RULE_MAINTENANCE_ES", ["BI14"], ["SYS.ES"], "ES 维护路径"),
  maintenanceRule("P15", "RULE_MAINTENANCE_DAAS", ["BI15"], ["SYS.DAAS"], "DAAS 维护路径"),
  maintenanceRule("P16", "RULE_MAINTENANCE_AVCS", ["BI16"], ["SYS.AVCS"], "AVCS 维护路径"),
  maintenanceRule("P17", "RULE_MAINTENANCE_NAVS", ["BI17"], ["SYS.NAVS"], "NAVS 维护路径"),
  maintenanceRule("P18", "RULE_MAINTENANCE_PES", ["BI19", "BI20"], ["SYS.PES"], "PES 维护路径"),
  maintenanceRule("P19", "RULE_MAINTENANCE_RCS", ["BI21", "BI22", "BI23", "BI24"], ["SYS.RCS"], "RCS 维护路径")
];

const ruleIds = new Set<string>();
const pathCodes = new Set<string>();
for (const rule of f3532PathRules) {
  if (ruleIds.has(rule.id)) {
    throw new Error(`duplicate F3532 path rule id: ${rule.id}`);
  }
  if (pathCodes.has(rule.path_code)) {
    throw new Error(`duplicate F3532 stable path code: ${rule.path_code}`);
  }
  if (rule.max_hops < 1 || rule.max_hops > 12) {
    throw new Error(`invalid max_hops for F3532 path rule ${rule.id}: ${rule.max_hops}`);
  }
  if (!rule.seed_selector && (rule.internal_seed_system_ids?.length ?? 0) === 0) {
    throw new Error(`F3532 path rule ${rule.id} has neither boundary nor internal seeds`);
  }
  ruleIds.add(rule.id);
  pathCodes.add(rule.path_code);
}
