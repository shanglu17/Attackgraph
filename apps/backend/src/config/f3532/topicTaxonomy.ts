import type { F3532DataTopic } from "../../types/domain.js";

export interface F3532TopicRuleConfig {
  id: string;
  priority: number;
  topic: Exclude<F3532DataTopic, "UNKNOWN">;
  patterns: string[];
}

export const f3532TopicRules: F3532TopicRuleConfig[] = [
  { id: "TOPIC_RTK", priority: 10, topic: "RTK_CORRECTION", patterns: ["RTK", "差分修正"] },
  { id: "TOPIC_SOFTWARE_LOAD", priority: 20, topic: "SOFTWARE_LOAD", patterns: ["引导加载", "软件升级", "固件", "管理软件"] },
  {
    id: "TOPIC_PARAMETER_CONFIGURATION",
    priority: 30,
    topic: "PARAMETER_CONFIGURATION",
    patterns: ["软件维护配置", "配置", "参数", "电子围栏", "备降点"]
  },
  { id: "TOPIC_AUDIO", priority: 40, topic: "AUDIO", patterns: ["音频", "语音", "通话", "麦克风"] },
  { id: "TOPIC_VIDEO", priority: 50, topic: "VIDEO", patterns: ["视频", "摄像头", "图像"] },
  { id: "TOPIC_ALERT", priority: 60, topic: "ALERT", patterns: ["告警", "报警"] },
  { id: "TOPIC_FAULT", priority: 70, topic: "FAULT_DIAGNOSIS", patterns: ["诊断", "故障", "日志", "自检"] },
  { id: "TOPIC_POWER", priority: 80, topic: "POWER", patterns: ["电池", "电量", "电压", "电流", "功率", "高压", "配电", "电推进"] },
  { id: "TOPIC_NAVIGATION", priority: 90, topic: "NAVIGATION", patterns: ["GNSS", "导航", "航向", "惯导", "高度"] },
  { id: "TOPIC_POSITION", priority: 100, topic: "POSITION", patterns: ["位置", "经纬度", "速度", "姿态", "角速度"] },
  { id: "TOPIC_FLIGHT_STATE", priority: 110, topic: "FLIGHT_STATE", patterns: ["飞行状态", "周期性状态", "在线状态", "系统状态"] },
  { id: "TOPIC_RECORDING", priority: 120, topic: "RECORDING", patterns: ["记录", "存储", "备份", "导出"] },
  { id: "TOPIC_COMMAND", priority: 130, topic: "COMMAND_CONTROL", patterns: ["控制指令", "维护指令", "加锁", "解锁", "起飞", "备降", "悬停", "制导指令"] },
  { id: "TOPIC_MISSION", priority: 140, topic: "MISSION_DATA", patterns: ["航线", "飞行计划", "任务", "气象"] },
  { id: "TOPIC_MAINTENANCE", priority: 150, topic: "MAINTENANCE", patterns: ["维护", "调试", "升级结果"] }
];

const topicRuleIds = new Set<string>();
for (const rule of f3532TopicRules) {
  if (topicRuleIds.has(rule.id)) {
    throw new Error(`duplicate F3532 topic rule id: ${rule.id}`);
  }
  if (rule.patterns.length === 0) {
    throw new Error(`F3532 topic rule ${rule.id} has no patterns`);
  }
  topicRuleIds.add(rule.id);
}
