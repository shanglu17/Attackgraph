import { f3532TopicRules } from "../../config/f3532/topicTaxonomy.js";
import type { F3532DataTopic, F3532GenerationEvidence } from "../../types/domain.js";

export interface TopicClassificationInput {
  source_id?: string;
  data_type?: string;
  data_description?: string;
  producer_name?: string;
  consumer_name?: string;
  function_ids?: string[];
}

export interface TopicClassificationResult {
  topic_ids: F3532DataTopic[];
  evidence: F3532GenerationEvidence[];
}

const typeFallbacks: Record<string, Exclude<F3532DataTopic, "UNKNOWN"> | undefined> = {
  ALERT: "ALERT",
  CMD: "COMMAND_CONTROL",
  CONFIG: "PARAMETER_CONFIGURATION",
  LOAD: "SOFTWARE_LOAD",
  STATE: "FLIGHT_STATE"
};

export function classifyF3532Topics(input: TopicClassificationInput): TopicClassificationResult {
  const searchable = [
    input.data_description,
    input.producer_name,
    input.consumer_name,
    input.data_type,
    ...(input.function_ids ?? [])
  ]
    .filter(Boolean)
    .join(" ")
    .normalize("NFKC");

  const topicIds = new Set<F3532DataTopic>();
  const evidence: F3532GenerationEvidence[] = [];
  for (const rule of [...f3532TopicRules].sort((a, b) => a.priority - b.priority)) {
    const matchedPattern = rule.patterns.find((pattern) => searchable.toUpperCase().includes(pattern.toUpperCase()));
    if (!matchedPattern) {
      continue;
    }
    topicIds.add(rule.topic);
    evidence.push({
      type: "TOPIC_RULE_MATCH",
      source_id: input.source_id,
      rule_id: rule.id,
      message: `关键词 '${matchedPattern}' 命中数据主题 ${rule.topic}`
    });
  }

  if (topicIds.size === 0) {
    const fallback = typeFallbacks[(input.data_type ?? "").trim().toUpperCase()];
    if (fallback) {
      topicIds.add(fallback);
      evidence.push({
        type: "TOPIC_TYPE_FALLBACK",
        source_id: input.source_id,
        rule_id: `TYPE_${(input.data_type ?? "").trim().toUpperCase()}`,
        message: `未命中关键词，按数据类型确定主题 ${fallback}`
      });
    } else {
      topicIds.add("UNKNOWN");
      evidence.push({
        type: "TOPIC_UNKNOWN",
        source_id: input.source_id,
        message: "未命中可解释的数据主题规则，保留为 UNKNOWN"
      });
    }
  }

  return { topic_ids: Array.from(topicIds).sort(), evidence };
}
