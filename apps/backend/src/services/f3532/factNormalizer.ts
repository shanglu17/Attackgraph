import {
  getConfiguredSystemClassification,
  resolveSystemIdentity,
  splitSystemNames
} from "../../config/f3532/systemAliases.js";
import type { F3532InputImportRequest } from "../../types/api.js";
import type {
  BoundaryDataFlowContinuationPolicy,
  BoundaryDataFlowDirection,
  BoundaryDataFlowFact,
  BoundaryInterfaceFact,
  F353203GenerationFacts,
  SystemDataFlowFact,
  SystemInterfaceFact,
  TrustBoundaryFact
} from "../../types/domain.js";
import { classifyF3532Topics } from "./topicClassifier.js";
import { compareNaturalBusinessIds, naturalSortUnique } from "./naturalSort.js";

type WorkbookInput = F3532InputImportRequest["workbook"];

export function normalizePrefixedBusinessId(raw: string | number, prefix: string): string {
  const value = String(raw).trim().toUpperCase().replace(/\s+/g, "");
  const numeric = value.match(/\d+/)?.[0];
  return numeric ? `${prefix}${Number(numeric)}` : `${prefix}${value.replace(/[^A-Z0-9]/g, "")}`;
}

export function normalizeBoundaryInterfaceId(raw: string | number): string {
  const numeric = String(raw).match(/\d+/)?.[0];
  return numeric ? `BI${String(Number(numeric)).padStart(2, "0")}` : normalizePrefixedBusinessId(raw, "BI");
}

export function normalizeSystemInterfaceId(raw: string | number): string {
  const numeric = String(raw).match(/\d+/)?.[0];
  return numeric ? `SI${Number(numeric)}` : normalizePrefixedBusinessId(raw, "SI");
}

export function extractBoundaryInterfaceRefs(raw: string | undefined): string[] {
  if (!raw) return [];
  const refs = new Set<string>();
  for (const match of raw.matchAll(/BI\s*[-]?\s*(\d+)\s*[~～至到-]\s*(?:BI\s*[-]?\s*)?(\d+)/gi)) {
    const start = Number(match[1]);
    const end = Number(match[2]);
    const step = start <= end ? 1 : -1;
    for (let value = start; step > 0 ? value <= end : value >= end; value += step) {
      refs.add(normalizeBoundaryInterfaceId(value));
    }
  }
  for (const match of raw.matchAll(/BI\s*[-]?\s*(\d+)/gi)) {
    refs.add(normalizeBoundaryInterfaceId(match[1]));
  }
  return naturalSortUnique(Array.from(refs));
}

export function extractFunctionIds(raw: string | undefined): string[] {
  if (!raw || raw.trim() === "/") return [];
  return naturalSortUnique(Array.from(raw.matchAll(/F\d+(?:\.\d+)*/gi), (match) => match[0].toUpperCase()));
}

function classifyDirection(
  producerId: string,
  consumerId: string,
  knownExternalIds: Set<string>,
  knownInternalIds: Set<string>
): BoundaryDataFlowDirection {
  const producerExternal = knownExternalIds.has(producerId) || getConfiguredSystemClassification(producerId) === "EXTERNAL";
  const consumerExternal = knownExternalIds.has(consumerId) || getConfiguredSystemClassification(consumerId) === "EXTERNAL";
  const producerInternal = knownInternalIds.has(producerId) || getConfiguredSystemClassification(producerId) === "INTERNAL";
  const consumerInternal = knownInternalIds.has(consumerId) || getConfiguredSystemClassification(consumerId) === "INTERNAL";

  if (producerExternal && consumerInternal) return "INBOUND";
  if (producerInternal && consumerExternal) return "OUTBOUND";
  if (producerInternal && consumerInternal) return "INTERNAL";
  return "UNKNOWN";
}

export function determineBoundaryDataFlowDirection(input: {
  producer_name: string;
  consumer_name: string;
  known_external_system_ids: Set<string>;
  known_internal_system_ids: Set<string>;
}): BoundaryDataFlowDirection {
  const producer = resolveSystemIdentity(input.producer_name);
  const consumer = resolveSystemIdentity(input.consumer_name);
  return classifyDirection(
    producer.system_id,
    consumer.system_id,
    input.known_external_system_ids,
    input.known_internal_system_ids
  );
}

function continuationPolicy(
  direction: BoundaryDataFlowDirection,
  producerId: string,
  dataType: string
): BoundaryDataFlowContinuationPolicy {
  if (direction === "OUTBOUND") return "STOP_AT_CONSUMER";
  if (direction === "INTERNAL") return "CONTINUE";
  if (direction !== "INBOUND") return "UNKNOWN";
  if (producerId === "SYS.GROUND_MAINTENANCE" && ["LOAD", "CONFIG"].includes(dataType)) {
    return "STOP_AT_CONSUMER";
  }
  return "RULE_DEPENDENT";
}

export function normalizeF3532WorkbookFacts(workbook: WorkbookInput, graphVersion = "in-memory"): F353203GenerationFacts {
  const warnings: string[] = [];
  const boundaryByInterface = new Map<string, string>();
  const trustBoundaries: TrustBoundaryFact[] = workbook.trust_boundaries.map((row) => {
    const boundaryId = String(row.boundary_id).trim().toUpperCase();
    for (const interfaceId of extractBoundaryInterfaceRefs(row.covered_scope)) {
      const existing = boundaryByInterface.get(interfaceId);
      if (existing && existing !== boundaryId) {
        warnings.push(`${interfaceId} 同时出现在 ${existing} 和 ${boundaryId} 的覆盖域，保留后者并标记待审核`);
      }
      boundaryByInterface.set(interfaceId, boundaryId);
    }
    return { id: boundaryId, name: row.name?.trim() || boundaryId };
  });

  const boundaryInterfaces: BoundaryInterfaceFact[] = workbook.boundary_interfaces.map((row) => {
    const id = normalizeBoundaryInterfaceId(row.id);
    const external = resolveSystemIdentity(row.external_entity);
    const accessNames = splitSystemNames(row.access_object);
    const access = accessNames.map((name) => resolveSystemIdentity(name));
    if (!external.recognized && external.warning) warnings.push(`${id}: ${external.warning}`);
    for (const item of access) {
      if (!item.recognized && item.warning) warnings.push(`${id}: ${item.warning}`);
    }
    return {
      id,
      external_system_id: external.system_id,
      external_name: row.external_entity,
      access_system_ids: naturalSortUnique(access.map((item) => item.system_id)),
      access_names: accessNames,
      security_boundary_id: boundaryByInterface.get(id)
    };
  });
  const biById = new Map(boundaryInterfaces.map((item) => [item.id, item]));

  const systemInterfaces: SystemInterfaceFact[] = workbook.system_interfaces.map((row) => {
    const producer = resolveSystemIdentity(row.producer);
    const consumer = resolveSystemIdentity(row.consumer);
    if (!producer.recognized && producer.warning) warnings.push(`${normalizeSystemInterfaceId(row.id)}: ${producer.warning}`);
    if (!consumer.recognized && consumer.warning) warnings.push(`${normalizeSystemInterfaceId(row.id)}: ${consumer.warning}`);
    return {
      id: normalizeSystemInterfaceId(row.id),
      producer_system_id: producer.system_id,
      consumer_system_id: consumer.system_id,
      producer_name: row.producer ?? producer.display_name,
      consumer_name: row.consumer ?? consumer.display_name,
      direction: row.direction,
      protocol: row.protocol
    };
  });

  const knownExternalIds = new Set(boundaryInterfaces.map((item) => item.external_system_id).filter((id): id is string => Boolean(id)));
  const knownInternalIds = new Set([
    ...systemInterfaces.flatMap((item) => [item.producer_system_id, item.consumer_system_id]),
    ...boundaryInterfaces.flatMap((item) => item.access_system_ids)
  ]);

  const boundaryDataFlows: BoundaryDataFlowFact[] = workbook.boundary_data_flows.map((row) => {
    const id = normalizePrefixedBusinessId(row.id, "BDF");
    const producer = resolveSystemIdentity(row.producer);
    const consumer = resolveSystemIdentity(row.consumer);
    const destinationNames = splitSystemNames(row.destination);
    const destinationIds = destinationNames.map((name) => resolveSystemIdentity(name).system_id);
    const boundaryInterfaceIds = extractBoundaryInterfaceRefs(row.boundary_interface_id);
    const securityBoundaryIds = naturalSortUnique(
      boundaryInterfaceIds.map((interfaceId) => biById.get(interfaceId)?.security_boundary_id ?? "").filter(Boolean)
    );
    const functionIds = extractFunctionIds(row.target_function);
    const dataType = (row.data_flow_type ?? "UNSPECIFIED").trim().toUpperCase();
    const direction = classifyDirection(producer.system_id, consumer.system_id, knownExternalIds, knownInternalIds);
    const topic = classifyF3532Topics({
      source_id: id,
      data_type: dataType,
      data_description: row.description,
      producer_name: row.producer,
      consumer_name: row.consumer,
      function_ids: functionIds
    });
    const rowWarnings: string[] = [];
    if (!producer.recognized && producer.warning) rowWarnings.push(producer.warning);
    if (!consumer.recognized && consumer.warning) rowWarnings.push(consumer.warning);
    if (boundaryInterfaceIds.length === 0) rowWarnings.push(`${id} 未引用边界接口 BI`);
    for (const interfaceId of boundaryInterfaceIds) {
      if (!biById.has(interfaceId)) rowWarnings.push(`${id} 引用不存在的边界接口 ${interfaceId}`);
      else if (!biById.get(interfaceId)?.security_boundary_id) rowWarnings.push(`${interfaceId} 未归属安保边界 SB`);
    }
    if (securityBoundaryIds.length > 1) rowWarnings.push(`${id} 的多个 BI 跨越不同安保边界: ${securityBoundaryIds.join("、")}`);
    if (direction === "UNKNOWN") rowWarnings.push(`${id} 无法根据已知内外部系统确定方向`);

    return {
      id,
      producer_id: producer.system_id,
      producer_name: row.producer ?? producer.display_name,
      consumer_id: consumer.system_id,
      consumer_name: row.consumer ?? consumer.display_name,
      destination_ids: naturalSortUnique(destinationIds),
      destination_names: destinationNames,
      direction,
      boundary_interface_ids: boundaryInterfaceIds,
      security_boundary_ids: securityBoundaryIds,
      data_type: dataType,
      data_description: row.description,
      function_ids: functionIds,
      function_text: row.target_function,
      continuation_policy: continuationPolicy(direction, producer.system_id, dataType),
      topic_ids: topic.topic_ids,
      source_sheet: "边界数据流",
      source_row: row.excel_row,
      warnings: rowWarnings,
      evidence: [
        {
          type: "BDF_DIRECTION",
          source_id: id,
          message: `${row.producer ?? "?"} → ${row.consumer ?? "?"} 判定为 ${direction}`
        },
        ...topic.evidence
      ]
    };
  });

  const systemInterfaceIds = new Set(systemInterfaces.map((item) => item.id));
  const systemDataFlows: SystemDataFlowFact[] = workbook.system_data_flows.map((row) => {
    const id = normalizePrefixedBusinessId(row.id, "SDF");
    const producer = resolveSystemIdentity(row.producer);
    const consumer = resolveSystemIdentity(row.consumer);
    const systemInterfaceId = row.system_interface_id ? normalizeSystemInterfaceId(row.system_interface_id) : undefined;
    const functionIds = extractFunctionIds(row.target_function);
    const dataType = (row.data_flow_type ?? "UNSPECIFIED").trim().toUpperCase();
    const topic = classifyF3532Topics({
      source_id: id,
      data_type: dataType,
      data_description: row.content,
      producer_name: row.producer,
      consumer_name: row.consumer,
      function_ids: functionIds
    });
    const rowWarnings: string[] = [];
    if (!producer.recognized && producer.warning) rowWarnings.push(producer.warning);
    if (!consumer.recognized && consumer.warning) rowWarnings.push(consumer.warning);
    if (!systemInterfaceId) rowWarnings.push(`${id} 未引用系统接口 SI`);
    else if (!systemInterfaceIds.has(systemInterfaceId)) rowWarnings.push(`${id} 引用不存在的系统接口 ${systemInterfaceId}`);
    return {
      id,
      producer_system_id: producer.system_id,
      consumer_system_id: consumer.system_id,
      producer_name: row.producer ?? producer.display_name,
      consumer_name: row.consumer ?? consumer.display_name,
      system_interface_id: systemInterfaceId,
      data_type: dataType,
      data_description: row.content,
      function_ids: functionIds,
      topic_ids: topic.topic_ids,
      source_row: row.excel_row,
      warnings: rowWarnings,
      evidence: topic.evidence
    };
  });

  return {
    graph_version: graphVersion,
    boundary_data_flows: boundaryDataFlows.sort((a, b) => compareNaturalBusinessIds(a.id, b.id)),
    system_data_flows: systemDataFlows.sort((a, b) => compareNaturalBusinessIds(a.id, b.id)),
    system_interfaces: systemInterfaces.sort((a, b) => compareNaturalBusinessIds(a.id, b.id)),
    boundary_interfaces: boundaryInterfaces.sort((a, b) => compareNaturalBusinessIds(a.id, b.id)),
    trust_boundaries: trustBoundaries.sort((a, b) => a.id.localeCompare(b.id)),
    warnings: naturalSortUnique(warnings)
  };
}
