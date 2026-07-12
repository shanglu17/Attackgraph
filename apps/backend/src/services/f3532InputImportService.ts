import crypto from "node:crypto";
import { graphChangeSetSchema, type F3532InputImportRequest } from "../types/api.js";
import type {
  AssetEdge,
  AssetNode,
  BoundaryInterface,
  FunctionLink,
  FunctionNode,
  GraphChangeSet,
  SystemDataFlow,
  ThreatActor,
  ThreatActorType,
  TrustBoundary
} from "../types/domain.js";

type F3532InputSheetName = keyof F3532InputImportRequest["workbook"];
type ImportErrorCategory = "field" | "binding";

export interface F3532InputImportErrorDetail {
  type: ImportErrorCategory;
  sheet?: F3532InputSheetName;
  row?: number;
  field?: string;
  message: string;
}

export interface F3532InputAcceptedSummary {
  boundary_interfaces: number;
  boundary_data_flows: number;
  system_interfaces: number;
  system_data_flows: number;
  threat_actors: number;
  trust_boundaries: number;
}

export interface F3532InputImportSummary {
  asset_nodes_to_add: number;
  asset_edges_to_add: number;
  boundary_interfaces_to_add: number;
  trust_boundaries_to_add: number;
  threat_actors_to_add: number;
  system_data_flows_to_add: number;
  function_nodes_to_add: number;
  function_links_to_add: number;
  warnings: string[];
}

export interface F3532InputImportPreviewResult {
  ok: boolean;
  accepted: F3532InputAcceptedSummary;
  errors: string[];
  error_details: F3532InputImportErrorDetail[];
  summary: F3532InputImportSummary;
}

export interface F3532InputImportPreparedChangeSet extends F3532InputImportPreviewResult {
  change_set?: GraphChangeSet;
}

interface SystemEndpoint {
  asset_id: string;
  name: string;
}

export class F3532InputImportService {
  preview(input: F3532InputImportRequest): F3532InputImportPreviewResult {
    const prepared = this.prepareInternal(input);
    return {
      ok: prepared.ok,
      accepted: prepared.accepted,
      errors: prepared.errors,
      error_details: prepared.error_details,
      summary: prepared.summary
    };
  }

  prepareChangeSet(input: F3532InputImportRequest, graphVersion: string): F3532InputImportPreparedChangeSet {
    return this.prepareInternal(input, graphVersion);
  }

  createBindingErrors(messages: string[]): F3532InputImportErrorDetail[] {
    return messages.map((message) => ({ type: "binding", message }));
  }

  private prepareInternal(input: F3532InputImportRequest, graphVersion?: string): F3532InputImportPreparedChangeSet {
    const accepted = this.createAcceptedSummary();
    const summary = this.createSummary();
    const errors: F3532InputImportErrorDetail[] = [];
    const assets = new Map<string, AssetNode>();
    const edges = new Map<string, AssetEdge>();
    const boundaryInterfaces = new Map<string, BoundaryInterface>();
    const trustBoundaries = new Map<string, TrustBoundary>();
    const threatActors = new Map<string, ThreatActor>();
    const systemDataFlows = new Map<string, SystemDataFlow>();
    const functionNodes = new Map<string, FunctionNode>();
    const functionLinks: FunctionLink[] = [];
    const boundaryIdByInterfaceId = new Map<string, string>();
    const boundaryIdsByActorId = new Map<string, Set<string>>();
    const systemEndpoints = new Map<string, SystemEndpoint>();
    const systemInterfaceIds = new Set<string>();

    for (const row of input.workbook.boundary_interfaces) {
      const interfaceId = this.normalizePrefixedId(row.id, "BI");
      if (!this.requireFields("boundary_interfaces", row.excel_row, row, ["id", "external_entity", "access_object", "physical_interconnect", "logical_protocol", "direction"], errors)) {
        continue;
      }
      if (boundaryInterfaces.has(interfaceId)) {
        errors.push(this.error("field", "boundary_interfaces", row.excel_row, "id", `duplicate boundary interface id: ${interfaceId}`));
        continue;
      }
      boundaryInterfaces.set(interfaceId, {
        interface_id: interfaceId,
        name: this.truncate(`${row.external_entity ?? ""}-${row.access_object ?? ""}`, 64),
        interface_class: row.interface_class,
        external_entity: row.external_entity,
        access_object: row.access_object,
        physical_interconnect: row.physical_interconnect,
        logical_protocol: row.logical_protocol,
        direction: row.direction,
        description: this.truncate(this.buildDescription(row.access_device, row.description, row.notes), 200)
      });
      accepted.boundary_interfaces += 1;
    }

    for (const row of input.workbook.threat_actors) {
      const actorId = this.normalizeThreatActorId(row.id);
      if (!this.requireFields("threat_actors", row.excel_row, row, ["id", "name", "actor_type"], errors)) {
        continue;
      }
      if (threatActors.has(actorId)) {
        errors.push(this.error("field", "threat_actors", row.excel_row, "id", `duplicate threat actor id: ${actorId}`));
        continue;
      }
      threatActors.set(actorId, {
        actor_id: actorId,
        name: this.sanitizeName(row.name ?? actorId, "Threat Actor"),
        actor_type: this.resolveActorType(row.actor_type, actorId),
        description: this.truncate(row.description, 200)
      });
      accepted.threat_actors += 1;
    }

    for (const row of input.workbook.trust_boundaries) {
      const boundaryId = this.normalizeBusinessId(row.boundary_id);
      if (!this.requireFields("trust_boundaries", row.excel_row, row, ["boundary_id", "name"], errors)) {
        continue;
      }
      if (trustBoundaries.has(boundaryId)) {
        errors.push(this.error("field", "trust_boundaries", row.excel_row, "boundary_id", `duplicate trust boundary id: ${boundaryId}`));
        continue;
      }

      const coveredInterfaces = this.extractBoundaryInterfaceRefs(row.covered_scope);
      for (const interfaceId of coveredInterfaces) {
        boundaryIdByInterfaceId.set(interfaceId, boundaryId);
      }
      const actorIds = this.extractThreatActorRefs(row.threat_actor_refs);
      for (const actorId of actorIds) {
        const set = boundaryIdsByActorId.get(actorId) ?? new Set<string>();
        set.add(boundaryId);
        boundaryIdsByActorId.set(actorId, set);
      }

      trustBoundaries.set(boundaryId, {
        boundary_id: boundaryId,
        name: this.sanitizeName(row.name ?? boundaryId, "Trust Boundary"),
        description: this.truncate(this.buildDescription(row.description, row.covered_scope), 200),
        domain_asset_ids: []
      });
      accepted.trust_boundaries += 1;
    }

    for (const [interfaceId, boundaryId] of boundaryIdByInterfaceId.entries()) {
      const bi = boundaryInterfaces.get(interfaceId);
      if (!bi) {
        summary.warnings.push(`Trust boundary references ${interfaceId}, but it is not present in 01/边界接口.`);
        continue;
      }
      boundaryInterfaces.set(interfaceId, { ...bi, boundary_id: boundaryId });
    }

    for (const [actorId, actor] of threatActors.entries()) {
      threatActors.set(actorId, {
        ...actor,
        boundary_ids: Array.from(boundaryIdsByActorId.get(actorId) ?? []).sort()
      });
    }

    for (const row of input.workbook.boundary_data_flows) {
      const bdfId = this.normalizePrefixedId(row.id, "BDF");
      if (!this.requireFields("boundary_data_flows", row.excel_row, row, ["id", "producer", "consumer", "boundary_interface_id"], errors)) {
        continue;
      }
      const interfaceIds = this.extractBoundaryInterfaceRefs(row.boundary_interface_id);
      const missingInterfaceIds = interfaceIds.filter((interfaceId) => !boundaryInterfaces.has(interfaceId));
      if (interfaceIds.length === 0 || missingInterfaceIds.length > 0) {
        errors.push(
          this.error(
            "binding",
            "boundary_data_flows",
            row.excel_row,
            "boundary_interface_id",
            `referenced boundary interface does not exist: ${missingInterfaceIds.join(", ") || row.boundary_interface_id}`
          )
        );
        continue;
      }
      const assetId = this.toInternalAssetId("IF", bdfId);
      const functionIds = this.collectFunctionNodes(row.target_function, functionNodes);
      assets.set(assetId, {
        asset_id: assetId,
        asset_name: this.sanitizeName(row.description ?? row.destination ?? bdfId, "Boundary Data Flow"),
        asset_type: "Interface",
        criticality: "Medium",
        security_domain: "Shared",
        description: this.truncate(this.buildDescription(row.producer, row.consumer, row.destination, row.description, row.notes), 200),
        source: "excel_import",
        business_id: bdfId,
        data_flow_type: row.data_flow_type ? row.data_flow_type.trim().toUpperCase() : undefined,
        boundary_interface_id: interfaceIds[0],
        boundary_interface_ids: interfaceIds,
        enters_internal_propagation: true
      });
      for (const functionId of functionIds) {
        functionLinks.push({ asset_id: assetId, function_id: functionId });
      }
      accepted.boundary_data_flows += 1;
    }

    for (const row of input.workbook.system_interfaces) {
      const siId = this.normalizePrefixedId(row.id, "SI");
      if (!this.requireFields("system_interfaces", row.excel_row, row, ["id", "producer", "consumer", "interface_type", "protocol", "direction"], errors)) {
        continue;
      }
      if (systemInterfaceIds.has(siId)) {
        errors.push(this.error("field", "system_interfaces", row.excel_row, "id", `duplicate system interface id: ${siId}`));
        continue;
      }
      systemInterfaceIds.add(siId);
      const producer = this.getOrCreateSystemEndpoint(row.producer ?? "", systemEndpoints, assets);
      const consumer = this.getOrCreateSystemEndpoint(row.consumer ?? "", systemEndpoints, assets);
      const edge = this.buildSystemInterfaceEdge(siId, producer.asset_id, consumer.asset_id, row);
      edges.set(edge.edge_id, edge);
      accepted.system_interfaces += 1;
    }

    for (const row of input.workbook.system_data_flows) {
      const sdfId = this.normalizePrefixedId(row.id, "SDF");
      if (!this.requireFields("system_data_flows", row.excel_row, row, ["id", "producer", "consumer", "system_interface_id"], errors)) {
        continue;
      }
      const siId = this.normalizePrefixedId(row.system_interface_id ?? "", "SI");
      if (!systemInterfaceIds.has(siId)) {
        errors.push(this.error("binding", "system_data_flows", row.excel_row, "system_interface_id", `referenced system interface does not exist: ${siId}`));
        continue;
      }
      if (systemDataFlows.has(sdfId)) {
        errors.push(this.error("field", "system_data_flows", row.excel_row, "id", `duplicate system data flow id: ${sdfId}`));
        continue;
      }
      const functionIds = this.collectFunctionNodes(row.target_function, functionNodes);
      const failureConditionIds = this.extractFailureConditionRefs(row.failure_condition);
      systemDataFlows.set(sdfId, {
        sdf_id: sdfId,
        producer: row.producer,
        consumer: row.consumer,
        content: row.content,
        data_flow_type: row.data_flow_type ? row.data_flow_type.trim().toUpperCase() : undefined,
        function_ids: functionIds,
        failure_condition_ids: failureConditionIds,
        system_interface_id: siId,
        description: this.buildDescription(row.destination, row.notes)
      });
      accepted.system_data_flows += 1;
    }

    for (const actorId of boundaryIdsByActorId.keys()) {
      if (!threatActors.has(actorId)) {
        summary.warnings.push(`Trust boundary references ${actorId}, but it is not present in 02/威胁主体.`);
      }
    }

    summary.asset_nodes_to_add = assets.size;
    summary.asset_edges_to_add = edges.size;
    summary.boundary_interfaces_to_add = boundaryInterfaces.size;
    summary.trust_boundaries_to_add = trustBoundaries.size;
    summary.threat_actors_to_add = threatActors.size;
    summary.system_data_flows_to_add = systemDataFlows.size;
    summary.function_nodes_to_add = functionNodes.size;
    summary.function_links_to_add = functionLinks.length;

    if (errors.length > 0 || !graphVersion) {
      return this.buildResult(accepted, summary, errors);
    }

    const changeSetCandidate: GraphChangeSet = {
      graph_version: graphVersion,
      asset_nodes: { add: Array.from(assets.values()).sort((a, b) => a.asset_id.localeCompare(b.asset_id)), update: [], delete: [] },
      asset_edges: { add: Array.from(edges.values()).sort((a, b) => a.edge_id.localeCompare(b.edge_id)), update: [], delete: [] },
      threat_points: { add: [], update: [], delete: [] },
      do326a_links: { add: [], update: [], delete: [] },
      function_nodes: { add: Array.from(functionNodes.values()).sort((a, b) => a.function_id.localeCompare(b.function_id)), update: [], delete: [] },
      trust_boundaries: { add: Array.from(trustBoundaries.values()).sort((a, b) => a.boundary_id.localeCompare(b.boundary_id)), update: [], delete: [] },
      threat_actors: { add: Array.from(threatActors.values()).sort((a, b) => a.actor_id.localeCompare(b.actor_id)), update: [], delete: [] },
      boundary_interfaces: { add: Array.from(boundaryInterfaces.values()).sort((a, b) => a.interface_id.localeCompare(b.interface_id)), update: [], delete: [] },
      system_data_flows: { add: Array.from(systemDataFlows.values()).sort((a, b) => a.sdf_id.localeCompare(b.sdf_id)), update: [], delete: [] },
      function_links: functionLinks
    };

    const parsed = graphChangeSetSchema.safeParse(changeSetCandidate);
    if (!parsed.success) {
      return this.buildResult(
        accepted,
        summary,
        parsed.error.issues.map((issue) => ({
          type: "field",
          field: issue.path.join("."),
          message: issue.message
        }))
      );
    }

    return { ...this.buildResult(accepted, summary, []), change_set: parsed.data };
  }

  private createAcceptedSummary(): F3532InputAcceptedSummary {
    return {
      boundary_interfaces: 0,
      boundary_data_flows: 0,
      system_interfaces: 0,
      system_data_flows: 0,
      threat_actors: 0,
      trust_boundaries: 0
    };
  }

  private createSummary(): F3532InputImportSummary {
    return {
      asset_nodes_to_add: 0,
      asset_edges_to_add: 0,
      boundary_interfaces_to_add: 0,
      trust_boundaries_to_add: 0,
      threat_actors_to_add: 0,
      system_data_flows_to_add: 0,
      function_nodes_to_add: 0,
      function_links_to_add: 0,
      warnings: []
    };
  }

  private buildResult(
    accepted: F3532InputAcceptedSummary,
    summary: F3532InputImportSummary,
    errorDetails: F3532InputImportErrorDetail[]
  ): F3532InputImportPreviewResult {
    return {
      ok: errorDetails.length === 0,
      accepted,
      errors: errorDetails.map((detail) => this.toErrorMessage(detail)),
      error_details: errorDetails,
      summary
    };
  }

  private requireFields(
    sheet: F3532InputSheetName,
    row: number | undefined,
    source: Record<string, unknown>,
    fields: string[],
    errors: F3532InputImportErrorDetail[]
  ): boolean {
    let valid = true;
    for (const field of fields) {
      const value = source[field];
      if (value === undefined || value === null || String(value).trim().length === 0 || String(value).trim() === "/") {
        errors.push(this.error("field", sheet, row, field, "required field is missing"));
        valid = false;
      }
    }
    return valid;
  }

  private buildSystemInterfaceEdge(
    siId: string,
    sourceAssetId: string,
    targetAssetId: string,
    row: F3532InputImportRequest["workbook"]["system_interfaces"][number]
  ): AssetEdge {
    const normalizedDirection = row.direction?.includes("双") || /bi/i.test(row.direction ?? "") ? "Bidirectional" : "Unidirectional";
    return {
      edge_id: `E-${sourceAssetId}-${targetAssetId}-${this.extractSequence(siId)}`,
      source_asset_id: sourceAssetId,
      target_asset_id: targetAssetId,
      link_type: "DataFlow",
      protocol_or_medium: this.truncate(this.firstNonEmpty(row.protocol, row.interface_type, "SystemInterface"), 64),
      direction: normalizedDirection,
      trust_level: "Trusted",
      description: this.truncate(this.buildDescription(siId, row.interface_type, row.content, row.notes), 200)
    };
  }

  private getOrCreateSystemEndpoint(
    rawName: string,
    registry: Map<string, SystemEndpoint>,
    assets: Map<string, AssetNode>
  ): SystemEndpoint {
    const normalizedName = this.normalizeName(rawName);
    const current = registry.get(normalizedName);
    if (current) {
      return current;
    }
    const endpoint: SystemEndpoint = {
      asset_id: this.toInternalAssetId("SYS", rawName),
      name: this.sanitizeName(rawName, "System")
    };
    registry.set(normalizedName, endpoint);
    assets.set(endpoint.asset_id, {
      asset_id: endpoint.asset_id,
      asset_name: endpoint.name,
      asset_type: "Terminal",
      criticality: "Medium",
      security_domain: "Internal",
      source: "excel_import",
      business_id: this.normalizeBusinessId(rawName)
    });
    return endpoint;
  }

  private collectFunctionNodes(raw: string | undefined, functionNodes: Map<string, FunctionNode>): string[] {
    if (!raw || raw.trim() === "/") {
      return [];
    }
    const ids = new Set<string>();
    for (const match of raw.matchAll(/F\d+(?:\.\d+)*/gi)) {
      ids.add(match[0].toUpperCase());
    }
    for (const id of ids) {
      if (!functionNodes.has(id)) {
        functionNodes.set(id, { function_id: id, name: id, description: this.truncate(raw, 200) });
      }
    }
    return Array.from(ids).sort((a, b) => a.localeCompare(b));
  }

  private extractBoundaryInterfaceRefs(raw: string | undefined): string[] {
    if (!raw) {
      return [];
    }
    const refs = new Set<string>();
    for (const match of raw.matchAll(/BI\s*[-]?\s*(\d+)\s*[~～至到-]\s*(?:BI\s*[-]?\s*)?(\d+)/gi)) {
      const start = Number(match[1]);
      const end = Number(match[2]);
      const step = start <= end ? 1 : -1;
      for (let value = start; step > 0 ? value <= end : value >= end; value += step) {
        refs.add(`BI${value}`);
      }
    }
    for (const match of raw.matchAll(/BI\s*[-]?\s*(\d+)/gi)) {
      refs.add(`BI${Number(match[1])}`);
    }
    return Array.from(refs).sort((a, b) => Number(a.replace(/\D/g, "")) - Number(b.replace(/\D/g, "")));
  }

  private extractThreatActorRefs(raw: string | undefined): string[] {
    if (!raw) {
      return [];
    }
    const refs = new Set<string>();
    for (const match of raw.matchAll(/TA-[A-Z]-\d+/gi)) {
      refs.add(match[0].toUpperCase());
    }
    return Array.from(refs).sort();
  }

  private extractFailureConditionRefs(raw: string | undefined): string[] {
    if (!raw || raw.trim().toUpperCase() === "N/A") {
      return [];
    }
    const refs = new Set<string>();
    for (const match of raw.matchAll(/(?:FC\s*)?(\d+(?:\.\d+)+)/gi)) {
      refs.add(`FC${match[1]}`.toUpperCase());
    }
    return Array.from(refs).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  }

  private resolveActorType(rawType: string | undefined, actorId: string): ThreatActorType {
    const value = `${rawType ?? ""} ${actorId}`.toLowerCase();
    if (/供应|third|vendor|ta-t/.test(value)) {
      return "third-party";
    }
    if (/内部|internal|ta-i/.test(value)) {
      return "internal";
    }
    return "external";
  }

  private normalizePrefixedId(raw: string | number, prefix: string): string {
    const value = String(raw).trim().toUpperCase().replace(/\s+/g, "");
    if (value.startsWith(prefix)) {
      return value.replace(new RegExp(`^${prefix}[-_]?`), prefix);
    }
    const numeric = value.match(/\d+/)?.[0];
    return numeric ? `${prefix}${Number(numeric)}` : `${prefix}${value.replace(/[^A-Z0-9]/g, "")}`;
  }

  private normalizeThreatActorId(raw: string | number): string {
    return String(raw).trim().toUpperCase().replace(/\s+/g, "");
  }

  private normalizeBusinessId(value: string): string {
    return value.trim().toUpperCase().replace(/\s+/g, "");
  }

  private normalizeName(value: string): string {
    return value.trim().toLowerCase().replace(/[^a-z0-9\u4e00-\u9fa5]+/g, "");
  }

  private toInternalAssetId(prefix: "SYS" | "IF", rawId: string): string {
    const normalizedId = rawId.trim().toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 18) || "NODE";
    const digest = crypto.createHash("sha1").update(rawId.trim().toUpperCase()).digest("hex").slice(0, 4).toUpperCase();
    return `${prefix}-${normalizedId}-${digest}`;
  }

  private sanitizeName(value: string, fallback: string): string {
    const safe = value
      .replace(/[()（）"'`~!@#$%^&*+=?<>[\]{}|\\]/g, " ")
      .replace(/[^A-Za-z0-9\u4e00-\u9fa5\s\-_\/]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    const candidate = safe.length > 0 ? safe : fallback;
    const withLeadingLetter = /^[A-Za-z\u4e00-\u9fa5]/.test(candidate) ? candidate : `${fallback} ${candidate}`;
    return this.truncate(withLeadingLetter, 48) ?? fallback;
  }

  private extractSequence(value: string): string {
    const number = value.match(/\d+/)?.[0] ?? "1";
    return String(Number(number)).padStart(2, "0");
  }

  private buildDescription(...values: Array<string | undefined>): string | undefined {
    const text = values
      .map((value) => value?.trim())
      .filter((value): value is string => Boolean(value))
      .join(" | ");
    return this.truncate(text, 500);
  }

  private firstNonEmpty(...values: Array<string | undefined>): string | undefined {
    return values.find((value) => typeof value === "string" && value.trim().length > 0)?.trim();
  }

  private truncate(value: string | undefined, maxLength: number): string | undefined {
    if (!value) {
      return undefined;
    }
    return value.length > maxLength ? value.slice(0, maxLength) : value;
  }

  private error(
    type: ImportErrorCategory,
    sheet: F3532InputSheetName,
    row: number | undefined,
    field: string,
    message: string
  ): F3532InputImportErrorDetail {
    return { type, sheet, row, field, message };
  }

  private toErrorMessage(detail: F3532InputImportErrorDetail): string {
    const prefix: string[] = [detail.type];
    if (detail.sheet) prefix.push(detail.sheet);
    if (detail.row) prefix.push(`row ${detail.row}`);
    if (detail.field) prefix.push(detail.field);
    return `${prefix.join(" / ")}: ${detail.message}`;
  }
}
