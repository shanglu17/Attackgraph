import crypto from "node:crypto";
import {
  assetEdgeSchema,
  assetNodeSchema,
  graphChangeSetSchema,
  threatPointSchema,
  type CxfImportRequest
} from "../types/api.js";
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
  ThreatPoint,
  TrustBoundary
} from "../types/domain.js";

type CxfSheetName = keyof CxfImportRequest["workbook"];
type ImportErrorCategory = "field" | "binding";
type AssetPrefix = "SYS" | "IF" | "EXT";
type ThreatKind = "ingress" | "integrity" | "control_misuse";
type NameRegistry = Map<string, Set<string>>;

const coreAssetId = "SYS-DO356AAMSCORE";
const tempControllerAssetId = "SYS-AMSTEMPCTRL";
const pressControllerAssetId = "SYS-AMSPRESSCTRL";
const warningKeywords = ["以下是样例", "填写要求", "填表要求", "注"];

const sheetLabels: Record<CxfSheetName, string> = {
  functional_assets: "功能资产",
  interface_assets: "边界数据流表",
  support_assets: "支持资产",
  data_assets: "数据资产",
  domain_properties: "域属性表",
  trust_boundaries: "信任边界表",
  threat_actors: "威胁主体表",
  boundary_interfaces: "边界接口表",
  system_data_flows: "系统数据流表"
};

const autoThreatProfiles: Array<{
  kind: ThreatKind;
  idSuffix: string;
  nameSuffix: string;
}> = [
  { kind: "ingress", idSuffix: "ING", nameSuffix: "ingress access threat" },
  { kind: "integrity", idSuffix: "INT", nameSuffix: "data integrity threat" },
  { kind: "control_misuse", idSuffix: "CTL", nameSuffix: "control misuse threat" }
];

const validDataFlowTypes = new Set(["CMD", "CONFIG", "STATE", "DATA", "LOAD", "ALERT"]);

interface AutoThreatSummary {
  threatpoint_id: string;
  related_asset_id: string;
  asset_name: string;
  threat_kind: ThreatKind;
  attack_vector: ThreatPoint["attack_vector"];
  stride_category: ThreatPoint["stride_category"];
}

interface AcceptedSummary {
  functional_assets: number;
  interface_assets: number;
  support_assets: number;
  data_assets: number;
  domain_properties: number;
}

interface EdgeDraft {
  source_asset_id: string;
  target_asset_id: string;
  link_type: AssetEdge["link_type"];
  protocol_or_medium?: string;
  direction: AssetEdge["direction"];
  trust_level?: AssetEdge["trust_level"];
  security_mechanism?: string;
  description?: string;
}

interface EndpointResolutionContext {
  sheet: CxfSheetName;
  row?: number;
  nameField: string;
  refField: string;
}

interface RegisteredDataAsset {
  asset_id: string;
  row: CxfImportRequest["workbook"]["data_assets"][number];
  linked_interface_ids: string[];
  domain_id?: string;
}

export interface CxfImportErrorDetail {
  type: ImportErrorCategory;
  sheet?: CxfSheetName;
  row?: number;
  field?: string;
  message: string;
}

export interface CxfImportSummary {
  asset_nodes_to_add: number;
  asset_edges_to_add: number;
  threat_points_to_add: number;
  auto_placeholder_assets_to_add: number;
  warnings: string[];
  auto_generated_threats: AutoThreatSummary[];
}

export interface CxfImportPreviewResult {
  ok: boolean;
  accepted: AcceptedSummary;
  errors: string[];
  error_details: CxfImportErrorDetail[];
  summary: CxfImportSummary;
}

export interface CxfImportPreparedChangeSet extends CxfImportPreviewResult {
  change_set?: GraphChangeSet;
}

export class CxfImportService {
  preview(input: CxfImportRequest): CxfImportPreviewResult {
    const prepared = this.prepareInternal(input);
    return {
      ok: prepared.ok,
      accepted: prepared.accepted,
      errors: prepared.errors,
      error_details: prepared.error_details,
      summary: prepared.summary
    };
  }

  prepareChangeSet(input: CxfImportRequest, graphVersion: string): CxfImportPreparedChangeSet {
    return this.prepareInternal(input, graphVersion);
  }

  createBindingErrors(messages: string[]): CxfImportErrorDetail[] {
    return messages.map((message) => ({
      type: "binding",
      message
    }));
  }

  private prepareInternal(input: CxfImportRequest, graphVersion?: string): CxfImportPreparedChangeSet {
    const accepted = this.createAcceptedSummary();
    const summary = this.createSummary();
    const errors: CxfImportErrorDetail[] = [];
    const businessIdToAssetId = new Map<string, string>();
    const nameRegistry: NameRegistry = new Map();
    const assets = new Map<string, AssetNode>();
    const edges = new Map<string, AssetEdge>();
    const interfaceAssetIds = new Set<string>();
    const dataAssetThreatIds = new Set<string>();
    const placeholderAssetIds = new Set<string>();
    const unresolvedEndpointNames = new Set<string>();
    const edgeSequenceByPair = new Map<string, number>();
    const registeredDataAssets: RegisteredDataAsset[] = [];
    const functionalAssetIdsToDelete = new Set<string>();
    const legacyImportedAssetIdsToDelete = new Set<string>();
    const autoThreatIdsToDelete = new Set<string>();
    const functionNodes = new Map<string, FunctionNode>();
    const functionLinks: FunctionLink[] = [];
    const interfaceAssetIdsByBoundary = new Map<string, Set<string>>();
    const domainIdToAssetIdGlobal = new Map<string, string>();

    const hasAmsReferences = this.scanInputForAmsReferences(input);

    if (hasAmsReferences) {
      this.registerDerivedSystemAssets(assets, nameRegistry, errors);
    }

    const functionalIdSet = new Set<string>();
    for (const row of input.workbook.functional_assets) {
      if (!this.ensureUniqueSheetId(functionalIdSet, "functional_assets", row.excel_row, row.id, errors)) {
        continue;
      }

      // Legacy imports may have created SYS- AssetNodes for functions; keep cleaning those up.
      functionalAssetIdsToDelete.add(this.toInternalAssetId("SYS", row.id));
      functionalAssetIdsToDelete.add(this.toLegacyInternalAssetId("SYS", row.id));

      const functionId = this.normalizeFunctionId(row.id);
      if (functionId && !functionNodes.has(functionId)) {
        functionNodes.set(functionId, {
          function_id: functionId,
          name: this.sanitizeAssetName(row.name, "Function"),
          description: row.description
        });
      }
      accepted.functional_assets += 1;
    }

    const supportIdSet = new Set<string>();
    const supportRows: Array<CxfImportRequest["workbook"]["support_assets"][number]> = [];
    for (const row of input.workbook.support_assets) {
      const businessId = this.normalizeBusinessId(row.id);
      if (!this.ensureUniqueSheetId(supportIdSet, "support_assets", row.excel_row, row.id, errors)) {
        continue;
      }
      legacyImportedAssetIdsToDelete.add(this.toLegacyInternalAssetId("EXT", row.id));

      const assetId = this.toInternalAssetId("EXT", row.id);
      const securityDomain =
        row.security_domain === "Internal" ||
        row.security_domain === "External" ||
        row.security_domain === "DMZ" ||
        row.security_domain === "Shared"
          ? row.security_domain
          : "External";
      const criticality =
        row.criticality === "High" || row.criticality === "Medium" || row.criticality === "Low"
          ? row.criticality
          : "Medium";
      const candidate: AssetNode = {
        asset_id: assetId,
        asset_name: this.sanitizeAssetName(row.name, "Support Asset"),
        asset_type: "Terminal",
        criticality,
        security_domain: securityDomain,
        source: "excel_import",
        business_id: businessId
      };
      if (!this.registerAsset(assets, candidate, errors, "support_assets", row.excel_row)) {
        continue;
      }

      supportRows.push(row);
      businessIdToAssetId.set(businessId, assetId);
      this.registerNameAlias(nameRegistry, row.name, assetId);
      accepted.support_assets += 1;
    }

    const dataIdSet = new Set<string>();
    for (const row of input.workbook.data_assets) {
      const businessId = this.normalizeBusinessId(row.id);
      if (!this.ensureUniqueSheetId(dataIdSet, "data_assets", row.excel_row, row.id, errors)) {
        continue;
      }
      legacyImportedAssetIdsToDelete.add(this.toLegacyInternalAssetId("SYS", row.id));

      const assetId = this.toInternalAssetId("SYS", row.id);
      const candidate: AssetNode = {
        asset_id: assetId,
        asset_name: this.sanitizeAssetName(row.name, "Data Asset"),
        asset_type: "Data",
        criticality: "Medium",
        security_domain: this.resolveDomainSecurityDomain(row.domain_id),
        data_classification: this.resolveDataClassification(`${row.name} ${row.data_type ?? ""} ${row.description ?? ""}`),
        description: this.buildDescription(
          row.data_flow_type,
          row.data_type,
          row.load_description,
          row.description,
          row.target_function ? `F:${row.target_function}` : undefined
        ),
        source: "excel_import",
        business_id: businessId,
        data_flow_type: row.data_flow_type ? row.data_flow_type.toUpperCase() : undefined
      };
      if (!this.registerAsset(assets, candidate, errors, "data_assets", row.excel_row)) {
        continue;
      }

      this.collectFunctionLinks(assetId, row.target_function, functionNodes, functionLinks);

      registeredDataAssets.push({
        asset_id: assetId,
        row,
        linked_interface_ids: this.parseLinkedInterfaces(row.linked_interfaces),
        domain_id: row.domain_id
      });
      if (row.data_flow_type && validDataFlowTypes.has(row.data_flow_type.toUpperCase())) {
        dataAssetThreatIds.add(assetId);
      }
      businessIdToAssetId.set(businessId, assetId);
      this.registerNameAlias(nameRegistry, row.name, assetId);
      accepted.data_assets += 1;
    }

    const interfaceIdSet = new Set<string>();
    const interfaceRows: Array<CxfImportRequest["workbook"]["interface_assets"][number]> = [];

    // Register domain properties as Interface-type assets for edge linking
    const domainIdToAssetId = new Map<string, string>();
    for (const row of input.workbook.domain_properties) {
      const businessId = this.normalizeBusinessId(row.id);
      if (!this.ensureUniqueSheetId(interfaceIdSet, "domain_properties", row.excel_row, row.id, errors)) {
        continue;
      }

      const assetId = this.toInternalAssetId("IF", row.id);
      const candidate: AssetNode = {
        asset_id: assetId,
        asset_name: this.sanitizeAssetName(row.name, "Domain"),
        asset_type: "Interface",
        criticality: "Medium",
        security_domain: (row.security_domain === "Internal" || row.security_domain === "External" || row.security_domain === "DMZ" || row.security_domain === "Shared")
          ? row.security_domain : "Shared",
        description: this.buildDescription("Domain property", row.description),
        source: "excel_import",
        tags: ["domain_property"],
        business_id: businessId
      };
      if (!this.registerAsset(assets, candidate, errors, "domain_properties", row.excel_row)) {
        continue;
      }

      domainIdToAssetId.set(businessId, assetId);
      domainIdToAssetIdGlobal.set(businessId, assetId);
      businessIdToAssetId.set(businessId, assetId);
      this.registerNameAlias(nameRegistry, row.name, assetId);
      accepted.domain_properties += 1;
    }

    for (const row of input.workbook.interface_assets) {
      const businessId = this.normalizeBusinessId(row.id);
      if (!this.ensureUniqueSheetId(interfaceIdSet, "interface_assets", row.excel_row, row.id, errors)) {
        continue;
      }
      legacyImportedAssetIdsToDelete.add(this.toLegacyInternalAssetId("IF", row.id));

      const assetId = this.toInternalAssetId("IF", row.id);
      const candidate: AssetNode = {
        asset_id: assetId,
        asset_name: this.sanitizeAssetName(this.buildInterfaceAssetName(row), "Interface Asset"),
        asset_type: "Interface",
        criticality: "Medium",
        security_domain: "Shared",
        description: this.buildDescription(
          row.data_flow_type,
          row.data_flow_description,
          row.logical_interface,
          row.physical_interface,
          row.network_domain,
          row.zone,
          row.purpose,
          row.target_function ? `F:${row.target_function}` : undefined
        ),
        source: "excel_import",
        business_id: businessId,
        data_flow_type: row.data_flow_type ? row.data_flow_type.toUpperCase() : undefined,
        bdf_ids: row.bdf_ids && row.bdf_ids.length > 0 ? row.bdf_ids : undefined,
        enters_internal_propagation: row.enters_internal_propagation,
        boundary_interface_id: row.boundary_interface_id ? this.normalizeBusinessId(row.boundary_interface_id) : undefined
      };
      if (!this.registerAsset(assets, candidate, errors, "interface_assets", row.excel_row)) {
        continue;
      }

      interfaceRows.push(row);
      businessIdToAssetId.set(businessId, assetId);
      this.registerNameAlias(nameRegistry, row.id, assetId);
      interfaceAssetIds.add(assetId);
      this.collectFunctionLinks(assetId, row.target_function, functionNodes, functionLinks);
      if (row.boundary_id) {
        const boundaryKey = this.normalizeBusinessId(row.boundary_id);
        const set = interfaceAssetIdsByBoundary.get(boundaryKey) ?? new Set<string>();
        set.add(assetId);
        interfaceAssetIdsByBoundary.set(boundaryKey, set);
      }
      accepted.interface_assets += 1;
    }

    const boundaryInterfaces = this.buildBoundaryInterfaces(input.workbook.boundary_interfaces ?? []);
    const trustBoundaries = this.buildTrustBoundaries(
      input.workbook.trust_boundaries ?? [],
      interfaceAssetIdsByBoundary,
      domainIdToAssetIdGlobal
    );
    const threatActors = this.buildThreatActors(input.workbook.threat_actors ?? [], input.workbook.trust_boundaries ?? []);
    const systemDataFlows = this.buildSystemDataFlows(input.workbook.system_data_flows ?? [], functionNodes);

    for (const row of supportRows) {
      const supportAssetId = businessIdToAssetId.get(this.normalizeBusinessId(row.id));
      if (!supportAssetId) {
        continue;
      }

      for (const linkedInterface of row.linked_interfaces ?? []) {
        const interfaceAssetId = businessIdToAssetId.get(this.normalizeBusinessId(linkedInterface));
        if (!interfaceAssetId) {
          errors.push({
            type: "binding",
            sheet: "support_assets",
            row: row.excel_row,
            field: "linked_interfaces",
            message: `referenced interface does not exist: ${linkedInterface}`
          });
          continue;
        }

        this.registerEdge(
          edges,
          edgeSequenceByPair,
          {
            source_asset_id: supportAssetId,
            target_asset_id: interfaceAssetId,
            link_type: "Logical",
            protocol_or_medium: "LinkedInterface",
            direction: "Bidirectional",
            trust_level: "Untrusted",
            description: this.buildDescription(`${sheetLabels.support_assets} ${row.id}`, `交联接口 ${linkedInterface}`)
          },
          errors
        );
      }
    }

    for (const row of interfaceRows) {
      const interfaceAssetId = businessIdToAssetId.get(this.normalizeBusinessId(row.id));
      if (!interfaceAssetId) {
        continue;
      }

      const producerAssetIds = this.resolveEndpointAssetIds(
        row.producer,
        row.producer_ref,
        { sheet: "interface_assets", row: row.excel_row, nameField: "producer", refField: "producer_ref" },
        businessIdToAssetId,
        nameRegistry,
        assets,
        placeholderAssetIds,
        unresolvedEndpointNames,
        errors
      );
      const consumerAssetIds = this.resolveEndpointAssetIds(
        row.consumer,
        row.consumer_ref,
        { sheet: "interface_assets", row: row.excel_row, nameField: "consumer", refField: "consumer_ref" },
        businessIdToAssetId,
        nameRegistry,
        assets,
        placeholderAssetIds,
        unresolvedEndpointNames,
        errors
      );

      if (producerAssetIds.length === 0 || consumerAssetIds.length === 0) {
        continue;
      }

      const protocolOrMedium = this.truncate(
        this.firstNonEmpty(
          row.logical_interface,
          row.physical_interface,
          row.network_domain,
          row.data_flow_type,
          "DataFlow"
        ),
        64
      );
      const description = this.buildDescription(row.data_flow_description, row.purpose, row.zone);

      for (const producerAssetId of producerAssetIds) {
        this.registerEdge(
          edges,
          edgeSequenceByPair,
          {
            source_asset_id: producerAssetId,
            target_asset_id: interfaceAssetId,
            link_type: "DataFlow",
            protocol_or_medium: protocolOrMedium,
            direction: "Bidirectional",
            trust_level: this.resolveTrustLevel(assets.get(producerAssetId), assets.get(interfaceAssetId), row),
            security_mechanism: this.resolveSecurityMechanism(row),
            description
          },
          errors,
          "interface_assets",
          row.excel_row
        );
      }

      for (const consumerAssetId of consumerAssetIds) {
        this.registerEdge(
          edges,
          edgeSequenceByPair,
          {
            source_asset_id: interfaceAssetId,
            target_asset_id: consumerAssetId,
            link_type: "DataFlow",
            protocol_or_medium: protocolOrMedium,
            direction: "Bidirectional",
            trust_level: this.resolveTrustLevel(assets.get(interfaceAssetId), assets.get(consumerAssetId), row),
            security_mechanism: this.resolveSecurityMechanism(row),
            description
          },
          errors,
          "interface_assets",
          row.excel_row
        );
      }
    }

    if (hasAmsReferences) {
      this.registerMinimalSystemEdges(edges, edgeSequenceByPair, errors);
    }
    this.registerDataOwnershipEdges(registeredDataAssets, edges, edgeSequenceByPair, errors);
    this.registerDataAssetInterfaceEdges(registeredDataAssets, interfaceRows, nameRegistry, businessIdToAssetId, assets, placeholderAssetIds, unresolvedEndpointNames, edges, edgeSequenceByPair, errors);

    const threatTargets = this.resolveThreatTargets(interfaceAssetIds, placeholderAssetIds, assets, edges);
    for (const id of dataAssetThreatIds) {
      threatTargets.add(id);
    }
    const threatPoints: ThreatPoint[] = [];
    for (const assetId of Array.from(threatTargets).sort()) {
      const asset = assets.get(assetId);
      if (!asset) {
        continue;
      }

      for (const profile of this.resolveThreatProfiles(asset)) {
        const threat = this.buildThreatPoint(asset, profile.kind);
        const parsed = threatPointSchema.safeParse(threat);
        if (!parsed.success) {
          errors.push({
            type: "field",
            message: `failed to generate threat for ${asset.asset_id}: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`
          });
          continue;
        }

        threatPoints.push(parsed.data);
        summary.auto_generated_threats.push({
          threatpoint_id: parsed.data.threatpoint_id,
          related_asset_id: parsed.data.related_asset_id,
          asset_name: asset.asset_name,
          threat_kind: profile.kind,
          attack_vector: parsed.data.attack_vector,
          stride_category: parsed.data.stride_category
        });
      }
    }

    summary.asset_nodes_to_add = assets.size;
    summary.asset_edges_to_add = edges.size;
    summary.threat_points_to_add = threatPoints.length;
    summary.auto_placeholder_assets_to_add = placeholderAssetIds.size;
    if (accepted.functional_assets > 0) {
      summary.warnings.push(
        `Created ${functionNodes.size} FunctionNode(s) and ${functionLinks.length} SUPPORTS_FUNCTION link(s) from functional/target_function references.`
      );
    }
    if (unresolvedEndpointNames.size > 0) {
      const names = Array.from(unresolvedEndpointNames).sort().slice(0, 15).join(", ");
      const more = unresolvedEndpointNames.size > 15 ? ` …+${unresolvedEndpointNames.size - 15} more` : "";
      summary.warnings.push(
        `Auto-created ${placeholderAssetIds.size} placeholder asset(s) for unresolved endpoint name(s): ${names}${more}. Add these to 支持资产 sheet or use producer_ref/consumer_ref to suppress this warning.`
      );
    } else if (placeholderAssetIds.size > 0) {
      summary.warnings.push(`Auto-created ${placeholderAssetIds.size} placeholder assets for unresolved interface endpoints.`);
    }
    if (warningKeywords.some((keyword) => (input.source.file_name ?? "").includes(keyword))) {
      summary.warnings.push("Input file name appears to contain template notes; verify the uploaded workbook is the filled version.");
    }

    if (errors.length > 0 || !graphVersion) {
      return this.buildResult(accepted, summary, errors);
    }

    this.collectAutoThreatIdsToDelete(autoThreatIdsToDelete, assets.keys());
    this.collectAutoThreatIdsToDelete(autoThreatIdsToDelete, legacyImportedAssetIdsToDelete.values());

    const changeSetCandidate: GraphChangeSet = {
      graph_version: graphVersion,
      asset_nodes: {
        add: Array.from(assets.values()).sort((a, b) => a.asset_id.localeCompare(b.asset_id)),
        update: [],
        delete: Array.from(new Set([...functionalAssetIdsToDelete, ...legacyImportedAssetIdsToDelete])).sort()
      },
      asset_edges: { add: Array.from(edges.values()).sort((a, b) => a.edge_id.localeCompare(b.edge_id)), update: [], delete: [] },
      threat_points: {
        add: threatPoints.sort((a, b) => a.threatpoint_id.localeCompare(b.threatpoint_id)),
        update: [],
        delete: Array.from(autoThreatIdsToDelete).sort()
      },
      do326a_links: { add: [], update: [], delete: [] },
      function_nodes: {
        add: Array.from(functionNodes.values()).sort((a, b) => a.function_id.localeCompare(b.function_id)),
        update: [],
        delete: []
      },
      trust_boundaries: {
        add: trustBoundaries.sort((a, b) => a.boundary_id.localeCompare(b.boundary_id)),
        update: [],
        delete: []
      },
      threat_actors: {
        add: threatActors.sort((a, b) => a.actor_id.localeCompare(b.actor_id)),
        update: [],
        delete: []
      },
      boundary_interfaces: {
        add: boundaryInterfaces.sort((a, b) => a.interface_id.localeCompare(b.interface_id)),
        update: [],
        delete: []
      },
      system_data_flows: {
        add: systemDataFlows.sort((a, b) => a.sdf_id.localeCompare(b.sdf_id)),
        update: [],
        delete: []
      },
      function_links: functionLinks
    };

    const parsedChangeSet = graphChangeSetSchema.safeParse(changeSetCandidate);
    if (!parsedChangeSet.success) {
      const changeSetErrors = parsedChangeSet.error.issues.map((issue) => ({
        type: "field" as const,
        field: issue.path.join("."),
        message: issue.message
      }));
      return this.buildResult(accepted, summary, changeSetErrors);
    }

    return {
      ...this.buildResult(accepted, summary, []),
      change_set: parsedChangeSet.data
    };
  }

  private registerDerivedSystemAssets(
    assets: Map<string, AssetNode>,
    nameRegistry: NameRegistry,
    errors: CxfImportErrorDetail[]
  ): void {
    const derivedAssets: AssetNode[] = [
      {
        asset_id: coreAssetId,
        asset_name: "DO356A AMS Core",
        asset_type: "Terminal",
        criticality: "High",
        security_domain: "Internal",
        description: "Auto-generated AMS core asset for multi-sheet import",
        source: "auto_generated",
        tags: ["ams_related"]
      },
      {
        asset_id: tempControllerAssetId,
        asset_name: "AMS Temperature Controller",
        asset_type: "Terminal",
        criticality: "High",
        security_domain: "Internal",
        description: "Auto-generated AMS related controller asset",
        source: "auto_generated",
        tags: ["ams_related", "controller"]
      },
      {
        asset_id: pressControllerAssetId,
        asset_name: "AMS Pressurization Controller",
        asset_type: "Terminal",
        criticality: "High",
        security_domain: "Internal",
        description: "Auto-generated AMS related controller asset",
        source: "auto_generated",
        tags: ["ams_related", "controller"]
      }
    ];

    for (const asset of derivedAssets) {
      this.registerAsset(assets, asset, errors);
    }

    this.registerNameAlias(nameRegistry, "Air Management System Core", coreAssetId);
    this.registerNameAlias(nameRegistry, "AMS Core", coreAssetId);
    this.registerNameAlias(nameRegistry, "Temperature Controller", tempControllerAssetId);
    this.registerNameAlias(nameRegistry, "Temp Ctrl", tempControllerAssetId);
    this.registerNameAlias(nameRegistry, "温控器", tempControllerAssetId);
    this.registerNameAlias(nameRegistry, "温控器 SBC USB 接口", tempControllerAssetId);
    this.registerNameAlias(nameRegistry, "Pressurization Controller", pressControllerAssetId);
    this.registerNameAlias(nameRegistry, "Press Ctrl", pressControllerAssetId);
    this.registerNameAlias(nameRegistry, "增压控制器", pressControllerAssetId);
  }

  private registerMinimalSystemEdges(
    edges: Map<string, AssetEdge>,
    edgeSequenceByPair: Map<string, number>,
    errors: CxfImportErrorDetail[]
  ): void {
    const minimalEdges: EdgeDraft[] = [
      {
        source_asset_id: coreAssetId,
        target_asset_id: tempControllerAssetId,
        link_type: "Logical",
        protocol_or_medium: "InternalControl",
        direction: "Bidirectional",
        trust_level: "Trusted",
        description: "Minimal AMS internal connectivity"
      },
      {
        source_asset_id: coreAssetId,
        target_asset_id: pressControllerAssetId,
        link_type: "Logical",
        protocol_or_medium: "InternalControl",
        direction: "Bidirectional",
        trust_level: "Trusted",
        description: "Minimal AMS internal connectivity"
      },
      {
        source_asset_id: tempControllerAssetId,
        target_asset_id: pressControllerAssetId,
        link_type: "Logical",
        protocol_or_medium: "ControllerSync",
        direction: "Bidirectional",
        trust_level: "Trusted",
        description: "Minimal controller-to-controller connectivity"
      }
    ];

    for (const edge of minimalEdges) {
      this.registerEdge(edges, edgeSequenceByPair, edge, errors);
    }
  }

  /** Canonical function id: extract F-number (F1..Fn) from a raw id/token; else normalized alphanumerics. */
  private normalizeFunctionId(raw: string | undefined): string | undefined {
    if (!raw) return undefined;
    const upper = raw.trim().toUpperCase();
    const match = upper.match(/F\d+/);
    if (match) return match[0];
    const normalized = upper.replace(/[^A-Z0-9]/g, "");
    return normalized.length > 0 ? normalized : undefined;
  }

  /** Parse comma/space-separated target_function tokens into SUPPORTS_FUNCTION links, auto-creating missing FunctionNodes. */
  private collectFunctionLinks(
    assetId: string,
    rawTargetFunction: string | undefined,
    functionNodes: Map<string, FunctionNode>,
    functionLinks: FunctionLink[]
  ): void {
    if (!rawTargetFunction) return;
    const tokens = rawTargetFunction
      .split(/[,，;；\s]+/)
      .map((token) => this.normalizeFunctionId(token))
      .filter((token): token is string => Boolean(token));
    for (const functionId of new Set(tokens)) {
      if (!functionNodes.has(functionId)) {
        functionNodes.set(functionId, { function_id: functionId, name: functionId });
      }
      functionLinks.push({ asset_id: assetId, function_id: functionId });
    }
  }

  private splitRefs(raw: string | undefined): string[] {
    if (!raw) return [];
    return raw
      .split(/[,，;；\s]+/)
      .map((token) => token.trim())
      .filter((token) => token.length > 0);
  }

  private buildBoundaryInterfaces(
    rows: CxfImportRequest["workbook"]["boundary_interfaces"]
  ): BoundaryInterface[] {
    const interfaces: BoundaryInterface[] = [];
    const seen = new Set<string>();
    for (const row of rows ?? []) {
      const interfaceId = this.normalizeBusinessId(row.id);
      if (!interfaceId || seen.has(interfaceId)) continue;
      seen.add(interfaceId);
      interfaces.push({
        interface_id: interfaceId,
        name: row.name,
        interface_class: row.interface_class,
        external_entity: row.external_entity,
        access_object: row.access_object,
        physical_interconnect: row.physical_interconnect,
        logical_protocol: row.logical_protocol,
        direction: row.direction,
        boundary_id: row.boundary_id ? this.normalizeBusinessId(row.boundary_id) : undefined,
        description: row.description
      });
    }
    return interfaces;
  }

  private buildTrustBoundaries(
    rows: CxfImportRequest["workbook"]["trust_boundaries"],
    interfaceAssetIdsByBoundary: Map<string, Set<string>>,
    domainIdToAssetId: Map<string, string>
  ): TrustBoundary[] {
    const boundaries: TrustBoundary[] = [];
    const seen = new Set<string>();
    for (const row of rows ?? []) {
      const boundaryId = this.normalizeBusinessId(row.id);
      if (!boundaryId || seen.has(boundaryId)) continue;
      seen.add(boundaryId);

      const interfaceAssetIds = Array.from(interfaceAssetIdsByBoundary.get(boundaryId) ?? []).sort();
      const domainAssetIds = (row.covered_domain_ids ?? [])
        .map((id) => domainIdToAssetId.get(this.normalizeBusinessId(id)))
        .filter((id): id is string => Boolean(id));

      boundaries.push({
        boundary_id: boundaryId,
        name: this.sanitizeAssetName(row.name, "Trust Boundary"),
        description: row.description,
        enters_internal_propagation: row.enters_internal_propagation,
        interface_asset_ids: interfaceAssetIds,
        domain_asset_ids: Array.from(new Set(domainAssetIds)).sort()
      });
    }
    return boundaries;
  }

  private buildThreatActors(
    actorRows: CxfImportRequest["workbook"]["threat_actors"],
    boundaryRows: CxfImportRequest["workbook"]["trust_boundaries"]
  ): ThreatActor[] {
    // Reverse-map TA -> boundaries from each boundary row's threat_actor_ids list.
    const boundaryIdsByActor = new Map<string, Set<string>>();
    for (const boundary of boundaryRows ?? []) {
      const boundaryId = this.normalizeBusinessId(boundary.id);
      for (const actorRef of boundary.threat_actor_ids ?? []) {
        const actorKey = this.normalizeBusinessId(actorRef);
        const set = boundaryIdsByActor.get(actorKey) ?? new Set<string>();
        set.add(boundaryId);
        boundaryIdsByActor.set(actorKey, set);
      }
    }

    const actors: ThreatActor[] = [];
    const seen = new Set<string>();
    for (const row of actorRows ?? []) {
      const actorId = this.normalizeBusinessId(row.id);
      if (!actorId || seen.has(actorId)) continue;
      seen.add(actorId);
      actors.push({
        actor_id: actorId,
        name: this.sanitizeAssetName(row.name, "Threat Actor"),
        actor_type: this.resolveThreatActorType(row.actor_type, actorId),
        description: row.description,
        boundary_ids: Array.from(boundaryIdsByActor.get(actorId) ?? []).sort()
      });
    }
    return actors;
  }

  private buildSystemDataFlows(
    rows: CxfImportRequest["workbook"]["system_data_flows"],
    functionNodes: Map<string, FunctionNode>
  ): SystemDataFlow[] {
    const flows: SystemDataFlow[] = [];
    const seen = new Set<string>();
    for (const row of rows ?? []) {
      const sdfId = this.normalizeBusinessId(row.id);
      if (!sdfId || seen.has(sdfId)) continue;
      seen.add(sdfId);
      const functionIds = Array.from(
        new Set(
          this.splitRefs(row.target_function)
            .map((token) => this.normalizeFunctionId(token))
            .filter((token): token is string => Boolean(token))
        )
      );
      for (const functionId of functionIds) {
        if (!functionNodes.has(functionId)) {
          functionNodes.set(functionId, { function_id: functionId, name: functionId });
        }
      }
      flows.push({
        sdf_id: sdfId,
        producer: row.producer,
        consumer: row.consumer,
        content: row.content,
        data_flow_type: row.data_flow_type ? row.data_flow_type.trim().toUpperCase() : undefined,
        function_ids: functionIds
      });
    }
    return flows;
  }

  private resolveThreatActorType(raw: string | undefined, actorId: string): ThreatActorType {
    const value = (raw ?? "").toLowerCase();
    if (value.includes("外部") || value.includes("external") || /TA-?E/i.test(actorId)) return "external";
    if (value.includes("内部") || value.includes("internal") || /TA-?I/i.test(actorId)) return "internal";
    if (value.includes("第三") || value.includes("third") || value.includes("供应")) return "third-party";
    return "external";
  }

  private registerDataOwnershipEdges(
    dataAssets: RegisteredDataAsset[],
    edges: Map<string, AssetEdge>,
    edgeSequenceByPair: Map<string, number>,
    errors: CxfImportErrorDetail[]
  ): void {
    for (const dataAsset of dataAssets) {
      const owners = this.resolveDataOwnerAssetIds(dataAsset.row);
      for (const ownerAssetId of owners) {
        this.registerEdge(
          edges,
          edgeSequenceByPair,
          {
            source_asset_id: ownerAssetId,
            target_asset_id: dataAsset.asset_id,
            link_type: "DataFlow",
            protocol_or_medium: this.truncate(this.firstNonEmpty(dataAsset.row.data_type, "AssetStorage"), 64),
            direction: "Bidirectional",
            trust_level: "Trusted",
            description: this.buildDescription("Derived data ownership", dataAsset.row.name, dataAsset.row.load_description)
          },
          errors
        );
      }
    }
  }

  private parseLinkedInterfaces(raw: string | undefined): string[] {
    if (!raw) return [];
    return raw
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter((s) => /^(SI|BI|SD|ACD|BD|SSD|ACI)\.?[A-Z0-9]+$/i.test(s));
  }

  private registerDataAssetInterfaceEdges(
    dataAssets: RegisteredDataAsset[],
    interfaceRows: CxfImportRequest["workbook"]["interface_assets"][number][],
    nameRegistry: NameRegistry,
    businessIdToAssetId: Map<string, string>,
    assets: Map<string, AssetNode>,
    placeholderAssetIds: Set<string>,
    unresolvedEndpointNames: Set<string>,
    edges: Map<string, AssetEdge>,
    edgeSequenceByPair: Map<string, number>,
    errors: CxfImportErrorDetail[]
  ): void {
    // Build map: SI.normalizedId → interfaceRow
    const interfaceRowMap = new Map<string, CxfImportRequest["workbook"]["interface_assets"][number]>();
    for (const row of interfaceRows) {
      interfaceRowMap.set(this.normalizeBusinessId(row.id), row);
    }

    for (const dataAsset of dataAssets) {
      if (dataAsset.linked_interface_ids.length === 0) {
        continue;
      }

      for (const ifaceId of dataAsset.linked_interface_ids) {
        const interfaceRow = interfaceRowMap.get(this.normalizeBusinessId(ifaceId));
        if (!interfaceRow) {
          errors.push({
            type: "binding",
            sheet: "data_assets",
            field: "linked_interfaces",
            message: `data asset ${dataAsset.asset_id} references non-existent interface: ${ifaceId}`
          });
          continue;
        }

        const interfaceAssetId = businessIdToAssetId.get(this.normalizeBusinessId(ifaceId));
        if (!interfaceAssetId) {
          continue;
        }

        // Producer → data asset: connect producer to the data traveling over this interface
        const producerIds = this.resolveEndpointAssetIds(
          interfaceRow.producer,
          interfaceRow.producer_ref,
          { sheet: "data_assets", nameField: "producer", refField: "producer_ref" },
          businessIdToAssetId,
          nameRegistry,
          assets,
          placeholderAssetIds,
          unresolvedEndpointNames,
          errors
        );
        for (const producerId of producerIds) {
          this.registerEdge(
            edges,
            edgeSequenceByPair,
            {
              source_asset_id: producerId,
              target_asset_id: dataAsset.asset_id,
              link_type: "DataFlow",
              protocol_or_medium: this.truncate(this.firstNonEmpty(dataAsset.row.data_flow_type, dataAsset.row.data_type, "AssetData"), 64),
              direction: "Bidirectional",
              trust_level: "Trusted",
              description: this.buildDescription("Data via", ifaceId, dataAsset.row.name)
            },
            errors
          );
        }

        // Data asset → consumer: connect data asset to the consumer
        const consumerIds = this.resolveEndpointAssetIds(
          interfaceRow.consumer,
          interfaceRow.consumer_ref,
          { sheet: "data_assets", nameField: "consumer", refField: "consumer_ref" },
          businessIdToAssetId,
          nameRegistry,
          assets,
          placeholderAssetIds,
          unresolvedEndpointNames,
          errors
        );
        for (const consumerId of consumerIds) {
          this.registerEdge(
            edges,
            edgeSequenceByPair,
            {
              source_asset_id: dataAsset.asset_id,
              target_asset_id: consumerId,
              link_type: "DataFlow",
              protocol_or_medium: this.truncate(this.firstNonEmpty(dataAsset.row.data_flow_type, dataAsset.row.data_type, "AssetData"), 64),
              direction: "Bidirectional",
              trust_level: "Trusted",
              description: this.buildDescription("Data via", ifaceId, dataAsset.row.name)
            },
            errors
          );
        }
      }
    }
  }

  private resolveDataOwnerAssetIds(row: CxfImportRequest["workbook"]["data_assets"][number]): Set<string> {
    const owners = new Set<string>();
    const text = `${row.id} ${row.name} ${row.data_type ?? ""} ${row.load_description ?? ""} ${row.description ?? ""}`.toLowerCase();

    if (/ia\.1|ia\.2|ia\.3|ia\.5|ia\.5a|ia\.5b|ia\.5c|ia\.6|ia\.7/.test(text)) {
      owners.add(tempControllerAssetId);
      owners.add(pressControllerAssetId);
    }
    if (/温控|temperature|tempctrl|temp ctrl/.test(text)) {
      owners.add(tempControllerAssetId);
    }
    if (/增压|pressurization|pressctrl|press ctrl/.test(text)) {
      owners.add(pressControllerAssetId);
    }
    if (/ams lru|ams controller|ams 控制器|各 ams lru|各 ams 控制器|两个 ams 控制器|温控器\/增压控制器/.test(text)) {
      owners.add(tempControllerAssetId);
      owners.add(pressControllerAssetId);
    }

    return owners;
  }

  private resolveThreatTargets(
    interfaceAssetIds: Set<string>,
    placeholderAssetIds: Set<string>,
    assets: Map<string, AssetNode>,
    edges: Map<string, AssetEdge>
  ): Set<string> {
    const threatTargets = new Set<string>(interfaceAssetIds);

    for (const edge of edges.values()) {
      const pairs: Array<[string, string]> = [
        [edge.source_asset_id, edge.target_asset_id],
        [edge.target_asset_id, edge.source_asset_id]
      ];
      for (const [assetId, counterpartId] of pairs) {
        if (!interfaceAssetIds.has(assetId)) {
          continue;
        }
        const counterpart = assets.get(counterpartId);
        if (!counterpart) {
          continue;
        }
        if (placeholderAssetIds.has(counterpartId) || counterpart.security_domain === "External" || counterpart.security_domain === "Shared") {
          threatTargets.add(counterpartId);
        }
      }
    }

    return threatTargets;
  }

  private extractDataFlowType(normalizedText: string): string | undefined {
    const match = normalizedText.match(/^(cmd|config|load|state|alert|data)\s*\|/);
    return match?.[1];
  }

  private resolveThreatProfiles(asset: AssetNode): Array<(typeof autoThreatProfiles)[number]> {
    const text = `${asset.asset_name} ${asset.description ?? ""}`.toLowerCase();
    const flowType = this.extractDataFlowType(text);

    if (flowType) {
      switch (flowType) {
        case "load":
        case "config":
        case "alert":
        case "data":
          return autoThreatProfiles.filter((p) => p.kind === "integrity");
        case "state":
          return autoThreatProfiles.filter((p) => p.kind !== "control_misuse");
        case "cmd":
          return autoThreatProfiles;
      }
    }

    return autoThreatProfiles.filter((profile) => {
      if (profile.kind !== "control_misuse") {
        return true;
      }
      return asset.asset_type === "Interface" || /control|command|controller|维护|gse|usb|arinc|can|命令|控制/.test(text);
    });
  }

  private buildThreatPoint(asset: AssetNode, threatKind: ThreatKind): ThreatPoint {
    const profile = autoThreatProfiles.find((item) => item.kind === threatKind)!;
    const threatText = `${asset.asset_name} ${asset.description ?? ""}`;
    return {
      threatpoint_id: `TP-${asset.asset_id}-AUTO-${profile.idSuffix}-01`,
      name: this.truncate(`AUTO ${asset.asset_name} ${profile.nameSuffix}`, 64) ?? `AUTO ${asset.asset_id} threat`,
      related_asset_id: asset.asset_id,
      stride_category: this.resolveThreatStrideCategory(threatKind, threatText),
      attack_vector: this.resolveAttackVector(threatText),
      entry_likelihood_level: this.resolveEntryLikelihood(asset, threatText),
      attack_complexity_level: this.resolveAttackComplexity(asset, threatText),
      threat_source: "external",
      preconditions: this.truncate(`Auto-generated ${threatKind} threat for ${asset.asset_name}`, 200)
    };
  }

  private createAcceptedSummary(): AcceptedSummary {
    return {
      functional_assets: 0,
      interface_assets: 0,
      support_assets: 0,
      data_assets: 0,
      domain_properties: 0
    };
  }

  private createSummary(): CxfImportSummary {
    return {
      asset_nodes_to_add: 0,
      asset_edges_to_add: 0,
      threat_points_to_add: 0,
      auto_placeholder_assets_to_add: 0,
      warnings: [],
      auto_generated_threats: []
    };
  }

  private buildResult(
    accepted: AcceptedSummary,
    summary: CxfImportSummary,
    errorDetails: CxfImportErrorDetail[]
  ): CxfImportPreviewResult {
    return {
      ok: errorDetails.length === 0,
      accepted,
      errors: errorDetails.map((detail) => this.toErrorMessage(detail)),
      error_details: errorDetails,
      summary
    };
  }

  private ensureUniqueSheetId(
    seen: Set<string>,
    sheet: CxfSheetName,
    row: number | undefined,
    rawId: string,
    errors: CxfImportErrorDetail[]
  ): boolean {
    const normalizedId = this.normalizeBusinessId(rawId);
    if (seen.has(normalizedId)) {
      errors.push({
        type: "field",
        sheet,
        row,
        field: "id",
        message: `duplicate id in ${sheetLabels[sheet]}: ${rawId}`
      });
      return false;
    }

    seen.add(normalizedId);
    return true;
  }

  private registerAsset(
    assets: Map<string, AssetNode>,
    candidate: AssetNode,
    errors: CxfImportErrorDetail[],
    sheet?: CxfSheetName,
    row?: number
  ): boolean {
    const parsed = assetNodeSchema.safeParse(candidate);
    if (!parsed.success) {
      errors.push({
        type: "field",
        sheet,
        row,
        message: `invalid asset ${candidate.asset_id}: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`
      });
      return false;
    }

    assets.set(parsed.data.asset_id, parsed.data);
    return true;
  }

  private registerEdge(
    edges: Map<string, AssetEdge>,
    edgeSequenceByPair: Map<string, number>,
    draft: EdgeDraft,
    errors: CxfImportErrorDetail[],
    sheet?: CxfSheetName,
    row?: number
  ): void {
    const normalized = this.normalizeBidirectionalDraft(draft);
    const dedupeKey = [
      normalized.source_asset_id,
      normalized.target_asset_id,
      normalized.link_type,
      normalized.direction,
      normalized.protocol_or_medium ?? "",
      normalized.trust_level ?? "",
      normalized.security_mechanism ?? ""
    ].join("|");
    if (edges.has(dedupeKey)) {
      return;
    }

    const pairKey = `${normalized.source_asset_id}|${normalized.target_asset_id}`;
    const nextIndex = (edgeSequenceByPair.get(pairKey) ?? 0) + 1;
    edgeSequenceByPair.set(pairKey, nextIndex);

    const candidate: AssetEdge = {
      edge_id: `E-${normalized.source_asset_id}-${normalized.target_asset_id}-${String(nextIndex).padStart(2, "0")}`,
      source_asset_id: normalized.source_asset_id,
      target_asset_id: normalized.target_asset_id,
      link_type: normalized.link_type,
      protocol_or_medium: this.truncate(normalized.protocol_or_medium, 64),
      direction: normalized.direction,
      trust_level: normalized.trust_level,
      security_mechanism: this.truncate(normalized.security_mechanism, 64),
      description: this.truncate(normalized.description, 200)
    };

    const parsed = assetEdgeSchema.safeParse(candidate);
    if (!parsed.success) {
      errors.push({
        type: "field",
        sheet,
        row,
        message: `invalid edge ${candidate.edge_id}: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`
      });
      return;
    }

    edges.set(dedupeKey, parsed.data);
  }

  private normalizeBidirectionalDraft(draft: EdgeDraft): EdgeDraft {
    if (draft.direction !== "Bidirectional") {
      return draft;
    }

    if (draft.source_asset_id.localeCompare(draft.target_asset_id) <= 0) {
      return draft;
    }

    return {
      ...draft,
      source_asset_id: draft.target_asset_id,
      target_asset_id: draft.source_asset_id
    };
  }

  private resolveEndpointAssetIds(
    rawName: string,
    rawRef: string | undefined,
    context: EndpointResolutionContext,
    businessIdToAssetId: Map<string, string>,
    nameRegistry: NameRegistry,
    assets: Map<string, AssetNode>,
    placeholderAssetIds: Set<string>,
    unresolvedEndpointNames: Set<string>,
    errors: CxfImportErrorDetail[]
  ): string[] {
    if (rawRef) {
      const referencedAssetId = businessIdToAssetId.get(this.normalizeBusinessId(rawRef));
      if (!referencedAssetId) {
        errors.push({
          type: "binding",
          sheet: context.sheet,
          row: context.row,
          field: context.refField,
          message: `referenced asset does not exist: ${rawRef}`
        });
        return [];
      }
      return [referencedAssetId];
    }

    const businessIdMatch = businessIdToAssetId.get(this.normalizeBusinessId(rawName));
    if (businessIdMatch) {
      return [businessIdMatch];
    }

    const compoundIds = this.resolveCompoundAmsAlias(rawName);
    if (compoundIds.length > 0) {
      return compoundIds;
    }

    const genericSystemEndpointIds = this.resolveGenericAmsEndpointAlias(rawName);
    if (genericSystemEndpointIds.length > 0) {
      return genericSystemEndpointIds;
    }

    const amsSpecificAssetId = this.resolveSpecificAmsAlias(rawName);
    if (amsSpecificAssetId) {
      return [amsSpecificAssetId];
    }

    const normalizedName = this.normalizeName(rawName);
    const matchingAssetIds = nameRegistry.get(normalizedName);
    if (matchingAssetIds?.size === 1) {
      return [Array.from(matchingAssetIds)[0]];
    }
    if ((matchingAssetIds?.size ?? 0) > 1) {
      errors.push({
        type: "binding",
        sheet: context.sheet,
        row: context.row,
        field: context.nameField,
        message: `ambiguous normalized name match for ${rawName}; add ${context.refField}`
      });
      return [];
    }

    // Always auto-create a placeholder; no hard error for unresolved names.
    // The caller collects these in unresolvedEndpointNames for the summary warning.
    const placeholder = this.createPlaceholderAsset(rawName);
    if (!assets.has(placeholder.asset_id)) {
      this.registerAsset(assets, placeholder, errors, context.sheet, context.row);
      placeholderAssetIds.add(placeholder.asset_id);
      this.registerNameAlias(nameRegistry, rawName, placeholder.asset_id);
      unresolvedEndpointNames.add(rawName);
    }
    return [placeholder.asset_id];
  }

  private scanInputForAmsReferences(input: CxfImportRequest): boolean {
    const amsPattern = /温控器|增压控制器|temperature\s*controller|pressurization\s*controller|temp\s*ctrl|press\s*ctrl|ams\s*core|air\s*management\s*system/i;
    for (const row of input.workbook.interface_assets) {
      if (amsPattern.test(row.producer) || amsPattern.test(row.consumer) || amsPattern.test(row.data_flow_description ?? "")) {
        return true;
      }
    }
    for (const row of input.workbook.data_assets) {
      if (amsPattern.test(row.name) || amsPattern.test(row.description ?? "") || amsPattern.test(row.load_description ?? "")) {
        return true;
      }
    }
    return false;
  }

  private createPlaceholderAsset(rawName: string): AssetNode {
    const normalized = this.normalizeName(rawName);
    const digest = crypto.createHash("sha1").update(normalized).digest("hex").slice(0, 6).toUpperCase();
    const isExternal = this.isAllowedExternalPlaceholder(rawName);
    return {
      asset_id: `EXT-PL-${digest}`,
      asset_name: this.sanitizeAssetName(rawName, "Placeholder"),
      asset_type: "Terminal",
      criticality: "Medium",
      security_domain: isExternal ? "External" : "Shared",
      description: "Auto-created placeholder asset from unresolved interface endpoint",
      is_placeholder: true,
      source: "auto_generated",
      tags: ["placeholder", "auto_generated"]
    };
  }

  private resolveDomainSecurityDomain(domainId: string | undefined): AssetNode["security_domain"] {
    if (!domainId) return "Internal";
    const id = domainId.toUpperCase().replace(/[\s.]/g, "");
    if (id === "D1" || id === "D2") return "External";
    if (id === "D3" || id === "D6") return "Shared";
    return "Internal";
  }

  private resolveCompoundAmsAlias(rawName: string): string[] {
    const normalized = this.normalizeName(rawName);
    const hasTemp = this.isTempControllerAlias(rawName);
    const hasPress = this.isPressControllerAlias(rawName);
    if (hasTemp && hasPress) {
      return [tempControllerAssetId, pressControllerAssetId];
    }
    if (normalized.includes("ams") && normalized.includes("控制器")) {
      return [tempControllerAssetId, pressControllerAssetId];
    }
    return [];
  }

  private resolveGenericAmsEndpointAlias(rawName: string): string[] {
    const normalized = this.normalizeName(rawName);
    if (normalized === "ams" || normalized === "airmanagementsystem") {
      return [tempControllerAssetId, pressControllerAssetId];
    }
    return [];
  }

  private resolveSpecificAmsAlias(rawName: string): string | undefined {
    if (this.isTempControllerAlias(rawName)) {
      return tempControllerAssetId;
    }
    if (this.isPressControllerAlias(rawName)) {
      return pressControllerAssetId;
    }
    if (this.isCoreAlias(rawName)) {
      return coreAssetId;
    }
    return undefined;
  }

  private resolveDataClassification(value: string): AssetNode["data_classification"] {
    const normalized = value.toLowerCase();
    if (/密钥|证书|firmware|固件|software|软件|crypt|key|certificate/.test(normalized)) {
      return "Sensitive";
    }
    if (/日志|监控|health|logging|log/.test(normalized)) {
      return "Internal";
    }
    return "Internal";
  }

  private buildInterfaceAssetName(row: CxfImportRequest["workbook"]["interface_assets"][number]): string {
    return [row.producer, row.consumer, row.purpose].filter((value): value is string => Boolean(value && value.trim().length > 0)).join(" ");
  }

  private resolveTrustLevel(
    source: AssetNode | undefined,
    target: AssetNode | undefined,
    row: CxfImportRequest["workbook"]["interface_assets"][number]
  ): AssetEdge["trust_level"] {
    const text = `${row.producer} ${row.consumer} ${row.logical_interface ?? ""} ${row.physical_interface ?? ""} ${row.network_domain ?? ""} ${
      row.purpose ?? ""
    }`.toLowerCase();

    if (/arinc|航电|引气/.test(text)) {
      return "Trusted";
    }
    if (/制造商|manufacturer|tls|vpn|secure/.test(text)) {
      return "Semi-Trusted";
    }
    if (/gse|维护|usb|wireless|wifi|航空公司|network|802\.11|外部/.test(text)) {
      return "Untrusted";
    }
    if (source?.security_domain === "External" || target?.security_domain === "External") {
      return "Untrusted";
    }
    if (source?.security_domain === "Shared" || target?.security_domain === "Shared") {
      return "Semi-Trusted";
    }
    return "Trusted";
  }

  private resolveSecurityMechanism(row: CxfImportRequest["workbook"]["interface_assets"][number]): string | undefined {
    const text = `${row.data_flow_description ?? ""} ${row.logical_interface ?? ""} ${row.physical_interface ?? ""}`;
    if (/tls|vpn|https/i.test(text)) {
      return "TLS";
    }
    if (/arinc\s*664/i.test(text)) {
      return "ARINC664";
    }
    return undefined;
  }

  private resolveAttackVector(value: string): ThreatPoint["attack_vector"] {
    const normalized = value.toLowerCase();
    if (/usb/.test(normalized)) {
      return "Physical";
    }
    if (/can|gse|维护/.test(normalized)) {
      return "Maintenance";
    }
    if (/无线|wi-?fi|802\.11|wireless/.test(normalized)) {
      return "Wireless";
    }
    return "Network";
  }

  private resolveThreatStrideCategory(threatKind: ThreatKind, value: string): ThreatPoint["stride_category"] {
    const normalized = value.toLowerCase();

    // Data flow type-driven mapping (stored as first token in description)
    const flowType = this.extractDataFlowType(normalized);
    if (flowType) {
      switch (flowType) {
        case "load":
          return "Tampering"; // Malicious software load
        case "config":
          return "Tampering"; // Malicious configuration/parameter tampering
        case "cmd":
          return threatKind === "ingress" ? "Spoofing" : "Tampering";
        case "state":
          return "Spoofing"; // State data forgery
        case "alert":
          return threatKind === "integrity" ? "DenialOfService" : "Tampering";
        case "data":
          return threatKind === "integrity" ? "InformationDisclosure" : "Tampering";
      }
    }

    // Fallback: keyword-based mapping
    if (/auth|certificate|cert|credential|identity|spoof|认证|证书|凭据|身份|伪装/.test(normalized)) {
      return "Spoofing";
    }
    if (threatKind === "control_misuse" || /control|command|controller|控制|命令/.test(normalized)) {
      return "ElevationOfPrivilege";
    }
    if (threatKind === "integrity" && /log|logging|monitor|health|leak|disclosure|日志|监控|健康|泄露/.test(normalized)) {
      return "InformationDisclosure";
    }
    return "Tampering";
  }

  private resolveEntryLikelihood(asset: AssetNode, value: string): ThreatPoint["entry_likelihood_level"] {
    const normalized = value.toLowerCase();
    if (asset.security_domain === "External" || /维护|wireless|wifi|802\.11|usb|gse|network|外部|航空公司/.test(normalized)) {
      return "High";
    }
    return "Medium";
  }

  private resolveAttackComplexity(asset: AssetNode, value: string): ThreatPoint["attack_complexity_level"] {
    const normalized = value.toLowerCase();
    if (/usb|can|gse|维护/.test(normalized)) {
      return "Low";
    }
    if (/arinc|trusted|航电/.test(normalized) && asset.security_domain === "Shared") {
      return "High";
    }
    return "Medium";
  }

  private isAllowedExternalPlaceholder(value: string): boolean {
    const normalized = this.normalizeName(value);
    return /gse|network|server|switch|router|bridge|usb|wireless|wifi|manufacturer|airline|ground|航电|引气|维护|航空公司|制造商|地面|设备|系统|gcu|acu|ccu|rtk|遥控站|转发服务器|综合管理计算机|综合控制计算机|大数据平台|调试计算机|电动发动机|电池管理|综管|飞控|飞管|激活装置|弹射桶|伞降ecu|高压配电盒|高压bms|配电盒|bms|感知避障/.test(
      normalized
    );
  }

  private isCoreAlias(value: string): boolean {
    const normalized = this.normalizeName(value);
    return /amscore|airmanagementsystemcore/.test(normalized);
  }

  private isTempControllerAlias(value: string): boolean {
    const normalized = this.normalizeName(value);
    return /tempctrl|temperaturecontroller|温控器|sbcusb接口/.test(normalized);
  }

  private isPressControllerAlias(value: string): boolean {
    const normalized = this.normalizeName(value);
    return /pressctrl|pressurizationcontroller|增压控制器/.test(normalized);
  }

  private normalizeBusinessId(value: string): string {
    return value.trim().toUpperCase();
  }

  private toInternalAssetId(prefix: AssetPrefix, rawId: string): string {
    const normalizedId = rawId.trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
    const digest = crypto.createHash("sha1").update(this.normalizeBusinessId(rawId)).digest("hex").slice(0, 4).toUpperCase();
    return `${prefix}-${normalizedId}-${digest}`;
  }

  private toLegacyInternalAssetId(prefix: AssetPrefix, rawId: string): string {
    const normalizedId = rawId.trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
    return `${prefix}-${normalizedId}`;
  }

  private collectAutoThreatIdsToDelete(target: Set<string>, assetIds: Iterable<string>): void {
    for (const assetId of assetIds) {
      target.add(`TP-${assetId}-AUTO-01`);
      for (const profile of autoThreatProfiles) {
        target.add(`TP-${assetId}-AUTO-${profile.idSuffix}-01`);
      }
    }
  }

  private registerNameAlias(nameRegistry: NameRegistry, rawName: string, assetId: string): void {
    const normalized = this.normalizeName(rawName);
    if (!normalized) {
      return;
    }
    const current = nameRegistry.get(normalized) ?? new Set<string>();
    current.add(assetId);
    nameRegistry.set(normalized, current);
  }

  private normalizeName(value: string): string {
    return value
      .trim()
      .toLowerCase()
      .replace(/（[^）]*）/g, "")
      .replace(/\([^)]*\)/g, "")
      .replace(/[、，,；;:：'"`~!@#$%^&*+=?<>[\]{}|\\/_\-\s]+/g, "")
      .replace(/\./g, "");
  }

  private sanitizeAssetName(value: string, fallback: string): string {
    const sanitized = value
      .replace(/（/g, " ")
      .replace(/）/g, " ")
      .replace(/[()]/g, " ")
      .replace(/[、，,；;:："'`~!@#$%^&*+=?<>[\]{}|\\]/g, " ")
      .replace(/\./g, " ")
      .replace(/\s+/g, " ")
      .trim();
    const collapsed = sanitized.length > 0 ? sanitized : fallback;
    const safeName = collapsed.replace(/[^A-Za-z0-9\u4e00-\u9fa5\s\-_\/]/g, " ").replace(/\s+/g, " ").trim();
    const candidate = safeName.length >= 2 ? safeName : fallback;
    const firstCharOk = /^[A-Za-z\u4e00-\u9fa5]/.test(candidate) ? candidate : `A ${candidate}`;
    return this.truncate(firstCharOk, 48) ?? fallback;
  }

  private buildDescription(...values: Array<string | undefined>): string | undefined {
    const description = values
      .map((value) => value?.trim())
      .filter((value): value is string => Boolean(value))
      .join(" | ");
    return this.truncate(description, 200);
  }

  private truncate(value: string | undefined, maxLength: number): string | undefined {
    if (!value) {
      return undefined;
    }
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      return undefined;
    }
    return trimmed.length > maxLength ? trimmed.slice(0, maxLength) : trimmed;
  }

  private firstNonEmpty(...values: Array<string | undefined>): string | undefined {
    return values.find((value) => typeof value === "string" && value.trim().length > 0)?.trim();
  }

  private toErrorMessage(detail: CxfImportErrorDetail): string {
    const prefix: string[] = [detail.type];
    if (detail.sheet) {
      prefix.push(detail.sheet);
    }
    if (detail.row) {
      prefix.push(`row ${detail.row}`);
    }
    if (detail.field) {
      prefix.push(detail.field);
    }
    return `${prefix.join(" / ")}: ${detail.message}`;
  }
}
