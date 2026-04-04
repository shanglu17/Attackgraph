import crypto from "node:crypto";
import {
  assetEdgeSchema,
  assetNodeSchema,
  graphChangeSetSchema,
  threatPointSchema,
  type CxfImportRequest
} from "../types/api.js";
import type { AssetEdge, AssetNode, GraphChangeSet, ThreatPoint } from "../types/domain.js";

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
  interface_assets: "接口资产",
  support_assets: "支持资产",
  data_assets: "数据资产"
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
    const placeholderAssetIds = new Set<string>();
    const edgeSequenceByPair = new Map<string, number>();
    const registeredDataAssets: RegisteredDataAsset[] = [];
    const functionalAssetIdsToDelete = new Set<string>();
    const legacyImportedAssetIdsToDelete = new Set<string>();
    const autoThreatIdsToDelete = new Set<string>();

    this.registerDerivedSystemAssets(assets, nameRegistry, errors);

    const functionalIdSet = new Set<string>();
    for (const row of input.workbook.functional_assets) {
      if (!this.ensureUniqueSheetId(functionalIdSet, "functional_assets", row.excel_row, row.id, errors)) {
        continue;
      }

      functionalAssetIdsToDelete.add(this.toInternalAssetId("SYS", row.id));
      functionalAssetIdsToDelete.add(this.toLegacyInternalAssetId("SYS", row.id));
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
      const candidate: AssetNode = {
        asset_id: assetId,
        asset_name: this.sanitizeAssetName(row.name, "Support Asset"),
        asset_type: "Terminal",
        criticality: "Medium",
        security_domain: "External",
        source: "excel_import"
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
        security_domain: "Internal",
        data_classification: this.resolveDataClassification(`${row.name} ${row.data_type ?? ""} ${row.description ?? ""}`),
        description: this.buildDescription(row.data_type, row.load_description, row.description),
        source: "excel_import"
      };
      if (!this.registerAsset(assets, candidate, errors, "data_assets", row.excel_row)) {
        continue;
      }

      registeredDataAssets.push({ asset_id: assetId, row });
      businessIdToAssetId.set(businessId, assetId);
      this.registerNameAlias(nameRegistry, row.name, assetId);
      accepted.data_assets += 1;
    }

    const interfaceIdSet = new Set<string>();
    const interfaceRows: Array<CxfImportRequest["workbook"]["interface_assets"][number]> = [];
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
          row.data_flow_description,
          row.logical_interface,
          row.physical_interface,
          row.network_domain,
          row.zone,
          row.purpose
        ),
        source: "excel_import"
      };
      if (!this.registerAsset(assets, candidate, errors, "interface_assets", row.excel_row)) {
        continue;
      }

      interfaceRows.push(row);
      businessIdToAssetId.set(businessId, assetId);
      this.registerNameAlias(nameRegistry, row.id, assetId);
      interfaceAssetIds.add(assetId);
      accepted.interface_assets += 1;
    }

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
        errors
      );

      if (producerAssetIds.length === 0 || consumerAssetIds.length === 0) {
        continue;
      }

      const protocolOrMedium = this.truncate(
        this.firstNonEmpty(row.logical_interface, row.physical_interface, row.network_domain),
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

    this.registerMinimalSystemEdges(edges, edgeSequenceByPair, errors);
    this.registerDataOwnershipEdges(registeredDataAssets, edges, edgeSequenceByPair, errors);

    const threatTargets = this.resolveThreatTargets(interfaceAssetIds, placeholderAssetIds, assets, edges);
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
        `Accepted ${accepted.functional_assets} functional rows as metadata only; no functional nodes are added to the attack graph.`
      );
    }
    if (placeholderAssetIds.size > 0) {
      summary.warnings.push(`Auto-created ${placeholderAssetIds.size} placeholder assets for unresolved external interface endpoints.`);
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
      do326a_links: { add: [], update: [], delete: [] }
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

  private resolveThreatProfiles(asset: AssetNode): Array<(typeof autoThreatProfiles)[number]> {
    const text = `${asset.asset_name} ${asset.description ?? ""}`.toLowerCase();
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
      data_assets: 0
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

    if (!this.isAllowedExternalPlaceholder(rawName)) {
      errors.push({
        type: "binding",
        sheet: context.sheet,
        row: context.row,
        field: context.nameField,
        message: `unresolved endpoint ${rawName}; add ${context.refField} or extend AMS alias rules`
      });
      return [];
    }

    const placeholder = this.createPlaceholderAsset(rawName);
    if (!assets.has(placeholder.asset_id)) {
      this.registerAsset(assets, placeholder, errors, context.sheet, context.row);
      placeholderAssetIds.add(placeholder.asset_id);
      this.registerNameAlias(nameRegistry, rawName, placeholder.asset_id);
    }
    return [placeholder.asset_id];
  }

  private createPlaceholderAsset(rawName: string): AssetNode {
    const normalized = this.normalizeName(rawName);
    const digest = crypto.createHash("sha1").update(normalized).digest("hex").slice(0, 6).toUpperCase();
    return {
      asset_id: `EXT-PL-${digest}`,
      asset_name: this.sanitizeAssetName(rawName, "External Placeholder"),
      asset_type: "Terminal",
      criticality: "Medium",
      security_domain: "External",
      description: "Auto-created placeholder asset from unresolved external interface endpoint",
      is_placeholder: true,
      source: "auto_generated",
      tags: ["placeholder", "auto_generated"]
    };
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
    return /gse|network|server|switch|router|bridge|usb|wireless|wifi|manufacturer|airline|ground|航电|引气|维护|航空公司|制造商|地面|设备|系统/.test(
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
