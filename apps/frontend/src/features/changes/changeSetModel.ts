import type { AssetEdge, AssetNode, ChangeSet, DO326ALink, GraphChangeSet, GraphData, ThreatPoint } from "../../types";

export type EntityType = "asset_nodes" | "asset_edges" | "threat_points" | "do326a_links";
export type DraftOperation = "add" | "update" | "delete";
export type EditorMode = "form" | "json";
export type EditableEntity = AssetNode | AssetEdge | ThreatPoint | DO326ALink;
export type FormState = Record<string, string>;

type FieldKind = "text" | "textarea" | "select" | "number" | "csv";

export interface FieldConfig {
  key: string;
  label: string;
  kind: FieldKind;
  required?: boolean;
  options?: string[];
  placeholder?: string;
}

export const ENTITY_TYPES: EntityType[] = ["asset_nodes", "asset_edges", "threat_points", "do326a_links"];

export const ENTITY_LABELS: Record<EntityType, string> = {
  asset_nodes: "AssetNode",
  asset_edges: "AssetEdge",
  threat_points: "ThreatPoint",
  do326a_links: "DO326A Link"
};

export const ENTITY_ID_FIELDS: Record<EntityType, string> = {
  asset_nodes: "asset_id",
  asset_edges: "edge_id",
  threat_points: "threatpoint_id",
  do326a_links: "link_id"
};

const assetTypeOptions = ["Terminal", "Interface", "Link", "Data"];
const criticalityOptions = ["High", "Medium", "Low"];
const securityDomainOptions = ["Internal", "External", "DMZ", "Shared"];
const dataClassificationOptions = ["Public", "Internal", "Sensitive", "Restricted"];
const linkTypeOptions = ["Physical", "Logical", "DataFlow", "Control"];
const directionOptions = ["Unidirectional", "Bidirectional"];
const trustLevelOptions = ["Trusted", "Semi-Trusted", "Untrusted"];
const strideCategoryOptions = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "InformationDisclosure",
  "DenialOfService",
  "ElevationOfPrivilege"
];
const attackVectorOptions = ["Network", "Wireless", "Physical", "Maintenance", "SupplyChain"];
const entryLikelihoodOptions = ["High", "Medium", "Low"];
const attackComplexityOptions = ["Low", "Medium", "High"];
const threatSourceOptions = ["internal", "external", "third-party"];
const detectionStatusOptions = ["None", "Monitoring", "Mitigated"];
const linkageTypeOptions = ["Requirement", "Evidence", "Mitigation"];
const reviewStatusOptions = ["Draft", "Reviewed", "Approved"];

export const ENTITY_FIELDS: Record<EntityType, FieldConfig[]> = {
  asset_nodes: [
    { key: "asset_id", label: "asset_id", kind: "text", required: true, placeholder: "SYS-DEMO1" },
    { key: "asset_name", label: "asset_name", kind: "text", required: true, placeholder: "Demo Asset" },
    { key: "asset_type", label: "asset_type", kind: "select", required: true, options: assetTypeOptions },
    { key: "criticality", label: "criticality", kind: "select", required: true, options: criticalityOptions },
    { key: "security_domain", label: "security_domain", kind: "select", options: securityDomainOptions },
    { key: "data_classification", label: "data_classification", kind: "select", options: dataClassificationOptions },
    { key: "description", label: "description", kind: "textarea", placeholder: "Optional description" },
    { key: "tags", label: "tags", kind: "csv", placeholder: "comma,separated,tags" }
  ],
  asset_edges: [
    { key: "edge_id", label: "edge_id", kind: "text", required: true, placeholder: "E-SYS-A-SYS-B-01" },
    { key: "source_asset_id", label: "source_asset_id", kind: "text", required: true, placeholder: "SYS-A" },
    { key: "target_asset_id", label: "target_asset_id", kind: "text", required: true, placeholder: "SYS-B" },
    { key: "link_type", label: "link_type", kind: "select", required: true, options: linkTypeOptions },
    { key: "direction", label: "direction", kind: "select", required: true, options: directionOptions },
    { key: "trust_level", label: "trust_level", kind: "select", options: trustLevelOptions },
    { key: "protocol_or_medium", label: "protocol_or_medium", kind: "text", placeholder: "Ethernet" },
    { key: "security_mechanism", label: "security_mechanism", kind: "text", placeholder: "TLS" },
    { key: "description", label: "description", kind: "textarea", placeholder: "Optional description" }
  ],
  threat_points: [
    { key: "threatpoint_id", label: "threatpoint_id", kind: "text", required: true, placeholder: "TP-SYS-A-01" },
    { key: "name", label: "name", kind: "text", required: true, placeholder: "Demo Threat Point" },
    { key: "related_asset_id", label: "related_asset_id", kind: "text", required: true, placeholder: "SYS-A" },
    { key: "stride_category", label: "stride_category", kind: "select", required: true, options: strideCategoryOptions },
    { key: "attack_vector", label: "attack_vector", kind: "select", required: true, options: attackVectorOptions },
    { key: "entry_likelihood_level", label: "entry_likelihood_level", kind: "select", required: true, options: entryLikelihoodOptions },
    { key: "attack_complexity_level", label: "attack_complexity_level", kind: "select", required: true, options: attackComplexityOptions },
    { key: "threat_source", label: "threat_source", kind: "select", required: true, options: threatSourceOptions },
    { key: "detection_status", label: "detection_status", kind: "select", options: detectionStatusOptions },
    { key: "expert_modifier", label: "expert_modifier", kind: "number", placeholder: "1.0" },
    { key: "preconditions", label: "preconditions", kind: "textarea", placeholder: "Optional preconditions" },
    { key: "cve_reference", label: "cve_reference", kind: "text", placeholder: "Optional CVE reference" },
    { key: "expert_adjustment_note", label: "expert_adjustment_note", kind: "textarea", placeholder: "Explain expert modifier when it differs from 1.0" },
    { key: "mitigation_reference", label: "mitigation_reference", kind: "text", placeholder: "Optional mitigation reference" }
  ],
  do326a_links: [
    { key: "link_id", label: "link_id", kind: "text", required: true, placeholder: "DL-001" },
    { key: "standard_id", label: "standard_id", kind: "text", required: true, placeholder: "DO-326A-3.2.1" },
    { key: "clause_title", label: "clause_title", kind: "text", required: true, placeholder: "Security Mapping" },
    { key: "linkage_type", label: "linkage_type", kind: "select", required: true, options: linkageTypeOptions },
    { key: "review_status", label: "review_status", kind: "select", required: true, options: reviewStatusOptions },
    { key: "semantic_element_id", label: "semantic_element_id", kind: "csv", required: true, placeholder: "SYS-A,TP-SYS-A-01" },
    { key: "reviewer", label: "reviewer", kind: "text", placeholder: "Required for Reviewed / Approved" },
    { key: "mapping_version", label: "mapping_version", kind: "text", placeholder: "Optional mapping version" },
    { key: "evidence_reference", label: "evidence_reference", kind: "textarea", placeholder: "Optional evidence reference" }
  ]
};

export const emptyChangeSet = (graphVersion: string): GraphChangeSet => ({
  graph_version: graphVersion,
  asset_nodes: { add: [], update: [], delete: [] },
  asset_edges: { add: [], update: [], delete: [] },
  threat_points: { add: [], update: [], delete: [] },
  do326a_links: { add: [], update: [], delete: [] }
});

function getNextLinkId(links: DO326ALink[]): string {
  const max = links.reduce((acc, link) => {
    const value = Number.parseInt(link.link_id.replace("DL-", ""), 10);
    return Number.isFinite(value) ? Math.max(acc, value) : acc;
  }, 0);
  return `DL-${String(max + 1).padStart(3, "0")}`;
}

export function getEntityItems(graph: GraphData | null, entityType: EntityType): EditableEntity[] {
  if (!graph) return [];
  switch (entityType) {
    case "asset_nodes": return graph.asset_nodes;
    case "asset_edges": return graph.asset_edges;
    case "threat_points": return graph.threat_points;
    case "do326a_links": return graph.do326a_links;
  }
}

export function getEntityId(entityType: EntityType, item: EditableEntity | Record<string, unknown>): string {
  const value = (item as Record<string, unknown>)[ENTITY_ID_FIELDS[entityType]];
  return typeof value === "string" ? value.trim() : "";
}

export function stringifyEntity(item: EditableEntity | null): string {
  return item ? JSON.stringify(item, null, 2) : "";
}

export function getDraftBucket(draft: GraphChangeSet, entityType: EntityType): ChangeSet<EditableEntity> {
  return draft[entityType] as ChangeSet<EditableEntity>;
}

export function hasDraftChanges(draft: GraphChangeSet | null): boolean {
  return Boolean(draft && ENTITY_TYPES.some((entityType) => {
    const bucket = getDraftBucket(draft, entityType);
    return bucket.add.length > 0 || bucket.update.length > 0 || bucket.delete.length > 0;
  }));
}

export function describeEntity(entityType: EntityType, item: EditableEntity): string {
  switch (entityType) {
    case "asset_nodes": return `${(item as AssetNode).asset_name} / ${(item as AssetNode).asset_type}`;
    case "asset_edges": return `${(item as AssetEdge).source_asset_id} → ${(item as AssetEdge).target_asset_id}`;
    case "threat_points": return `${(item as ThreatPoint).name} / ${(item as ThreatPoint).related_asset_id}`;
    case "do326a_links": return `${(item as DO326ALink).standard_id} / ${(item as DO326ALink).review_status}`;
  }
}

export function createEntityTemplate(entityType: EntityType, graph: GraphData): EditableEntity {
  const firstAssetId = graph.asset_nodes[0]?.asset_id ?? "SYS-DEMO1";
  const secondAssetId = graph.asset_nodes[1]?.asset_id ?? firstAssetId;
  const firstSemanticId = graph.threat_points[0]?.threatpoint_id ?? graph.asset_nodes[0]?.asset_id ?? "SYS-DEMO1";

  switch (entityType) {
    case "asset_nodes":
      return { asset_id: "SYS-DEMO1", asset_name: "Demo Asset", asset_type: "Terminal", criticality: "Medium", security_domain: "Internal", description: "Created from ChangeSet editor" };
    case "asset_edges":
      return { edge_id: `E-${firstAssetId}-${secondAssetId}-01`, source_asset_id: firstAssetId, target_asset_id: secondAssetId, link_type: "Logical", protocol_or_medium: "Ethernet", direction: "Bidirectional", trust_level: "Trusted" };
    case "threat_points":
      return { threatpoint_id: `TP-${firstAssetId}-01`, name: "Demo Threat Point", related_asset_id: firstAssetId, stride_category: "Tampering", attack_vector: "Network", entry_likelihood_level: "Medium", attack_complexity_level: "Medium", threat_source: "external" };
    case "do326a_links":
      return { link_id: getNextLinkId(graph.do326a_links), standard_id: "DO-326A-3.2.1", clause_title: "Security Mapping", semantic_element_id: [firstSemanticId], linkage_type: "Requirement", review_status: "Draft" };
  }
}

export function createFormState(entityType: EntityType, item: EditableEntity | null): FormState {
  const nextState: FormState = {};
  for (const field of ENTITY_FIELDS[entityType]) {
    const value = item ? (item as unknown as Record<string, unknown>)[field.key] : undefined;
    if (Array.isArray(value)) nextState[field.key] = value.map(String).join(", ");
    else if (typeof value === "number") nextState[field.key] = String(value);
    else nextState[field.key] = typeof value === "string" ? value : "";
  }
  return nextState;
}

export function formStateToObject(entityType: EntityType, formState: FormState): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const field of ENTITY_FIELDS[entityType]) {
    const rawValue = (formState[field.key] ?? "").trim();
    if (field.kind === "csv") {
      const values = rawValue.split(",").map((entry) => entry.trim()).filter(Boolean);
      if (field.required || values.length > 0) result[field.key] = values;
    } else if (field.kind === "number") {
      if (rawValue) {
        const numericValue = Number(rawValue);
        result[field.key] = Number.isFinite(numericValue) ? numericValue : rawValue;
      }
    } else if (rawValue || field.required) {
      result[field.key] = rawValue;
    }
  }
  return result;
}

export function parseEditorValue(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("Editor JSON must be a single object");
  }
  return parsed as Record<string, unknown>;
}

export function upsertEntity(items: EditableEntity[], entityType: EntityType, nextItem: EditableEntity): EditableEntity[] {
  const nextId = getEntityId(entityType, nextItem);
  return [...items.filter((item) => getEntityId(entityType, item) !== nextId), nextItem];
}
