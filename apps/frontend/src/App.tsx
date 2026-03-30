import { useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  applyEdgeChanges,
  applyNodeChanges,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange
} from "reactflow";
import "reactflow/dist/style.css";
import {
  commitChangeSet,
  exportModelingResult,
  getGraph,
  persistPaths,
  runAnalysis,
  seedGenericData,
  seedSampleData,
  validateChangeSet
} from "./api";
import type {
  AssetEdge,
  AssetNode,
  AttackPath,
  ChangeSet,
  DO326ALink,
  GraphChangeSet,
  GraphData,
  ThreatPoint
} from "./types";

type EntityType = Exclude<keyof GraphChangeSet, "graph_version">;
type DraftOperation = "add" | "update" | "delete";
type EditorMode = "form" | "json";
type EditableEntity = AssetNode | AssetEdge | ThreatPoint | DO326ALink;
type FormState = Record<string, string>;
type FieldKind = "text" | "textarea" | "select" | "number" | "csv";

interface FieldConfig {
  key: string;
  label: string;
  kind: FieldKind;
  required?: boolean;
  options?: string[];
  placeholder?: string;
}

const ENTITY_TYPES: EntityType[] = ["asset_nodes", "asset_edges", "threat_points", "do326a_links"];
const ENTITY_LABELS: Record<EntityType, string> = {
  asset_nodes: "AssetNode",
  asset_edges: "AssetEdge",
  threat_points: "ThreatPoint",
  do326a_links: "DO326A Link"
};
const ENTITY_ID_FIELDS: Record<EntityType, string> = {
  asset_nodes: "asset_id",
  asset_edges: "edge_id",
  threat_points: "threatpoint_id",
  do326a_links: "link_id"
};
const domainOrder = ["Internal", "Shared", "DMZ", "External"];
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

const ENTITY_FIELDS: Record<EntityType, FieldConfig[]> = {
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
    {
      key: "entry_likelihood_level",
      label: "entry_likelihood_level",
      kind: "select",
      required: true,
      options: entryLikelihoodOptions
    },
    {
      key: "attack_complexity_level",
      label: "attack_complexity_level",
      kind: "select",
      required: true,
      options: attackComplexityOptions
    },
    { key: "threat_source", label: "threat_source", kind: "select", required: true, options: threatSourceOptions },
    { key: "detection_status", label: "detection_status", kind: "select", options: detectionStatusOptions },
    { key: "expert_modifier", label: "expert_modifier", kind: "number", placeholder: "1.0" },
    { key: "preconditions", label: "preconditions", kind: "textarea", placeholder: "Optional preconditions" },
    { key: "cve_reference", label: "cve_reference", kind: "text", placeholder: "Optional CVE reference" },
    {
      key: "expert_adjustment_note",
      label: "expert_adjustment_note",
      kind: "textarea",
      placeholder: "Explain expert modifier when it differs from 1.0"
    },
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

const emptyChangeSet = (graphVersion: string): GraphChangeSet => ({
  graph_version: graphVersion,
  asset_nodes: { add: [], update: [], delete: [] },
  asset_edges: { add: [], update: [], delete: [] },
  threat_points: { add: [], update: [], delete: [] },
  do326a_links: { add: [], update: [], delete: [] }
});

function inferDomain(asset: AssetNode): string {
  return asset.security_domain ?? "Shared";
}

function buildLanePosition(assets: AssetNode[]): Record<string, { x: number; y: number }> {
  const laneCounts = new Map<string, number>();
  const positions: Record<string, { x: number; y: number }> = {};
  const laneGroups = new Map<string, AssetNode[]>();
  for (const lane of domainOrder) {
    laneCounts.set(lane, 0);
    laneGroups.set(lane, []);
  }

  for (const asset of assets) {
    const lane = inferDomain(asset);
    const list = laneGroups.get(lane) ?? laneGroups.get("Shared") ?? [];
    list.push(asset);
    laneGroups.set(lane, list);
  }

  const maxLaneDepth = Math.max(...Array.from(laneGroups.values(), (items) => items.length), 1);
  const xGap = maxLaneDepth >= 5 ? 210 : 225;
  const yGap = maxLaneDepth >= 5 ? 104 : 118;

  for (const lane of domainOrder) {
    const laneIndex = domainOrder.indexOf(lane);
    for (const asset of laneGroups.get(lane) ?? []) {
      const row = laneCounts.get(lane) ?? 0;
      laneCounts.set(lane, row + 1);
      positions[asset.asset_id] = {
        x: Math.max(0, laneIndex) * xGap,
        y: row * yGap
      };
    }
  }
  return positions;
}

function edgeIdSetFromPath(path: AttackPath | null): Set<string> {
  return new Set((path?.traverses ?? []).map((item) => (item.edge_id.endsWith("#rev") ? item.edge_id.replace("#rev", "") : item.edge_id)));
}

function getNextLinkId(links: DO326ALink[]): string {
  const max = links.reduce((acc, link) => {
    const value = Number.parseInt(link.link_id.replace("DL-", ""), 10);
    return Number.isFinite(value) ? Math.max(acc, value) : acc;
  }, 0);
  return `DL-${String(max + 1).padStart(3, "0")}`;
}

function createExportFileName(analysisBatchId?: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const batchPart = analysisBatchId ? `-${analysisBatchId.replace(/[^a-zA-Z0-9-_]+/g, "_")}` : "";
  return `astra-aviation-threat-modeling-result${batchPart}-${timestamp}.json`;
}

function downloadJson(payload: unknown, fileName: string): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  window.URL.revokeObjectURL(url);
}

function getEntityItems(graph: GraphData | null, entityType: EntityType): EditableEntity[] {
  if (!graph) {
    return [];
  }
  switch (entityType) {
    case "asset_nodes":
      return graph.asset_nodes;
    case "asset_edges":
      return graph.asset_edges;
    case "threat_points":
      return graph.threat_points;
    case "do326a_links":
      return graph.do326a_links;
  }
}

function getEntityId(entityType: EntityType, item: EditableEntity | Record<string, unknown>): string {
  const idField = ENTITY_ID_FIELDS[entityType];
  const value = (item as Record<string, unknown>)[idField];
  return typeof value === "string" ? value.trim() : "";
}

function stringifyEntity(item: EditableEntity | null): string {
  return item ? JSON.stringify(item, null, 2) : "";
}

function getDraftBucket(draft: GraphChangeSet, entityType: EntityType): ChangeSet<EditableEntity> {
  return draft[entityType] as ChangeSet<EditableEntity>;
}

function hasDraftChanges(draft: GraphChangeSet | null): boolean {
  if (!draft) {
    return false;
  }
  return ENTITY_TYPES.some((entityType) => {
    const bucket = getDraftBucket(draft, entityType);
    return bucket.add.length > 0 || bucket.update.length > 0 || bucket.delete.length > 0;
  });
}

function describeEntity(entityType: EntityType, item: EditableEntity): string {
  switch (entityType) {
    case "asset_nodes":
      return `${(item as AssetNode).asset_name} / ${(item as AssetNode).asset_type}`;
    case "asset_edges":
      return `${(item as AssetEdge).source_asset_id} -> ${(item as AssetEdge).target_asset_id}`;
    case "threat_points":
      return `${(item as ThreatPoint).name} / ${(item as ThreatPoint).related_asset_id}`;
    case "do326a_links":
      return `${(item as DO326ALink).standard_id} / ${(item as DO326ALink).review_status}`;
  }
}

function createEntityTemplate(entityType: EntityType, graph: GraphData): EditableEntity {
  const firstAssetId = graph.asset_nodes[0]?.asset_id ?? "SYS-DEMO1";
  const secondAssetId = graph.asset_nodes[1]?.asset_id ?? firstAssetId;
  const firstSemanticId = graph.threat_points[0]?.threatpoint_id ?? graph.asset_nodes[0]?.asset_id ?? "SYS-DEMO1";

  switch (entityType) {
    case "asset_nodes":
      return {
        asset_id: "SYS-DEMO1",
        asset_name: "Demo Asset",
        asset_type: "Terminal",
        criticality: "Medium",
        security_domain: "Internal",
        description: "Created from ChangeSet editor"
      };
    case "asset_edges":
      return {
        edge_id: `E-${firstAssetId}-${secondAssetId}-01`,
        source_asset_id: firstAssetId,
        target_asset_id: secondAssetId,
        link_type: "Logical",
        protocol_or_medium: "Ethernet",
        direction: "Bidirectional",
        trust_level: "Trusted"
      };
    case "threat_points":
      return {
        threatpoint_id: `TP-${firstAssetId}-01`,
        name: "Demo Threat Point",
        related_asset_id: firstAssetId,
        stride_category: "Tampering",
        attack_vector: "Network",
        entry_likelihood_level: "Medium",
        attack_complexity_level: "Medium",
        threat_source: "external"
      };
    case "do326a_links":
      return {
        link_id: getNextLinkId(graph.do326a_links),
        standard_id: "DO-326A-3.2.1",
        clause_title: "Security Mapping",
        semantic_element_id: [firstSemanticId],
        linkage_type: "Requirement",
        review_status: "Draft"
      };
  }
}

function createFormState(entityType: EntityType, item: EditableEntity | null): FormState {
  const nextState: FormState = {};
  for (const field of ENTITY_FIELDS[entityType]) {
    const value = item ? ((item as unknown as Record<string, unknown>)[field.key] as unknown) : undefined;
    if (Array.isArray(value)) {
      nextState[field.key] = value.map((entry) => String(entry)).join(", ");
    } else if (typeof value === "number") {
      nextState[field.key] = String(value);
    } else if (typeof value === "string") {
      nextState[field.key] = value;
    } else {
      nextState[field.key] = "";
    }
  }
  return nextState;
}

function formStateToObject(entityType: EntityType, formState: FormState): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const field of ENTITY_FIELDS[entityType]) {
    const rawValue = (formState[field.key] ?? "").trim();

    if (field.kind === "csv") {
      const values = rawValue
        .split(",")
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
      if (field.required || values.length > 0) {
        result[field.key] = values;
      }
      continue;
    }

    if (field.kind === "number") {
      if (rawValue.length === 0) {
        continue;
      }
      const numericValue = Number(rawValue);
      result[field.key] = Number.isFinite(numericValue) ? numericValue : rawValue;
      continue;
    }

    if (rawValue.length === 0) {
      if (field.required) {
        result[field.key] = "";
      }
      continue;
    }

    result[field.key] = rawValue;
  }

  return result;
}

function parseEditorValue(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("Editor JSON must be a single object");
  }
  return parsed as Record<string, unknown>;
}

function upsertEntity(items: EditableEntity[], entityType: EntityType, nextItem: EditableEntity): EditableEntity[] {
  const nextId = getEntityId(entityType, nextItem);
  return [...items.filter((item) => getEntityId(entityType, item) !== nextId), nextItem];
}

export function App() {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [draft, setDraft] = useState<GraphChangeSet | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [message, setMessage] = useState("Load graph data to start");
  const [busy, setBusy] = useState(false);
  const [exportBatchId, setExportBatchId] = useState("");
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [layoutVersion, setLayoutVersion] = useState(0);
  const [editorMode, setEditorMode] = useState<EditorMode>("form");
  const [editorEntityType, setEditorEntityType] = useState<EntityType>("asset_nodes");
  const [editorOperation, setEditorOperation] = useState<DraftOperation>("add");
  const [selectedExistingId, setSelectedExistingId] = useState("");
  const [editorValue, setEditorValue] = useState("");
  const [formState, setFormState] = useState<FormState>(createFormState("asset_nodes", null));

  const selectedPath = useMemo(
    () => (selectedPathId ? paths.find((item) => item.path_id === selectedPathId) ?? null : null),
    [paths, selectedPathId]
  );
  const links = graph?.do326a_links ?? [];
  const existingItems = useMemo(() => getEntityItems(graph, editorEntityType), [graph, editorEntityType]);
  const selectedExistingItem = useMemo(
    () => existingItems.find((item) => getEntityId(editorEntityType, item) === selectedExistingId) ?? null,
    [editorEntityType, existingItems, selectedExistingId]
  );

  const laneStats = useMemo(() => {
    const stats = new Map<string, number>();
    for (const lane of domainOrder) {
      stats.set(lane, 0);
    }
    for (const asset of graph?.asset_nodes ?? []) {
      const lane = inferDomain(asset);
      stats.set(lane, (stats.get(lane) ?? 0) + 1);
    }
    return Array.from(stats.entries()).filter(([, count]) => count > 0);
  }, [graph]);

  const draftSummary = useMemo(
    () =>
      draft
        ? ENTITY_TYPES.map((entityType) => {
            const bucket = getDraftBucket(draft, entityType);
            return {
              entityType,
              add: bucket.add.length,
              update: bucket.update.length,
              delete: bucket.delete.length
            };
          })
        : [],
    [draft]
  );

  useEffect(() => {
    if (!graph) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const pathEdgeIds = edgeIdSetFromPath(selectedPath);
    const lanePosition = buildLanePosition(graph.asset_nodes);
    const threatCountByAsset = new Map<string, number>();
    for (const threat of graph.threat_points) {
      threatCountByAsset.set(threat.related_asset_id, (threatCountByAsset.get(threat.related_asset_id) ?? 0) + 1);
    }

    const createdNodes: Node[] = graph.asset_nodes.map((asset, index) => {
      const threatCount = threatCountByAsset.get(asset.asset_id) ?? 0;
      const position = lanePosition[asset.asset_id] ?? { x: index * 180, y: 0 };
      return {
        id: asset.asset_id,
        position,
        data: {
          label: (
            <div className="topo-node">
              <strong>{asset.asset_name}</strong>
              <span>{asset.asset_type}</span>
              <small>{inferDomain(asset)}</small>
              {threatCount > 0 ? <em>Threat x {threatCount}</em> : null}
            </div>
          )
        },
        style: {
          border: "1px solid #435279",
          borderRadius: "10px",
          background: "#131c34",
          color: "#dbe5ff",
          width: 168,
          padding: 2
        }
      };
    });

    const createdEdges: Edge[] = graph.asset_edges.map((assetEdge) => {
      const highlighted = pathEdgeIds.has(assetEdge.edge_id);
      return {
        id: assetEdge.edge_id,
        source: assetEdge.source_asset_id,
        target: assetEdge.target_asset_id,
        label: `${assetEdge.link_type}${assetEdge.trust_level ? `/${assetEdge.trust_level}` : ""}`,
        animated: highlighted,
        style: {
          stroke: highlighted ? "#7aa2ff" : "#3e4a70",
          strokeWidth: highlighted ? 2.8 : 1.4
        },
        labelStyle: { fill: highlighted ? "#bcd0ff" : "#90a0c8", fontSize: 11 }
      };
    });

    setNodes(createdNodes);
    setEdges(createdEdges);
  }, [graph, selectedPath, layoutVersion]);

  useEffect(() => {
    if (!graph) {
      setSelectedExistingId("");
      setEditorValue("");
      setFormState(createFormState(editorEntityType, null));
      return;
    }

    if (editorOperation === "add") {
      setSelectedExistingId("");
      const template = createEntityTemplate(editorEntityType, graph);
      setEditorValue(stringifyEntity(template));
      setFormState(createFormState(editorEntityType, template));
      return;
    }

    const candidateIds = existingItems.map((item) => getEntityId(editorEntityType, item)).filter((id) => id.length > 0);
    const nextSelectedId = candidateIds.includes(selectedExistingId) ? selectedExistingId : (candidateIds[0] ?? "");
    if (nextSelectedId !== selectedExistingId) {
      setSelectedExistingId(nextSelectedId);
      return;
    }

    if (editorOperation === "update") {
      setEditorValue(stringifyEntity(selectedExistingItem));
      setFormState(createFormState(editorEntityType, selectedExistingItem));
    } else {
      setEditorValue("");
      setFormState(createFormState(editorEntityType, selectedExistingItem));
    }
  }, [editorEntityType, editorOperation, existingItems, graph, selectedExistingId, selectedExistingItem]);

  async function handleLoadGraph() {
    try {
      setBusy(true);
      const data = await getGraph();
      setGraph(data);
      setDraft(emptyChangeSet(data.graph_version));
      setMessage(`Graph loaded: version ${data.graph_version}. Draft reset.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to load graph");
    } finally {
      setBusy(false);
    }
  }

  function handleResetDraft() {
    if (!graph) {
      return;
    }
    setDraft(emptyChangeSet(graph.graph_version));
    setMessage(`Draft cleared for graph version ${graph.graph_version}`);
  }

  function handleLoadEditorSource() {
    if (!graph) {
      return;
    }
    const sourceItem = editorOperation === "add" ? createEntityTemplate(editorEntityType, graph) : selectedExistingItem;
    setEditorValue(stringifyEntity(sourceItem));
    setFormState(createFormState(editorEntityType, sourceItem));
  }

  function handleEditorModeChange(nextMode: EditorMode) {
    if (nextMode === editorMode) {
      return;
    }

    if (nextMode === "json") {
      setEditorValue(JSON.stringify(formStateToObject(editorEntityType, formState), null, 2));
      setEditorMode(nextMode);
      return;
    }

    try {
      setFormState(createFormState(editorEntityType, parseEditorValue(editorValue) as unknown as EditableEntity));
    } catch {
      if (graph) {
        const sourceItem = editorOperation === "add" ? createEntityTemplate(editorEntityType, graph) : selectedExistingItem;
        setFormState(createFormState(editorEntityType, sourceItem));
      } else {
        setFormState(createFormState(editorEntityType, null));
      }
    }
    setEditorMode(nextMode);
  }

  function handleStageChange() {
    if (!graph || !draft) {
      return;
    }

    if (editorOperation === "delete") {
      const deleteId = selectedExistingId.trim();
      if (!deleteId) {
        setMessage(`Select one ${ENTITY_LABELS[editorEntityType]} to delete`);
        return;
      }

      const existsInGraph = existingItems.some((item) => getEntityId(editorEntityType, item) === deleteId);
      setDraft((current) => {
        if (!current) {
          return current;
        }
        const bucket = getDraftBucket(current, editorEntityType);
        const nextBucket: ChangeSet<EditableEntity> = {
          add: bucket.add.filter((item) => getEntityId(editorEntityType, item) !== deleteId),
          update: bucket.update.filter((item) => getEntityId(editorEntityType, item) !== deleteId),
          delete: existsInGraph ? Array.from(new Set([...bucket.delete, deleteId])) : bucket.delete.filter((item) => item !== deleteId)
        };
        return { ...current, [editorEntityType]: nextBucket };
      });
      setMessage(`Queued delete for ${ENTITY_LABELS[editorEntityType]} ${deleteId}`);
      return;
    }

    try {
      const parsedEntity =
        editorMode === "form"
          ? (formStateToObject(editorEntityType, formState) as unknown as EditableEntity)
          : (parseEditorValue(editorValue) as unknown as EditableEntity);
      const nextId = getEntityId(editorEntityType, parsedEntity);
      if (!nextId) {
        throw new Error(`JSON must include ${ENTITY_ID_FIELDS[editorEntityType]}`);
      }

      setDraft((current) => {
        if (!current) {
          return current;
        }
        const bucket = getDraftBucket(current, editorEntityType);
        const isAlreadyNew = bucket.add.some((item) => getEntityId(editorEntityType, item) === nextId);
        const shouldStoreAsAdd = editorOperation === "add" || isAlreadyNew;
        const nextBucket: ChangeSet<EditableEntity> = {
          add: shouldStoreAsAdd ? upsertEntity(bucket.add, editorEntityType, parsedEntity) : bucket.add.filter((item) => getEntityId(editorEntityType, item) !== nextId),
          update: shouldStoreAsAdd ? bucket.update.filter((item) => getEntityId(editorEntityType, item) !== nextId) : upsertEntity(bucket.update, editorEntityType, parsedEntity),
          delete: bucket.delete.filter((item) => item !== nextId)
        };
        return { ...current, [editorEntityType]: nextBucket };
      });
      setMessage(`Queued ${editorOperation} for ${ENTITY_LABELS[editorEntityType]} ${nextId}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Invalid editor payload");
    }
  }

  function handleRemoveDraftEntry(entityType: EntityType, operation: DraftOperation, id: string) {
    setDraft((current) => {
      if (!current) {
        return current;
      }
      const bucket = getDraftBucket(current, entityType);
      const nextBucket: ChangeSet<EditableEntity> = {
        add: operation === "add" ? bucket.add.filter((item) => getEntityId(entityType, item) !== id) : bucket.add,
        update: operation === "update" ? bucket.update.filter((item) => getEntityId(entityType, item) !== id) : bucket.update,
        delete: operation === "delete" ? bucket.delete.filter((item) => item !== id) : bucket.delete
      };
      return { ...current, [entityType]: nextBucket };
    });
  }

  async function handleValidate() {
    if (!draft) {
      return;
    }
    try {
      setBusy(true);
      const result = await validateChangeSet(draft);
      setMessage(result.valid ? "Draft validation passed" : `Draft validation failed: ${result.errors.join("; ")}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to validate draft");
    } finally {
      setBusy(false);
    }
  }

  async function handleCommit() {
    if (!draft) {
      return;
    }
    if (!hasDraftChanges(draft)) {
      setMessage("Draft is empty. Queue at least one change before commit.");
      return;
    }
    try {
      setBusy(true);
      const result = await commitChangeSet(draft);
      if (result.committed) {
        setMessage(`Commit succeeded: ${result.commit_id}, version ${result.new_version}`);
        await handleLoadGraph();
      } else {
        setMessage(`Commit failed: ${(result.errors ?? []).join("; ")}`);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to commit draft");
    } finally {
      setBusy(false);
    }
  }

  async function handleRunAnalysis() {
    try {
      setBusy(true);
      const result = await runAnalysis();
      setPaths(result.paths);
      setSelectedPathId(result.paths[0]?.path_id ?? null);
      setExportBatchId(result.paths[0]?.analysis_batch_id ?? "");
      setMessage(`Analysis done: ${result.count} paths`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Analysis failed");
    } finally {
      setBusy(false);
    }
  }

  async function handlePersistPaths() {
    if (paths.length === 0) {
      setMessage("No paths to persist");
      return;
    }
    try {
      setBusy(true);
      const result = await persistPaths(paths);
      setMessage(`Persisted ${result.persisted} paths`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Persist failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleSeedSample() {
    try {
      setBusy(true);
      const result = await seedSampleData();
      setMessage(
        `DO-356A seed complete: assets=${result.counts.asset_nodes}, edges=${result.counts.asset_edges}, threats=${result.counts.threat_points}, links=${result.counts.do326a_links}`
      );
      await handleLoadGraph();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Seed failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleSeedGeneric() {
    try {
      setBusy(true);
      const result = await seedGenericData();
      setMessage(
        `Generic seed complete: assets=${result.counts.asset_nodes}, edges=${result.counts.asset_edges}, threats=${result.counts.threat_points}, links=${result.counts.do326a_links}`
      );
      await handleLoadGraph();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Seed failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleExportResult() {
    try {
      setBusy(true);
      const analysisBatchId = exportBatchId.trim() || undefined;
      const payload = await exportModelingResult(analysisBatchId);
      downloadJson(payload, createExportFileName(analysisBatchId));
      setMessage(
        analysisBatchId
          ? `Exported modeling result for analysis batch ${analysisBatchId}`
          : "Exported modeling result for the full dataset"
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Failed to export modeling result");
    } finally {
      setBusy(false);
    }
  }

  const kpi = {
    assets: graph?.asset_nodes.length ?? 0,
    threats: graph?.threat_points.length ?? 0,
    paths: paths.length,
    links: links.length,
    version: graph?.graph_version ?? "-"
  };

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>ASTRA 航空威胁建模语义分析系统</h1>
          <p>Aviation Semantic Threat Reasoning & Analysis System</p>
        </div>
        <div className="header-actions">
          <button className="button primary" onClick={handleSeedSample} disabled={busy}>
            Load DO-356A Demo
          </button>
          <button className="button" onClick={handleSeedGeneric} disabled={busy}>
            Load Generic Demo
          </button>
          <button className="button" onClick={handleLoadGraph} disabled={busy}>
            Refresh Graph
          </button>
        </div>
      </header>

      <section className="kpi-grid">
        <article className="kpi-card">
          <span>AssetNode</span>
          <strong>{kpi.assets}</strong>
        </article>
        <article className="kpi-card">
          <span>ThreatPoint</span>
          <strong>{kpi.threats}</strong>
        </article>
        <article className="kpi-card">
          <span>AttackPath</span>
          <strong>{kpi.paths}</strong>
        </article>
        <article className="kpi-card">
          <span>DO326A Link</span>
          <strong>{kpi.links}</strong>
        </article>
      </section>

      <div className="layout">
        <aside className="panel left">
          <h3>Domain View</h3>
          <p>Assets grouped by security domain</p>
          <div className="lane-row">
            {laneStats.map(([lane, count]) => (
              <span key={lane} className="lane-pill">
                {lane} / {count}
              </span>
            ))}
          </div>
          <div className="scroll-panel domain-scroll-panel">
            <div className="list compact">
              {(graph?.asset_nodes ?? []).map((asset) => (
                <div key={asset.asset_id} className="item vertical">
                  <strong>{asset.asset_name}</strong>
                  <span>{asset.asset_id}</span>
                  <span>
                    {asset.asset_type} / {asset.criticality}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </aside>

        <main className="panel center">
          <h3>Topology Canvas</h3>
          <div className="toolbar">
            <button className="button" onClick={handleRunAnalysis} disabled={busy}>
              Run DPS Analysis
            </button>
            <button className="button" onClick={handlePersistPaths} disabled={busy || paths.length === 0}>
              Persist Paths
            </button>
            <button className="button" onClick={() => setLayoutVersion((v) => v + 1)} disabled={busy || !graph}>
              Re-layout
            </button>
          </div>
          <div className="topology-canvas">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              fitViewOptions={{ padding: 0.08 }}
              minZoom={0.2}
              maxZoom={1.5}
              onNodesChange={(changes: NodeChange[]) => setNodes((current) => applyNodeChanges(changes, current))}
              onEdgesChange={(changes: EdgeChange[]) => setEdges((current) => applyEdgeChanges(changes, current))}
            >
              <MiniMap pannable zoomable style={{ width: 136, height: 88 }} />
              <Controls />
              <Background gap={16} color="#243353" />
            </ReactFlow>
          </div>
        </main>

        <aside className="panel right review-panel">
          <h3>Review Panel</h3>
          <p className="status">{message}</p>
          <div className="toolbar wrap">
            <input
              className="input-field"
              value={exportBatchId}
              onChange={(event) => setExportBatchId(event.target.value)}
              placeholder="analysis_batch_id (optional)"
            />
            <button className="button" onClick={handleExportResult} disabled={busy}>
              Export Modeling JSON
            </button>
          </div>

          <h3>Path Ranking</h3>
          <div className="scroll-panel path-scroll-panel">
            <div className="list path-list">
              {paths.map((path) => (
                <div
                  key={path.path_id}
                  className={`item vertical clickable ${selectedPathId === path.path_id ? "active" : ""}`}
                  onClick={() => setSelectedPathId(path.path_id)}
                >
                  <strong>
                    {path.priority_label} / {path.path_id}
                  </strong>
                  <span>{path.hop_sequence}</span>
                  <span>normalized={path.normalized_score.toFixed(3)}</span>
                  <span>{path.is_low_priority ? "low priority" : "mitigation queue"}</span>
                </div>
              ))}
              {paths.length === 0 ? <div className="item vertical">Run analysis to populate attack paths.</div> : null}
            </div>
          </div>
        </aside>

        <footer className="panel bottom">
          <div className="changeset-header">
            <div>
              <h3>ChangeSet Studio</h3>
              <p>Queue real graph edits, validate them, then commit as one atomic change set.</p>
            </div>
            <div className="changeset-meta">
              <span className="pill">graph_version {draft?.graph_version ?? "-"}</span>
              {draftSummary.map((item) => (
                <span key={item.entityType} className="pill">
                  {ENTITY_LABELS[item.entityType]} +{item.add} / ~{item.update} / -{item.delete}
                </span>
              ))}
            </div>
          </div>

          <div className="toolbar wrap">
            <button className="button" onClick={handleValidate} disabled={!draft || busy}>
              Validate Draft
            </button>
            <button className="button primary" onClick={handleCommit} disabled={!draft || busy || !hasDraftChanges(draft)}>
              Commit Draft
            </button>
            <button className="button" onClick={handleResetDraft} disabled={!draft || busy}>
              Reset Draft
            </button>
            <button className="button" onClick={handleLoadGraph} disabled={busy}>
              Reload Latest Graph
            </button>
          </div>

          <div className="changeset-grid">
            <section className="editor-shell">
              <div className="field-grid">
                <label className="field-stack">
                  <span className="field-label">Entity</span>
                  <select
                    className="input-field"
                    value={editorEntityType}
                    onChange={(event) => setEditorEntityType(event.target.value as EntityType)}
                    disabled={!graph}
                  >
                    {ENTITY_TYPES.map((entityType) => (
                      <option key={entityType} value={entityType}>
                        {ENTITY_LABELS[entityType]}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="field-stack">
                  <span className="field-label">Operation</span>
                  <select
                    className="input-field"
                    value={editorOperation}
                    onChange={(event) => setEditorOperation(event.target.value as DraftOperation)}
                    disabled={!graph}
                  >
                    <option value="add">add</option>
                    <option value="update">update</option>
                    <option value="delete">delete</option>
                  </select>
                </label>
              </div>

              {editorOperation !== "add" ? (
                <label className="field-stack">
                  <span className="field-label">Current {ENTITY_LABELS[editorEntityType]}</span>
                  <select
                    className="input-field"
                    value={selectedExistingId}
                    onChange={(event) => setSelectedExistingId(event.target.value)}
                    disabled={!graph || existingItems.length === 0}
                  >
                    {existingItems.length === 0 ? <option value="">No items available</option> : null}
                    {existingItems.map((item) => {
                      const id = getEntityId(editorEntityType, item);
                      return (
                        <option key={id} value={id}>
                          {id}
                        </option>
                      );
                    })}
                  </select>
                </label>
              ) : null}

              <div className="editor-actions">
                <button className="button" onClick={handleLoadEditorSource} disabled={!graph}>
                  {editorOperation === "add" ? "Load Template" : "Load Current Item"}
                </button>
                <button className="button primary" onClick={handleStageChange} disabled={!draft || busy || !graph}>
                  Queue {editorOperation}
                </button>
              </div>

              {editorOperation === "delete" ? (
                <div className="preview-card">
                  <strong>Delete Preview</strong>
                  <p className="muted">
                    Deleting removes the selected entity from the persisted graph. Existing staged add/update entries with the same ID
                    are cleaned up automatically.
                  </p>
                  <pre>{stringifyEntity(selectedExistingItem)}</pre>
                </div>
              ) : (
                <div className="editor-fill editor-body">
                  <div className="mode-toggle" role="tablist" aria-label="Editor mode">
                    <button
                      className={`mode-toggle-button ${editorMode === "form" ? "active" : ""}`}
                      onClick={() => handleEditorModeChange("form")}
                      type="button"
                      disabled={!graph}
                    >
                      Form
                    </button>
                    <button
                      className={`mode-toggle-button ${editorMode === "json" ? "active" : ""}`}
                      onClick={() => handleEditorModeChange("json")}
                      type="button"
                      disabled={!graph}
                    >
                      JSON
                    </button>
                  </div>

                  {editorMode === "form" ? (
                    <div className="form-grid editor-fill">
                      {ENTITY_FIELDS[editorEntityType].map((field) => (
                        <label key={field.key} className={`field-stack ${field.kind === "textarea" ? "field-span-2" : ""}`}>
                          <span className="field-label">
                            {field.label}
                            {field.required ? " *" : ""}
                          </span>

                          {field.kind === "textarea" ? (
                            <textarea
                              className="input-field form-textarea"
                              value={formState[field.key] ?? ""}
                              onChange={(event) =>
                                setFormState((current) => ({
                                  ...current,
                                  [field.key]: event.target.value
                                }))
                              }
                              placeholder={field.placeholder}
                              spellCheck={false}
                              disabled={!graph}
                            />
                          ) : field.kind === "select" ? (
                            <select
                              className="input-field"
                              value={formState[field.key] ?? ""}
                              onChange={(event) =>
                                setFormState((current) => ({
                                  ...current,
                                  [field.key]: event.target.value
                                }))
                              }
                              disabled={!graph}
                            >
                              <option value="">{field.required ? "Select one" : "Optional"}</option>
                              {(field.options ?? []).map((option) => (
                                <option key={option} value={option}>
                                  {option}
                                </option>
                              ))}
                            </select>
                          ) : (
                            <input
                              className="input-field"
                              type={field.kind === "number" ? "number" : "text"}
                              value={formState[field.key] ?? ""}
                              onChange={(event) =>
                                setFormState((current) => ({
                                  ...current,
                                  [field.key]: event.target.value
                                }))
                              }
                              placeholder={field.placeholder}
                              spellCheck={false}
                              disabled={!graph}
                            />
                          )}
                        </label>
                      ))}
                    </div>
                  ) : (
                    <label className="field-stack editor-fill">
                      <span className="field-label">Entity JSON</span>
                      <textarea
                        className="input-field draft-json editor-fill"
                        value={editorValue}
                        onChange={(event) => setEditorValue(event.target.value)}
                        spellCheck={false}
                        disabled={!graph}
                      />
                    </label>
                  )}
                </div>
              )}
            </section>

            <section className="queue-shell">
              <div className="preview-card queue-list-card">
                <strong>Queued Changes</strong>
                <div className="stage-list">
                  {draft && hasDraftChanges(draft) ? (
                    ENTITY_TYPES.map((entityType) => {
                      const bucket = getDraftBucket(draft, entityType);
                      return (
                        <div key={entityType} className="stage-group">
                          <div className="stage-group-header">
                            <span>{ENTITY_LABELS[entityType]}</span>
                            <span className="pill">
                              +{bucket.add.length} / ~{bucket.update.length} / -{bucket.delete.length}
                            </span>
                          </div>

                          {bucket.add.map((item) => {
                            const id = getEntityId(entityType, item);
                            return (
                              <div key={`add-${id}`} className="stage-entry">
                                <div className="stage-entry-main">
                                  <span className="tag">add</span>
                                  <strong>{id}</strong>
                                  <span>{describeEntity(entityType, item)}</span>
                                </div>
                                <button className="button" onClick={() => handleRemoveDraftEntry(entityType, "add", id)}>
                                  Remove
                                </button>
                              </div>
                            );
                          })}

                          {bucket.update.map((item) => {
                            const id = getEntityId(entityType, item);
                            return (
                              <div key={`update-${id}`} className="stage-entry">
                                <div className="stage-entry-main">
                                  <span className="tag">update</span>
                                  <strong>{id}</strong>
                                  <span>{describeEntity(entityType, item)}</span>
                                </div>
                                <button className="button" onClick={() => handleRemoveDraftEntry(entityType, "update", id)}>
                                  Remove
                                </button>
                              </div>
                            );
                          })}

                          {bucket.delete.map((id) => (
                            <div key={`delete-${id}`} className="stage-entry">
                              <div className="stage-entry-main">
                                <span className="tag">delete</span>
                                <strong>{id}</strong>
                              </div>
                              <button className="button" onClick={() => handleRemoveDraftEntry(entityType, "delete", id)}>
                                Remove
                              </button>
                            </div>
                          ))}
                        </div>
                      );
                    })
                  ) : (
                    <div className="item vertical">
                      <strong>Draft is empty</strong>
                      <span>Load the graph, choose an entity, and queue add/update/delete changes here.</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="preview-card queue-json-card">
                <strong>Draft JSON Preview</strong>
                <pre>{draft ? JSON.stringify(draft, null, 2) : "Load graph data to initialize a change set."}</pre>
              </div>
            </section>
          </div>
        </footer>
      </div>
    </div>
  );
}
