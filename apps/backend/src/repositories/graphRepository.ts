import crypto from "node:crypto";
import type { QueryResult, Session } from "neo4j-driver";
import { getDriver } from "../db/neo4j.js";
import type {
  AttackPath,
  AuditRecord,
  BoundaryDataFlowReportRow,
  DO326ALink,
  FunctionPropagationPath,
  FunctionPropagationReportRow,
  GraphChangeSet,
  GraphSnapshot,
  InternalDataFlowReportRow,
  ModelingExportBundle,
  ReviewStatus,
  TrustBoundaryReportRow
} from "../types/domain.js";
import type { FpAnalysisInput } from "../services/fpAnalysisService.js";
import { collectBoundaryReachableSdfIds } from "../services/fpAnalysisService.js";

const graphVersionNodeId = "GRAPH_VERSION";

/** Sort ids like F1, F2, F10 or BDF2, BDF10 by their trailing number, deduplicating. */
function sortByTrailingNumber(ids: string[]): string[] {
  const trailingNumber = (id: string): number => {
    const match = id.match(/(\d+)\s*$/);
    return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
  };
  return Array.from(new Set(ids)).sort((a, b) => {
    const diff = trailingNumber(a) - trailingNumber(b);
    return diff !== 0 ? diff : a.localeCompare(b);
  });
}

interface QueryRunner {
  run: (query: string, parameters?: Record<string, unknown>) => Promise<QueryResult>;
}

export class GraphChangeSetValidationError extends Error {
  readonly errors: string[];

  constructor(errors: string[]) {
    super(errors.join("; "));
    this.name = "GraphChangeSetValidationError";
    this.errors = errors;
  }
}

export class GraphRepository {
  async ensureConstraints(): Promise<void> {
    const session = getDriver().session();
    try {
      await session.run("CREATE CONSTRAINT asset_unique IF NOT EXISTS FOR (a:AssetNode) REQUIRE a.asset_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT edge_unique IF NOT EXISTS FOR ()-[r:ASSET_EDGE]-() REQUIRE r.edge_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT threat_unique IF NOT EXISTS FOR (t:ThreatPoint) REQUIRE t.threatpoint_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT do326a_link_unique IF NOT EXISTS FOR (l:DO326A_Link) REQUIRE l.link_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT graph_version_unique IF NOT EXISTS FOR (v:GraphVersion) REQUIRE v.id IS UNIQUE");
      await session.run("CREATE CONSTRAINT function_unique IF NOT EXISTS FOR (f:FunctionNode) REQUIRE f.function_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT trust_boundary_unique IF NOT EXISTS FOR (sb:TrustBoundary) REQUIRE sb.boundary_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT threat_actor_unique IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.actor_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT boundary_interface_unique IF NOT EXISTS FOR (bi:BoundaryInterface) REQUIRE bi.interface_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT system_data_flow_unique IF NOT EXISTS FOR (sdf:SystemDataFlow) REQUIRE sdf.sdf_id IS UNIQUE");
      await session.run("CREATE CONSTRAINT function_propagation_unique IF NOT EXISTS FOR (fp:FunctionPropagationPath) REQUIRE fp.fp_id IS UNIQUE");
      await session.run("DROP CONSTRAINT path_unique IF EXISTS");
      await session.run(
        `MATCH (p:AttackPath)
         WITH p.analysis_batch_id AS analysis_batch_id, p.path_id AS path_id, p
         ORDER BY coalesce(p.generated_at, datetime({epochMillis: 0})) DESC
         WITH analysis_batch_id, path_id, collect(p) AS paths
         WHERE analysis_batch_id IS NOT NULL AND path_id IS NOT NULL AND size(paths) > 1
         FOREACH (duplicate IN tail(paths) | DETACH DELETE duplicate)`
      );
      await session.run(
        "CREATE CONSTRAINT path_unique IF NOT EXISTS FOR (p:AttackPath) REQUIRE (p.analysis_batch_id, p.path_id) IS UNIQUE"
      );
      await session.run(
        "MERGE (v:GraphVersion {id: $id}) ON CREATE SET v.value = $version ON MATCH SET v.value = coalesce(v.value, $version)",
        { id: graphVersionNodeId, version: "v1" }
      );
    } finally {
      await session.close();
    }
  }

  async getGraph(): Promise<GraphSnapshot> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead(async (tx) => {
        const [
          versionRes,
          assetsRes,
          edgesRes,
          threatsRes,
          linksRes,
          functionsRes,
          boundariesRes,
          actorsRes,
          interfacesRes,
          sdfRes,
          fpRes
        ] =
          await Promise.all([
            tx.run("MATCH (v:GraphVersion {id: $id}) RETURN v.value AS graph_version", { id: graphVersionNodeId }),
            tx.run("MATCH (a:AssetNode) RETURN a ORDER BY a.asset_id"),
            tx.run(
              "MATCH (s:AssetNode)-[r:ASSET_EDGE]->(t:AssetNode) RETURN r.edge_id AS edge_id, s.asset_id AS source_asset_id, t.asset_id AS target_asset_id, r.link_type AS link_type, r.protocol_or_medium AS protocol_or_medium, r.direction AS direction, r.trust_level AS trust_level, r.security_mechanism AS security_mechanism, r.description AS description ORDER BY edge_id"
            ),
            tx.run(
              "MATCH (th:ThreatPoint)-[:OVERLAY_ON]->(a:AssetNode) RETURN th.threatpoint_id AS threatpoint_id, th.name AS name, a.asset_id AS related_asset_id, th.stride_category AS stride_category, th.attack_vector AS attack_vector, th.entry_likelihood_level AS entry_likelihood_level, th.attack_complexity_level AS attack_complexity_level, th.threat_source AS threat_source, th.preconditions AS preconditions, th.detection_status AS detection_status, th.cve_reference AS cve_reference, th.expert_modifier AS expert_modifier, th.expert_adjustment_note AS expert_adjustment_note, th.mitigation_reference AS mitigation_reference ORDER BY threatpoint_id"
            ),
            tx.run("MATCH (l:DO326A_Link) RETURN l ORDER BY l.link_id"),
            tx.run("MATCH (f:FunctionNode) RETURN f ORDER BY f.function_id"),
            tx.run(
              "MATCH (sb:TrustBoundary) OPTIONAL MATCH (sb)-[:HAS_INTERFACE]->(bi:BoundaryInterface) OPTIONAL MATCH (sb)-[:COVERS_DOMAIN]->(d:AssetNode) RETURN sb.boundary_id AS boundary_id, sb.name AS name, sb.description AS description, sb.enters_internal_propagation AS enters_internal_propagation, collect(DISTINCT bi.interface_id) AS interface_asset_ids, collect(DISTINCT d.asset_id) AS domain_asset_ids ORDER BY boundary_id"
            ),
            tx.run(
              "MATCH (ta:ThreatActor) OPTIONAL MATCH (ta)-[:THREATENS]->(sb:TrustBoundary) RETURN ta.actor_id AS actor_id, ta.name AS name, ta.actor_type AS actor_type, ta.description AS description, collect(DISTINCT sb.boundary_id) AS boundary_ids ORDER BY actor_id"
            ),
            tx.run("MATCH (bi:BoundaryInterface) RETURN bi ORDER BY bi.interface_id"),
            tx.run(
              "MATCH (sdf:SystemDataFlow) OPTIONAL MATCH (sdf)-[:SUPPORTS_FUNCTION]->(f:FunctionNode) RETURN sdf.sdf_id AS sdf_id, sdf.producer AS producer, sdf.consumer AS consumer, sdf.content AS content, sdf.data_flow_type AS data_flow_type, sdf.description AS description, collect(DISTINCT f.function_id) AS function_ids ORDER BY sdf_id"
            ),
            tx.run(
              "MATCH (fp:FunctionPropagationPath) OPTIONAL MATCH (fp)-[:INCLUDES_BDF]->(bdf:AssetNode) OPTIONAL MATCH (fp)-[:INCLUDES_SDF]->(sdf:SystemDataFlow) RETURN fp.fp_id AS fp_id, fp.data_type_label AS data_type_label, fp.system_path_text AS system_path_text, fp.sdf_note AS sdf_note, fp.description AS description, collect(DISTINCT bdf.business_id) AS bdf_ids, collect(DISTINCT sdf.sdf_id) AS sdf_ids ORDER BY fp_id"
            )
          ]);
        return {
          versionRes,
          assetsRes,
          edgesRes,
          threatsRes,
          linksRes,
          functionsRes,
          boundariesRes,
          actorsRes,
          interfacesRes,
          sdfRes,
          fpRes
        };
      });

      return {
        graph_version: (result.versionRes.records[0]?.get("graph_version") as string) ?? "v1",
        asset_nodes: result.assetsRes.records.map((record) => {
          const properties = record.get("a").properties as Record<string, unknown>;
          return {
            asset_id: String(properties.asset_id),
            asset_name: String(properties.asset_name),
            asset_type: properties.asset_type as GraphSnapshot["asset_nodes"][number]["asset_type"],
            criticality: properties.criticality as GraphSnapshot["asset_nodes"][number]["criticality"],
            security_domain: (properties.security_domain as GraphSnapshot["asset_nodes"][number]["security_domain"]) ?? undefined,
            description: (properties.description as string | undefined) ?? undefined,
            data_classification:
              (properties.data_classification as GraphSnapshot["asset_nodes"][number]["data_classification"]) ?? undefined,
            tags: (properties.tags as string[] | undefined) ?? undefined,
            is_placeholder: (properties.is_placeholder as boolean | undefined) ?? undefined,
            source: (properties.source as GraphSnapshot["asset_nodes"][number]["source"] | undefined) ?? undefined,
            business_id: (properties.business_id as string | undefined) ?? undefined,
            data_flow_type: (properties.data_flow_type as string | undefined) ?? undefined,
            bdf_ids: (properties.bdf_ids as string[] | undefined) ?? undefined,
            enters_internal_propagation:
              (properties.enters_internal_propagation as boolean | undefined) ?? undefined,
            boundary_interface_id: (properties.boundary_interface_id as string | undefined) ?? undefined
          };
        }),
        asset_edges: result.edgesRes.records.map((record) => ({
          edge_id: record.get("edge_id") as string,
          source_asset_id: record.get("source_asset_id") as string,
          target_asset_id: record.get("target_asset_id") as string,
          link_type: record.get("link_type") as GraphSnapshot["asset_edges"][number]["link_type"],
          protocol_or_medium: (record.get("protocol_or_medium") as string | null) ?? undefined,
          direction: record.get("direction") as GraphSnapshot["asset_edges"][number]["direction"],
          trust_level: (record.get("trust_level") as GraphSnapshot["asset_edges"][number]["trust_level"]) ?? undefined,
          security_mechanism: (record.get("security_mechanism") as string | null) ?? undefined,
          description: (record.get("description") as string | null) ?? undefined
        })),
        threat_points: result.threatsRes.records.map((record) => ({
          threatpoint_id: record.get("threatpoint_id") as string,
          name: record.get("name") as string,
          related_asset_id: record.get("related_asset_id") as string,
          stride_category: record.get("stride_category") as GraphSnapshot["threat_points"][number]["stride_category"],
          attack_vector: record.get("attack_vector") as GraphSnapshot["threat_points"][number]["attack_vector"],
          entry_likelihood_level: record.get(
            "entry_likelihood_level"
          ) as GraphSnapshot["threat_points"][number]["entry_likelihood_level"],
          attack_complexity_level: record.get(
            "attack_complexity_level"
          ) as GraphSnapshot["threat_points"][number]["attack_complexity_level"],
          threat_source: record.get("threat_source") as GraphSnapshot["threat_points"][number]["threat_source"],
          preconditions: (record.get("preconditions") as string | null) ?? undefined,
          detection_status: (record.get("detection_status") as GraphSnapshot["threat_points"][number]["detection_status"]) ?? undefined,
          cve_reference: (record.get("cve_reference") as string | null) ?? undefined,
          expert_modifier: (record.get("expert_modifier") as number | null) ?? undefined,
          expert_adjustment_note: (record.get("expert_adjustment_note") as string | null) ?? undefined,
          mitigation_reference: (record.get("mitigation_reference") as string | null) ?? undefined
        })),
        do326a_links: result.linksRes.records.map((record) => {
          const properties = record.get("l").properties as Record<string, unknown>;
          return {
            link_id: String(properties.link_id),
            standard_id: String(properties.standard_id),
            clause_title: String(properties.clause_title),
            semantic_element_id: ((properties.semantic_element_id as unknown[]) ?? []).map((value) => String(value)),
            linkage_type: properties.linkage_type as GraphSnapshot["do326a_links"][number]["linkage_type"],
            evidence_reference: (properties.evidence_reference as string | undefined) ?? undefined,
            review_status: properties.review_status as GraphSnapshot["do326a_links"][number]["review_status"],
            reviewer: (properties.reviewer as string | undefined) ?? undefined,
            mapping_version: (properties.mapping_version as string | undefined) ?? undefined
          };
        }),
        function_nodes: result.functionsRes.records.map((record) => {
          const properties = record.get("f").properties as Record<string, unknown>;
          return {
            function_id: String(properties.function_id),
            name: String(properties.name),
            description: (properties.description as string | undefined) ?? undefined
          };
        }),
        trust_boundaries: result.boundariesRes.records.map((record) => ({
          boundary_id: record.get("boundary_id") as string,
          name: record.get("name") as string,
          description: (record.get("description") as string | null) ?? undefined,
          enters_internal_propagation: (record.get("enters_internal_propagation") as boolean | null) ?? undefined,
          interface_asset_ids: ((record.get("interface_asset_ids") as unknown[]) ?? []).map((value) => String(value)),
          domain_asset_ids: ((record.get("domain_asset_ids") as unknown[]) ?? []).map((value) => String(value))
        })),
        threat_actors: result.actorsRes.records.map((record) => ({
          actor_id: record.get("actor_id") as string,
          name: record.get("name") as string,
          actor_type: record.get("actor_type") as GraphSnapshot["threat_actors"][number]["actor_type"],
          description: (record.get("description") as string | null) ?? undefined,
          boundary_ids: ((record.get("boundary_ids") as unknown[]) ?? []).map((value) => String(value))
        })),
        boundary_interfaces: result.interfacesRes.records.map((record) => {
          const properties = record.get("bi").properties as Record<string, unknown>;
          return {
            interface_id: String(properties.interface_id),
            name: (properties.name as string | undefined) ?? undefined,
            interface_class: (properties.interface_class as string | undefined) ?? undefined,
            external_entity: (properties.external_entity as string | undefined) ?? undefined,
            access_object: (properties.access_object as string | undefined) ?? undefined,
            physical_interconnect: (properties.physical_interconnect as string | undefined) ?? undefined,
            logical_protocol: (properties.logical_protocol as string | undefined) ?? undefined,
            direction: (properties.direction as string | undefined) ?? undefined,
            boundary_id: (properties.boundary_id as string | undefined) ?? undefined,
            description: (properties.description as string | undefined) ?? undefined
          };
        }),
        system_data_flows: result.sdfRes.records.map((record) => ({
          sdf_id: record.get("sdf_id") as string,
          producer: (record.get("producer") as string | null) ?? undefined,
          consumer: (record.get("consumer") as string | null) ?? undefined,
          content: (record.get("content") as string | null) ?? undefined,
          data_flow_type: (record.get("data_flow_type") as string | null) ?? undefined,
          description: (record.get("description") as string | null) ?? undefined,
          function_ids: ((record.get("function_ids") as unknown[]) ?? []).map((value) => String(value))
        })),
        function_propagation_paths: result.fpRes.records.map((record) => ({
          fp_id: record.get("fp_id") as string,
          data_type_label: (record.get("data_type_label") as string | null) ?? undefined,
          system_path_text: (record.get("system_path_text") as string | null) ?? undefined,
          sdf_note: (record.get("sdf_note") as string | null) ?? undefined,
          description: (record.get("description") as string | null) ?? undefined,
          bdf_ids: ((record.get("bdf_ids") as unknown[]) ?? []).map((value) => String(value)),
          sdf_ids: ((record.get("sdf_ids") as unknown[]) ?? []).map((value) => String(value))
        }))
      };
    } finally {
      await session.close();
    }
  }

  async validateChangeSet(changeSet: GraphChangeSet): Promise<{ valid: boolean; errors: string[] }> {
    const session = getDriver().session();
    try {
      const errors = await this.collectChangeSetValidationErrors(session, changeSet);
      return { valid: errors.length === 0, errors };
    } finally {
      await session.close();
    }
  }

  async commitChangeSet(changeSet: GraphChangeSet, userId: string): Promise<{ new_version: string; commit_id: string }> {
    const session = getDriver().session();
    const commitId = crypto.randomUUID();
    const newVersion = `v_${Date.now()}`;

    try {
      await session.executeWrite(async (tx) => {
        const validationErrors = await this.collectChangeSetValidationErrors(tx, changeSet);
        if (validationErrors.length > 0) {
          throw new GraphChangeSetValidationError(validationErrors);
        }

        for (const linkId of changeSet.do326a_links.delete) {
          await tx.run("MATCH (l:DO326A_Link {link_id: $link_id}) DETACH DELETE l", { link_id: linkId });
        }
        for (const threatId of changeSet.threat_points.delete) {
          await tx.run("MATCH (th:ThreatPoint {threatpoint_id: $threatpoint_id}) DETACH DELETE th", {
            threatpoint_id: threatId
          });
        }
        for (const edgeId of changeSet.asset_edges.delete) {
          await tx.run("MATCH ()-[r:ASSET_EDGE {edge_id: $edge_id}]-() DELETE r", { edge_id: edgeId });
        }
        for (const assetId of changeSet.asset_nodes.delete) {
          await tx.run("MATCH (a:AssetNode {asset_id: $asset_id}) DETACH DELETE a", { asset_id: assetId });
        }
        for (const functionId of changeSet.function_nodes?.delete ?? []) {
          await tx.run("MATCH (f:FunctionNode {function_id: $function_id}) DETACH DELETE f", { function_id: functionId });
        }
        for (const boundaryId of changeSet.trust_boundaries?.delete ?? []) {
          await tx.run("MATCH (sb:TrustBoundary {boundary_id: $boundary_id}) DETACH DELETE sb", { boundary_id: boundaryId });
        }
        for (const actorId of changeSet.threat_actors?.delete ?? []) {
          await tx.run("MATCH (ta:ThreatActor {actor_id: $actor_id}) DETACH DELETE ta", { actor_id: actorId });
        }
        for (const interfaceId of changeSet.boundary_interfaces?.delete ?? []) {
          await tx.run("MATCH (bi:BoundaryInterface {interface_id: $interface_id}) DETACH DELETE bi", { interface_id: interfaceId });
        }
        for (const sdfId of changeSet.system_data_flows?.delete ?? []) {
          await tx.run("MATCH (sdf:SystemDataFlow {sdf_id: $sdf_id}) DETACH DELETE sdf", { sdf_id: sdfId });
        }
        for (const fpId of changeSet.function_propagation_paths?.delete ?? []) {
          await tx.run("MATCH (fp:FunctionPropagationPath {fp_id: $fp_id}) DETACH DELETE fp", { fp_id: fpId });
        }

        for (const asset of [...changeSet.asset_nodes.add, ...changeSet.asset_nodes.update]) {
          await tx.run(
            "MERGE (a:AssetNode {asset_id: $asset_id}) SET a.asset_name = $asset_name, a.asset_type = $asset_type, a.criticality = $criticality, a.security_domain = $security_domain, a.description = $description, a.data_classification = $data_classification, a.tags = $tags, a.is_placeholder = $is_placeholder, a.source = $source, a.business_id = $business_id, a.data_flow_type = $data_flow_type, a.bdf_ids = $bdf_ids, a.enters_internal_propagation = $enters_internal_propagation, a.boundary_interface_id = $boundary_interface_id",
            {
              ...asset,
              security_domain: asset.security_domain ?? null,
              description: asset.description ?? null,
              data_classification: asset.data_classification ?? null,
              tags: asset.tags ?? [],
              is_placeholder: asset.is_placeholder ?? false,
              source: asset.source ?? null,
              business_id: asset.business_id ?? null,
              data_flow_type: asset.data_flow_type ?? null,
              bdf_ids: asset.bdf_ids ?? [],
              enters_internal_propagation: asset.enters_internal_propagation ?? null,
              boundary_interface_id: asset.boundary_interface_id ?? null
            }
          );
        }

        for (const fn of [...(changeSet.function_nodes?.add ?? []), ...(changeSet.function_nodes?.update ?? [])]) {
          await tx.run(
            "MERGE (f:FunctionNode {function_id: $function_id}) SET f.name = $name, f.description = $description",
            { ...fn, description: fn.description ?? null }
          );
        }

        for (const boundary of [
          ...(changeSet.trust_boundaries?.add ?? []),
          ...(changeSet.trust_boundaries?.update ?? [])
        ]) {
          await tx.run(
            "MERGE (sb:TrustBoundary {boundary_id: $boundary_id}) SET sb.name = $name, sb.description = $description, sb.enters_internal_propagation = $enters_internal_propagation WITH sb OPTIONAL MATCH (sb)-[old:HAS_INTERFACE|COVERS_DOMAIN]->() DELETE old",
            {
              boundary_id: boundary.boundary_id,
              name: boundary.name,
              description: boundary.description ?? null,
              enters_internal_propagation: boundary.enters_internal_propagation ?? null
            }
          );
          await tx.run(
            "MATCH (sb:TrustBoundary {boundary_id: $boundary_id}) UNWIND $domain_asset_ids AS did MATCH (d:AssetNode {asset_id: did}) MERGE (sb)-[:COVERS_DOMAIN]->(d)",
            { boundary_id: boundary.boundary_id, domain_asset_ids: boundary.domain_asset_ids ?? [] }
          );
        }

        for (const bi of [
          ...(changeSet.boundary_interfaces?.add ?? []),
          ...(changeSet.boundary_interfaces?.update ?? [])
        ]) {
          await tx.run(
            "MERGE (bi:BoundaryInterface {interface_id: $interface_id}) SET bi.name = $name, bi.interface_class = $interface_class, bi.external_entity = $external_entity, bi.access_object = $access_object, bi.physical_interconnect = $physical_interconnect, bi.logical_protocol = $logical_protocol, bi.direction = $direction, bi.boundary_id = $boundary_id, bi.description = $description WITH bi OPTIONAL MATCH (bi)-[old:CARRIES_FLOW]->() DELETE old WITH bi OPTIONAL MATCH (sb:TrustBoundary)-[oldhi:HAS_INTERFACE]->(bi) DELETE oldhi",
            {
              interface_id: bi.interface_id,
              name: bi.name ?? null,
              interface_class: bi.interface_class ?? null,
              external_entity: bi.external_entity ?? null,
              access_object: bi.access_object ?? null,
              physical_interconnect: bi.physical_interconnect ?? null,
              logical_protocol: bi.logical_protocol ?? null,
              direction: bi.direction ?? null,
              boundary_id: bi.boundary_id ?? null,
              description: bi.description ?? null
            }
          );
          if (bi.boundary_id) {
            await tx.run(
              "MATCH (bi:BoundaryInterface {interface_id: $interface_id}), (sb:TrustBoundary {boundary_id: $boundary_id}) MERGE (sb)-[:HAS_INTERFACE]->(bi)",
              { interface_id: bi.interface_id, boundary_id: bi.boundary_id }
            );
          }
        }

        // Link each BDF interface asset to the boundary interface it flows over.
        for (const asset of [...changeSet.asset_nodes.add, ...changeSet.asset_nodes.update]) {
          if (!asset.boundary_interface_id) {
            continue;
          }
          await tx.run(
            "MATCH (bi:BoundaryInterface {interface_id: $interface_id}), (a:AssetNode {asset_id: $asset_id}) MERGE (bi)-[:CARRIES_FLOW]->(a)",
            { interface_id: asset.boundary_interface_id, asset_id: asset.asset_id }
          );
        }

        for (const actor of [...(changeSet.threat_actors?.add ?? []), ...(changeSet.threat_actors?.update ?? [])]) {
          await tx.run(
            "MERGE (ta:ThreatActor {actor_id: $actor_id}) SET ta.name = $name, ta.actor_type = $actor_type, ta.description = $description WITH ta OPTIONAL MATCH (ta)-[old:THREATENS]->() DELETE old",
            { actor_id: actor.actor_id, name: actor.name, actor_type: actor.actor_type, description: actor.description ?? null }
          );
          await tx.run(
            "MATCH (ta:ThreatActor {actor_id: $actor_id}) UNWIND $boundary_ids AS bid MATCH (sb:TrustBoundary {boundary_id: bid}) MERGE (ta)-[:THREATENS]->(sb)",
            { actor_id: actor.actor_id, boundary_ids: actor.boundary_ids ?? [] }
          );
        }

        for (const sdf of [
          ...(changeSet.system_data_flows?.add ?? []),
          ...(changeSet.system_data_flows?.update ?? [])
        ]) {
          await tx.run(
            "MERGE (sdf:SystemDataFlow {sdf_id: $sdf_id}) SET sdf.producer = $producer, sdf.consumer = $consumer, sdf.content = $content, sdf.data_flow_type = $data_flow_type, sdf.description = $description WITH sdf OPTIONAL MATCH (sdf)-[old:SUPPORTS_FUNCTION]->() DELETE old",
            {
              sdf_id: sdf.sdf_id,
              producer: sdf.producer ?? null,
              consumer: sdf.consumer ?? null,
              content: sdf.content ?? null,
              data_flow_type: sdf.data_flow_type ?? null,
              description: sdf.description ?? null
            }
          );
          await tx.run(
            "MATCH (sdf:SystemDataFlow {sdf_id: $sdf_id}) UNWIND $function_ids AS fid MATCH (f:FunctionNode {function_id: fid}) MERGE (sdf)-[:SUPPORTS_FUNCTION]->(f)",
            { sdf_id: sdf.sdf_id, function_ids: sdf.function_ids ?? [] }
          );
        }

        for (const fp of [
          ...(changeSet.function_propagation_paths?.add ?? []),
          ...(changeSet.function_propagation_paths?.update ?? [])
        ]) {
          await tx.run(
            "MERGE (fp:FunctionPropagationPath {fp_id: $fp_id}) SET fp.data_type_label = $data_type_label, fp.system_path_text = $system_path_text, fp.sdf_note = $sdf_note, fp.description = $description WITH fp OPTIONAL MATCH (fp)-[old:INCLUDES_BDF|INCLUDES_SDF]->() DELETE old",
            {
              fp_id: fp.fp_id,
              data_type_label: fp.data_type_label ?? null,
              system_path_text: fp.system_path_text ?? null,
              sdf_note: fp.sdf_note ?? null,
              description: fp.description ?? null
            }
          );
          await tx.run(
            "MATCH (fp:FunctionPropagationPath {fp_id: $fp_id}) UNWIND $bdf_ids AS bid MATCH (a:AssetNode {business_id: bid}) MERGE (fp)-[:INCLUDES_BDF]->(a)",
            { fp_id: fp.fp_id, bdf_ids: fp.bdf_ids ?? [] }
          );
          await tx.run(
            "MATCH (fp:FunctionPropagationPath {fp_id: $fp_id}) UNWIND $sdf_ids AS sid MATCH (sdf:SystemDataFlow {sdf_id: sid}) MERGE (fp)-[:INCLUDES_SDF]->(sdf)",
            { fp_id: fp.fp_id, sdf_ids: fp.sdf_ids ?? [] }
          );
        }

        for (const link of changeSet.function_links ?? []) {
          await tx.run(
            "MATCH (a:AssetNode {asset_id: $asset_id}), (f:FunctionNode {function_id: $function_id}) MERGE (a)-[:SUPPORTS_FUNCTION]->(f)",
            { asset_id: link.asset_id, function_id: link.function_id }
          );
        }

        for (const edge of [...changeSet.asset_edges.add, ...changeSet.asset_edges.update]) {
          await tx.run(
            "MATCH (s:AssetNode {asset_id: $source_asset_id}), (t:AssetNode {asset_id: $target_asset_id}) MERGE (s)-[r:ASSET_EDGE {edge_id: $edge_id}]->(t) SET r.link_type = $link_type, r.protocol_or_medium = $protocol_or_medium, r.direction = $direction, r.trust_level = $trust_level, r.security_mechanism = $security_mechanism, r.description = $description",
            {
              ...edge,
              protocol_or_medium: edge.protocol_or_medium ?? null,
              trust_level: edge.trust_level ?? null,
              security_mechanism: edge.security_mechanism ?? null,
              description: edge.description ?? null
            }
          );
        }

        for (const threat of [...changeSet.threat_points.add, ...changeSet.threat_points.update]) {
          await tx.run(
            "MERGE (th:ThreatPoint {threatpoint_id: $threatpoint_id}) SET th.name = $name, th.stride_category = $stride_category, th.attack_vector = $attack_vector, th.entry_likelihood_level = $entry_likelihood_level, th.attack_complexity_level = $attack_complexity_level, th.threat_source = $threat_source, th.preconditions = $preconditions, th.detection_status = $detection_status, th.cve_reference = $cve_reference, th.expert_modifier = $expert_modifier, th.expert_adjustment_note = $expert_adjustment_note, th.mitigation_reference = $mitigation_reference WITH th OPTIONAL MATCH (th)-[old:OVERLAY_ON]->() DELETE old WITH th MATCH (a:AssetNode {asset_id: $related_asset_id}) MERGE (th)-[:OVERLAY_ON]->(a)",
            {
              ...threat,
              preconditions: threat.preconditions ?? null,
              detection_status: threat.detection_status ?? null,
              cve_reference: threat.cve_reference ?? null,
              expert_modifier: threat.expert_modifier ?? 1.0,
              expert_adjustment_note: threat.expert_adjustment_note ?? null,
              mitigation_reference: threat.mitigation_reference ?? null
            }
          );
        }

        for (const link of [...changeSet.do326a_links.add, ...changeSet.do326a_links.update]) {
          await tx.run(
            "MERGE (l:DO326A_Link {link_id: $link_id}) SET l.standard_id = $standard_id, l.clause_title = $clause_title, l.semantic_element_id = $semantic_element_id, l.linkage_type = $linkage_type, l.evidence_reference = $evidence_reference, l.review_status = $review_status, l.reviewer = $reviewer, l.mapping_version = $mapping_version",
            {
              ...link,
              evidence_reference: link.evidence_reference ?? null,
              reviewer: link.reviewer ?? null,
              mapping_version: link.mapping_version ?? null
            }
          );

          await tx.run(
            "MATCH (l:DO326A_Link {link_id: $link_id}) OPTIONAL MATCH (l)-[old:MAPS_TO]->() DELETE old",
            { link_id: link.link_id }
          );
          await tx.run(
            "MATCH (l:DO326A_Link {link_id: $link_id}) UNWIND $semantic_element_id AS sem_id OPTIONAL MATCH (a:AssetNode {asset_id: sem_id}) OPTIONAL MATCH (th:ThreatPoint {threatpoint_id: sem_id}) OPTIONAL MATCH (p:AttackPath {path_id: sem_id}) WITH l, sem_id, coalesce(a, th, p) AS target WHERE target IS NOT NULL MERGE (l)-[:MAPS_TO {semantic_element_id: sem_id}]->(target)",
            {
              link_id: link.link_id,
              semantic_element_id: link.semantic_element_id
            }
          );
        }

        await tx.run("MATCH (v:GraphVersion {id: $id}) SET v.value = $new_version", {
          id: graphVersionNodeId,
          new_version: newVersion
        });

        await tx.run(
          "CREATE (c:CommitAudit {commit_id: $commit_id, user_id: $user_id, created_at: datetime(), summary: $summary, new_version: $new_version})",
          {
            commit_id: commitId,
            user_id: userId,
            new_version: newVersion,
            summary: `asset_nodes(+${changeSet.asset_nodes.add.length}/~${changeSet.asset_nodes.update.length}/-${changeSet.asset_nodes.delete.length}), asset_edges(+${changeSet.asset_edges.add.length}/~${changeSet.asset_edges.update.length}/-${changeSet.asset_edges.delete.length}), threat_points(+${changeSet.threat_points.add.length}/~${changeSet.threat_points.update.length}/-${changeSet.threat_points.delete.length}), do326a_links(+${changeSet.do326a_links.add.length}/~${changeSet.do326a_links.update.length}/-${changeSet.do326a_links.delete.length})`
          }
        );
      });

      return { new_version: newVersion, commit_id: commitId };
    } finally {
      await session.close();
    }
  }

  async getGraphVersion(): Promise<string> {
    const session = getDriver().session();
    try {
      const result = await session.run("MATCH (v:GraphVersion {id: $id}) RETURN v.value AS version", {
        id: graphVersionNodeId
      });
      return (result.records[0]?.get("version") as string) ?? "v1";
    } finally {
      await session.close();
    }
  }

  async getModelingExportBundle(analysisBatchId?: string): Promise<ModelingExportBundle> {
    const [graph, analysis_paths, do326a_links] = await Promise.all([
      this.getGraph(),
      this.getAttackPaths(analysisBatchId),
      this.getDo326ALinks()
    ]);

    return {
      graph,
      analysis_paths,
      do326a_links
    };
  }

  /** vol3 §4.2 信任边界汇总表: SB | 说明 | 对应接口(BI) | 相关威胁主体(TA). */
  async getTrustBoundaryReport(): Promise<TrustBoundaryReportRow[]> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) =>
        tx.run(
          `MATCH (sb:TrustBoundary)
           OPTIONAL MATCH (sb)-[:HAS_INTERFACE]->(bi:BoundaryInterface)
           OPTIONAL MATCH (ta:ThreatActor)-[:THREATENS]->(sb)
           RETURN sb.boundary_id AS boundary_id, sb.name AS name, sb.description AS description,
                  collect(DISTINCT bi.interface_id) AS interfaces,
                  collect(DISTINCT ta.actor_id) AS threat_actors
           ORDER BY boundary_id`
        )
      );
      return result.records.map((record) => ({
        boundary_id: record.get("boundary_id") as string,
        name: record.get("name") as string,
        description: (record.get("description") as string | null) ?? undefined,
        interfaces: ((record.get("interfaces") as unknown[]) ?? [])
          .filter((value) => value !== null && value !== undefined)
          .map((value) => String(value))
          .sort(),
        threat_actors: ((record.get("threat_actors") as unknown[]) ?? [])
          .filter((value) => value !== null && value !== undefined)
          .map((value) => String(value))
          .sort()
      }));
    } finally {
      await session.close();
    }
  }

  /**
   * vol3 §4.3.x 边界数据流分析表: 数据流类型 | 典型接口(BI) | 关联BDF | 关联功能(F) | 是否进入内部传播.
   * Grouped by (boundary, data_flow_type, enters_internal_propagation) so that a mixed group —
   * e.g. SB-01 DATA carrying both an inbound 是 flow and outbound 否 read-outs — splits into a 是
   * row and a 否 row instead of collapsing to one 是 row.
   */
  async getBoundaryDataFlowReport(): Promise<BoundaryDataFlowReportRow[]> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) =>
        tx.run(
          `MATCH (sb:TrustBoundary)-[:HAS_INTERFACE]->(bi:BoundaryInterface)-[:CARRIES_FLOW]->(bdf:AssetNode)
           OPTIONAL MATCH (bdf)-[:SUPPORTS_FUNCTION]->(f:FunctionNode)
           RETURN sb.boundary_id AS boundary_id, sb.name AS boundary_name,
                  bi.interface_id AS interface_id,
                  bdf.business_id AS bdf_id,
                  coalesce(bdf.data_flow_type, 'UNSPECIFIED') AS data_flow_type,
                  coalesce(bdf.enters_internal_propagation, sb.enters_internal_propagation, false) AS enters_internal_propagation,
                  collect(DISTINCT f.function_id) AS function_ids
           ORDER BY boundary_id, data_flow_type, interface_id, bdf_id`
        )
      );

      // Aggregate per (boundary, data_flow_type, enters_internal_propagation) in JS.
      const groups = new Map<string, BoundaryDataFlowReportRow>();
      for (const record of result.records) {
        const boundaryId = record.get("boundary_id") as string;
        const dataFlowType = record.get("data_flow_type") as string;
        const entersInternal = (record.get("enters_internal_propagation") as boolean | null) === true;
        const key = `${boundaryId} ${dataFlowType} ${entersInternal}`;
        const row =
          groups.get(key) ??
          ({
            boundary_id: boundaryId,
            boundary_name: record.get("boundary_name") as string,
            data_flow_type: dataFlowType,
            interfaces: [],
            bdf_ids: [],
            function_ids: [],
            enters_internal_propagation: entersInternal
          } satisfies BoundaryDataFlowReportRow);

        const interfaceId = record.get("interface_id") as string | null;
        if (interfaceId) {
          row.interfaces.push(String(interfaceId));
        }
        const bdfId = record.get("bdf_id") as string | null;
        if (bdfId) {
          row.bdf_ids.push(String(bdfId));
        }
        for (const fn of (record.get("function_ids") as unknown[]) ?? []) {
          if (fn !== null && fn !== undefined) {
            row.function_ids.push(String(fn));
          }
        }
        groups.set(key, row);
      }

      return Array.from(groups.values())
        .map((row) => ({
          ...row,
          interfaces: Array.from(new Set(row.interfaces)).sort(),
          bdf_ids: Array.from(new Set(row.bdf_ids)).sort(),
          function_ids: Array.from(new Set(row.function_ids)).sort()
        }))
        .sort((a, b) => {
          if (a.boundary_id !== b.boundary_id) {
            return a.boundary_id.localeCompare(b.boundary_id);
          }
          if (a.data_flow_type !== b.data_flow_type) {
            return a.data_flow_type.localeCompare(b.data_flow_type);
          }
          // 是 (enters internal propagation) before 否
          return a.enters_internal_propagation === b.enters_internal_propagation ? 0 : a.enters_internal_propagation ? -1 : 1;
        });
    } finally {
      await session.close();
    }
  }

  /** vol3 表4-5 功能传播路径(FP): FP | 数据类型 | 入口BI | 关联BDF | 关联SDF | 系统传播路径 | 影响功能. */
  async getFunctionPropagationReport(): Promise<FunctionPropagationReportRow[]> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead((tx) =>
        tx.run(
          `MATCH (fp:FunctionPropagationPath)
           OPTIONAL MATCH (fp)-[:INCLUDES_BDF]->(bdf:AssetNode)
           OPTIONAL MATCH (bi:BoundaryInterface)-[:CARRIES_FLOW]->(bdf)
           OPTIONAL MATCH (bdf)-[:SUPPORTS_FUNCTION]->(fb:FunctionNode)
           OPTIONAL MATCH (fp)-[:INCLUDES_SDF]->(sdf:SystemDataFlow)
           OPTIONAL MATCH (sdf)-[:SUPPORTS_FUNCTION]->(fs:FunctionNode)
           RETURN fp.fp_id AS fp_id, fp.data_type_label AS data_type,
                  fp.system_path_text AS system_path, fp.sdf_note AS sdf_note,
                  collect(DISTINCT bi.interface_id) AS entry_bis,
                  collect(DISTINCT bdf.business_id) AS bdf_ids,
                  collect(DISTINCT sdf.sdf_id) AS sdf_ids,
                  collect(DISTINCT fb.function_id) AS bdf_function_ids,
                  collect(DISTINCT fs.function_id) AS sdf_function_ids
           ORDER BY fp_id`
        )
      );

      const toIds = (value: unknown): string[] =>
        ((value as unknown[]) ?? []).filter((item) => item !== null && item !== undefined).map((item) => String(item));

      return result.records.map((record) => {
        const functionIds = sortByTrailingNumber([
          ...toIds(record.get("bdf_function_ids")),
          ...toIds(record.get("sdf_function_ids"))
        ]);
        return {
          fp_id: record.get("fp_id") as string,
          data_type: (record.get("data_type") as string | null) ?? "",
          entry_bis: sortByTrailingNumber(toIds(record.get("entry_bis"))),
          bdf_ids: sortByTrailingNumber(toIds(record.get("bdf_ids"))),
          sdf_ids: sortByTrailingNumber(toIds(record.get("sdf_ids"))),
          sdf_note: (record.get("sdf_note") as string | null) ?? undefined,
          system_path: (record.get("system_path") as string | null) ?? "",
          function_ids: functionIds
        } satisfies FunctionPropagationReportRow;
      });
    } finally {
      await session.close();
    }
  }

  /**
   * Internal data flow analysis (IMS-centric): one row per SystemDataFlow, flagging which flows
   * are NOT reachable from any boundary entry (pure internal flows). Reuses the FP traversal logic
   * (collectBoundaryReachableSdfIds) for the reachable set; does not change FP/report output.
   */
  async getInternalDataFlowReport(): Promise<InternalDataFlowReportRow[]> {
    const isIms = (name: string): boolean => name.trim().toUpperCase() === "IMS";
    const session = getDriver().session();
    let sdfRows: Array<{
      sdf_id: string;
      producer: string;
      consumer: string;
      data_flow_type: string;
      content?: string;
      function_ids: string[];
    }>;
    try {
      const result = await session.executeRead((tx) =>
        tx.run(
          `MATCH (sdf:SystemDataFlow)
           OPTIONAL MATCH (sdf)-[:SUPPORTS_FUNCTION]->(f:FunctionNode)
           RETURN sdf.sdf_id AS sdf_id, sdf.producer AS producer, sdf.consumer AS consumer,
                  sdf.data_flow_type AS data_flow_type, sdf.content AS content,
                  collect(DISTINCT f.function_id) AS function_ids
           ORDER BY sdf_id`
        )
      );
      const toIds = (value: unknown): string[] =>
        ((value as unknown[]) ?? []).filter((item) => item !== null && item !== undefined).map((item) => String(item));
      sdfRows = result.records.map((record) => ({
        sdf_id: String(record.get("sdf_id")),
        producer: (record.get("producer") as string | null) ?? "",
        consumer: (record.get("consumer") as string | null) ?? "",
        data_flow_type: (record.get("data_flow_type") as string | null) ?? "",
        content: (record.get("content") as string | null) ?? undefined,
        function_ids: sortByTrailingNumber(toIds(record.get("function_ids")))
      }));
    } finally {
      await session.close();
    }

    const inputs = await this.getFunctionPropagationInputs();
    const reachable = collectBoundaryReachableSdfIds(inputs);

    const originClass = (producer: string, consumer: string): string => {
      if (isIms(producer)) {
        return "IMS发起";
      }
      if (isIms(consumer)) {
        return "汇入IMS";
      }
      return "其他内部";
    };
    const orderRank = (originClass: string): number =>
      originClass === "IMS发起" ? 0 : originClass === "汇入IMS" ? 1 : 2;
    const trailingNumber = (id: string): number => {
      const match = id.match(/(\d+)\s*$/);
      return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
    };

    return sdfRows
      .map((row) => ({
        sdf_id: row.sdf_id,
        producer: row.producer,
        consumer: row.consumer,
        data_flow_type: row.data_flow_type,
        content: row.content,
        function_ids: row.function_ids,
        origin_class: originClass(row.producer, row.consumer),
        boundary_reachable: reachable.has(row.sdf_id)
      } satisfies InternalDataFlowReportRow))
      .sort((a, b) => {
        const rankDiff = orderRank(a.origin_class) - orderRank(b.origin_class);
        if (rankDiff !== 0) {
          return rankDiff;
        }
        return trailingNumber(a.sdf_id) - trailingNumber(b.sdf_id);
      });
  }

  /** Reads BDF start points (with entry subsystem from BI) + SDF edges for FP analysis. */
  async getFunctionPropagationInputs(): Promise<FpAnalysisInput> {
    const session = getDriver().session();
    try {
      const { bdfRes, sdfRes } = await session.executeRead(async (tx) => {
        const [bdfRes, sdfRes] = await Promise.all([
          tx.run(
            `MATCH (bdf:AssetNode) WHERE bdf.boundary_interface_id IS NOT NULL
             OPTIONAL MATCH (bi:BoundaryInterface {interface_id: bdf.boundary_interface_id})
             OPTIONAL MATCH (sb:TrustBoundary {boundary_id: bi.boundary_id})
             OPTIONAL MATCH (bdf)-[:SUPPORTS_FUNCTION]->(f:FunctionNode)
             RETURN bdf.business_id AS business_id, bdf.data_flow_type AS data_flow_type,
                    bdf.boundary_interface_id AS boundary_interface_id,
                    bi.access_object AS entry_subsystem, bi.external_entity AS external_entity,
                    bi.boundary_id AS entry_boundary,
                    coalesce(bdf.enters_internal_propagation, sb.enters_internal_propagation) AS enters_internal_propagation,
                    collect(DISTINCT f.function_id) AS function_ids
             ORDER BY business_id`
          ),
          tx.run(
            `MATCH (sdf:SystemDataFlow)
             OPTIONAL MATCH (sdf)-[:SUPPORTS_FUNCTION]->(f:FunctionNode)
             RETURN sdf.sdf_id AS sdf_id, sdf.producer AS producer, sdf.consumer AS consumer,
                    sdf.data_flow_type AS data_flow_type, collect(DISTINCT f.function_id) AS function_ids
             ORDER BY sdf_id`
          )
        ]);
        return { bdfRes, sdfRes };
      });

      const toIds = (value: unknown): string[] =>
        ((value as unknown[]) ?? []).filter((item) => item !== null && item !== undefined).map((item) => String(item));

      return {
        bdfs: bdfRes.records
          .filter((record) => record.get("business_id"))
          // A BDF only seeds internal propagation if it injects inward. Outbound read-out flows
          // marked 否 (enters_internal_propagation=false, on the BDF or its SB) are excluded as
          // start points — so they no longer drive FP or boundary-reachability. Unset → included
          // (backward compatible with templates that lack the column).
          .filter((record) => record.get("enters_internal_propagation") !== false)
          .map((record) => ({
            business_id: String(record.get("business_id")),
            data_flow_type: (record.get("data_flow_type") as string | null) ?? undefined,
            boundary_interface_id: (record.get("boundary_interface_id") as string | null) ?? undefined,
            entry_subsystem: (record.get("entry_subsystem") as string | null) ?? undefined,
            external_entity: (record.get("external_entity") as string | null) ?? undefined,
            entry_boundary: (record.get("entry_boundary") as string | null) ?? undefined,
            function_ids: toIds(record.get("function_ids"))
          })),
        sdfs: sdfRes.records.map((record) => ({
          sdf_id: String(record.get("sdf_id")),
          producer: (record.get("producer") as string | null) ?? undefined,
          consumer: (record.get("consumer") as string | null) ?? undefined,
          data_flow_type: (record.get("data_flow_type") as string | null) ?? undefined,
          function_ids: toIds(record.get("function_ids"))
        }))
      };
    } finally {
      await session.close();
    }
  }

  /** Replaces all FunctionPropagationPath nodes (and their INCLUDES_* links) with the computed set. */
  async replaceFunctionPropagationPaths(paths: FunctionPropagationPath[]): Promise<number> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run("MATCH (fp:FunctionPropagationPath) DETACH DELETE fp");
        for (const fp of paths) {
          await tx.run(
            "MERGE (fp:FunctionPropagationPath {fp_id: $fp_id}) SET fp.data_type_label = $data_type_label, fp.system_path_text = $system_path_text, fp.sdf_note = $sdf_note, fp.description = $description",
            {
              fp_id: fp.fp_id,
              data_type_label: fp.data_type_label ?? null,
              system_path_text: fp.system_path_text ?? null,
              sdf_note: fp.sdf_note ?? null,
              description: fp.description ?? null
            }
          );
          await tx.run(
            "MATCH (fp:FunctionPropagationPath {fp_id: $fp_id}) UNWIND $bdf_ids AS bid MATCH (a:AssetNode {business_id: bid}) MERGE (fp)-[:INCLUDES_BDF]->(a)",
            { fp_id: fp.fp_id, bdf_ids: fp.bdf_ids ?? [] }
          );
          await tx.run(
            "MATCH (fp:FunctionPropagationPath {fp_id: $fp_id}) UNWIND $sdf_ids AS sid MATCH (sdf:SystemDataFlow {sdf_id: sid}) MERGE (fp)-[:INCLUDES_SDF]->(sdf)",
            { fp_id: fp.fp_id, sdf_ids: fp.sdf_ids ?? [] }
          );
        }
      });
      return paths.length;
    } finally {
      await session.close();
    }
  }

  async persistAttackPaths(paths: AttackPath[]): Promise<number> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        const pathsByBatch = new Map<string, string[]>();
        for (const path of paths) {
          const batchPathIds = pathsByBatch.get(path.analysis_batch_id) ?? [];
          batchPathIds.push(path.path_id);
          pathsByBatch.set(path.analysis_batch_id, batchPathIds);
        }

        for (const [analysis_batch_id, path_ids] of pathsByBatch.entries()) {
          await tx.run(
            "MATCH (p:AttackPath {analysis_batch_id: $analysis_batch_id}) WHERE NOT p.path_id IN $path_ids DETACH DELETE p",
            { analysis_batch_id, path_ids }
          );
        }

        for (const path of paths) {
          await tx.run(
            "MERGE (p:AttackPath {analysis_batch_id: $analysis_batch_id, path_id: $path_id}) SET p.entry_point_id = $entry_point_id, p.target_asset_id = $target_asset_id, p.hop_sequence = $hop_sequence, p.hop_count = $hop_count, p.path_probability = $path_probability, p.raw_score = $raw_score, p.dps_score = $dps_score, p.heuristic_score = $heuristic_score, p.normalized_score = $normalized_score, p.priority_label = $priority_label, p.is_low_priority = $is_low_priority, p.score_config_version = $score_config_version, p.explanations = $explanations, p.generated_by = $generated_by, p.generated_at = datetime($generated_at)",
            path
          );

          await tx.run(
            "MATCH (p:AttackPath {analysis_batch_id: $analysis_batch_id, path_id: $path_id}) OPTIONAL MATCH (p)-[old:STARTS_FROM|TARGETS|TRAVERSES]->() DELETE old",
            { analysis_batch_id: path.analysis_batch_id, path_id: path.path_id }
          );
          await tx.run(
            "MATCH (p:AttackPath {analysis_batch_id: $analysis_batch_id, path_id: $path_id}), (th:ThreatPoint {threatpoint_id: $entry_point_id}) MERGE (p)-[:STARTS_FROM]->(th)",
            { analysis_batch_id: path.analysis_batch_id, path_id: path.path_id, entry_point_id: path.entry_point_id }
          );
          await tx.run(
            "MATCH (p:AttackPath {analysis_batch_id: $analysis_batch_id, path_id: $path_id}), (a:AssetNode {asset_id: $target_asset_id}) MERGE (p)-[:TARGETS]->(a)",
            { analysis_batch_id: path.analysis_batch_id, path_id: path.path_id, target_asset_id: path.target_asset_id }
          );

          for (const traverse of path.traverses) {
            await tx.run(
              "MATCH (p:AttackPath {analysis_batch_id: $analysis_batch_id, path_id: $path_id}), (a:AssetNode {asset_id: $asset_id}) MERGE (p)-[r:TRAVERSES {hop: $hop, edge_id: $edge_id}]->(a) SET r.edge_factor = $edge_factor",
              {
                analysis_batch_id: path.analysis_batch_id,
                path_id: path.path_id,
                hop: traverse.hop,
                edge_id: traverse.edge_id,
                asset_id: traverse.asset_id,
                edge_factor: traverse.edge_factor
              }
            );
          }
        }
      });
      return paths.length;
    } finally {
      await session.close();
    }
  }

  async getAttackPaths(analysisBatchId?: string): Promise<AttackPath[]> {
    const session = getDriver().session();
    try {
      const where = analysisBatchId ? "WHERE p.analysis_batch_id = $analysis_batch_id" : "";
      const result = await session.run(
        `MATCH (p:AttackPath) ${where}
         OPTIONAL MATCH (p)-[tr:TRAVERSES]->(a:AssetNode)
         WITH p, collect({hop: tr.hop, edge_id: tr.edge_id, asset_id: a.asset_id, edge_factor: tr.edge_factor}) AS traverses
         RETURN p.path_id AS path_id, p.analysis_batch_id AS analysis_batch_id, p.entry_point_id AS entry_point_id, p.target_asset_id AS target_asset_id, p.hop_sequence AS hop_sequence, p.hop_count AS hop_count, p.path_probability AS path_probability, p.raw_score AS raw_score, p.dps_score AS dps_score, p.heuristic_score AS heuristic_score, p.normalized_score AS normalized_score, p.priority_label AS priority_label, p.is_low_priority AS is_low_priority, p.score_config_version AS score_config_version, p.explanations AS explanations, p.generated_by AS generated_by, toString(p.generated_at) AS generated_at, traverses ORDER BY p.raw_score DESC`,
        { analysis_batch_id: analysisBatchId }
      );
      return result.records.map((record) => ({
        path_id: record.get("path_id") as string,
        analysis_batch_id: record.get("analysis_batch_id") as string,
        entry_point_id: record.get("entry_point_id") as string,
        target_asset_id: record.get("target_asset_id") as string,
        hop_sequence: record.get("hop_sequence") as string,
        hop_count: Number(record.get("hop_count")),
        path_probability: Number(record.get("path_probability")),
        raw_score: Number(record.get("raw_score")),
        dps_score: Number(record.get("dps_score")),
        heuristic_score: Number(record.get("heuristic_score")),
        normalized_score: Number(record.get("normalized_score")),
        priority_label: record.get("priority_label") as AttackPath["priority_label"],
        is_low_priority: Boolean(record.get("is_low_priority")),
        score_config_version: record.get("score_config_version") as string,
        explanations: (record.get("explanations") as string[]) ?? [],
        generated_by: record.get("generated_by") as string,
        generated_at: record.get("generated_at") as string,
        traverses: ((record.get("traverses") as Array<Record<string, unknown>>) ?? [])
          .filter((item) => item.edge_id && item.asset_id)
          .map((item) => ({
            hop: Number(item.hop),
            edge_id: String(item.edge_id),
            asset_id: String(item.asset_id),
            edge_factor: Number(item.edge_factor ?? 1)
          }))
      }));
    } finally {
      await session.close();
    }
  }

  async getAuditCommits(): Promise<AuditRecord[]> {
    const session = getDriver().session();
    try {
      const result = await session.run(
        "MATCH (c:CommitAudit) RETURN c.commit_id AS commit_id, c.user_id AS user_id, toString(c.created_at) AS created_at, c.summary AS summary, c.new_version AS new_version ORDER BY c.created_at DESC LIMIT 100"
      );
      return result.records.map((record) => ({
        commit_id: record.get("commit_id") as string,
        user_id: record.get("user_id") as string,
        created_at: record.get("created_at") as string,
        summary: record.get("summary") as string,
        new_version: record.get("new_version") as string
      }));
    } finally {
      await session.close();
    }
  }

  async getDo326ALinks(): Promise<DO326ALink[]> {
    const session = getDriver().session();
    try {
      const result = await session.run("MATCH (l:DO326A_Link) RETURN l ORDER BY l.link_id");
      return result.records.map((record) => {
        const properties = record.get("l").properties as Record<string, unknown>;
        return {
          link_id: String(properties.link_id),
          standard_id: String(properties.standard_id),
          clause_title: String(properties.clause_title),
          semantic_element_id: ((properties.semantic_element_id as unknown[]) ?? []).map((value) => String(value)),
          linkage_type: properties.linkage_type as DO326ALink["linkage_type"],
          evidence_reference: (properties.evidence_reference as string | undefined) ?? undefined,
          review_status: properties.review_status as DO326ALink["review_status"],
          reviewer: (properties.reviewer as string | undefined) ?? undefined,
          mapping_version: (properties.mapping_version as string | undefined) ?? undefined
        };
      });
    } finally {
      await session.close();
    }
  }

  async upsertDo326ALink(link: DO326ALink): Promise<DO326ALink> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run(
          "MERGE (l:DO326A_Link {link_id: $link_id}) SET l.standard_id = $standard_id, l.clause_title = $clause_title, l.semantic_element_id = $semantic_element_id, l.linkage_type = $linkage_type, l.evidence_reference = $evidence_reference, l.review_status = $review_status, l.reviewer = $reviewer, l.mapping_version = $mapping_version",
          {
            ...link,
            evidence_reference: link.evidence_reference ?? null,
            reviewer: link.reviewer ?? null,
            mapping_version: link.mapping_version ?? null
          }
        );
        await tx.run("MATCH (l:DO326A_Link {link_id: $link_id}) OPTIONAL MATCH (l)-[old:MAPS_TO]->() DELETE old", {
          link_id: link.link_id
        });
        await tx.run(
          "MATCH (l:DO326A_Link {link_id: $link_id}) UNWIND $semantic_element_id AS sem_id OPTIONAL MATCH (a:AssetNode {asset_id: sem_id}) OPTIONAL MATCH (th:ThreatPoint {threatpoint_id: sem_id}) OPTIONAL MATCH (p:AttackPath {path_id: sem_id}) WITH l, sem_id, coalesce(a, th, p) AS target WHERE target IS NOT NULL MERGE (l)-[:MAPS_TO {semantic_element_id: sem_id}]->(target)",
          {
            link_id: link.link_id,
            semantic_element_id: link.semantic_element_id
          }
        );
      });
      return link;
    } finally {
      await session.close();
    }
  }

  async reviewDo326ALink(linkId: string, reviewStatus: ReviewStatus, reviewer?: string): Promise<DO326ALink | null> {
    const session = getDriver().session();
    try {
      const result = await session.executeWrite(async (tx) =>
        tx.run(
          "MATCH (l:DO326A_Link {link_id: $link_id}) SET l.review_status = $review_status, l.reviewer = $reviewer RETURN l",
          {
            link_id: linkId,
            review_status: reviewStatus,
            reviewer: reviewer ?? null
          }
        )
      );
      const node = result.records[0]?.get("l");
      if (!node) {
        return null;
      }
      const properties = node.properties as Record<string, unknown>;
      return {
        link_id: String(properties.link_id),
        standard_id: String(properties.standard_id),
        clause_title: String(properties.clause_title),
        semantic_element_id: ((properties.semantic_element_id as unknown[]) ?? []).map((value) => String(value)),
        linkage_type: properties.linkage_type as DO326ALink["linkage_type"],
        evidence_reference: (properties.evidence_reference as string | undefined) ?? undefined,
        review_status: properties.review_status as DO326ALink["review_status"],
        reviewer: (properties.reviewer as string | undefined) ?? undefined,
        mapping_version: (properties.mapping_version as string | undefined) ?? undefined
      };
    } finally {
      await session.close();
    }
  }

  private async collectChangeSetValidationErrors(queryRunner: QueryRunner, changeSet: GraphChangeSet): Promise<string[]> {
    const errors: string[] = [];

    const [dbVersionResult, existingAssetsResult, existingThreatResult, existingPathResult] = await Promise.all([
      queryRunner.run("MATCH (v:GraphVersion {id: $id}) RETURN v.value AS version", {
        id: graphVersionNodeId
      }),
      queryRunner.run("MATCH (a:AssetNode) RETURN a.asset_id AS asset_id, a.security_domain AS security_domain"),
      queryRunner.run("MATCH (th:ThreatPoint) RETURN th.threatpoint_id AS threatpoint_id"),
      queryRunner.run("MATCH (p:AttackPath) RETURN p.path_id AS path_id")
    ]);

    const dbVersion = (dbVersionResult.records[0]?.get("version") as string) ?? "v1";
    if (dbVersion !== changeSet.graph_version) {
      errors.push(`graph version conflict: current=${dbVersion}, submitted=${changeSet.graph_version}`);
    }

    const deletedAssetIds = new Set(changeSet.asset_nodes.delete);
    const deletedThreatIds = new Set(changeSet.threat_points.delete);

    const existingAssetMap = new Map<string, string | null>(
      existingAssetsResult.records
        .map((record) => [record.get("asset_id") as string, (record.get("security_domain") as string | null) ?? null] as const)
        .filter(([assetId]) => !deletedAssetIds.has(assetId))
    );
    const draftAssetMap = new Map<string, string | null>(
      [...changeSet.asset_nodes.add, ...changeSet.asset_nodes.update].map((asset) => [asset.asset_id, asset.security_domain ?? null])
    );

    const referencedAssetIds = new Set<string>();
    for (const edge of [...changeSet.asset_edges.add, ...changeSet.asset_edges.update]) {
      referencedAssetIds.add(edge.source_asset_id);
      referencedAssetIds.add(edge.target_asset_id);
    }
    for (const threat of [...changeSet.threat_points.add, ...changeSet.threat_points.update]) {
      referencedAssetIds.add(threat.related_asset_id);
    }

    for (const assetId of referencedAssetIds) {
      if (!draftAssetMap.has(assetId) && !existingAssetMap.has(assetId)) {
        errors.push(`referenced asset does not exist: ${assetId}`);
      }
    }

    for (const edge of [...changeSet.asset_edges.add, ...changeSet.asset_edges.update]) {
      const sourceDomain = draftAssetMap.get(edge.source_asset_id) ?? existingAssetMap.get(edge.source_asset_id) ?? null;
      const targetDomain = draftAssetMap.get(edge.target_asset_id) ?? existingAssetMap.get(edge.target_asset_id) ?? null;
      if (sourceDomain && targetDomain && sourceDomain !== targetDomain && !edge.trust_level) {
        errors.push(`edge ${edge.edge_id} crosses security domains and requires trust_level`);
      }
    }

    const semanticIds = new Set<string>();
    for (const link of [...changeSet.do326a_links.add, ...changeSet.do326a_links.update]) {
      for (const id of link.semantic_element_id) {
        semanticIds.add(id);
      }
      if ((link.review_status === "Reviewed" || link.review_status === "Approved") && !link.reviewer) {
        errors.push(`DO326A_Link ${link.link_id} requires reviewer for status ${link.review_status}`);
      }
    }

    const semanticKnownIds = new Set<string>([
      ...existingAssetMap.keys(),
      ...existingThreatResult.records
        .map((record) => record.get("threatpoint_id") as string)
        .filter((threatId) => !deletedThreatIds.has(threatId)),
      ...existingPathResult.records.map((record) => record.get("path_id") as string),
      ...changeSet.asset_nodes.add.map((item) => item.asset_id),
      ...changeSet.asset_nodes.update.map((item) => item.asset_id),
      ...changeSet.threat_points.add.map((item) => item.threatpoint_id),
      ...changeSet.threat_points.update.map((item) => item.threatpoint_id)
    ]);

    for (const semanticId of semanticIds) {
      if (!semanticKnownIds.has(semanticId)) {
        errors.push(`DO326A semantic_element_id does not exist: ${semanticId}`);
      }
    }

    return errors;
  }

  private async resetAndCommitSeed(
    session: Session,
    changeSet: GraphChangeSet,
    newVersion: string,
    userId: string
  ): Promise<{ commit_id: string; new_version: string; counts: Record<string, number> }> {
    await session.executeWrite(async (tx) => {
      await tx.run("MATCH (n) DETACH DELETE n");
      await tx.run("MERGE (v:GraphVersion {id: $id}) SET v.value = $version", {
        id: graphVersionNodeId,
        version: newVersion
      });
    });

    const commit = await this.commitChangeSet({ ...changeSet, graph_version: newVersion }, userId);

    return {
      commit_id: commit.commit_id,
      new_version: commit.new_version,
      counts: {
        asset_nodes: changeSet.asset_nodes.add.length,
        asset_edges: changeSet.asset_edges.add.length,
        threat_points: changeSet.threat_points.add.length,
        do326a_links: changeSet.do326a_links.add.length
      }
    };
  }

  async seedSampleData(userId = "seed-script"): Promise<{ commit_id: string; new_version: string; counts: Record<string, number> }> {
    const session = getDriver().session();
    const newVersion = `v_seed_${Date.now()}`;

    const changeSet: GraphChangeSet = {
      graph_version: "v1",
      asset_nodes: {
        add: [
          {
            asset_id: "SYS-AMS",
            asset_name: "Air Management System",
            asset_type: "Terminal",
            criticality: "High",
            security_domain: "Internal",
            description: "DO-356A Appendix D example system"
          },
          {
            asset_id: "SYS-PRCTRL",
            asset_name: "Pressurization Controller",
            asset_type: "Terminal",
            criticality: "High",
            security_domain: "Internal",
            description: "Primary target for FC.3 catastrophic condition"
          },
          {
            asset_id: "SYS-TMPCTRL",
            asset_name: "Temperature Controller",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "Internal"
          },
          {
            asset_id: "IF-CAN",
            asset_name: "Maintenance CAN Interface",
            asset_type: "Interface",
            criticality: "Medium",
            security_domain: "Shared"
          },
          {
            asset_id: "IF-ETHSW",
            asset_name: "Ethernet Switch Interface",
            asset_type: "Interface",
            criticality: "Medium",
            security_domain: "Shared"
          },
          {
            asset_id: "IF-AR664",
            asset_name: "ARINC 664 Interface",
            asset_type: "Interface",
            criticality: "Medium",
            security_domain: "Shared"
          },
          {
            asset_id: "IF-USB9",
            asset_name: "USB Interface (Optional, not used in operation)",
            asset_type: "Interface",
            criticality: "Low",
            security_domain: "Shared"
          },
          {
            asset_id: "EXT-GSE",
            asset_name: "Maintenance GSE",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "External"
          },
          {
            asset_id: "EXT-IFE",
            asset_name: "In-flight Entertainment System",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "External"
          },
          {
            asset_id: "EXT-WBRIDGE",
            asset_name: "Wireless Bridge",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "External"
          },
          {
            asset_id: "EXT-AVIONIC",
            asset_name: "Avionic System",
            asset_type: "Terminal",
            criticality: "High",
            security_domain: "External"
          },
          {
            asset_id: "EXT-BLEED",
            asset_name: "Bleed System",
            asset_type: "Terminal",
            criticality: "High",
            security_domain: "External"
          },
          {
            asset_id: "EXT-AIRNET",
            asset_name: "Airline Network",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "External"
          },
          {
            asset_id: "EXT-MFGNET",
            asset_name: "Manufacturer Network",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "External"
          },
          {
            asset_id: "SYS-FLSDATA",
            asset_name: "Field Loadable Software",
            asset_type: "Data",
            criticality: "High",
            security_domain: "Internal",
            data_classification: "Sensitive"
          },
          {
            asset_id: "SYS-CFGDATA",
            asset_name: "Configuration Files",
            asset_type: "Data",
            criticality: "Medium",
            security_domain: "Internal",
            data_classification: "Internal"
          },
          {
            asset_id: "SYS-FWDATA",
            asset_name: "Controller Firmware",
            asset_type: "Data",
            criticality: "High",
            security_domain: "Internal",
            data_classification: "Sensitive"
          }
        ],
        update: [],
        delete: []
      },
      asset_edges: {
        add: [
          {
            edge_id: "E-SYS-PRCTRL-IF-CAN-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "IF-CAN",
            link_type: "Control",
            protocol_or_medium: "CAN",
            direction: "Bidirectional",
            trust_level: "Semi-Trusted",
            security_mechanism: "MaintenanceModeSR3"
          },
          {
            edge_id: "E-IF-CAN-EXT-GSE-01",
            source_asset_id: "IF-CAN",
            target_asset_id: "EXT-GSE",
            link_type: "Physical",
            protocol_or_medium: "CAN",
            direction: "Bidirectional",
            trust_level: "Semi-Trusted"
          },
          {
            edge_id: "E-SYS-PRCTRL-IF-ETHSW-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "IF-ETHSW",
            link_type: "Logical",
            protocol_or_medium: "Ethernet",
            direction: "Bidirectional",
            trust_level: "Semi-Trusted"
          },
          {
            edge_id: "E-IF-ETHSW-EXT-IFE-01",
            source_asset_id: "IF-ETHSW",
            target_asset_id: "EXT-IFE",
            link_type: "DataFlow",
            protocol_or_medium: "Ethernet",
            direction: "Bidirectional",
            trust_level: "Untrusted"
          },
          {
            edge_id: "E-IF-ETHSW-EXT-WBRIDGE-01",
            source_asset_id: "IF-ETHSW",
            target_asset_id: "EXT-WBRIDGE",
            link_type: "Logical",
            protocol_or_medium: "Ethernet",
            direction: "Bidirectional",
            trust_level: "Untrusted"
          },
          {
            edge_id: "E-EXT-WBRIDGE-EXT-AIRNET-01",
            source_asset_id: "EXT-WBRIDGE",
            target_asset_id: "EXT-AIRNET",
            link_type: "Logical",
            protocol_or_medium: "802.11",
            direction: "Bidirectional",
            trust_level: "Untrusted"
          },
          {
            edge_id: "E-EXT-WBRIDGE-EXT-MFGNET-01",
            source_asset_id: "EXT-WBRIDGE",
            target_asset_id: "EXT-MFGNET",
            link_type: "Logical",
            protocol_or_medium: "TLSVPN",
            direction: "Bidirectional",
            trust_level: "Semi-Trusted",
            security_mechanism: "TLS"
          },
          {
            edge_id: "E-SYS-PRCTRL-SYS-TMPCTRL-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "SYS-TMPCTRL",
            link_type: "Logical",
            protocol_or_medium: "Ethernet",
            direction: "Bidirectional",
            trust_level: "Trusted",
            security_mechanism: "TLS"
          },
          {
            edge_id: "E-SYS-PRCTRL-IF-AR664-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "IF-AR664",
            link_type: "Logical",
            protocol_or_medium: "ARINC664",
            direction: "Bidirectional",
            trust_level: "Trusted",
            security_mechanism: "ARINC664Secure"
          },
          {
            edge_id: "E-IF-AR664-EXT-AVIONIC-01",
            source_asset_id: "IF-AR664",
            target_asset_id: "EXT-AVIONIC",
            link_type: "DataFlow",
            protocol_or_medium: "ARINC664",
            direction: "Bidirectional",
            trust_level: "Trusted"
          },
          {
            edge_id: "E-SYS-PRCTRL-EXT-BLEED-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "EXT-BLEED",
            link_type: "Control",
            protocol_or_medium: "PressureCommand",
            direction: "Unidirectional",
            trust_level: "Trusted"
          },
          {
            edge_id: "E-SYS-PRCTRL-SYS-FLSDATA-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "SYS-FLSDATA",
            link_type: "DataFlow",
            protocol_or_medium: "FLSStorage",
            direction: "Bidirectional",
            trust_level: "Trusted",
            security_mechanism: "SignatureCheck"
          },
          {
            edge_id: "E-SYS-PRCTRL-SYS-CFGDATA-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "SYS-CFGDATA",
            link_type: "DataFlow",
            protocol_or_medium: "ConfigStorage",
            direction: "Bidirectional",
            trust_level: "Trusted"
          },
          {
            edge_id: "E-SYS-PRCTRL-SYS-FWDATA-01",
            source_asset_id: "SYS-PRCTRL",
            target_asset_id: "SYS-FWDATA",
            link_type: "DataFlow",
            protocol_or_medium: "FirmwareStorage",
            direction: "Bidirectional",
            trust_level: "Trusted",
            security_mechanism: "SignatureCheck"
          }
        ],
        update: [],
        delete: []
      },
      threat_points: {
        add: [
          {
            threatpoint_id: "TP-IF-CAN-01",
            name: "TS1 CAN interface direct attack on pressurization storage",
            related_asset_id: "IF-CAN",
            stride_category: "Tampering",
            attack_vector: "Maintenance",
            entry_likelihood_level: "Medium",
            attack_complexity_level: "Low",
            threat_source: "external",
            preconditions: "Direct CAN access during maintenance window",
            detection_status: "Monitoring",
            mitigation_reference: "SR3"
          },
          {
            threatpoint_id: "TP-EXT-GSE-01",
            name: "TS2 Maintenance GSE to pressurization storage attack",
            related_asset_id: "EXT-GSE",
            stride_category: "ElevationOfPrivilege",
            attack_vector: "Maintenance",
            entry_likelihood_level: "Medium",
            attack_complexity_level: "Low",
            threat_source: "external",
            preconditions: "MRO without security training and maintenance mode enabled",
            mitigation_reference: "SR3"
          },
          {
            threatpoint_id: "TP-EXT-WBRIDGE-01",
            name: "TS3 Wireless bridge multi-stage attack path",
            related_asset_id: "EXT-WBRIDGE",
            stride_category: "Spoofing",
            attack_vector: "Wireless",
            entry_likelihood_level: "High",
            attack_complexity_level: "Medium",
            threat_source: "external",
            preconditions: "Aircraft on-ground and external wireless access available",
            mitigation_reference: "SR2"
          },
          {
            threatpoint_id: "TP-EXT-IFE-01",
            name: "TS4 IFE Ethernet interface attack path",
            related_asset_id: "EXT-IFE",
            stride_category: "Tampering",
            attack_vector: "Network",
            entry_likelihood_level: "Medium",
            attack_complexity_level: "Medium",
            threat_source: "external",
            preconditions: "IFE reachable via Ethernet switch",
            mitigation_reference: "SR1"
          }
        ],
        update: [],
        delete: []
      },
      do326a_links: {
        add: [
          {
            link_id: "DL-101",
            standard_id: "DO-356A-AppD-TableD5-TS1",
            clause_title: "TS.1 CAN direct attack scenario",
            semantic_element_id: ["TP-IF-CAN-01", "SYS-PRCTRL", "IF-CAN"],
            linkage_type: "Requirement",
            review_status: "Draft"
          },
          {
            link_id: "DL-102",
            standard_id: "DO-356A-AppD-TableD5-TS2",
            clause_title: "TS.2 GSE maintenance attack scenario",
            semantic_element_id: ["TP-EXT-GSE-01", "EXT-GSE", "SYS-PRCTRL"],
            linkage_type: "Evidence",
            review_status: "Draft"
          },
          {
            link_id: "DL-103",
            standard_id: "DO-356A-AppD-TableD5-TS3",
            clause_title: "TS.3 Wireless bridge multi-stage attack scenario",
            semantic_element_id: ["TP-EXT-WBRIDGE-01", "EXT-WBRIDGE", "IF-ETHSW", "SYS-PRCTRL"],
            linkage_type: "Evidence",
            review_status: "Draft"
          },
          {
            link_id: "DL-104",
            standard_id: "DO-356A-AppD-TableD5-TS4",
            clause_title: "TS.4 IFE Ethernet interface attack scenario",
            semantic_element_id: ["TP-EXT-IFE-01", "EXT-IFE", "IF-ETHSW", "SYS-PRCTRL"],
            linkage_type: "Evidence",
            review_status: "Draft"
          },
          {
            link_id: "DL-105",
            standard_id: "DO-356A-AppD-D17-SR1-SR3",
            clause_title: "Security requirements SR1/SR2/SR3",
            semantic_element_id: ["IF-ETHSW", "IF-CAN", "TP-EXT-WBRIDGE-01", "TP-EXT-IFE-01"],
            linkage_type: "Requirement",
            review_status: "Draft"
          }
        ],
        update: [],
        delete: []
      }
    };

    try {
      return await this.resetAndCommitSeed(session, changeSet, newVersion, userId);
    } finally {
      await session.close();
    }
  }

  async seedGenericExample(userId = "seed-script"): Promise<{ commit_id: string; new_version: string; counts: Record<string, number> }> {
    const session = getDriver().session();
    const newVersion = `v_generic_${Date.now()}`;

    const changeSet: GraphChangeSet = {
      graph_version: "v1",
      asset_nodes: {
        add: [
          {
            asset_id: "SYS-CTRL",
            asset_name: "Generic Control Unit",
            asset_type: "Terminal",
            criticality: "High",
            security_domain: "Internal",
            description: "Simple generic example kept separate from the DO-356A dataset"
          },
          {
            asset_id: "IF-MAINT",
            asset_name: "Maintenance Interface",
            asset_type: "Interface",
            criticality: "Medium",
            security_domain: "Shared",
            description: "Common service interface used during maintenance"
          },
          {
            asset_id: "EXT-LAPTOP",
            asset_name: "Service Laptop",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "External",
            description: "External device temporarily connected for service work"
          },
          {
            asset_id: "SYS-LOG",
            asset_name: "Event Log Store",
            asset_type: "Data",
            criticality: "Low",
            security_domain: "Internal",
            data_classification: "Internal"
          }
        ],
        update: [],
        delete: []
      },
      asset_edges: {
        add: [
          {
            edge_id: "E-SYS-CTRL-IF-MAINT-01",
            source_asset_id: "SYS-CTRL",
            target_asset_id: "IF-MAINT",
            link_type: "Control",
            protocol_or_medium: "Ethernet",
            direction: "Bidirectional",
            trust_level: "Semi-Trusted",
            security_mechanism: "RoleCheck",
            description: "Maintenance control and status channel"
          },
          {
            edge_id: "E-IF-MAINT-EXT-LAPTOP-01",
            source_asset_id: "IF-MAINT",
            target_asset_id: "EXT-LAPTOP",
            link_type: "Physical",
            protocol_or_medium: "Ethernet",
            direction: "Bidirectional",
            trust_level: "Untrusted",
            description: "Temporary wired maintenance connection"
          },
          {
            edge_id: "E-SYS-CTRL-SYS-LOG-01",
            source_asset_id: "SYS-CTRL",
            target_asset_id: "SYS-LOG",
            link_type: "DataFlow",
            protocol_or_medium: "LocalStorage",
            direction: "Bidirectional",
            trust_level: "Trusted",
            description: "Local event logging"
          }
        ],
        update: [],
        delete: []
      },
      threat_points: {
        add: [
          {
            threatpoint_id: "TP-EXT-LAPTOP-01",
            name: "Service laptop misuse over maintenance port",
            related_asset_id: "EXT-LAPTOP",
            stride_category: "Tampering",
            attack_vector: "Maintenance",
            entry_likelihood_level: "Medium",
            attack_complexity_level: "Low",
            threat_source: "external",
            preconditions: "Laptop is connected to the maintenance interface",
            detection_status: "Monitoring",
            mitigation_reference: "GEN-SR-01"
          }
        ],
        update: [],
        delete: []
      },
      do326a_links: {
        add: [
          {
            link_id: "DL-GEN-001",
            standard_id: "GEN-EX-TS1",
            clause_title: "Generic maintenance access scenario",
            semantic_element_id: ["TP-EXT-LAPTOP-01", "EXT-LAPTOP", "IF-MAINT", "SYS-CTRL"],
            linkage_type: "Evidence",
            review_status: "Draft"
          },
          {
            link_id: "DL-GEN-002",
            standard_id: "GEN-EX-SR1",
            clause_title: "Role check on maintenance access",
            semantic_element_id: ["IF-MAINT", "SYS-CTRL"],
            linkage_type: "Requirement",
            review_status: "Draft"
          }
        ],
        update: [],
        delete: []
      }
    };

    try {
      return await this.resetAndCommitSeed(session, changeSet, newVersion, userId);
    } finally {
      await session.close();
    }
  }
}
