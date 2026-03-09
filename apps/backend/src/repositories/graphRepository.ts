import crypto from "node:crypto";
import { getDriver } from "../db/neo4j.js";
import type {
  AttackPath,
  AuditRecord,
  DO326ALink,
  GraphChangeSet,
  GraphSnapshot,
  ReviewStatus
} from "../types/domain.js";

const graphVersionNodeId = "GRAPH_VERSION";

export class GraphRepository {
  async ensureConstraints(): Promise<void> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        await tx.run("CREATE CONSTRAINT asset_unique IF NOT EXISTS FOR (a:AssetNode) REQUIRE a.asset_id IS UNIQUE");
        await tx.run("CREATE CONSTRAINT edge_unique IF NOT EXISTS FOR ()-[r:ASSET_EDGE]-() REQUIRE r.edge_id IS UNIQUE");
        await tx.run("CREATE CONSTRAINT threat_unique IF NOT EXISTS FOR (t:ThreatPoint) REQUIRE t.threatpoint_id IS UNIQUE");
        await tx.run("CREATE CONSTRAINT path_unique IF NOT EXISTS FOR (p:AttackPath) REQUIRE p.path_id IS UNIQUE");
        await tx.run("CREATE CONSTRAINT do326a_link_unique IF NOT EXISTS FOR (l:DO326A_Link) REQUIRE l.link_id IS UNIQUE");
        await tx.run("CREATE CONSTRAINT graph_version_unique IF NOT EXISTS FOR (v:GraphVersion) REQUIRE v.id IS UNIQUE");
      });

      await session.executeWrite(async (tx) => {
        await tx.run(
          "MERGE (v:GraphVersion {id: $id}) ON CREATE SET v.value = $version ON MATCH SET v.value = coalesce(v.value, $version)",
          { id: graphVersionNodeId, version: "v1" }
        );
      });
    } finally {
      await session.close();
    }
  }

  async getGraph(): Promise<GraphSnapshot> {
    const session = getDriver().session();
    try {
      const result = await session.executeRead(async (tx) => {
        const [versionRes, assetsRes, edgesRes, threatsRes, linksRes] = await Promise.all([
          tx.run("MATCH (v:GraphVersion {id: $id}) RETURN v.value AS graph_version", { id: graphVersionNodeId }),
          tx.run("MATCH (a:AssetNode) RETURN a ORDER BY a.asset_id"),
          tx.run(
            "MATCH (s:AssetNode)-[r:ASSET_EDGE]->(t:AssetNode) RETURN r.edge_id AS edge_id, s.asset_id AS source_asset_id, t.asset_id AS target_asset_id, r.link_type AS link_type, r.protocol_or_medium AS protocol_or_medium, r.direction AS direction, r.trust_level AS trust_level, r.security_mechanism AS security_mechanism, r.description AS description ORDER BY edge_id"
          ),
          tx.run(
            "MATCH (th:ThreatPoint)-[:OVERLAY_ON]->(a:AssetNode) RETURN th.threatpoint_id AS threatpoint_id, th.name AS name, a.asset_id AS related_asset_id, th.stride_category AS stride_category, th.attack_vector AS attack_vector, th.entry_likelihood_level AS entry_likelihood_level, th.attack_complexity_level AS attack_complexity_level, th.threat_source AS threat_source, th.preconditions AS preconditions, th.detection_status AS detection_status, th.cve_reference AS cve_reference, th.expert_modifier AS expert_modifier, th.expert_adjustment_note AS expert_adjustment_note, th.mitigation_reference AS mitigation_reference ORDER BY threatpoint_id"
          ),
          tx.run("MATCH (l:DO326A_Link) RETURN l ORDER BY l.link_id")
        ]);
        return { versionRes, assetsRes, edgesRes, threatsRes, linksRes };
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
            tags: (properties.tags as string[] | undefined) ?? undefined
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
        })
      };
    } finally {
      await session.close();
    }
  }

  async validateChangeSet(changeSet: GraphChangeSet): Promise<{ valid: boolean; errors: string[] }> {
    const session = getDriver().session();
    const errors: string[] = [];

    try {
      const dbVersionResult = await session.run("MATCH (v:GraphVersion {id: $id}) RETURN v.value AS version", {
        id: graphVersionNodeId
      });
      const dbVersion = (dbVersionResult.records[0]?.get("version") as string) ?? "v1";
      if (dbVersion !== changeSet.graph_version) {
        errors.push(`graph version conflict: current=${dbVersion}, submitted=${changeSet.graph_version}`);
      }

      const allReferencedAssetIds = new Set<string>();
      for (const edge of [...changeSet.asset_edges.add, ...changeSet.asset_edges.update]) {
        allReferencedAssetIds.add(edge.source_asset_id);
        allReferencedAssetIds.add(edge.target_asset_id);
      }
      for (const threat of [...changeSet.threat_points.add, ...changeSet.threat_points.update]) {
        allReferencedAssetIds.add(threat.related_asset_id);
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

      const existingAssetsResult = await session.run("MATCH (a:AssetNode) RETURN a.asset_id AS asset_id, a.security_domain AS security_domain");
      const existingAssetMap = new Map<string, string | null>(
        existingAssetsResult.records.map((record) => [record.get("asset_id") as string, (record.get("security_domain") as string | null) ?? null])
      );

      const draftAssetMap = new Map<string, string | null>(
        [...changeSet.asset_nodes.add, ...changeSet.asset_nodes.update].map((asset) => [asset.asset_id, asset.security_domain ?? null])
      );

      for (const assetId of allReferencedAssetIds) {
        if (!existingAssetMap.has(assetId) && !draftAssetMap.has(assetId)) {
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

      const existingThreatResult = await session.run("MATCH (th:ThreatPoint) RETURN th.threatpoint_id AS threatpoint_id");
      const existingPathResult = await session.run("MATCH (p:AttackPath) RETURN p.path_id AS path_id");
      const semanticKnownIds = new Set<string>([
        ...existingAssetMap.keys(),
        ...existingThreatResult.records.map((record) => record.get("threatpoint_id") as string),
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

        for (const asset of [...changeSet.asset_nodes.add, ...changeSet.asset_nodes.update]) {
          await tx.run(
            "MERGE (a:AssetNode {asset_id: $asset_id}) SET a.asset_name = $asset_name, a.asset_type = $asset_type, a.criticality = $criticality, a.security_domain = $security_domain, a.description = $description, a.data_classification = $data_classification, a.tags = $tags",
            {
              ...asset,
              security_domain: asset.security_domain ?? null,
              description: asset.description ?? null,
              data_classification: asset.data_classification ?? null,
              tags: asset.tags ?? []
            }
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

  async persistAttackPaths(paths: AttackPath[]): Promise<number> {
    const session = getDriver().session();
    try {
      await session.executeWrite(async (tx) => {
        for (const path of paths) {
          await tx.run(
            "MERGE (p:AttackPath {path_id: $path_id}) SET p.analysis_batch_id = $analysis_batch_id, p.entry_point_id = $entry_point_id, p.target_asset_id = $target_asset_id, p.hop_sequence = $hop_sequence, p.hop_count = $hop_count, p.path_probability = $path_probability, p.raw_score = $raw_score, p.dps_score = $dps_score, p.heuristic_score = $heuristic_score, p.normalized_score = $normalized_score, p.priority_label = $priority_label, p.is_low_priority = $is_low_priority, p.score_config_version = $score_config_version, p.explanations = $explanations, p.generated_by = $generated_by, p.generated_at = datetime($generated_at)",
            path
          );

          await tx.run(
            "MATCH (p:AttackPath {path_id: $path_id}) OPTIONAL MATCH (p)-[old:STARTS_FROM|TARGETS|TRAVERSES]->() DELETE old",
            { path_id: path.path_id }
          );
          await tx.run(
            "MATCH (p:AttackPath {path_id: $path_id}), (th:ThreatPoint {threatpoint_id: $entry_point_id}) MERGE (p)-[:STARTS_FROM]->(th)",
            { path_id: path.path_id, entry_point_id: path.entry_point_id }
          );
          await tx.run(
            "MATCH (p:AttackPath {path_id: $path_id}), (a:AssetNode {asset_id: $target_asset_id}) MERGE (p)-[:TARGETS]->(a)",
            { path_id: path.path_id, target_asset_id: path.target_asset_id }
          );

          for (const traverse of path.traverses) {
            await tx.run(
              "MATCH (p:AttackPath {path_id: $path_id}), (a:AssetNode {asset_id: $asset_id}) MERGE (p)-[r:TRAVERSES {hop: $hop, edge_id: $edge_id}]->(a) SET r.edge_factor = $edge_factor",
              {
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

  async seedSampleData(userId = "seed-script"): Promise<{ commit_id: string; new_version: string; counts: Record<string, number> }> {
    const session = getDriver().session();
    const newVersion = `v_seed_${Date.now()}`;

    const changeSet: GraphChangeSet = {
      graph_version: "v1",
      asset_nodes: {
        add: [
          {
            asset_id: "SYS-CIS",
            asset_name: "Central Information System",
            asset_type: "Terminal",
            criticality: "High",
            security_domain: "Internal"
          },
          {
            asset_id: "IS-PMAT",
            asset_name: "Internal Device PMAT",
            asset_type: "Terminal",
            criticality: "Medium",
            security_domain: "Internal"
          },
          {
            asset_id: "EXT-WIFI",
            asset_name: "Airport Wi-Fi",
            asset_type: "Terminal",
            criticality: "Low",
            security_domain: "External"
          },
          {
            asset_id: "IF-80211",
            asset_name: "Wireless Interface",
            asset_type: "Interface",
            criticality: "Medium",
            security_domain: "Shared"
          }
        ],
        update: [],
        delete: []
      },
      asset_edges: {
        add: [
          {
            edge_id: "E-EXT-WIFI-IF-80211-01",
            source_asset_id: "EXT-WIFI",
            target_asset_id: "IF-80211",
            link_type: "DataFlow",
            protocol_or_medium: "802.11",
            direction: "Bidirectional",
            trust_level: "Untrusted"
          },
          {
            edge_id: "E-IF-80211-SYS-CIS-01",
            source_asset_id: "IF-80211",
            target_asset_id: "SYS-CIS",
            link_type: "Logical",
            protocol_or_medium: "802.11",
            direction: "Bidirectional",
            trust_level: "Semi-Trusted",
            security_mechanism: "WPA3"
          },
          {
            edge_id: "E-IS-PMAT-SYS-CIS-01",
            source_asset_id: "IS-PMAT",
            target_asset_id: "SYS-CIS",
            link_type: "Logical",
            protocol_or_medium: "802.11",
            direction: "Bidirectional",
            trust_level: "Trusted",
            security_mechanism: "TLS"
          }
        ],
        update: [],
        delete: []
      },
      threat_points: {
        add: [
          {
            threatpoint_id: "TP-EXT-WIFI-01",
            name: "Spoofed wireless entry",
            related_asset_id: "EXT-WIFI",
            stride_category: "Spoofing",
            attack_vector: "Wireless",
            entry_likelihood_level: "High",
            attack_complexity_level: "Medium",
            threat_source: "external",
            detection_status: "Monitoring"
          },
          {
            threatpoint_id: "TP-IS-PMAT-01",
            name: "Internal info disclosure",
            related_asset_id: "IS-PMAT",
            stride_category: "InformationDisclosure",
            attack_vector: "Network",
            entry_likelihood_level: "Medium",
            attack_complexity_level: "Low",
            threat_source: "internal"
          }
        ],
        update: [],
        delete: []
      },
      do326a_links: {
        add: [
          {
            link_id: "DL-001",
            standard_id: "DO-326A-3.2.1",
            clause_title: "Security Risk Assessment",
            semantic_element_id: ["SYS-CIS", "TP-EXT-WIFI-01"],
            linkage_type: "Requirement",
            review_status: "Draft"
          }
        ],
        update: [],
        delete: []
      }
    };

    try {
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
    } finally {
      await session.close();
    }
  }
}
