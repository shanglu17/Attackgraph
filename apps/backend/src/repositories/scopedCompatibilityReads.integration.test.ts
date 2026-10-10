import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, describe, it } from "node:test";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { F3532AnalysisRepository } from "./f3532AnalysisRepository.js";
import { GraphRepository } from "./graphRepository.js";
import { StandardRepository } from "./standardRepository.js";

const graphRepository = new GraphRepository();
const f3532Repository = new F3532AnalysisRepository();
const standardRepository = new StandardRepository();
const runId = randomUUID();
const projectA = randomUUID();
const projectB = randomUUID();
const modelA = randomUUID();
const modelB = randomUUID();
const revisionA = randomUUID();
const revisionB = randomUUID();

const scopeA = { project_id: projectA, model_id: modelA, revision_id: revisionA };
const scopeB = { project_id: projectB, model_id: modelB, revision_id: revisionB };

after(async () => {
  const session = getDriver().session();
  try {
    await session.run(
      `MATCH (node {p16_test_run: $run_id}) DETACH DELETE node`,
      { run_id: runId },
    );
  } finally {
    await session.close();
    await closeDriver();
  }
});

describe("P1.6 scoped compatibility reads", () => {
  it("keeps duplicate legacy identifiers isolated across every compatibility projection", async () => {
    const session = getDriver().session();
    try {
      await session.run(
        `UNWIND $workspaces AS workspace
         CREATE (project:Project {
           id: workspace.project_id, business_id: workspace.project_business_id,
           name: workspace.marker, p16_test_run: $run_id
         })
         CREATE (model:Model {
           id: workspace.model_id, project_id: workspace.project_id,
           business_id: 'MODEL-001', name: workspace.marker, p16_test_run: $run_id
         })
         CREATE (revision:Revision {
           id: workspace.revision_id, project_id: workspace.project_id,
           model_id: workspace.model_id, business_id: 'REV-001',
           status: 'Draft', version: 1, p16_test_run: $run_id
         })
         CREATE (project)-[:HAS_MODEL]->(model)-[:HAS_REVISION]->(revision)
         CREATE (assetA:AssetNode {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'ASSET-001', legacy_id: 'ASSET-001',
           asset_id: 'ASSET-001', asset_name: workspace.marker, asset_type: 'System',
           criticality: 'High', p16_test_run: $run_id
         })
         CREATE (assetB:AssetNode {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'ASSET-002', legacy_id: 'ASSET-002',
           asset_id: 'ASSET-002', asset_name: workspace.marker + '-target', asset_type: 'System',
           criticality: 'Medium', p16_test_run: $run_id
         })
         CREATE (assetA)-[:ASSET_EDGE {
           id: randomUUID(), project_id: workspace.project_id, revision_id: workspace.revision_id,
           business_id: 'EDGE-001', legacy_id: 'EDGE-001', edge_id: 'EDGE-001',
           link_type: 'DataFlow', direction: 'Directed'
         }]->(assetB)
         CREATE (threat:ThreatPoint {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'THREAT-001', legacy_id: 'THREAT-001',
           threatpoint_id: 'THREAT-001', name: workspace.marker,
           stride_category: 'Spoofing', attack_vector: 'Network',
           entry_likelihood_level: 'Possible', attack_complexity_level: 'Medium',
           threat_source: 'External', detection_status: 'Unknown', expert_modifier: 1.0,
           p16_test_run: $run_id
         })-[:OVERLAY_ON]->(assetA)
         CREATE (:DO326A_Link {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'LINK-001', legacy_id: 'LINK-001',
           link_id: 'LINK-001', standard_id: workspace.marker, clause_title: workspace.marker,
           semantic_element_id: ['ASSET-001'], linkage_type: 'TracesTo', review_status: 'Draft',
           p16_test_run: $run_id
         })
         CREATE (:CommitAudit {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'COMMIT-001', legacy_id: 'COMMIT-001',
           commit_id: 'COMMIT-001', user_id: workspace.marker, summary: workspace.marker,
           new_version: 'v-test', created_at: datetime(), p16_test_run: $run_id
         })
         CREATE (:AttackPath {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, analysis_batch_id: 'BATCH-001',
           business_id: 'PATH-001', legacy_id: 'PATH-001', path_id: 'PATH-001',
           entry_point_id: 'THREAT-001', target_asset_id: 'ASSET-002', hop_sequence: workspace.marker,
           hop_count: 1, path_probability: 0.5, raw_score: 0.5, dps_score: 0.5,
           heuristic_score: 0.5, normalized_score: 0.5, priority_label: 'Medium',
           is_low_priority: false, score_config_version: 'test', explanations: [workspace.marker],
           generated_by: workspace.marker, generated_at: datetime(), p16_test_run: $run_id
         })
         CREATE (:FailureCondition {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'FC-001', legacy_id: 'FC-001',
           failure_condition_id: 'FC-001', name: workspace.marker, flight_phases: [],
           hazard_class: 'Test', severity: 'Major', p16_test_run: $run_id
         })
         CREATE (:ThreatCondition {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'TC-001', legacy_id: 'TC-001',
           tc_id: 'TC-001', description: workspace.marker, p16_test_run: $run_id
         })
         CREATE (:ThreatScenario {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'TS-001', legacy_id: 'TS-001',
           ts_id: 'TS-001', attack_path: workspace.marker, p16_test_run: $run_id
         })
         CREATE (:StandardMapping {
           id: randomUUID(), project_id: workspace.project_id, model_id: workspace.model_id,
           revision_id: workspace.revision_id, business_id: 'MAP-001', legacy_id: 'MAP-001',
           mapping_id: 'MAP-001', standard_id: 'ASTM-F3532-23', clause_id: workspace.marker,
           semantic_element_type: 'AssetNode', semantic_element_id: 'ASSET-001',
           linkage_type: 'TracesTo', review_status: 'Draft', p16_test_run: $run_id
         })`,
        {
          run_id: runId,
          workspaces: [
            { ...scopeA, project_business_id: `P16-A-${runId}`, marker: "SCOPE-A" },
            { ...scopeB, project_business_id: `P16-B-${runId}`, marker: "SCOPE-B" },
          ],
        },
      );
    } finally {
      await session.close();
    }

    const [graphA, graphB] = await Promise.all([
      graphRepository.getGraph(scopeA),
      graphRepository.getGraph(scopeB),
    ]);
    assert.deepEqual(graphA.asset_nodes.map(({ asset_name }) => asset_name), ["SCOPE-A", "SCOPE-A-target"]);
    assert.deepEqual(graphB.asset_nodes.map(({ asset_name }) => asset_name), ["SCOPE-B", "SCOPE-B-target"]);
    assert.equal(graphA.asset_edges.length, 1);
    assert.equal(graphB.asset_edges.length, 1);

    const [linksA, linksB, pathsA, pathsB, auditsA, auditsB] = await Promise.all([
      graphRepository.getDo326ALinks(scopeA),
      graphRepository.getDo326ALinks(scopeB),
      graphRepository.getAttackPaths(scopeA, "BATCH-001"),
      graphRepository.getAttackPaths(scopeB, "BATCH-001"),
      graphRepository.getAuditCommits(scopeA),
      graphRepository.getAuditCommits(scopeB),
    ]);
    assert.equal(linksA[0].standard_id, "SCOPE-A");
    assert.equal(linksB[0].standard_id, "SCOPE-B");
    assert.equal(pathsA[0].hop_sequence, "SCOPE-A");
    assert.equal(pathsB[0].hop_sequence, "SCOPE-B");
    assert.equal(auditsA[0].user_id, "SCOPE-A");
    assert.equal(auditsB[0].user_id, "SCOPE-B");

    const [failureA, failureB, f3532A, f3532B, mappingsA, mappingsB] = await Promise.all([
      f3532Repository.getFailureConditionContexts(scopeA),
      f3532Repository.getFailureConditionContexts(scopeB),
      f3532Repository.getF353204(scopeA),
      f3532Repository.getF353204(scopeB),
      standardRepository.getMappings(scopeA),
      standardRepository.getMappings(scopeB),
    ]);
    assert.equal(failureA[0].name, "SCOPE-A");
    assert.equal(failureB[0].name, "SCOPE-B");
    assert.equal(f3532A.threat_conditions[0].description, "SCOPE-A");
    assert.equal(f3532B.threat_scenarios[0].attack_path, "SCOPE-B");
    assert.equal(mappingsA[0].clause_id, "SCOPE-A");
    assert.equal(mappingsB[0].clause_id, "SCOPE-B");
  });
});
