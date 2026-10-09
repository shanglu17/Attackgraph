import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, describe, it } from "node:test";
import { closeDriver, getDriver } from "../db/neo4j.js";
import {
  LegacyIdentityNotFoundError,
  LegacyIdentityRepository,
  UnsupportedLegacyEntityTypeError,
} from "./legacyIdentityRepository.js";

const repository = new LegacyIdentityRepository();
const runId = randomUUID();
const projectA = randomUUID();
const projectB = randomUUID();
const revisionA = randomUUID();
const revisionB = randomUUID();

after(async () => {
  const session = getDriver().session();
  try {
    await session.run(
      `MATCH (node)
       WHERE node.p15_test_run = $run_id
       DETACH DELETE node`,
      { run_id: runId },
    );
  } finally {
    await session.close();
    await closeDriver();
  }
});

describe("LegacyIdentityRepository", () => {
  it("resolves duplicate legacy business ids only inside an explicit scope", async () => {
    const nodeA1 = randomUUID();
    const nodeA2 = randomUUID();
    const nodeB1 = randomUUID();
    const nodeB2 = randomUUID();
    const edgeA = randomUUID();
    const edgeB = randomUUID();
    const session = getDriver().session();
    try {
      await session.run(
        `CREATE (a1:AssetNode {
           id: $node_a1, project_id: $project_a, revision_id: $revision_a,
           business_id: 'ASSET-001', legacy_id: 'ASSET-001', asset_id: 'ASSET-001',
           p15_test_run: $run_id
         })
         CREATE (a2:AssetNode {
           id: $node_a2, project_id: $project_a, revision_id: $revision_a,
           business_id: 'ASSET-002', legacy_id: 'ASSET-002', asset_id: 'ASSET-002',
           p15_test_run: $run_id
         })
         CREATE (b1:AssetNode {
           id: $node_b1, project_id: $project_b, revision_id: $revision_b,
           business_id: 'ASSET-001', legacy_id: 'ASSET-001', asset_id: 'ASSET-001',
           p15_test_run: $run_id
         })
         CREATE (b2:AssetNode {
           id: $node_b2, project_id: $project_b, revision_id: $revision_b,
           business_id: 'ASSET-002', legacy_id: 'ASSET-002', asset_id: 'ASSET-002',
           p15_test_run: $run_id
         })
         CREATE (a1)-[:ASSET_EDGE {
           id: $edge_a, project_id: $project_a, revision_id: $revision_a,
           business_id: 'EDGE-001', legacy_id: 'EDGE-001', edge_id: 'EDGE-001'
         }]->(a2)
         CREATE (b1)-[:ASSET_EDGE {
           id: $edge_b, project_id: $project_b, revision_id: $revision_b,
           business_id: 'EDGE-001', legacy_id: 'EDGE-001', edge_id: 'EDGE-001'
         }]->(b2)`,
        {
          run_id: runId,
          project_a: projectA,
          revision_a: revisionA,
          project_b: projectB,
          revision_b: revisionB,
          node_a1: nodeA1,
          node_a2: nodeA2,
          node_b1: nodeB1,
          node_b2: nodeB2,
          edge_a: edgeA,
          edge_b: edgeB,
        },
      );
    } finally {
      await session.close();
    }

    const resolvedA = await repository.resolveNode({
      project_id: projectA,
      revision_id: revisionA,
      entity_type: "AssetNode",
      identifier: "ASSET-001",
    });
    const resolvedB = await repository.resolveNode({
      project_id: projectB,
      revision_id: revisionB,
      entity_type: "AssetNode",
      identifier: "ASSET-001",
    });
    assert.equal(resolvedA.id, nodeA1);
    assert.equal(resolvedB.id, nodeB1);
    assert.notEqual(resolvedA.id, resolvedB.id);

    const resolvedEdgeA = await repository.resolveAssetEdge({
      project_id: projectA,
      revision_id: revisionA,
      identifier: "EDGE-001",
    });
    const resolvedEdgeB = await repository.resolveAssetEdge({
      project_id: projectB,
      revision_id: revisionB,
      identifier: "EDGE-001",
    });
    assert.equal(resolvedEdgeA.id, edgeA);
    assert.equal(resolvedEdgeB.id, edgeB);

    await assert.rejects(
      repository.resolveNode({
        project_id: projectA,
        revision_id: revisionB,
        entity_type: "AssetNode",
        identifier: "ASSET-001",
      }),
      LegacyIdentityNotFoundError,
    );
    await assert.rejects(
      repository.resolveNode({
        project_id: projectA,
        revision_id: revisionA,
        entity_type: "UnknownNode",
        identifier: "ASSET-001",
      }),
      UnsupportedLegacyEntityTypeError,
    );
  });
});
