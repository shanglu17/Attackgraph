import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { systemModelCommitRequestSchema, type SystemModelCommitRequest } from "@attackgraph/contracts";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { CommandPayloadMismatchError } from "../services/governance/commandReceipt.js";
import { SystemModelImportService } from "../services/systemModelImportService.js";
import { GovernanceRepository } from "./governanceRepository.js";
import { SystemModelRepository } from "./systemModelRepository.js";

const runId = randomUUID();
const projectIds: string[] = [];
const governance = new GovernanceRepository();
const repository = new SystemModelRepository();
const service = new SystemModelImportService(repository);

after(async () => {
  if (projectIds.length > 0) {
    const session = getDriver().session();
    try {
      await session.run(
        `MATCH (node) WHERE node.project_id IN $project_ids OR (node:Project AND node.id IN $project_ids) DETACH DELETE node`,
        { project_ids: projectIds },
      );
    } finally {
      await session.close();
    }
  }
  await closeDriver();
});

function command(projectId: string, revisionId: string): SystemModelCommitRequest {
  return systemModelCommitRequestSchema.parse({
    actor: "phase2-integration-test",
    command_id: `phase2:${runId}:import`,
    project_id: projectId,
    revision_id: revisionId,
    expected_revision_version: 1,
    import: {
      contract_version: "system-model.v2",
      source: {
        business_id: "GENERIC-SOURCE-001", source_type: "json", name: "Generic fixture",
        content_hash: "b".repeat(64), parser_name: "generic-json", parser_version: "1.0.0",
      },
      entities: {
        assets: [
          { business_id: "ASSET-A", name: "A", category: "System", source_locator: { sheet: "Assets", row: 2, field_locators: { name: "B2" } } },
          { business_id: "ASSET-B", name: "B", category: "System" },
        ],
        functions: [{ business_id: "FN-1", name: "Process generic data" }],
        interfaces: [{ business_id: "IF-1", name: "Link", interface_type: "Logical", direction: "Bidirectional", asset_business_ids: ["ASSET-A", "ASSET-B"] }],
        data_flows: [{ business_id: "FLOW-1", name: "Data", producer_asset_business_id: "ASSET-A", consumer_asset_business_id: "ASSET-B", interface_business_id: "IF-1", supported_function_business_ids: ["FN-1"] }],
        security_boundaries: [{ business_id: "BOUNDARY-1", name: "Boundary", boundary_type: "Trust", member_asset_business_ids: ["ASSET-A"] }],
        external_entities: [],
        evidence_records: [{ business_id: "EVIDENCE-1", evidence_type: "source", title: "Input", reference: "GENERIC-SOURCE-001" }],
        trace_links: [{ business_id: "TRACE-1", link_type: "SUPPORTS", source: { type: "EvidenceRecord", business_id: "EVIDENCE-1" }, target: { type: "DataFlow", business_id: "FLOW-1" } }],
      },
    },
  });
}

test("generic import is scoped, traceable, atomic and idempotent", async () => {
  const workspace = await governance.createProjectWorkspace({
    actor: "phase2-integration-test",
    command_id: `phase2:${runId}:workspace`,
    project: { business_id: `PHASE2-${runId}`, name: "Phase 2 integration" },
    model: { business_id: "MODEL-1", name: "Generic model", level: "system" },
    revision: { business_id: "REV-1" },
    standard_profile: { business_id: "PROFILE-326A-356A", name: "326A/356A", profile_version: "1", standard_references: ["DO-326A", "DO-356A"] },
  });
  projectIds.push(workspace.project.id);
  const request = command(workspace.project.id, workspace.revision.id);
  const committed = await service.commit(request);
  assert.equal(committed.committed, true);
  assert.equal(committed.replayed, false);
  assert.equal(committed.new_revision_version, 2);

  const model = await repository.read(workspace.project.id, workspace.revision.id);
  assert.equal(model.entities.assets.length, 2);
  assert.equal(model.entities.data_flows.length, 1);
  assert.equal(model.entities.trace_links[0].source.business_id, "EVIDENCE-1");
  assert.equal(model.entities.assets[0].source_locator?.field_locators.name, "B2");
  assert.equal(model.sources[0].content_hash, "b".repeat(64));

  const replayed = await service.commit(request);
  assert.equal(replayed.replayed, true);
  assert.equal(replayed.audit_event_id, committed.audit_event_id);
  assert.deepEqual(replayed.created_ids, committed.created_ids);

  const changed = structuredClone(request);
  changed.import.entities.assets[0].name = "Changed payload";
  await assert.rejects(service.commit(changed), CommandPayloadMismatchError);

  const session = getDriver().session();
  try {
    const provenance = await session.run(
      `MATCH (entity:SystemModelElement {project_id: $project_id, revision_id: $revision_id})
             -[:DERIVED_FROM_SOURCE]->(source:SourceRecord)
       RETURN count(entity) AS count, count(DISTINCT source) AS sources`,
      { project_id: workspace.project.id, revision_id: workspace.revision.id },
    );
    const count = Number(provenance.records[0].get("count").toString());
    assert.equal(count, 8);
    assert.equal(Number(provenance.records[0].get("sources").toString()), 1);
  } finally {
    await session.close();
  }
});
