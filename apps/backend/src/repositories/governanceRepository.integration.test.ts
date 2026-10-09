import assert from "node:assert/strict";
import { after, describe, it } from "node:test";
import { randomUUID } from "node:crypto";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { GovernanceConflictError, GovernanceRepository } from "./governanceRepository.js";

const repository = new GovernanceRepository();
const runId = randomUUID();
const projectIds: string[] = [];

function workspaceCommand(projectBusinessId: string, commandId: string) {
  return {
    actor: "phase1-integration-test",
    command_id: commandId,
    project: {
      business_id: projectBusinessId,
      name: `Integration project ${projectBusinessId}`,
    },
    model: {
      business_id: "SHARED-MODEL-001",
      name: "Shared business identity test model",
      level: "aircraft",
    },
    revision: { business_id: "REV-001" },
    standard_profile: {
      business_id: "PROFILE-326A-356A",
      name: "DO-326A / DO-356A",
      profile_version: "1.0.0",
      standard_references: ["DO-326A", "DO-356A"],
    },
  };
}

after(async () => {
  if (projectIds.length > 0) {
    const session = getDriver().session();
    try {
      await session.run(
        `MATCH (node)
         WHERE node.project_id IN $project_ids
            OR (node:Project AND node.id IN $project_ids)
         DETACH DELETE node`,
        { project_ids: projectIds },
      );
    } finally {
      await session.close();
    }
  }
  await closeDriver();
});

describe("GovernanceRepository", () => {
  it("supports scoped business IDs, idempotent commands, and an immutable approval path", async () => {
    const createACommandId = `p1.2:${runId}:create-a`;
    const createBCommandId = `p1.2:${runId}:create-b`;
    const workspaceA = await repository.createProjectWorkspace(
      workspaceCommand(`P1-2-${runId}-A`, createACommandId),
    );
    projectIds.push(workspaceA.project.id);
    const workspaceB = await repository.createProjectWorkspace(
      workspaceCommand(`P1-2-${runId}-B`, createBCommandId),
    );
    projectIds.push(workspaceB.project.id);

    assert.equal(workspaceA.model.business_id, workspaceB.model.business_id);
    assert.notEqual(workspaceA.model.id, workspaceB.model.id);
    assert.notEqual(workspaceA.project.id, workspaceB.project.id);
    assert.equal(workspaceA.revision.status, "Draft");
    assert.equal(workspaceA.standard_profile_version.maturity, "Draft");

    const replayedWorkspace = await repository.createProjectWorkspace(
      workspaceCommand(`IGNORED-ON-REPLAY-${runId}`, createACommandId),
    );
    assert.equal(replayedWorkspace.replayed, true);
    assert.equal(replayedWorkspace.project.id, workspaceA.project.id);

    const freezeCommandId = `p1.2:${runId}:freeze-a`;
    const frozen = await repository.freezeRevision({
      actor: "phase1-integration-test",
      command_id: freezeCommandId,
      project_id: workspaceA.project.id,
      revision_id: workspaceA.revision.id,
      expected_revision_version: 1,
      baseline: { business_id: "BL-001", content_hash: "a".repeat(64) },
    });
    assert.equal(frozen.replayed, false);
    assert.equal(frozen.value.status, "Frozen");
    assert.equal(frozen.value.version, 1);

    const replayedFreeze = await repository.freezeRevision({
      actor: "phase1-integration-test",
      command_id: freezeCommandId,
      project_id: workspaceA.project.id,
      revision_id: workspaceA.revision.id,
      expected_revision_version: 1,
      baseline: { business_id: "IGNORED-ON-REPLAY", content_hash: "b".repeat(64) },
    });
    assert.equal(replayedFreeze.replayed, true);
    assert.equal(replayedFreeze.value.id, frozen.value.id);

    const approveCommandId = `p1.2:${runId}:approve-a`;
    const approved = await repository.approveBaseline({
      actor: "phase1-integration-test",
      command_id: approveCommandId,
      project_id: workspaceA.project.id,
      baseline_id: frozen.value.id,
      expected_baseline_version: 1,
      rationale: "P1.2 controlled approval integration test",
    });
    assert.equal(approved.value.status, "Approved");
    assert.equal(approved.value.version, 2);
    assert.equal(approved.value.content_hash, "a".repeat(64));

    const replayedApproval = await repository.approveBaseline({
      actor: "phase1-integration-test",
      command_id: approveCommandId,
      project_id: workspaceA.project.id,
      baseline_id: frozen.value.id,
      expected_baseline_version: 1,
      rationale: "Ignored on replay",
    });
    assert.equal(replayedApproval.replayed, true);
    assert.equal(replayedApproval.value.version, 2);

    await assert.rejects(
      repository.approveBaseline({
        actor: "phase1-integration-test",
        command_id: `p1.2:${runId}:approve-again`,
        project_id: workspaceA.project.id,
        baseline_id: frozen.value.id,
        expected_baseline_version: 2,
        rationale: "An Approved Baseline must not be updated",
      }),
      GovernanceConflictError,
    );

    assert.equal("updateBaseline" in repository, false);

    const session = getDriver().session();
    try {
      const auditResult = await session.run(
        `MATCH (event:AuditEvent)
         WHERE event.command_id STARTS WITH $prefix
         RETURN count(event) AS count`,
        { prefix: `p1.2:${runId}:` },
      );
      assert.equal(auditResult.records[0].get("count").toNumber(), 4);
    } finally {
      await session.close();
    }
  });
});
