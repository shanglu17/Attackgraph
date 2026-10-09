import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, describe, it } from "node:test";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { CommandPayloadMismatchError } from "../services/governance/commandReceipt.js";
import { GovernanceRepository } from "./governanceRepository.js";
import {
  RevisionNotWritableError,
  RevisionUnitOfWork,
  RevisionWriteConflictError,
  RevisionWriteScopeError,
} from "./revisionUnitOfWork.js";

const governanceRepository = new GovernanceRepository();
const unitOfWork = new RevisionUnitOfWork();
const runId = randomUUID();
const projectIds: string[] = [];

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (
    typeof value === "object" &&
    value !== null &&
    "toNumber" in value &&
    typeof value.toNumber === "function"
  ) {
    return value.toNumber();
  }
  throw new TypeError(`Expected a numeric value, received ${String(value)}`);
}

function workspaceCommand(suffix: string) {
  return {
    actor: "phase1.4-integration-test",
    command_id: `p1.4:${runId}:workspace:${suffix}`,
    project: {
      business_id: `P1-4-${runId}-${suffix}`,
      name: `P1.4 project ${suffix}`,
    },
    model: {
      business_id: "MODEL-001",
      name: "P1.4 revision write model",
      level: "system",
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

function probeWrite(input: {
  project_id: string;
  revision_id: string;
  expected_revision_version: number;
  command_id: string;
  probe_id: string;
}) {
  return unitOfWork.execute(
    {
      actor: "phase1.4-integration-test",
      command_id: input.command_id,
      project_id: input.project_id,
      revision_id: input.revision_id,
      expected_revision_version: input.expected_revision_version,
      event_type: "REVISION_PROBE_WRITTEN",
      request_canonicalizer: "phase1.revision-probe/v1",
      payload: { probe_id: input.probe_id },
      summary: `Write P1.4 probe ${input.probe_id}`,
    },
    async ({ transaction, project_id, revision_id, new_revision_version }) => {
      await transaction.run(
        `CREATE (:P14WriteProbe {
           id: $probe_id,
           project_id: $project_id,
           revision_id: $revision_id,
           revision_version: $revision_version
         })`,
        {
          probe_id: input.probe_id,
          project_id,
          revision_id,
          revision_version: new_revision_version,
        },
      );
      return { probe_id: input.probe_id };
    },
  );
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

describe("RevisionUnitOfWork", () => {
  it("enforces scope, optimistic concurrency, rollback, audit, replay, and Draft status", async () => {
    const workspaceA = await governanceRepository.createProjectWorkspace(workspaceCommand("A"));
    const workspaceB = await governanceRepository.createProjectWorkspace(workspaceCommand("B"));
    projectIds.push(workspaceA.project.id, workspaceB.project.id);

    const commandId = `p1.4:${runId}:write-a`;
    const probeId = `probe-${runId}-a`;
    const committed = await probeWrite({
      project_id: workspaceA.project.id,
      revision_id: workspaceA.revision.id,
      expected_revision_version: 1,
      command_id: commandId,
      probe_id: probeId,
    });
    assert.equal(committed.replayed, false);
    assert.equal(committed.new_revision_version, 2);
    assert.equal(committed.value.probe_id, probeId);

    const replayed = await unitOfWork.execute(
      {
        actor: "phase1.4-integration-test",
        command_id: commandId,
        project_id: workspaceA.project.id,
        revision_id: workspaceA.revision.id,
        expected_revision_version: 1,
        event_type: "REVISION_PROBE_WRITTEN",
        request_canonicalizer: "phase1.revision-probe/v1",
        payload: { probe_id: probeId },
        summary: `Write P1.4 probe ${probeId}`,
      },
      async () => {
        throw new Error("replay must not execute the mutation");
      },
    );
    assert.equal(replayed.replayed, true);
    assert.equal(replayed.audit_event_id, committed.audit_event_id);
    assert.equal(replayed.new_revision_version, 2);

    await assert.rejects(
      probeWrite({
        project_id: workspaceA.project.id,
        revision_id: workspaceA.revision.id,
        expected_revision_version: 1,
        command_id: commandId,
        probe_id: `different-${probeId}`,
      }),
      CommandPayloadMismatchError,
    );
    await assert.rejects(
      probeWrite({
        project_id: workspaceA.project.id,
        revision_id: workspaceA.revision.id,
        expected_revision_version: 1,
        command_id: `p1.4:${runId}:stale-a`,
        probe_id: `probe-${runId}-stale`,
      }),
      RevisionWriteConflictError,
    );
    await assert.rejects(
      probeWrite({
        project_id: workspaceA.project.id,
        revision_id: workspaceB.revision.id,
        expected_revision_version: 1,
        command_id: `p1.4:${runId}:cross-scope`,
        probe_id: `probe-${runId}-cross-scope`,
      }),
      RevisionWriteScopeError,
    );

    const rollbackProbeId = `probe-${runId}-rollback`;
    await assert.rejects(
      unitOfWork.execute(
        {
          actor: "phase1.4-integration-test",
          command_id: `p1.4:${runId}:rollback`,
          project_id: workspaceB.project.id,
          revision_id: workspaceB.revision.id,
          expected_revision_version: 1,
          event_type: "REVISION_PROBE_WRITTEN",
          request_canonicalizer: "phase1.revision-probe/v1",
          payload: { probe_id: rollbackProbeId },
          summary: "This transaction must roll back",
        },
        async ({ transaction, project_id, revision_id }) => {
          await transaction.run(
            "CREATE (:P14WriteProbe {id: $id, project_id: $project_id, revision_id: $revision_id})",
            { id: rollbackProbeId, project_id, revision_id },
          );
          throw new Error("intentional rollback");
        },
      ),
      /intentional rollback/,
    );

    const session = getDriver().session();
    try {
      const rollbackState = await session.run(
        `MATCH (revision:Revision {id: $revision_id})
         OPTIONAL MATCH (probe:P14WriteProbe {id: $probe_id})
         OPTIONAL MATCH (event:AuditEvent {command_id: $command_id})
         RETURN revision.version AS version, count(probe) AS probes, count(event) AS events`,
        {
          revision_id: workspaceB.revision.id,
          probe_id: rollbackProbeId,
          command_id: `p1.4:${runId}:rollback`,
        },
      );
      assert.equal(numeric(rollbackState.records[0].get("version")), 1);
      assert.equal(numeric(rollbackState.records[0].get("probes")), 0);
      assert.equal(numeric(rollbackState.records[0].get("events")), 0);
    } finally {
      await session.close();
    }

    const concurrent = await Promise.allSettled([
      probeWrite({
        project_id: workspaceB.project.id,
        revision_id: workspaceB.revision.id,
        expected_revision_version: 1,
        command_id: `p1.4:${runId}:concurrent-1`,
        probe_id: `probe-${runId}-concurrent-1`,
      }),
      probeWrite({
        project_id: workspaceB.project.id,
        revision_id: workspaceB.revision.id,
        expected_revision_version: 1,
        command_id: `p1.4:${runId}:concurrent-2`,
        probe_id: `probe-${runId}-concurrent-2`,
      }),
    ]);
    assert.equal(concurrent.filter((result) => result.status === "fulfilled").length, 1);
    const rejected = concurrent.find((result) => result.status === "rejected");
    assert.ok(rejected && rejected.status === "rejected");
    assert.ok(rejected.reason instanceof RevisionWriteConflictError);

    const frozen = await governanceRepository.freezeRevision({
      actor: "phase1.4-integration-test",
      command_id: `p1.4:${runId}:freeze-a`,
      project_id: workspaceA.project.id,
      revision_id: workspaceA.revision.id,
      expected_revision_version: 2,
      baseline: {
        business_id: "BL-P1-4",
        content_hash: "d".repeat(64),
      },
    });
    assert.equal(frozen.value.status, "Frozen");
    await assert.rejects(
      probeWrite({
        project_id: workspaceA.project.id,
        revision_id: workspaceA.revision.id,
        expected_revision_version: 3,
        command_id: `p1.4:${runId}:closed-a`,
        probe_id: `probe-${runId}-closed`,
      }),
      RevisionNotWritableError,
    );

    const verificationSession = getDriver().session();
    try {
      const verified = await verificationSession.run(
        `MATCH (event:AuditEvent {command_id: $command_id})-[:AFFECTS]->(revision:Revision)
         MATCH (probe:P14WriteProbe {id: $probe_id})
         RETURN event.request_hash_algorithm AS algorithm,
                event.request_canonicalizer AS canonicalizer,
                event.subject_version_before AS version_before,
                event.subject_version_after AS version_after,
                revision.id AS revision_id,
                probe.revision_version AS probe_version`,
        { command_id: commandId, probe_id: probeId },
      );
      assert.equal(verified.records.length, 1);
      assert.equal(verified.records[0].get("algorithm"), "sha256");
      assert.equal(verified.records[0].get("canonicalizer"), "phase1.revision-probe/v1");
      assert.equal(numeric(verified.records[0].get("version_before")), 1);
      assert.equal(numeric(verified.records[0].get("version_after")), 2);
      assert.equal(verified.records[0].get("revision_id"), workspaceA.revision.id);
      assert.equal(numeric(verified.records[0].get("probe_version")), 2);
    } finally {
      await verificationSession.close();
    }
  });
});
