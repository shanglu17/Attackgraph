import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  fingerprintApproveBaseline,
  fingerprintCommandPayload,
  fingerprintCreateProjectWorkspace,
  fingerprintFreezeRevision,
} from "./commandFingerprint.js";

const workspaceInput = {
  actor: "reviewer",
  command_id: "command-a",
  project: { business_id: "PROJECT-A", name: "Project A" },
  model: { business_id: "MODEL-1", name: "Model", level: "system" },
  revision: { business_id: "REV-1" },
  standard_profile: {
    business_id: "PROFILE-1",
    name: "DO-326A / DO-356A",
    profile_version: "1.0.0",
    standard_references: ["DO-326A", "DO-356A"],
  },
};

describe("governance command fingerprints", () => {
  it("ignores command id and normalizes set-like standard references", () => {
    const first = fingerprintCreateProjectWorkspace(workspaceInput);
    const equivalent = fingerprintCreateProjectWorkspace({
      ...workspaceInput,
      command_id: "command-b",
      actor: " reviewer ",
      standard_profile: {
        ...workspaceInput.standard_profile,
        standard_references: ["DO-356A", "DO-326A", "DO-356A"],
      },
    });

    assert.equal(first.request_hash, equivalent.request_hash);
    assert.equal(first.request_canonicalizer, "governance.create-project-workspace/v1");
  });

  it("changes when a semantic workspace field or actor changes", () => {
    const first = fingerprintCreateProjectWorkspace(workspaceInput);
    const changedProject = fingerprintCreateProjectWorkspace({
      ...workspaceInput,
      project: { ...workspaceInput.project, business_id: "PROJECT-B" },
    });
    const changedActor = fingerprintCreateProjectWorkspace({
      ...workspaceInput,
      actor: "another-reviewer",
    });

    assert.notEqual(first.request_hash, changedProject.request_hash);
    assert.notEqual(first.request_hash, changedActor.request_hash);
  });

  it("normalizes case-only differences in UUID and content hash representations", () => {
    const first = fingerprintFreezeRevision({
      actor: "reviewer",
      command_id: "freeze-a",
      project_id: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
      revision_id: "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB",
      expected_revision_version: 1,
      baseline: { business_id: "BL-1", content_hash: "C".repeat(64) },
    });
    const equivalent = fingerprintFreezeRevision({
      actor: "reviewer",
      command_id: "freeze-b",
      project_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      revision_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      expected_revision_version: 1,
      baseline: { business_id: "BL-1", content_hash: "c".repeat(64) },
    });

    assert.equal(first.request_hash, equivalent.request_hash);
  });

  it("includes approval rationale and expected version in approval semantics", () => {
    const first = fingerprintApproveBaseline({
      actor: "approver",
      command_id: "approve-a",
      project_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      baseline_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      expected_baseline_version: 1,
      rationale: "Reviewed",
    });
    const changed = fingerprintApproveBaseline({
      actor: "approver",
      command_id: "approve-a",
      project_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      baseline_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      expected_baseline_version: 2,
      rationale: "Different decision",
    });

    assert.notEqual(first.request_hash, changed.request_hash);
  });

  it("rejects non-finite numbers instead of hashing them like null", () => {
    assert.throws(
      () => fingerprintCommandPayload("test.command/v1", { value: Number.NaN }),
      /must be finite/,
    );
  });
});
