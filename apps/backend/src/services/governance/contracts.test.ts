import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  approveBaselineSchema,
  createProjectWorkspaceSchema,
  freezeRevisionSchema,
} from "./contracts.js";

describe("governance command contracts", () => {
  it("normalizes a valid workspace command", () => {
    const parsed = createProjectWorkspaceSchema.parse({
      actor: "  reviewer@example.test  ",
      command_id: "  create-project-1  ",
      project: { business_id: "PROJECT-A", name: "  Project A  " },
      model: { business_id: "MODEL-001", name: "  Aircraft Model  ", level: "aircraft" },
      revision: { business_id: "REV-001" },
      standard_profile: {
        business_id: "PROFILE-326A-356A",
        name: "  DO-326A / DO-356A  ",
        profile_version: "  1.0.0  ",
        standard_references: ["DO-326A", "DO-356A"],
      },
    });

    assert.equal(parsed.actor, "reviewer@example.test");
    assert.equal(parsed.project.name, "Project A");
    assert.equal(parsed.standard_profile.profile_version, "1.0.0");
  });

  it("rejects malformed business identifiers", () => {
    const result = createProjectWorkspaceSchema.safeParse({
      actor: "reviewer",
      command_id: "create-project-2",
      project: { business_id: "PROJECT A", name: "Project A" },
      model: { business_id: "MODEL-001", name: "Model", level: "system" },
      revision: { business_id: "REV-001" },
      standard_profile: {
        business_id: "PROFILE-1",
        name: "Profile",
        profile_version: "1.0.0",
        standard_references: ["DO-326A"],
      },
    });

    assert.equal(result.success, false);
  });

  it("normalizes content hashes and requires optimistic versions", () => {
    const parsed = freezeRevisionSchema.parse({
      actor: "reviewer",
      command_id: "freeze-1",
      project_id: "11111111-1111-4111-8111-111111111111",
      revision_id: "22222222-2222-4222-8222-222222222222",
      expected_revision_version: 1,
      baseline: { business_id: "BL-001", content_hash: "A".repeat(64) },
    });
    assert.equal(parsed.baseline.content_hash, "a".repeat(64));

    const invalidApproval = approveBaselineSchema.safeParse({
      actor: "approver",
      command_id: "approve-1",
      project_id: "11111111-1111-4111-8111-111111111111",
      baseline_id: "33333333-3333-4333-8333-333333333333",
      expected_baseline_version: 0,
      rationale: "Reviewed",
    });
    assert.equal(invalidApproval.success, false);
  });
});
