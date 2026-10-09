import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  legacyPlanHash,
  resolveLegacyContext,
  stableIssueKey,
  type LegacyAttachmentPlan,
} from "./legacyAttachment.js";

describe("legacy attachment configuration", () => {
  it("keeps generic and Appendix D data in distinct projects", () => {
    const generic = resolveLegacyContext("generic-legacy");
    const appendix = resolveLegacyContext("do356a-appendix-d");

    assert.equal(generic.project.business_id, "legacy-unclassified");
    assert.equal(appendix.project.business_id, "legacy-do356a-appendix-d");
    assert.notEqual(generic.project.business_id, appendix.project.business_id);
    assert.deepEqual(generic.standard_profile.standard_references, ["DO-326A", "DO-356A"]);
    assert.deepEqual(appendix.standard_profile.standard_references, ["DO-356A"]);
  });

  it("produces deterministic issue and plan hashes", () => {
    const issueKey = stableIssueKey({
      datasetKind: "do356a-appendix-d",
      issueType: "MISSING_SOURCE_LOCATOR",
      subjectLabel: "AssetNode",
      subjectKeys: ["B", "A"],
    });
    const reorderedIssueKey = stableIssueKey({
      datasetKind: "do356a-appendix-d",
      issueType: "MISSING_SOURCE_LOCATOR",
      subjectLabel: "AssetNode",
      subjectKeys: ["A", "B"],
    });
    assert.equal(issueKey, reorderedIssueKey);
    assert.match(issueKey, /^[a-f0-9]{64}$/);

    const plan = {
      migration_id: "P1.3_LEGACY_ATTACHMENT",
      requested_dataset_kind: "do356a-appendix-d",
      detected_dataset_kind: "do356a-appendix-d",
      context: resolveLegacyContext("do356a-appendix-d"),
      inventory: [],
      issues: [],
      summary: {
        known_entities: 0,
        attachable_entities: 0,
        fully_scoped_entities: 0,
        blocking_issue_count: 0,
        non_blocking_issue_count: 0,
      },
      blocked: false,
    } satisfies Omit<LegacyAttachmentPlan, "plan_hash">;
    assert.equal(legacyPlanHash(plan), legacyPlanHash(structuredClone(plan)));
  });
});
