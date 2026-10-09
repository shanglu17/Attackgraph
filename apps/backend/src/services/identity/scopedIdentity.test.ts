import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  legacyGlobalBusinessConstraintNames,
  scopedIdentityConstraintNames,
  scopedNodeIdentityDefinitions,
} from "./scopedIdentity.js";

describe("scoped identity registry", () => {
  it("uses unique labels, legacy keys, and constraint names", () => {
    assert.equal(
      new Set(scopedNodeIdentityDefinitions.map(({ label }) => label)).size,
      scopedNodeIdentityDefinitions.length,
    );
    assert.ok(scopedNodeIdentityDefinitions.every(({ legacyKey }) => legacyKey.length > 0));
    assert.equal(new Set(scopedIdentityConstraintNames).size, scopedIdentityConstraintNames.length);
    assert.equal(
      new Set(legacyGlobalBusinessConstraintNames).size,
      legacyGlobalBusinessConstraintNames.length,
    );
  });

  it("keeps AttackPath business identity inside its analysis run", () => {
    const attackPath = scopedNodeIdentityDefinitions.find(({ label }) => label === "AttackPath");
    assert.equal(attackPath?.businessScope, "analysis-run");
  });
});
