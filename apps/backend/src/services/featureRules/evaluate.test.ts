import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { evaluateFeatureRules } from "./evaluate.js";
import { fixture, fact } from "./testFixture.js";

test("supported requirements produce a pending candidate, never human approval", () => {
  const result = evaluateFeatureRules(fixture());
  assert.equal(result.decisions[0].decision, "candidate");
  assert.deepEqual(result.decisions[0].blocked_by, []);
  assert.equal(result.decisions[0].review_status, "pending_review");
  assert.equal(result.experimental, true);
});

test("missing, explicitly absent, and conflicting facts have different decisions", () => {
  const input = fixture();
  input.features[0].EXP = [];
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "needs_evidence");
  input.features[0].EXP = [fact("external_reachable", "absent")];
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "requirements_not_met");
  input.features[0].EXP.push(fact("external_reachable", "present"));
  const conflict = evaluateFeatureRules(input).decisions[0];
  assert.equal(conflict.decision, "needs_evidence");
  assert.equal(conflict.required_checks[0].state, "C");
});

test("only verified and located evidence supports facts", () => {
  const input = fixture();
  input.evidence[0].review_status = "pending_review";
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "needs_evidence");
  input.evidence[0].review_status = "verified";
  input.evidence[0].source_locator.section = null;
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "needs_evidence");
});

test("same feature on another scope cannot block the candidate", () => {
  const input = fixture();
  input.scopes.push({ ...input.scopes[0], scope_id: "OTHER", boundary_id: "other-link" });
  input.features[0].protections = [fact("strong_mutual_auth", "present", ["OTHER"])];
  assert.equal(evaluateFeatureRules(input).decisions.find(d => d.scope_id === "SCOPE")?.decision, "candidate_protection_unresolved");
  input.features[0].protections = [fact("strong_mutual_auth", "present")];
  assert.equal(evaluateFeatureRules(input).decisions.find(d => d.scope_id === "SCOPE")?.decision, "blocked");
  assert.deepEqual(evaluateFeatureRules(input).decisions.find(d => d.scope_id === "SCOPE")?.blocked_by, ["strong_mutual_auth"]);
});

test("a downgrade action does not claim blocking", () => {
  const input = fixture();
  input.features[0].protections = [fact("strong_mutual_auth", "present")];
  input.policies[0].protection_actions[0].action = "downgrade";
  const row = evaluateFeatureRules(input).decisions[0];
  assert.equal(row.decision, "candidate_scoped");
  assert.deepEqual(row.blocked_by, []);
});

test("unreviewed rules do not execute even with matching inputs", () => {
  const input = fixture();
  input.rules[0].review_status = "TODO_REVIEW";
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "rule_not_executed");
});

test("actual source draft is not silently promoted or interpreted as no threats", () => {
  const input = fixture();
  input.rules = [JSON.parse(readFileSync(new URL("./fixtures/INT_UNAU_001.json", import.meta.url), "utf8"))];
  input.policies = [];
  const result = evaluateFeatureRules(input);
  assert.equal(result.decisions[0].decision, "rule_not_executed");
  assert.equal(result.executed_count, 0);
});

test("missing policy, version mismatch and uncovered protection cannot execute", () => {
  const input = fixture();
  input.policies[0].rule_version = "wrong";
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "rule_not_executed");
  input.policies[0].rule_version = "test-only";
  input.policies[0].protection_actions = [];
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "rule_not_executed");
});

test("operational phase gates rules instead of borrowing another phase", () => {
  const input = fixture();
  input.policies[0].applicable_phases = ["maintenance"];
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "not_applicable");
  input.policies[0].applicable_phases = ["flight"];
  input.features[0].context.operational_phase = [];
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "needs_evidence");
});

test("dangling evidence and duplicate record IDs fail before evaluation", () => {
  const input = fixture();
  input.features[0].EXP[0].evidence_refs = ["MISSING"];
  assert.throws(() => evaluateFeatureRules(input), /evidence/i);
  const duplicate = fixture();
  duplicate.assets.push(duplicate.assets[0]);
  assert.throws(() => evaluateFeatureRules(duplicate), /duplicate/i);
});

test("unknown Threat IDs cannot enter the preview", () => {
  const input = fixture();
  input.rules[0].output_threat_id = "INVENTED";
  assert.throws(() => evaluateFeatureRules(input));
});

test("ordering does not change decisions; input is not mutated", () => {
  const input = fixture();
  input.features[0].EXP.push(fact("wireless", "present"));
  const original = structuredClone(input);
  const first = evaluateFeatureRules(input);
  assert.deepEqual(input, original);
  input.features[0].EXP.reverse();
  input.evidence.reverse();
  assert.deepEqual(evaluateFeatureRules(input), first);
});

test("blocking one rule does not suppress another rule's candidate", () => {
  const input = fixture();
  input.features[0].protections = [fact("strong_mutual_auth", "present")];
  input.rules.push({ ...input.rules[0], rule_id: "TEST-SECOND", excluding_features: [] });
  input.policies.push({ ...input.policies[0], rule_id: "TEST-SECOND", protection_actions: [] });
  const result = evaluateFeatureRules(input);
  assert.deepEqual(result.decisions.map(x => x.decision).sort(), ["blocked", "candidate"]);
});

test("a policy for an external actor does not apply to a compromised trusted actor", () => {
  const input = fixture();
  input.scopes[0].attacker_profile = "compromised_trusted_actor";
  input.features[0].protections = [fact("strong_mutual_auth", "present")];
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "not_applicable");
});

test("OR accepts one supported alternative but AND still requires every group", () => {
  const input = fixture();
  input.rules[0].required_features = [{ any_of: ["external_reachable", "cross_boundary"] }, { any_of: ["weak_auth"] }];
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "needs_evidence");
  input.features[0].EXP.push(fact("weak_auth", "present"));
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "candidate");
});

test("explicit context conditions are evaluated instead of ignored", () => {
  const input = fixture();
  const enriched = { ...input, rules: [{ ...input.rules[0], context_requirements: [{ any_of: ["access_window_open"] }] }] };
  assert.equal(evaluateFeatureRules(enriched).decisions[0].decision, "needs_evidence");
  enriched.features[0].EXP.push(fact("access_window_open", "absent"));
  assert.equal(evaluateFeatureRules(enriched).decisions[0].decision, "not_applicable");
});

test("an unresolved legacy exclusion effect is not treated as an approved rule", () => {
  const input = fixture();
  input.rules[0].exclusion_effect = "TODO_REVIEW";
  assert.equal(evaluateFeatureRules(input).decisions[0].decision, "rule_not_executed");
});
