import { createHash } from "node:crypto";
import { dimensions, previewSchema, validateReferences } from "./contract.js";

type State = "T" | "F" | "U" | "C";
type Decision = "rule_not_executed" | "not_applicable" | "needs_evidence" | "requirements_not_met" |
  "blocked" | "candidate_scoped" | "candidate_protection_unresolved" | "candidate";
interface Check { feature_id: string; state: State; evidence_refs: string[]; reasons: string[] }
interface GroupCheck { any_of: string[]; state: State; checks: Check[] }

// Arrays in this contract are sets; canonicalize without mutating caller records.
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical).sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b)));
  if (value !== null && typeof value === "object") return Object.fromEntries(
    Object.entries(value).sort(([a], [b]) => compare(a, b)).map(([k, v]) => [k, canonical(v)]));
  return value;
}
function compare(a: string, b: string) { return a < b ? -1 : a > b ? 1 : 0; }
function sorted(xs: string[]) { return [...new Set(xs)].sort(compare); }
function combine(states: State[], operator: "AND" | "OR"): State {
  const decisive = operator === "AND" ? "F" : "T";
  if (states.includes(decisive)) return decisive;
  if (states.includes("C")) return "C";
  if (states.includes("U")) return "U";
  return operator === "AND" ? "T" : "F";
}

export function evaluateFeatureRules(raw: unknown) {
  const input = previewSchema.parse(raw);
  validateReferences(input);
  const evidence = new Map(input.evidence.map(e => [e.evidence_id, e]));
  const supported = (refs: string[]) => refs.length > 0 && refs.every(ref => {
    const e = evidence.get(ref)!;
    return e.review_status === "verified" && Object.values(e.source_locator).some(v => v !== null);
  });
  const decisions = [];
  for (const scope of [...input.scopes].sort((a, b) => compare(a.scope_id, b.scope_id))) {
    const asset = input.assets.find(a => a.asset_id === scope.asset_id)!;
    const features = input.features.find(f => f.asset_id === asset.asset_id);
    const facts = features ? [...dimensions.flatMap(d => features[d]), ...features.protections] : [];
    function check(feature_id: string): Check {
      const scoped = facts.filter(f => f.feature_id === feature_id && f.scope.includes(scope.scope_id));
      const usable = scoped.filter(f => supported(f.evidence_refs));
      const states = new Set(usable.map(f => f.state));
      const state: State = states.has("ambiguous") || (states.has("present") && states.has("absent")) ? "C" :
        states.has("present") ? "T" : states.has("absent") ? "F" : "U";
      return { feature_id, state, evidence_refs: sorted(scoped.flatMap(f => f.evidence_refs)),
        reasons: sorted([...(scoped.length === 0 ? ["no_fact_in_scope"] : []),
          ...(usable.length < scoped.length ? ["unverified_or_unlocated_evidence"] : []),
          ...(state === "C" ? ["conflicting_or_ambiguous_facts"] : []), ...(state === "U" ? ["unknown"] : [])]) };
    }
    function groups(gs: { any_of: string[] }[]): GroupCheck[] {
      return [...gs].sort((a, b) => compare(sorted(a.any_of).join("\0"), sorted(b.any_of).join("\0")))
        .map(g => { const checks = sorted(g.any_of).map(check);
          return { any_of: sorted(g.any_of), state: combine(checks.map(c => c.state), "OR"), checks }; });
    }
    for (const rule of [...input.rules].sort((a, b) => compare(a.rule_id, b.rule_id))) {
      const policy = input.policies.find(p => p.rule_id === rule.rule_id);
      let decision: Decision = "rule_not_executed";
      const reasons: string[] = [];
      let required_checks: GroupCheck[] = [];
      let context_checks: GroupCheck[] = [];
      let supporting_checks: Check[] = [];
      let protection_checks: (Check & { action: string; effect_description: string; basis_evidence_refs: string[] })[] = [];
      let executed = false;
      if (!rule.enabled || rule.review_status !== "APPROVED" || !rule.reviewer || !rule.review_basis || rule.exclusion_effect === "TODO_REVIEW") {
        reasons.push("rule_disabled_or_unreviewed");
      } else if (asset.asset_type !== rule.asset_type) {
        decision = "not_applicable"; reasons.push("asset_type_mismatch");
      } else if (!policy || policy.rule_version !== rule.version || !supported(policy.review_evidence_refs) ||
        policy.protection_actions.length !== rule.excluding_features.length ||
        !policy.protection_actions.every(a => rule.excluding_features.includes(a.feature_id) && supported(a.basis_evidence_refs))) {
        reasons.push("missing_unreviewed_or_incompatible_policy");
      } else if (!features || policy.feature_version !== features.version) {
        reasons.push("missing_or_incompatible_feature_version");
      } else {
        executed = true;
        if (!policy.applicable_attacker_profiles.includes(scope.attacker_profile)) {
          decision = "not_applicable"; reasons.push("attacker_outside_rule_policy");
        } else if (!policy.applicable_phases.includes(scope.operational_phase)) {
          decision = "not_applicable"; reasons.push("phase_outside_rule_policy");
        } else if (!asset.operational_phase.includes(scope.operational_phase) || !supported(asset.evidence_refs) ||
          !features.context.operational_phase.includes(scope.operational_phase) ||
          !supported(scope.evidence_refs) || !supported(features.context.evidence_refs)) {
          decision = "needs_evidence"; reasons.push("scope_asset_or_context_unconfirmed");
        } else {
          context_checks = groups(rule.context_requirements);
          required_checks = groups(rule.required_features);
          supporting_checks = sorted(rule.supporting_features).map(check);
          const ctx = combine(context_checks.map(c => c.state), "AND");
          const required = combine(required_checks.map(c => c.state), "AND");
          if (ctx === "F") { decision = "not_applicable"; reasons.push("context_requirements_not_met"); }
          else if (ctx !== "T") { decision = "needs_evidence"; reasons.push("context_unresolved"); }
          else if (required === "F") { decision = "requirements_not_met"; reasons.push("required_features_absent"); }
          else if (required !== "T") { decision = "needs_evidence"; reasons.push("required_features_unresolved"); }
          else {
            protection_checks = [...policy.protection_actions].sort((a, b) => compare(a.feature_id, b.feature_id))
              .map(a => ({ ...check(a.feature_id), action: a.action, effect_description: a.effect_description,
                basis_evidence_refs: sorted(a.basis_evidence_refs) }));
            if (protection_checks.some(c => c.state === "T" && c.action === "block")) decision = "blocked";
            else if (protection_checks.some(c => c.state === "U" || c.state === "C")) decision = "candidate_protection_unresolved";
            else if (protection_checks.some(c => c.state === "T" && c.action === "downgrade")) decision = "candidate_scoped";
            else decision = "candidate";
          }
        }
      }
      decisions.push({ scenario_id: input.scenario_id, scope_id: scope.scope_id, asset_id: asset.asset_id,
        prototype_asset_id: asset.prototype_asset_id, rule_id: rule.rule_id, rule_version: rule.version,
        feature_version: features?.version ?? null, policy_version: policy?.version ?? null,
        output_threat_id: rule.output_threat_id, decision, executed, reasons: sorted(reasons),
        review_status: "pending_review" as const, required_checks, context_checks, supporting_checks, protection_checks,
        blocked_by: protection_checks.filter(c => c.state === "T" && c.action === "block").map(c => c.feature_id),
        evidence_refs: sorted([...asset.evidence_refs, ...scope.evidence_refs, ...(features?.context.evidence_refs ?? []),
          ...(policy?.review_evidence_refs ?? []), ...required_checks.flatMap(g => g.checks.flatMap(c => c.evidence_refs)),
          ...context_checks.flatMap(g => g.checks.flatMap(c => c.evidence_refs)), ...supporting_checks.flatMap(c => c.evidence_refs),
          ...protection_checks.flatMap(c => [...c.evidence_refs, ...c.basis_evidence_refs])]) });
    }
  }
  return { contract_version: input.contract_version, semantics_version: "experimental-0.1", experimental: true as const,
    input_sha256: createHash("sha256").update(JSON.stringify(canonical(input))).digest("hex"),
    executed_count: decisions.filter(d => d.executed).length, decisions,
    evidence_index: canonical(input.evidence), scope_index: canonical(input.scopes) };
}
