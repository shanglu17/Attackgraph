// Synthetic fixtures only: neither domain approval nor experimental reference data.
export function fact(feature_id: string, state: string, scope = ["SCOPE"]) {
  return { feature_id, state, scope, evidence_refs: ["FACT-E"], note: "synthetic_test_only" };
}

export function fixture() {
  const evidence = (evidence_id: string) => ({
    evidence_id, source: "synthetic_test_only", source_locator: {
      section: "fixture" as string | null, page: null, figure: null, sheet: null, row: null
    }, excerpt: null, source_sha256: null, extraction_method: "manual",
    confidence: null, review_status: "verified", version: "test-only"
  });
  return {
    contract_version: "feature-preview-0.1", scenario_id: "SYNTHETIC_TEST_ONLY",
    assets: [{ asset_id: "A", asset_type: "INT", name: "fixture", layer: null,
      operational_phase: ["flight"], evidence_refs: ["FACT-E"], prototype_asset_id: null, version: "test-only" }],
    features: [{ feature_record_id: "F", asset_id: "A", EXP: [fact("external_reachable", "present")],
      TRU: [], PCX: [], EXE: [], INF: [], FUN: [], protections: [fact("strong_mutual_auth", "absent")],
      context: { operational_phase: ["flight"], access_window: null, modification_window: null,
        assumptions: [], evidence_refs: ["FACT-E"] }, evidence_refs: ["FACT-E"], version: "test-only" }],
    rules: [{ rule_id: "TEST-ONLY", asset_type: "INT", required_features: [{ any_of: ["external_reachable"] }],
      supporting_features: ["wireless"], excluding_features: ["strong_mutual_auth"], context_requirements: [],
      output_threat_id: "T.INT.UNAU", explanation_template: "test", version: "test-only", source: "synthetic_test_only",
      source_required_text: "synthetic_test_only", exclusion_effect: "block", review_status: "APPROVED",
      reviewer: "synthetic_test_only", review_basis: "synthetic_test_only", enabled: true, review_notes: [] }],
    evidence: [evidence("FACT-E"), evidence("REVIEW-E")],
    scopes: [{ scope_id: "SCOPE", asset_id: "A", boundary_id: "link", operational_phase: "flight",
      attacker_profile: "synthetic_external_actor", evidence_refs: ["FACT-E"] }],
    policies: [{ rule_id: "TEST-ONLY", rule_version: "test-only", version: "test-only",
      applicable_attacker_profiles: ["synthetic_external_actor"],
      feature_version: "test-only", applicable_phases: ["flight"], review_evidence_refs: ["REVIEW-E"],
      protection_actions: [{ feature_id: "strong_mutual_auth", action: "block", effect_description: "synthetic action",
        basis_evidence_refs: ["REVIEW-E"] }] }]
  };
}
