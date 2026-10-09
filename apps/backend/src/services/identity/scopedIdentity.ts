export interface ScopedNodeIdentityDefinition {
  label: string;
  legacyKey: string;
  idConstraint: string;
  businessConstraint: string;
  businessScope: "revision" | "analysis-run";
}

export const scopedNodeIdentityDefinitions: readonly ScopedNodeIdentityDefinition[] = [
  { label: "AssetNode", legacyKey: "asset_id", idConstraint: "asset_node_id_unique", businessConstraint: "asset_node_scope_business_id_unique", businessScope: "revision" },
  { label: "FunctionNode", legacyKey: "function_id", idConstraint: "function_node_id_unique", businessConstraint: "function_node_scope_business_id_unique", businessScope: "revision" },
  { label: "TrustBoundary", legacyKey: "boundary_id", idConstraint: "trust_boundary_id_unique", businessConstraint: "trust_boundary_scope_business_id_unique", businessScope: "revision" },
  { label: "BoundaryInterface", legacyKey: "interface_id", idConstraint: "boundary_interface_id_unique", businessConstraint: "boundary_interface_scope_business_id_unique", businessScope: "revision" },
  { label: "SystemDataFlow", legacyKey: "sdf_id", idConstraint: "system_data_flow_id_unique", businessConstraint: "system_data_flow_scope_business_id_unique", businessScope: "revision" },
  { label: "ThreatActor", legacyKey: "actor_id", idConstraint: "threat_actor_id_unique", businessConstraint: "threat_actor_scope_business_id_unique", businessScope: "revision" },
  { label: "FunctionPropagationPath", legacyKey: "fp_id", idConstraint: "function_propagation_path_id_unique", businessConstraint: "function_propagation_path_scope_business_id_unique", businessScope: "revision" },
  { label: "ThreatPoint", legacyKey: "threatpoint_id", idConstraint: "threat_point_id_unique", businessConstraint: "threat_point_scope_business_id_unique", businessScope: "revision" },
  { label: "AttackPath", legacyKey: "path_id", idConstraint: "attack_path_id_unique", businessConstraint: "attack_path_scope_run_business_id_unique", businessScope: "analysis-run" },
  { label: "FailureCondition", legacyKey: "failure_condition_id", idConstraint: "failure_condition_id_unique_v2", businessConstraint: "failure_condition_scope_business_id_unique", businessScope: "revision" },
  { label: "ThreatCondition", legacyKey: "tc_id", idConstraint: "threat_condition_id_unique_v2", businessConstraint: "threat_condition_scope_business_id_unique", businessScope: "revision" },
  { label: "ThreatScenario", legacyKey: "ts_id", idConstraint: "threat_scenario_id_unique_v2", businessConstraint: "threat_scenario_scope_business_id_unique", businessScope: "revision" },
  { label: "DO326A_Link", legacyKey: "link_id", idConstraint: "do326a_link_id_unique", businessConstraint: "do326a_link_scope_business_id_unique", businessScope: "revision" },
  { label: "StandardMapping", legacyKey: "mapping_id", idConstraint: "standard_mapping_id_unique", businessConstraint: "standard_mapping_scope_business_id_unique", businessScope: "revision" },
  { label: "CommitAudit", legacyKey: "commit_id", idConstraint: "commit_audit_id_unique", businessConstraint: "commit_audit_scope_business_id_unique", businessScope: "revision" },
] as const;

export const scopedRelationshipIdentityDefinitions = [
  {
    relationshipType: "ASSET_EDGE",
    legacyKey: "edge_id",
    idConstraint: "asset_edge_id_unique",
    businessConstraint: "asset_edge_scope_business_id_unique",
  },
] as const;

export const legacyGlobalBusinessConstraintNames = [
  "asset_unique",
  "edge_unique",
  "threat_unique",
  "do326a_link_unique",
  "function_unique",
  "trust_boundary_unique",
  "threat_actor_unique",
  "boundary_interface_unique",
  "system_data_flow_unique",
  "function_propagation_unique",
  "failure_condition_unique",
  "threat_condition_unique",
  "threat_scenario_unique",
  "path_unique",
  "standard_mapping_unique",
] as const;

export const standardKnowledgeConstraintDefinitions = [
  {
    name: "standard_clause_unique",
    query: "CREATE CONSTRAINT standard_clause_unique IF NOT EXISTS FOR (n:StandardClause) REQUIRE (n.std, n.clause_id) IS UNIQUE",
  },
  {
    name: "standard_artifact_type_unique",
    query: "CREATE CONSTRAINT standard_artifact_type_unique IF NOT EXISTS FOR (n:StandardArtifactType) REQUIRE n.artifact_id IS UNIQUE",
  },
  {
    name: "standard_artifact_field_unique",
    query: "CREATE CONSTRAINT standard_artifact_field_unique IF NOT EXISTS FOR (n:StandardArtifactField) REQUIRE n.field_id IS UNIQUE",
  },
  {
    name: "standard_pipeline_stage_unique",
    query: "CREATE CONSTRAINT standard_pipeline_stage_unique IF NOT EXISTS FOR (n:StandardPipelineStage) REQUIRE n.stage_id IS UNIQUE",
  },
  {
    name: "standard_kb_unique",
    query: "CREATE CONSTRAINT standard_kb_unique IF NOT EXISTS FOR (n:StandardKnowledgeBase) REQUIRE n.standard_id IS UNIQUE",
  },
] as const;

export const scopedIdentityConstraintNames = [
  ...scopedNodeIdentityDefinitions.flatMap(({ idConstraint, businessConstraint }) => [
    idConstraint,
    businessConstraint,
  ]),
  ...scopedRelationshipIdentityDefinitions.flatMap(({ idConstraint, businessConstraint }) => [
    idConstraint,
    businessConstraint,
  ]),
] as const;

export function findScopedNodeIdentity(label: string): ScopedNodeIdentityDefinition | undefined {
  return scopedNodeIdentityDefinitions.find((definition) => definition.label === label);
}
