import type { MigrationDefinition } from "./types.js";

const registeredEngineeringLabels = ["ThreatPoint", "ThreatCondition", "ThreatScenario"];

function numeric(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "object" && value !== null && "toNumber" in value && typeof value.toNumber === "function") {
    return value.toNumber();
  }
  return Number(value ?? 0);
}

export const migration0012: MigrationDefinition = {
  id: "0012_engineering_legacy_identity_compatibility",
  description: "Preserve scoped legacy identity fields on standard-neutral engineering entities",
  signature: [
    "engineering-legacy-identity-compatibility:v1",
    JSON.stringify(registeredEngineeringLabels),
    "EngineeringElement.legacy_id=business_id",
    "PromotedCoreDraft:AttackPath.analysis_batch_id=source AnalysisRun.business_id",
  ].join("\n"),
  risk: "non-destructive",
  steps: [
    "Backfill legacy_id on engineering entities that reuse registered legacy labels",
    "Backfill the legacy analysis batch scope on promoted AttackPath drafts",
    "Verify the compatibility fields remain complete",
  ],
  async apply(database) {
    await database.run(
      "MATCH (entity:EngineeringElement) " +
      "WHERE any(label IN labels(entity) WHERE label IN $labels) AND entity.legacy_id IS NULL " +
      "SET entity.legacy_id = entity.business_id",
      { labels: registeredEngineeringLabels },
    );
    await database.run(
      "MATCH (core:PromotedCoreDraft:AttackPath) " +
      "WHERE core.analysis_batch_id IS NULL " +
      "OPTIONAL MATCH (core)-[:DERIVED_FROM]->(:DerivedResult)<-[:PRODUCED]-(run:AnalysisRun) " +
      "SET core.legacy_id = coalesce(core.legacy_id, core.business_id), " +
      "core.analysis_batch_id = coalesce(run.business_id, core.source_run_id)",
    );
  },
  async verify(database) {
    const engineering = await database.run(
      "MATCH (entity:EngineeringElement) " +
      "WHERE any(label IN labels(entity) WHERE label IN $labels) AND entity.legacy_id IS NULL " +
      "RETURN count(entity) AS count",
      { labels: registeredEngineeringLabels },
    );
    const attackPaths = await database.run(
      "MATCH (core:PromotedCoreDraft:AttackPath) " +
      "WHERE core.legacy_id IS NULL OR core.analysis_batch_id IS NULL RETURN count(core) AS count",
    );
    const diagnostics: string[] = [];
    const engineeringCount = numeric(engineering.records[0]?.get("count"));
    const attackPathCount = numeric(attackPaths.records[0]?.get("count"));
    if (engineeringCount > 0) diagnostics.push(`${engineeringCount} engineering entity identity record(s) remain incomplete`);
    if (attackPathCount > 0) diagnostics.push(`${attackPathCount} promoted AttackPath identity record(s) remain incomplete`);
    return { ok: diagnostics.length === 0, diagnostics };
  },
};
