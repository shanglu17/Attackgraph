import { randomUUID } from "node:crypto";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { ImpactRepository } from "../repositories/impactRepository.js";
import { AssuranceWorkProductService } from "../services/assuranceWorkProductService.js";
import { ImpactService } from "../services/impactService.js";

const actor = "phase5-controlled-demo";

async function seedComparison() {
  const suffix = randomUUID();
  const ids = {
    project: randomUUID(), model: randomUUID(), profile: randomUUID(),
    sourceRevision: randomUUID(), targetRevision: randomUUID(), baseline: randomUUID(),
  };
  const session = getDriver().session();
  try {
    await session.executeWrite((transaction) => transaction.run(
      `CREATE (project:Project {id: $project, business_id: $project_business_id, name: 'Phase 5 controlled demonstration', status: 'Active', version: 1})
       CREATE (model:Model {id: $model, project_id: $project, business_id: $model_business_id, name: 'Controlled aircraft model', level: 'Aircraft', status: 'Active', version: 1})
       CREATE (profile:StandardProfileVersion {id: $profile, project_id: $project, business_id: $profile_business_id, name: 'DO-326A / DO-356A Phase 5 profile', profile_version: 'phase5.1.0', maturity: 'Approved', standard_references: ['DO-326A','DO-356A']})
       CREATE (sourceRevision:Revision {id: $source_revision, project_id: $project, model_id: $model, standard_profile_version_id: $profile, business_id: $source_revision_business_id, status: 'Closed', version: 2})
       CREATE (targetRevision:Revision {id: $target_revision, project_id: $project, model_id: $model, standard_profile_version_id: $profile, business_id: $target_revision_business_id, status: 'Draft', version: 1})
       CREATE (baseline:Baseline {id: $baseline, project_id: $project, model_id: $model, source_revision_id: $source_revision, standard_profile_version_id: $profile, business_id: $baseline_business_id, content_hash: $hash, status: 'Approved', version: 2, frozen_at: datetime(), frozen_by: $actor, approved_at: datetime(), approved_by: $actor, created_at: datetime(), created_by: $actor})
       CREATE (project)-[:HAS_MODEL]->(model) CREATE (project)-[:HAS_STANDARD_PROFILE_VERSION]->(profile)
       CREATE (model)-[:HAS_REVISION]->(sourceRevision) CREATE (model)-[:HAS_REVISION]->(targetRevision) CREATE (model)-[:HAS_BASELINE]->(baseline)
       CREATE (sourceRevision)-[:USES_STANDARD_PROFILE_VERSION]->(profile) CREATE (targetRevision)-[:USES_STANDARD_PROFILE_VERSION]->(profile) CREATE (sourceRevision)-[:FROZEN_AS]->(baseline)
       WITH sourceRevision, targetRevision
       CREATE (sourceRecord:SourceRecord {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'P5-SOURCE', source_type: 'controlled-example', name: 'Phase 5 source', content_hash: $hash, parser_name: 'phase5-controlled-demo', parser_version: '1.0.0'})
       CREATE (targetRecord:SourceRecord {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'P5-SOURCE', source_type: 'controlled-example', name: 'Phase 5 source', content_hash: $hash, parser_name: 'phase5-controlled-demo', parser_version: '1.0.0'})
       CREATE (sourceAsset:CoreEntity:SystemModelElement:Asset {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'P5-ASSET', entity_type: 'Asset', name: 'Original communication asset', category: 'System', tags: [], lifecycle_status: 'Active'})
       CREATE (targetAsset:CoreEntity:SystemModelElement:Asset {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'P5-ASSET', entity_type: 'Asset', name: 'Updated communication asset', category: 'System', tags: [], lifecycle_status: 'Active'})
       CREATE (sourceThreat:CoreEntity:SystemModelElement:DraftThreat {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'P5-THREAT', entity_type: 'DraftThreat', name: 'Integrity threat', status: 'Draft', threat_type: 'Integrity', target_asset_business_id: 'P5-ASSET', standard_reference: 'DO-356A', tags: []})
       CREATE (targetThreat:CoreEntity:SystemModelElement:DraftThreat {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'P5-THREAT', entity_type: 'DraftThreat', name: 'Integrity threat', status: 'Draft', threat_type: 'Integrity', target_asset_business_id: 'P5-ASSET', standard_reference: 'DO-356A', tags: []})
       CREATE (sourceLink:CoreEntity:SystemModelElement:TraceLink {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'P5-LINK', entity_type: 'TraceLink', link_type: 'IDENTIFIES', source_type: 'DraftThreat', source_business_id: 'P5-THREAT', target_type: 'Asset', target_business_id: 'P5-ASSET'})
       CREATE (targetLink:CoreEntity:SystemModelElement:TraceLink {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'P5-LINK', entity_type: 'TraceLink', link_type: 'IDENTIFIES', source_type: 'DraftThreat', source_business_id: 'P5-THREAT', target_type: 'Asset', target_business_id: 'P5-ASSET'})
       CREATE (sourceRevision)-[:CONTAINS]->(sourceRecord) CREATE (sourceRevision)-[:CONTAINS]->(sourceAsset) CREATE (sourceRevision)-[:CONTAINS]->(sourceThreat) CREATE (sourceRevision)-[:CONTAINS]->(sourceLink)
       CREATE (targetRevision)-[:CONTAINS]->(targetRecord) CREATE (targetRevision)-[:CONTAINS]->(targetAsset) CREATE (targetRevision)-[:CONTAINS]->(targetThreat) CREATE (targetRevision)-[:CONTAINS]->(targetLink)
       CREATE (sourceAsset)-[:DERIVED_FROM_SOURCE]->(sourceRecord) CREATE (sourceThreat)-[:DERIVED_FROM_SOURCE]->(sourceRecord) CREATE (sourceLink)-[:DERIVED_FROM_SOURCE]->(sourceRecord)
       CREATE (targetAsset)-[:DERIVED_FROM_SOURCE]->(targetRecord) CREATE (targetThreat)-[:DERIVED_FROM_SOURCE]->(targetRecord) CREATE (targetLink)-[:DERIVED_FROM_SOURCE]->(targetRecord)`,
      {
        ...ids, source_revision: ids.sourceRevision, target_revision: ids.targetRevision,
        project_business_id: `PHASE5-IMPACT-DEMO-${suffix}`,
        model_business_id: `P5-MODEL-${suffix}`, profile_business_id: `P5-PROFILE-${suffix}`,
        source_revision_business_id: `P5-REV-A-${suffix}`, target_revision_business_id: `P5-REV-B-${suffix}`,
        baseline_business_id: `P5-BASELINE-${suffix}`, hash: "5".repeat(64), actor,
      },
    ));
    return { ids, suffix };
  } finally {
    await session.close();
  }
}

async function main() {
  const { ids, suffix } = await seedComparison();
  const repository = new ImpactRepository();
  const service = new ImpactService(repository);
  const preview = await service.preview({
    project_id: ids.project, from: { baseline_id: ids.baseline }, to: { revision_id: ids.targetRevision },
  });
  const created = await service.create({
    actor, command_id: `phase5-demo:${suffix}:assessment`, project_id: ids.project,
    revision_id: ids.targetRevision, expected_revision_version: 1,
    assessment: {
      business_id: `P5-IMPACT-${suffix}`, title: "Controlled baseline impact assessment",
      from: { baseline_id: ids.baseline }, to: { revision_id: ids.targetRevision },
      rationale: "Demonstrate deterministic Phase 5 impact propagation.",
    },
  });
  const replay = await service.create({
    actor, command_id: `phase5-demo:${suffix}:assessment`, project_id: ids.project,
    revision_id: ids.targetRevision, expected_revision_version: 1,
    assessment: {
      business_id: `P5-IMPACT-${suffix}`, title: "Controlled baseline impact assessment",
      from: { baseline_id: ids.baseline }, to: { revision_id: ids.targetRevision },
      rationale: "Demonstrate deterministic Phase 5 impact propagation.",
    },
  });
  const assessment = (await repository.readAssessments(ids.project, ids.targetRevision, created.assessment_id))[0];
  let revisionVersion = created.new_revision_version;
  for (const [index, item] of assessment.items.entries()) {
    const disposition = await service.dispose({
      actor: "phase5-human-reviewer", command_id: `phase5-demo:${suffix}:disposition:${index}`,
      project_id: ids.project, revision_id: ids.targetRevision, expected_revision_version: revisionVersion,
      disposition: {
        business_id: `P5-DISPOSITION-${suffix}-${index}`, assessment_id: assessment.id, impact_item_id: item.id,
        decision: index === 0 ? "Reanalyze" : "Accept", rationale: "Controlled human impact disposition.",
        reviewer_role: "Security Engineer",
      },
    });
    revisionVersion = disposition.new_revision_version;
  }
  const resolved = (await repository.readAssessments(ids.project, ids.targetRevision, created.assessment_id))[0];
  const workProduct = await new AssuranceWorkProductService().generate({
    project_id: ids.project, revision_id: ids.targetRevision, actor,
  });
  console.log(JSON.stringify({
    project_id: ids.project, baseline_id: ids.baseline, revision_id: ids.targetRevision,
    preview_hash: preview.preview_hash, changed: preview.differences.map((item) => item.entity.business_id),
    impacted: preview.impacted.map((item) => ({ business_id: item.entity.business_id, kind: item.impact_kind, distance: item.distance })),
    command_replayed: replay.replayed, assessment_status: resolved.status,
    dispositions: resolved.items.map((item) => item.disposition?.decision),
    work_product_status: workProduct.metadata.package_status,
    work_product_sections: workProduct.sections.map((section) => section.section_id),
    compliance_claim: false, disclaimer: workProduct.metadata.disclaimer,
  }, null, 2));
}

main().catch((error) => { console.error(error); process.exitCode = 1; }).finally(() => closeDriver());
