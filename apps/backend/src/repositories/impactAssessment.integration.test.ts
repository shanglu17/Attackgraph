import assert from "node:assert/strict";
import { after, test } from "node:test";
import { randomUUID } from "node:crypto";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { ImpactRepository } from "./impactRepository.js";
import { ImpactService } from "../services/impactService.js";
import { AssuranceWorkProductService } from "../services/assuranceWorkProductService.js";
import { TraceabilityReportService } from "../services/traceabilityReportService.js";
import { CommandPayloadMismatchError } from "../services/governance/commandReceipt.js";

const projects: string[] = [];

after(async () => {
  if (projects.length > 0) {
    const session = getDriver().session();
    try {
      await session.run("MATCH (node) WHERE node.project_id IN $ids OR (node:Project AND node.id IN $ids) DETACH DELETE node", { ids: projects });
    } finally {
      await session.close();
    }
  }
  await closeDriver();
});

test("Phase 5 compares baselines, propagates impact, records dispositions and produces bounded work products", async () => {
  const suffix = randomUUID();
  const ids = { project: randomUUID(), model: randomUUID(), profile: randomUUID(), sourceRevision: randomUUID(), targetRevision: randomUUID(), baseline: randomUUID() };
  projects.push(ids.project);
  const session = getDriver().session();
  try {
    await session.executeWrite((tx) => tx.run(
      `CREATE (project:Project {id: $project, business_id: $project_business_id, name: 'Phase 5 integration', status: 'Active', version: 1})
       CREATE (model:Model {id: $model, project_id: $project, business_id: $model_business_id, name: 'Model', level: 'Aircraft', status: 'Active', version: 1})
       CREATE (profile:StandardProfileVersion {id: $profile, project_id: $project, business_id: $profile_business_id, name: 'DO-326A / DO-356A', profile_version: '1.0', maturity: 'Approved', standard_references: ['DO-326A','DO-356A']})
       CREATE (sourceRevision:Revision {id: $source_revision, project_id: $project, model_id: $model, standard_profile_version_id: $profile, business_id: $source_revision_business_id, status: 'Closed', version: 2})
       CREATE (targetRevision:Revision {id: $target_revision, project_id: $project, model_id: $model, standard_profile_version_id: $profile, business_id: $target_revision_business_id, status: 'Draft', version: 1})
       CREATE (baseline:Baseline {id: $baseline, project_id: $project, model_id: $model, source_revision_id: $source_revision, standard_profile_version_id: $profile, business_id: $baseline_business_id, content_hash: $hash, status: 'Approved', version: 2, frozen_at: datetime(), frozen_by: 'integration', created_at: datetime(), created_by: 'integration'})
       CREATE (project)-[:HAS_MODEL]->(model) CREATE (project)-[:HAS_STANDARD_PROFILE_VERSION]->(profile)
       CREATE (model)-[:HAS_REVISION]->(sourceRevision) CREATE (model)-[:HAS_REVISION]->(targetRevision) CREATE (model)-[:HAS_BASELINE]->(baseline)
       CREATE (sourceRevision)-[:USES_STANDARD_PROFILE_VERSION]->(profile) CREATE (targetRevision)-[:USES_STANDARD_PROFILE_VERSION]->(profile) CREATE (sourceRevision)-[:FROZEN_AS]->(baseline)
       WITH sourceRevision, targetRevision
       CREATE (sourceA:SourceRecord {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'SRC-1', source_type: 'fixture', name: 'Controlled source', content_hash: $hash, parser_name: 'fixture', parser_version: '1'})
       CREATE (targetA:SourceRecord {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'SRC-1', source_type: 'fixture', name: 'Controlled source', content_hash: $hash, parser_name: 'fixture', parser_version: '1'})
       CREATE (sourceAsset:CoreEntity:SystemModelElement:Asset {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'ASSET-1', entity_type: 'Asset', name: 'Original asset', category: 'System', tags: [], lifecycle_status: 'Active'})
       CREATE (targetAsset:CoreEntity:SystemModelElement:Asset {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'ASSET-1', entity_type: 'Asset', name: 'Changed asset', category: 'System', tags: [], lifecycle_status: 'Active'})
       CREATE (sourceThreat:CoreEntity:SystemModelElement:DraftThreat {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'THREAT-1', entity_type: 'DraftThreat', name: 'Threat', status: 'Draft', threat_type: 'Integrity', target_asset_business_id: 'ASSET-1', standard_reference: 'DO-356A', tags: []})
       CREATE (targetThreat:CoreEntity:SystemModelElement:DraftThreat {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'THREAT-1', entity_type: 'DraftThreat', name: 'Threat', status: 'Draft', threat_type: 'Integrity', target_asset_business_id: 'ASSET-1', standard_reference: 'DO-356A', tags: []})
       CREATE (sourceLink:CoreEntity:SystemModelElement:TraceLink {id: randomUUID(), project_id: $project, revision_id: $source_revision, business_id: 'LINK-1', entity_type: 'TraceLink', link_type: 'IDENTIFIES', source_type: 'DraftThreat', source_business_id: 'THREAT-1', target_type: 'Asset', target_business_id: 'ASSET-1'})
       CREATE (targetLink:CoreEntity:SystemModelElement:TraceLink {id: randomUUID(), project_id: $project, revision_id: $target_revision, business_id: 'LINK-1', entity_type: 'TraceLink', link_type: 'IDENTIFIES', source_type: 'DraftThreat', source_business_id: 'THREAT-1', target_type: 'Asset', target_business_id: 'ASSET-1'})
       CREATE (sourceRevision)-[:CONTAINS]->(sourceA) CREATE (sourceRevision)-[:CONTAINS]->(sourceAsset) CREATE (sourceRevision)-[:CONTAINS]->(sourceThreat) CREATE (sourceRevision)-[:CONTAINS]->(sourceLink)
       CREATE (targetRevision)-[:CONTAINS]->(targetA) CREATE (targetRevision)-[:CONTAINS]->(targetAsset) CREATE (targetRevision)-[:CONTAINS]->(targetThreat) CREATE (targetRevision)-[:CONTAINS]->(targetLink)
       CREATE (sourceAsset)-[:DERIVED_FROM_SOURCE]->(sourceA) CREATE (sourceThreat)-[:DERIVED_FROM_SOURCE]->(sourceA) CREATE (sourceLink)-[:DERIVED_FROM_SOURCE]->(sourceA)
       CREATE (targetAsset)-[:DERIVED_FROM_SOURCE]->(targetA) CREATE (targetThreat)-[:DERIVED_FROM_SOURCE]->(targetA) CREATE (targetLink)-[:DERIVED_FROM_SOURCE]->(targetA)`,
      {
        project: ids.project, model: ids.model, profile: ids.profile, source_revision: ids.sourceRevision, target_revision: ids.targetRevision, baseline: ids.baseline,
        project_business_id: `P5-${suffix}`, model_business_id: `P5-MODEL-${suffix}`, profile_business_id: `P5-PROFILE-${suffix}`,
        source_revision_business_id: `P5-REV-A-${suffix}`, target_revision_business_id: `P5-REV-B-${suffix}`, baseline_business_id: `P5-BASE-${suffix}`, hash: "a".repeat(64),
      },
    ));
  } finally {
    await session.close();
  }

  const repository = new ImpactRepository();
  const service = new ImpactService(repository);
  const preview = await service.preview({ project_id: ids.project, from: { baseline_id: ids.baseline }, to: { revision_id: ids.targetRevision } });
  assert.deepEqual(preview.differences.map((item) => item.entity.business_id), ["ASSET-1"]);
  assert.deepEqual(preview.impacted.map((item) => [item.entity.business_id, item.impact_kind]), [["ASSET-1", "Direct"], ["THREAT-1", "Propagated"]]);

  const command = {
    actor: "phase5-integration", command_id: `phase5:${suffix}:assessment`, project_id: ids.project, revision_id: ids.targetRevision, expected_revision_version: 1,
    assessment: { business_id: `P5-IMPACT-${suffix}`, title: "Controlled impact", from: { baseline_id: ids.baseline }, to: { revision_id: ids.targetRevision }, rationale: "Controlled comparison" },
  };
  const created = await service.create(command);
  assert.equal(created.item_count, 2);
  assert.equal((await service.create(command)).replayed, true);
  await assert.rejects(service.create({ ...command, assessment: { ...command.assessment, rationale: "Different payload" } }), CommandPayloadMismatchError);

  let assessment = (await repository.readAssessments(ids.project, ids.targetRevision, created.assessment_id))[0];
  assert.equal(assessment.status, "Open");
  let version = created.new_revision_version;
  for (const [index, item] of assessment.items.entries()) {
    const disposition = await service.dispose({
      actor: "phase5-reviewer", command_id: `phase5:${suffix}:disposition:${index}`, project_id: ids.project, revision_id: ids.targetRevision, expected_revision_version: version,
      disposition: { business_id: `P5-DISPOSITION-${suffix}-${index}`, assessment_id: assessment.id, impact_item_id: item.id, decision: index === 0 ? "Reanalyze" : "Accept", rationale: "Reviewed impact", reviewer_role: "Security Engineer" },
    });
    version = disposition.new_revision_version;
  }
  assessment = (await repository.readAssessments(ids.project, ids.targetRevision, created.assessment_id))[0];
  assert.equal(assessment.status, "Resolved");
  assert.equal(assessment.items.every((item) => item.disposition?.reviewer === "phase5-reviewer"), true);

  const workProduct = await new AssuranceWorkProductService().generate({ project_id: ids.project, revision_id: ids.targetRevision, actor: "phase5-reporter" });
  assert.equal(workProduct.sections.some((section) => section.section_id === "DO326-TRACEABILITY"), true);
  assert.equal(workProduct.sections.some((section) => section.section_id === "DO356-SECURITY-ASSESSMENT"), true);
  assert.equal(workProduct.metadata.package_status, "Draft");
  assert.equal(workProduct.impact_assessments[0].status, "Resolved");
  assert.match(workProduct.metadata.disclaimer, /do not constitute/);

  const historical = await new TraceabilityReportService().generate({ project_id: ids.project, baseline_id: ids.baseline }, "phase5-reporter");
  assert.equal(historical.context.revision.id, ids.sourceRevision);
  assert.equal(historical.context.baseline?.id, ids.baseline);
  assert.equal(historical.assets[0].name, "Original asset");
});
