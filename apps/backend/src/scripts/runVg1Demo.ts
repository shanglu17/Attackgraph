import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { systemModelCommitRequestSchema } from "@attackgraph/contracts";
import { closeDriver } from "../db/neo4j.js";
import { GovernanceRepository } from "../repositories/governanceRepository.js";
import { SystemModelImportService } from "../services/systemModelImportService.js";
import { TraceabilityReportService } from "../services/traceabilityReportService.js";

const actor = "vg1-controlled-demo";

async function main() {
  const sourcePath = fileURLToPath(new URL("../../../../examples/vg1-controlled-source.json", import.meta.url));
  const sourceBytes = await readFile(sourcePath);
  const source = JSON.parse(sourceBytes.toString("utf8")) as {
    asset: { business_id: string; name: string };
    evidence: { business_id: string; reference: string };
    draft_threat: { business_id: string; name: string; standard_reference: string };
  };
  const sourceHash = createHash("sha256").update(sourceBytes).digest("hex");
  const governance = new GovernanceRepository();
  const workspace = await governance.createProjectWorkspace({
    actor,
    command_id: "vg1-demo-v1:create-workspace",
    project: {
      business_id: "VG1-DEMO-PROJECT",
      name: "VG-1 DO-356A traceability demonstration",
      description: "Controlled standard-neutral vertical slice",
    },
    model: { business_id: "VG1-MODEL", name: "VG-1 system model", level: "system" },
    revision: { business_id: "VG1-REVISION-001" },
    standard_profile: {
      business_id: "VG1-PROFILE-326A-356A",
      name: "DO-326A / DO-356A pilot profile",
      profile_version: "vg1.0.0",
      standard_references: ["DO-326A", "DO-356A"],
    },
  });

  const imported = await new SystemModelImportService().commit(systemModelCommitRequestSchema.parse({
    actor,
    command_id: "vg1-demo-v1:import-model",
    project_id: workspace.project.id,
    revision_id: workspace.revision.id,
    expected_revision_version: 1,
    import: {
      contract_version: "system-model.v2",
      source: {
        business_id: "VG1-SOURCE-001",
        source_type: "json",
        name: "VG-1 controlled source",
        content_hash: sourceHash,
        media_type: "application/json",
        parser_name: "vg1-controlled-fixture",
        parser_version: "1.0.0",
      },
      entities: {
        assets: [{
          business_id: source.asset.business_id,
          name: source.asset.name,
          category: "System",
          source_locator: { json_pointer: "/asset", field_locators: { name: "/asset/name" } },
        }],
        functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [],
        evidence_records: [{
          business_id: source.evidence.business_id,
          evidence_type: "controlled-fixture",
          title: "VG-1 trace basis",
          reference: source.evidence.reference,
          content_hash: sourceHash,
          source_locator: { json_pointer: "/evidence", field_locators: { reference: "/evidence/reference" } },
        }],
        draft_threats: [{
          business_id: source.draft_threat.business_id,
          name: source.draft_threat.name,
          description: "Synthetic Draft threat used only to prove the traceability pipeline.",
          threat_type: "UntrustedDataIngress",
          target_asset_business_id: source.asset.business_id,
          standard_reference: source.draft_threat.standard_reference,
          rationale: "Controlled example derived from the repository-owned source fixture.",
          source_locator: { json_pointer: "/draft_threat", field_locators: { name: "/draft_threat/name" } },
        }],
        trace_links: [
          {
            business_id: "VG1-TRACE-EVIDENCE-THREAT",
            link_type: "SUPPORTS",
            source: { type: "EvidenceRecord", business_id: source.evidence.business_id },
            target: { type: "DraftThreat", business_id: source.draft_threat.business_id },
          },
          {
            business_id: "VG1-TRACE-THREAT-ASSET",
            link_type: "RELATED_TO",
            source: { type: "DraftThreat", business_id: source.draft_threat.business_id },
            target: { type: "Asset", business_id: source.asset.business_id },
          },
        ],
      },
    },
  }));

  const reports = new TraceabilityReportService();
  const revisionReport = await reports.generate({
    project_id: workspace.project.id,
    revision_id: workspace.revision.id,
  }, actor);
  const frozen = await governance.freezeRevision({
    actor,
    command_id: "vg1-demo-v1:freeze-baseline",
    project_id: workspace.project.id,
    revision_id: workspace.revision.id,
    expected_revision_version: imported.new_revision_version,
    baseline: { business_id: "VG1-BASELINE-001", content_hash: revisionReport.metadata.content_hash },
  });
  const baselineReport = await reports.generate({
    project_id: workspace.project.id,
    baseline_id: frozen.value.id,
  }, actor);

  console.log(JSON.stringify({
    project_id: workspace.project.id,
    revision_id: workspace.revision.id,
    baseline_id: frozen.value.id,
    replayed: { workspace: workspace.replayed, import: imported.replayed, freeze: frozen.replayed },
    report: baselineReport,
  }, null, 2));
}

main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(closeDriver);
