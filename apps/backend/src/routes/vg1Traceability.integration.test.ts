import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import express from "express";
import { after, before, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { TraceabilityReport } from "@attackgraph/contracts";
import { closeDriver, getDriver } from "../db/neo4j.js";
import router from "./index.js";

let server: ReturnType<express.Express["listen"]>;
let baseUrl = "";
const projectIds: string[] = [];

before(async () => {
  const app = express();
  app.use(express.json());
  app.use(router);
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ message: error instanceof Error ? error.message : String(error) });
  });
  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (projectIds.length > 0) {
    const session = getDriver().session();
    try {
      await session.run(
        `MATCH (node)
         WHERE node.project_id IN $project_ids OR (node:Project AND node.id IN $project_ids)
         DETACH DELETE node`,
        { project_ids: projectIds },
      );
    } finally {
      await session.close();
    }
  }
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await closeDriver();
});

async function json<T>(response: Response): Promise<T> {
  const value = await response.json();
  assert.ok(response.ok, JSON.stringify(value));
  return value as T;
}

test("VG-1 creates, views, freezes and exports a traceable DO-356A Draft chain", async () => {
  const suffix = randomUUID();
  const workspaceResponse = await fetch(`${baseUrl}/api/v2/governance/workspaces`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      actor: "vg1-http-test",
      command_id: `vg1:${suffix}:workspace`,
      project: { business_id: `VG1-${suffix}`, name: "VG-1 HTTP test" },
      model: { business_id: "MODEL-1", name: "System model", level: "system" },
      revision: { business_id: "REV-1" },
      standard_profile: {
        business_id: "PROFILE-326A-356A",
        name: "DO-326A / DO-356A",
        profile_version: "vg1-test",
        standard_references: ["DO-326A", "DO-356A"],
      },
    }),
  });
  assert.equal(workspaceResponse.status, 201);
  const workspace = await json<{
    project: { id: string };
    revision: { id: string; version: number };
  }>(workspaceResponse);
  projectIds.push(workspace.project.id);

  const importResponse = await fetch(`${baseUrl}/api/v2/system-model/import/commit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      actor: "vg1-http-test",
      command_id: `vg1:${suffix}:import`,
      project_id: workspace.project.id,
      revision_id: workspace.revision.id,
      expected_revision_version: workspace.revision.version,
      import: {
        contract_version: "system-model.v2",
        source: {
          business_id: "SOURCE-1",
          source_type: "json",
          name: "Controlled VG-1 fixture",
          content_hash: "a".repeat(64),
          parser_name: "vg1-http-test",
          parser_version: "1.0.0",
        },
        entities: {
          assets: [{ business_id: "ASSET-1", name: "Connected system", category: "System" }],
          functions: [], interfaces: [], data_flows: [], security_boundaries: [], external_entities: [],
          evidence_records: [{
            business_id: "EVIDENCE-1", evidence_type: "controlled-fixture",
            title: "Trace basis", reference: "fixture://vg1/source-1",
          }],
          draft_threats: [{
            business_id: "THREAT-1", name: "Untrusted data ingress", threat_type: "UntrustedDataIngress",
            target_asset_business_id: "ASSET-1", standard_reference: "DO-356A",
            rationale: "Synthetic Draft content for vertical-slice verification.",
          }],
          trace_links: [
            {
              business_id: "TRACE-EVIDENCE-THREAT", link_type: "SUPPORTS",
              source: { type: "EvidenceRecord", business_id: "EVIDENCE-1" },
              target: { type: "DraftThreat", business_id: "THREAT-1" },
            },
            {
              business_id: "TRACE-THREAT-ASSET", link_type: "RELATED_TO",
              source: { type: "DraftThreat", business_id: "THREAT-1" },
              target: { type: "Asset", business_id: "ASSET-1" },
            },
          ],
        },
      },
    }),
  });
  assert.equal(importResponse.status, 201);
  const imported = await json<{ new_revision_version: number }>(importResponse);

  const revisionQuery = new URLSearchParams({ project_id: workspace.project.id, revision_id: workspace.revision.id });
  const reportResponse = await fetch(`${baseUrl}/api/v2/traceability/report?${revisionQuery}`, {
    headers: { "x-user-id": "vg1-reviewer" },
  });
  const report = await json<TraceabilityReport>(reportResponse);
  assert.equal(report.metadata.contract_version, "traceability-report.v1");
  assert.equal(report.metadata.generator_version, "astra.traceability-report/2.0.0");
  assert.equal(report.metadata.generated_by, "vg1-reviewer");
  assert.equal(report.metadata.integrity_status, "not_frozen");
  assert.deepEqual(report.context.standard_profile_version.standard_references, ["DO-326A", "DO-356A"]);
  assert.equal(report.sources[0].business_id, "SOURCE-1");
  assert.equal(report.sources[0].created_by, "vg1-http-test");
  assert.equal(report.draft_threats[0].status, "Draft");
  assert.equal(report.chains.length, 2);
  assert.ok(report.chains.some((chain) => chain.source.type === "EvidenceRecord" && chain.target.type === "DraftThreat"));
  assert.ok(report.chains.some((chain) => chain.source.type === "DraftThreat" && chain.target.type === "Asset"));
  assert.ok(report.chains.every((chain) => chain.source_record_business_id === "SOURCE-1"));

  const freezeResponse = await fetch(`${baseUrl}/api/v2/governance/revisions/freeze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      actor: "vg1-approver",
      command_id: `vg1:${suffix}:freeze`,
      project_id: workspace.project.id,
      revision_id: workspace.revision.id,
      expected_revision_version: imported.new_revision_version,
      baseline: { business_id: "BASELINE-1", content_hash: report.metadata.content_hash },
    }),
  });
  assert.equal(freezeResponse.status, 201);
  const frozen = await json<{ value: { id: string; frozen_by: string } }>(freezeResponse);
  assert.equal(frozen.value.frozen_by, "vg1-approver");

  const baselineQuery = new URLSearchParams({ project_id: workspace.project.id, baseline_id: frozen.value.id });
  const exportResponse = await fetch(`${baseUrl}/api/v2/traceability/report/export?${baselineQuery}`, {
    headers: { "x-user-id": "vg1-exporter" },
  });
  assert.equal(exportResponse.status, 200);
  assert.match(exportResponse.headers.get("content-disposition") ?? "", /attachment; filename="astra-traceability-BASELINE-1\.json"/);
  const exported = await json<TraceabilityReport>(exportResponse);
  assert.equal(exported.metadata.generated_by, "vg1-exporter");
  assert.equal(exported.metadata.integrity_status, "matched");
  assert.equal(exported.context.baseline?.business_id, "BASELINE-1");
  assert.equal(exported.context.project.id, workspace.project.id);
  assert.equal(exported.context.revision.id, workspace.revision.id);
  assert.equal(exported.metadata.content_hash, report.metadata.content_hash);
  assert.ok(exported.audit.some((event) => event.event_type === "REVISION_FROZEN"));
});
