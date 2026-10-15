import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { createApp } from "../app.js";
import { closeDriver, getDriver } from "../db/neo4j.js";
import { GovernanceRepository } from "../repositories/governanceRepository.js";

let server: ReturnType<ReturnType<typeof createApp>["listen"]>;
let baseUrl = "";
const projectIds: string[] = [];
const authorKey = "phase6-author-key-000001";
const approverKey = "phase6-approver-key-001";

before(async () => {
  process.env.ASTRA_API_KEYS_JSON = JSON.stringify([
    { key: authorKey, actor_id: "phase6-author", display_name: "Phase 6 Author", roles: ["SecurityEngineer"] },
    { key: approverKey, actor_id: "phase6-approver", display_name: "Phase 6 Approver", roles: ["EngineeringApprover"] },
  ]);
  server = createApp({ log: () => undefined }).listen(0, "127.0.0.1");
  await once(server, "listening");
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (projectIds.length > 0) {
    const session = getDriver().session();
    try {
      await session.run("MATCH (node) WHERE node.project_id IN $ids OR (node:Project AND node.id IN $ids) DETACH DELETE node", { ids: projectIds });
    } finally { await session.close(); }
  }
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  delete process.env.ASTRA_API_KEYS_JSON;
  await closeDriver();
});

async function post(path: string, key: string, body: unknown) {
  return fetch(baseUrl + path, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${key}` }, body: JSON.stringify(body) });
}

async function body<T>(response: Response): Promise<T> {
  const value = await response.json();
  assert.ok(response.ok, JSON.stringify(value));
  return value as T;
}

test("authenticated review E2E attributes comments and enforces separation of duties", async () => {
  const suffix = randomUUID();
  const workspace = await new GovernanceRepository().createProjectWorkspace({
    actor: "phase6-setup", command_id: `phase6:${suffix}:workspace`,
    project: { business_id: `P6-${suffix}`, name: "Phase 6 review E2E" },
    model: { business_id: "MODEL-1", name: "System", level: "system" }, revision: { business_id: "REV-1" },
    standard_profile: { business_id: "PROFILE-326A-356A", name: "DO-326A / DO-356A", profile_version: "phase6-test", standard_references: ["DO-326A", "DO-356A"] },
  });
  projectIds.push(workspace.project.id);
  const session = getDriver().session();
  try {
    await session.run(
      `MATCH (revision:Revision {id: $revision_id})
       CREATE (subject:CoreEntity:EngineeringElement:SecurityRequirement {
         id: $subject_id, project_id: $project_id, revision_id: $revision_id,
         entity_type: 'SecurityRequirement', business_id: 'REQ-1', status: 'Draft', revision_version: 1,
         payload_json: $payload_json
       }) CREATE (revision)-[:CONTAINS]->(subject)`,
      { project_id: workspace.project.id, revision_id: workspace.revision.id, subject_id: randomUUID(), payload_json: JSON.stringify({ business_id: "REQ-1", name: "Authenticated requirement", status: "Draft" }) },
    );
  } finally { await session.close(); }

  const base = { project_id: workspace.project.id, revision_id: workspace.revision.id };
  const created = await body<{ session_id: string; new_revision_version: number }>(await post("/api/v2/reviews/sessions", authorKey, {
    ...base, command_id: `phase6:${suffix}:session`, expected_revision_version: 1,
    session: { business_id: "SESSION-1", title: "Requirement approval", subject: { type: "SecurityRequirement", business_id: "REQ-1", version: 1 }, candidate_business_ids: [] },
  }));
  assert.equal(created.new_revision_version, 2);

  const commented = await body<{ new_revision_version: number }>(await post("/api/v2/reviews/comments", authorKey, {
    ...base, command_id: `phase6:${suffix}:comment`, expected_revision_version: 2, session_id: created.session_id,
    comment: { business_id: "COMMENT-1", body: "Evidence and acceptance criterion checked." },
  }));
  assert.equal(commented.new_revision_version, 3);

  const selfDecision = await post("/api/v2/reviews/decisions", authorKey, {
    ...base, command_id: `phase6:${suffix}:self-decision`, expected_revision_version: 3, session_id: created.session_id,
    review: { business_id: "DECISION-SELF", decision: "Accept", rationale: "Should be refused" },
  });
  assert.equal(selfDecision.status, 403);

  const decisionCommand = {
    ...base, command_id: `phase6:${suffix}:decision`, expected_revision_version: 3, session_id: created.session_id,
    review: { business_id: "DECISION-1", decision: "Approve", rationale: "Independent approval after evidence review" },
  };
  const decided = await body<{ decision_id: string; new_revision_version: number }>(await post("/api/v2/reviews/decisions", approverKey, decisionCommand));
  assert.equal(decided.new_revision_version, 4);
  const replayed = await body<typeof decided & { replayed: boolean }>(await post("/api/v2/reviews/decisions", approverKey, decisionCommand));
  assert.equal(replayed.replayed, true);
  assert.equal(replayed.decision_id, decided.decision_id);
  assert.equal(replayed.new_revision_version, decided.new_revision_version);

  const read = await fetch(`${baseUrl}/api/v2/reviews?project_id=${workspace.project.id}&revision_id=${workspace.revision.id}`, { headers: { authorization: `Bearer ${approverKey}` } });
  const stored = await body<{ sessions: Array<{ status: string; comments: Array<{ author_actor_id: string; author_role: string }>; decision?: { reviewer: string; reviewer_role: string; subject_version: number; decided_at: string } }> }>(read);
  assert.equal(stored.sessions[0].status, "Approved");
  assert.equal(stored.sessions[0].comments[0].author_actor_id, "phase6-author");
  assert.equal(stored.sessions[0].comments[0].author_role, "SecurityEngineer");
  assert.equal(stored.sessions[0].decision?.reviewer, "phase6-approver");
  assert.equal(stored.sessions[0].decision?.reviewer_role, "EngineeringApprover");
  assert.equal(stored.sessions[0].decision?.subject_version, 1);
  assert.ok(stored.sessions[0].decision?.decided_at);

  const health = await body<{ ok: boolean; status: string; checks: { neo4j: string; migrations: string } }>(await fetch(`${baseUrl}/api/v2/operations/health`));
  assert.deepEqual(health.checks, { neo4j: "available", migrations: "current" });
  assert.equal(health.ok, true);
  const metrics = await body<{ requests_total: number; errors_total: number; latency_ms: { p95: number } }>(await fetch(`${baseUrl}/api/v2/operations/metrics`));
  assert.ok(metrics.requests_total >= 7);
  assert.ok(metrics.errors_total >= 0);
  assert.ok(metrics.latency_ms.p95 >= 0);
});
