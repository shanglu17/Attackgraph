import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { createReviewSession, getReviewWorkspace } from "../src/api.js";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

test("review API sends the bearer credential only in the authorization header", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  globalThis.fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(JSON.stringify({ contract_version: "review-workspace.v1", project_id: "p", revision_id: "r", revision_version: 1, sessions: [] }), { status: 200, headers: { "content-type": "application/json" } });
  };
  await getReviewWorkspace("project-id", "revision-id", "secret-api-key");
  assert.equal((calls[0].init?.headers as Record<string, string>).Authorization, "Bearer secret-api-key");
  assert.equal(calls[0].url.includes("secret-api-key"), false);
});

test("review session command preserves versioned subject and command id", async () => {
  let requestBody = "";
  globalThis.fetch = async (_input, init) => {
    requestBody = String(init?.body);
    return new Response(JSON.stringify({ recorded: true, replayed: false, audit_event_id: "a", new_revision_version: 2, session_id: "s", session_status: "Open" }), { status: 201, headers: { "content-type": "application/json" } });
  };
  const command = {
    command_id: "command-1", project_id: "11111111-1111-4111-8111-111111111111", revision_id: "22222222-2222-4222-8222-222222222222", expected_revision_version: 1,
    session: { business_id: "SESSION-1", title: "Review", subject: { type: "SecurityRequirement" as const, business_id: "REQ-1", version: 7 }, candidate_business_ids: [] },
  };
  await createReviewSession(command, "secret-api-key");
  assert.deepEqual(JSON.parse(requestBody), command);
});
