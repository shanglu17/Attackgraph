import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { authenticateRequest, AuthenticationRequiredError, parseConfiguredIdentities, requireRole, AuthorizationDeniedError } from "./apiKeyIdentity.js";

const raw = JSON.stringify([
  { key: "author-key-0000000001", actor_id: "author-1", display_name: "Author One", roles: ["SecurityEngineer"] },
  { key: "approver-key-0000001", actor_id: "approver-1", display_name: "Approver One", roles: ["EngineeringApprover"] },
]);

describe("API key identity", () => {
  it("maps a bearer secret to an attributed actor without returning the secret", () => {
    const principal = authenticateRequest({ headers: { authorization: "Bearer author-key-0000000001" } }, parseConfiguredIdentities(raw));
    assert.deepEqual(principal, { actor_id: "author-1", display_name: "Author One", roles: ["SecurityEngineer"] });
    assert.equal("key" in principal, false);
  });

  it("rejects missing or invalid credentials and enforces roles", () => {
    assert.throws(() => authenticateRequest({ headers: {} }, parseConfiguredIdentities(raw)), AuthenticationRequiredError);
    const principal = authenticateRequest({ headers: { authorization: "Bearer author-key-0000000001" } }, parseConfiguredIdentities(raw));
    assert.throws(() => requireRole(principal, ["EngineeringApprover"]), AuthorizationDeniedError);
  });
});
