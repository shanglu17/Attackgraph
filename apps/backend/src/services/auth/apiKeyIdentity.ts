import { createHash, timingSafeEqual } from "node:crypto";
import type { Request } from "express";
import { reviewRoleSchema, type AuthenticatedPrincipal, type ReviewRole } from "@attackgraph/contracts";
import { z } from "zod";

const configuredIdentitySchema = z.object({
  key: z.string().min(16),
  actor_id: z.string().trim().min(1).max(200),
  display_name: z.string().trim().min(1).max(200),
  roles: z.array(reviewRoleSchema).min(1),
});

const configuredIdentitiesSchema = z.array(configuredIdentitySchema);

export class AuthenticationRequiredError extends Error {
  readonly statusCode = 401;
  constructor(message = "A valid ASTRA API key is required") {
    super(message);
    this.name = "AuthenticationRequiredError";
  }
}

export class AuthorizationDeniedError extends Error {
  readonly statusCode = 403;
  constructor(message: string) {
    super(message);
    this.name = "AuthorizationDeniedError";
  }
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export function parseConfiguredIdentities(raw = process.env.ASTRA_API_KEYS_JSON): Array<AuthenticatedPrincipal & { key_digest: Buffer }> {
  if (!raw?.trim()) return [];
  const parsed = configuredIdentitiesSchema.parse(JSON.parse(raw));
  return parsed.map((identity) => ({
    actor_id: identity.actor_id,
    display_name: identity.display_name,
    roles: [...new Set(identity.roles)],
    key_digest: digest(identity.key),
  }));
}

export function authenticateRequest(
  request: Pick<Request, "headers">,
  configured = parseConfiguredIdentities(),
): AuthenticatedPrincipal {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith("Bearer ")) throw new AuthenticationRequiredError();
  const candidate = digest(authorization.slice("Bearer ".length).trim());
  const match = configured.find((identity) => timingSafeEqual(identity.key_digest, candidate));
  if (!match) throw new AuthenticationRequiredError("The supplied ASTRA API key is invalid");
  return { actor_id: match.actor_id, display_name: match.display_name, roles: match.roles };
}

export function requireRole(principal: AuthenticatedPrincipal, allowed: ReviewRole[]): ReviewRole {
  const role = allowed.find((candidate) => principal.roles.includes(candidate));
  if (!role) {
    throw new AuthorizationDeniedError(`actor '${principal.actor_id}' lacks one of the required roles: ${allowed.join(", ")}`);
  }
  return role;
}
