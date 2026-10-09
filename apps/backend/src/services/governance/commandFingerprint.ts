import { createHash } from "node:crypto";
import type {
  ApproveBaselineInput,
  CreateProjectWorkspaceInput,
  FreezeRevisionInput,
} from "./contracts.js";

export interface CommandFingerprint {
  request_hash: string;
  request_hash_algorithm: "sha256";
  request_canonicalizer: string;
}

export type CanonicalValue = null | boolean | number | string | CanonicalValue[] | {
  [key: string]: CanonicalValue;
};

function canonicalJson(value: CanonicalValue): string {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("command fingerprint payload numbers must be finite");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value !== "object") {
    throw new TypeError(`unsupported command fingerprint value: ${typeof value}`);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

export function fingerprintCommandPayload(
  requestCanonicalizer: string,
  payload: CanonicalValue,
): CommandFingerprint {
  const canonicalRequest = `${requestCanonicalizer}\n${canonicalJson(payload)}`;
  return {
    request_hash: createHash("sha256").update(canonicalRequest, "utf8").digest("hex"),
    request_hash_algorithm: "sha256",
    request_canonicalizer: requestCanonicalizer,
  };
}

function trimmed(value: string): string {
  return value.trim();
}

export function fingerprintCreateProjectWorkspace(
  input: CreateProjectWorkspaceInput,
): CommandFingerprint {
  return fingerprintCommandPayload("governance.create-project-workspace/v1", {
    actor: trimmed(input.actor),
    project: {
      business_id: trimmed(input.project.business_id),
      name: trimmed(input.project.name),
      description: input.project.description === undefined ? null : trimmed(input.project.description),
    },
    model: {
      business_id: trimmed(input.model.business_id),
      name: trimmed(input.model.name),
      level: trimmed(input.model.level),
    },
    revision: {
      business_id: trimmed(input.revision.business_id),
    },
    standard_profile: {
      business_id: trimmed(input.standard_profile.business_id),
      name: trimmed(input.standard_profile.name),
      profile_version: trimmed(input.standard_profile.profile_version),
      standard_references: [...new Set(input.standard_profile.standard_references.map(trimmed))].sort(),
    },
  });
}

export function fingerprintFreezeRevision(input: FreezeRevisionInput): CommandFingerprint {
  return fingerprintCommandPayload("governance.freeze-revision/v1", {
    actor: trimmed(input.actor),
    project_id: input.project_id.toLowerCase(),
    revision_id: input.revision_id.toLowerCase(),
    expected_revision_version: input.expected_revision_version,
    baseline: {
      business_id: trimmed(input.baseline.business_id),
      content_hash: input.baseline.content_hash.trim().toLowerCase(),
    },
  });
}

export function fingerprintApproveBaseline(input: ApproveBaselineInput): CommandFingerprint {
  return fingerprintCommandPayload("governance.approve-baseline/v1", {
    actor: trimmed(input.actor),
    project_id: input.project_id.toLowerCase(),
    baseline_id: input.baseline_id.toLowerCase(),
    expected_baseline_version: input.expected_baseline_version,
    rationale: trimmed(input.rationale),
  });
}
