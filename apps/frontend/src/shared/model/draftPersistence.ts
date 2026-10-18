import {
  analysisConfigurationSchema,
  systemModelImportPayloadSchema,
} from "@attackgraph/contracts";
import type { Draft } from "./workbench";
export function restoreDraft(
  value: unknown,
  project_id: string,
  revision_id: string,
): Draft | null {
  if (!value || typeof value !== "object") return null;
  const saved = value as Partial<Draft>;
  if (
    saved.project_id !== project_id ||
    saved.revision_id !== revision_id ||
    !Number.isInteger(saved.base_version) ||
    !saved.base_version ||
    saved.base_version < 1
  )
    return null;
  const parsed = systemModelImportPayloadSchema.safeParse({
    contract_version: "system-model.v2",
    source: {
      business_id: "RESTORE",
      source_type: "draft",
      name: "Draft",
      content_hash: "0".repeat(64),
      parser_name: "workbench",
      parser_version: "1",
    },
    entities: saved.entities,
  });
  const configuration = analysisConfigurationSchema.safeParse(
    saved.configuration,
  );
  return parsed.success && configuration.success
    ? {
        project_id,
        revision_id,
        base_version: saved.base_version,
        entities: parsed.data.entities,
        configuration: configuration.data,
      }
    : null;
}
