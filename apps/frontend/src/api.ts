import type {
  AttackPath,
  CxfImportCommitResult,
  CxfImportPreviewResult,
  CxfImportRequest,
  DO326ALink,
  GraphChangeSet,
  GraphData,
  ModelingExportData,
  ReviewStatus
} from "./types";

const baseUrl = "http://localhost:4000";

async function ensureOk(response: Response, fallbackMessage: string): Promise<void> {
  if (!response.ok) {
    let detail = fallbackMessage;
    try {
      const payload = (await response.json()) as { message?: string; errors?: string[] };
      if (payload?.message) {
        detail = payload.message;
      } else if (payload?.errors?.length) {
        detail = payload.errors.join("; ");
      }
    } catch {
      // ignore JSON parse failure
    }
    throw new Error(detail);
  }
}

export async function getGraph(): Promise<GraphData> {
  const response = await fetch(`${baseUrl}/graph`);
  await ensureOk(response, "Failed to load graph");
  return response.json();
}

export async function validateChangeSet(changeSet: GraphChangeSet): Promise<{ valid: boolean; errors: string[] }> {
  const response = await fetch(`${baseUrl}/graph/changeset/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changeSet)
  });
  await ensureOk(response, "Failed to validate changeset");
  return response.json();
}

export async function commitChangeSet(
  changeSet: GraphChangeSet
): Promise<{ committed: boolean; commit_id?: string; new_version?: string; errors?: string[] }> {
  const response = await fetch(`${baseUrl}/graph/changeset/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify(changeSet)
  });
  await ensureOk(response, "Failed to commit changeset");
  return response.json();
}

export async function previewCxfImport(payload: CxfImportRequest): Promise<CxfImportPreviewResult> {
  const response = await fetch(`${baseUrl}/imports/cxf-asset-inventory/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return (await response.json()) as CxfImportPreviewResult;
}

export async function commitCxfImport(payload: CxfImportRequest): Promise<CxfImportCommitResult> {
  const response = await fetch(`${baseUrl}/imports/cxf-asset-inventory/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify(payload)
  });
  return (await response.json()) as CxfImportCommitResult;
}

export async function runAnalysis(payload?: {
  analysis_batch_id?: string;
  max_hops?: number;
  generated_by?: string;
  scope_asset_ids?: string[];
  dps_hop_decay?: number;
}): Promise<{ count: number; paths: AttackPath[] }> {
  const response = await fetch(`${baseUrl}/analysis/attack-paths/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      analysis_batch_id: payload?.analysis_batch_id ?? `batch-${Date.now()}`,
      max_hops: payload?.max_hops ?? 3,
      generated_by: payload?.generated_by ?? "frontend-user",
      scope_asset_ids: payload?.scope_asset_ids,
      dps_hop_decay: payload?.dps_hop_decay
    })
  });
  await ensureOk(response, "Failed to run attack path analysis");
  return response.json();
}

export async function seedSampleData(): Promise<{
  seeded: boolean;
  commit_id: string;
  new_version: string;
  counts: { asset_nodes: number; asset_edges: number; threat_points: number; do326a_links: number };
}> {
  const response = await fetch(`${baseUrl}/admin/seed/sample`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-seed" }
  });
  await ensureOk(response, "Failed to seed sample data");
  return response.json();
}

export async function seedGenericData(): Promise<{
  seeded: boolean;
  commit_id: string;
  new_version: string;
  counts: { asset_nodes: number; asset_edges: number; threat_points: number; do326a_links: number };
}> {
  const response = await fetch(`${baseUrl}/admin/seed/generic`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-generic-seed" }
  });
  await ensureOk(response, "Failed to seed generic example data");
  return response.json();
}

export async function persistPaths(paths: AttackPath[]): Promise<{ persisted: number }> {
  const response = await fetch(`${baseUrl}/analysis/attack-paths/persist`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ paths })
  });
  await ensureOk(response, "Failed to persist paths");
  return response.json();
}

export async function getDo326aLinks(): Promise<{ count: number; links: DO326ALink[] }> {
  const response = await fetch(`${baseUrl}/compliance/do326a-links`);
  await ensureOk(response, "Failed to load DO326A links");
  return response.json();
}

export async function exportModelingResult(analysis_batch_id?: string): Promise<ModelingExportData> {
  const searchParams = new URLSearchParams();
  if (analysis_batch_id && analysis_batch_id.trim().length > 0) {
    searchParams.set("analysis_batch_id", analysis_batch_id.trim());
  }

  const query = searchParams.toString();
  const response = await fetch(`${baseUrl}/exports/modeling-result${query ? `?${query}` : ""}`);
  await ensureOk(response, "Failed to export modeling result");
  return response.json();
}

export async function createOrUpdateDo326aLink(link: DO326ALink): Promise<{ created: boolean; link: DO326ALink }> {
  const response = await fetch(`${baseUrl}/compliance/do326a-links`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(link)
  });
  await ensureOk(response, "Failed to save DO326A link");
  return response.json();
}

export async function reviewDo326aLink(
  link_id: string,
  review_status: ReviewStatus,
  reviewer?: string
): Promise<{ updated: boolean; link: DO326ALink }> {
  const response = await fetch(`${baseUrl}/compliance/do326a-links/${link_id}/review`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ review_status, reviewer })
  });
  await ensureOk(response, "Failed to update review status");
  return response.json();
}
