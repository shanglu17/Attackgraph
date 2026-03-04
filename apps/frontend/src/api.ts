import type { AttackPath, GraphChangeSet, GraphData } from "./types";

const baseUrl = "http://localhost:4000";

export async function getGraph(): Promise<GraphData> {
  const response = await fetch(`${baseUrl}/graph`);
  if (!response.ok) {
    throw new Error("加载图数据失败");
  }
  return response.json();
}

export async function validateChangeSet(changeSet: GraphChangeSet): Promise<{ valid: boolean; errors: string[] }> {
  const response = await fetch(`${baseUrl}/graph/changeset/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changeSet)
  });
  return response.json();
}

export async function commitChangeSet(
  changeSet: GraphChangeSet
): Promise<{ committed: boolean; commitId?: string; newVersion?: string; errors?: string[] }> {
  const response = await fetch(`${baseUrl}/graph/changeset/commit`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-user" },
    body: JSON.stringify(changeSet)
  });
  return response.json();
}

export async function runAnalysis(): Promise<{ count: number; paths: AttackPath[] }> {
  const response = await fetch(`${baseUrl}/analysis/attack-paths/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      analysisBatchId: `batch-${Date.now()}`,
      maxHops: 3,
      generatedBy: "frontend-user"
    })
  });
  if (!response.ok) {
    throw new Error("攻击路径推演失败");
  }
  return response.json();
}

export async function seedSampleData(): Promise<{
  seeded: boolean;
  commitId: string;
  newVersion: string;
  counts: { assets: number; edges: number; threats: number };
}> {
  const response = await fetch(`${baseUrl}/admin/seed/sample`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-user-id": "frontend-seed" }
  });
  if (!response.ok) {
    throw new Error("示例数据初始化失败");
  }
  return response.json();
}

export async function persistPaths(paths: AttackPath[]): Promise<{ persisted: number }> {
  const response = await fetch(`${baseUrl}/analysis/attack-paths/persist`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ paths })
  });
  if (!response.ok) {
    throw new Error("路径持久化失败");
  }
  return response.json();
}
