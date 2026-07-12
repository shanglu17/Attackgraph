import type { FailureCondition, FhaImportRequest, FhaSeverity } from "./types";

export interface ParsedFhaDocument {
  payload: FhaImportRequest;
  counts: Record<FhaSeverity, number>;
}

export async function parseFhaDocument(file: File): Promise<ParsedFhaDocument> {
  const mammoth = await import("mammoth");
  const result = await mammoth.convertToHtml({ arrayBuffer: await file.arrayBuffer() });
  const document = new DOMParser().parseFromString(result.value, "text/html");
  const table = Array.from(document.querySelectorAll("table")).find((candidate) =>
    candidate.textContent?.includes("失效状态及其编号")
  );
  if (!table) {
    throw new Error("DOCX 中未找到包含“失效状态及其编号”的 FHA 表格。");
  }

  const failureConditions: FailureCondition[] = [];
  const seen = new Set<string>();
  for (const row of Array.from(table.querySelectorAll("tr")).slice(1)) {
    const cells = Array.from(row.querySelectorAll("th,td")).map((cell) => normalizeText(cell.textContent));
    if (cells.length < 5) {
      continue;
    }
    const rawCondition = cells[2];
    const match = rawCondition.match(/^(FC\d+(?:\.\d+)+)\s*(.*)$/i);
    if (!match) {
      continue;
    }
    const failureConditionId = match[1].toUpperCase();
    if (seen.has(failureConditionId)) {
      throw new Error(`FHA 表中存在重复编号：${failureConditionId}`);
    }
    seen.add(failureConditionId);
    const hazardClass = cells[3].toUpperCase();
    failureConditions.push({
      failure_condition_id: failureConditionId,
      name: match[2].trim() || failureConditionId,
      flight_phases: parseFlightPhases(cells[1]),
      hazard_class: hazardClass,
      severity: severityFromHazardClass(hazardClass),
      max_failure_probability: cells[4] || undefined,
      source_ref: file.name
    });
  }

  if (failureConditions.length === 0) {
    throw new Error("FHA 表格中未解析到 FC 编号。");
  }

  const counts = failureConditions.reduce<Record<FhaSeverity, number>>(
    (acc, item) => {
      acc[item.severity] += 1;
      return acc;
    },
    { Catastrophic: 0, Hazardous: 0, Major: 0, Minor: 0, NoSafetyEffect: 0, Unknown: 0 }
  );

  return {
    payload: {
      source: {
        file_name: file.name,
        submitted_by: "frontend-user",
        submitted_at: new Date().toISOString()
      },
      failure_conditions: failureConditions
    },
    counts
  };
}

function severityFromHazardClass(value: string): FhaSeverity {
  switch (value.replace(/\s+/g, "")) {
    case "I":
      return "Catastrophic";
    case "II":
      return "Hazardous";
    case "III":
      return "Major";
    case "IV":
      return "Minor";
    case "V":
      return "NoSafetyEffect";
    default:
      return "Unknown";
  }
}

function parseFlightPhases(value: string): string[] {
  if (!value) {
    return [];
  }
  if (value.toUpperCase() === "ALL") {
    return ["ALL"];
  }
  return value
    .split(/[\/、,，;；\s]+/)
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);
}

function normalizeText(value: string | null): string {
  return (value ?? "").replace(/\s+/g, " ").trim();
}
