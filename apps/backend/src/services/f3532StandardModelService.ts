import fs from "node:fs/promises";
import path from "node:path";
import type { F3532StandardImportRequest } from "../types/api.js";
import type { StandardRelationType } from "../types/domain.js";

type CsvRow = Record<string, string>;

const relationTypeByCsvValue: Record<string, StandardRelationType> = {
  references: "REFERENCES",
  triggers: "TRIGGERS",
  tailors: "TAILORS",
  defined_by: "DEFINES",
  depends_on: "DEPENDS_ON",
  checklist_of: "CHECKS",
  produces: "PRODUCES",
  iterates_with: "ITERATES_WITH"
};

export class F3532StandardModelService {
  async loadCsvDirectory(csvDir: string): Promise<F3532StandardImportRequest> {
    const [clauses, relations, artifacts, fields, stages] = await Promise.all([
      this.readCsv(path.join(csvDir, "clauses.csv")),
      this.readCsv(path.join(csvDir, "clause_relations.csv")),
      this.readCsv(path.join(csvDir, "artifact_types.csv")),
      this.readCsv(path.join(csvDir, "artifact_fields.csv")),
      this.readCsv(path.join(csvDir, "pipeline_stages.csv"))
    ]);

    return {
      standard_id: "ASTM-F3532-23",
      source: {
        model_version: "f3532_model_csv",
        source_ref: csvDir
      },
      clauses: clauses.map((row) => ({
        clause_id: row.clause_id,
        std: row.std || "ASTM-F3532-23",
        parent_id: this.optional(row.parent_id),
        level: this.optionalNumber(row.level),
        number: this.optional(row.number),
        section: this.optional(row.section),
        title_zh: this.optional(row.title_zh),
        title_en: this.optional(row.title_en),
        clause_type: this.optional(row.clause_type),
        normative: this.optional(row.normative),
        keywords: this.splitList(row.keywords),
        pdf_page: this.optionalNumber(row.pdf_page),
        text_zh: this.optional(row.text_zh),
        text_en: this.optional(row.text_en),
        notes: this.optional(row.notes)
      })),
      clause_relations: relations.map((row) => ({
        relation_id: row.rel_id,
        source_clause_id: row.from_clause_id,
        target_clause_id: row.to_clause_id,
        relation_type: relationTypeByCsvValue[row.relation_type] ?? "REFERENCES",
        description: this.optional(row.description)
      })),
      artifact_types: artifacts.map((row) => ({
        artifact_id: row.artifact_id,
        name_zh: row.name_zh,
        name_en: this.optional(row.name_en),
        io_role: row.io_role === "output" || row.io_role === "intermediate" ? row.io_role : "input",
        pipeline_slot: row.pipeline_slot,
        primary_clause_id: this.optional(row.primary_clause_id),
        primary_clause_title: this.optional(row.primary_clause_title),
        scope_status:
          row.scope_status === "placeholder" || row.scope_status === "deprecated" || row.scope_status === "active"
            ? row.scope_status
            : undefined,
        source_ref: this.optional(row.source_ref),
        description: this.optional(row.description)
      })),
      artifact_fields: fields.map((row) => ({
        field_id: row.field_id,
        artifact_id: row.artifact_id,
        artifact_name: this.optional(row.artifact_name),
        seq: this.optionalNumber(row.seq) ?? 1,
        field_name_zh: row.field_name_zh,
        required: row.required === "必填" || /^true$/i.test(row.required),
        data_type: row.data_type || "text",
        enum_or_ref: this.optional(row.enum_or_ref),
        fill_guidance: this.optional(row.fill_guidance),
        example: this.optional(row.example),
        clause_ref: this.optional(row.clause_ref),
        clause_title: this.optional(row.clause_title),
        source: this.optional(row.source),
        trace_role: this.optional(row.trace_role)
      })),
      pipeline_stages: stages.map((row) => ({
        stage_id: row.stage_id,
        stage_name: this.optional(row.stage_title),
        key_question: this.optional(row.question),
        inputs: this.splitSemicolonList(row.input_artifacts),
        activities: this.optional(row.analyst_activities),
        outputs: this.splitSemicolonList(row.output_artifacts),
        termination_condition: this.optional(row.iteration_termination)
      }))
    };
  }

  private async readCsv(filePath: string): Promise<CsvRow[]> {
    const text = await fs.readFile(filePath, "utf8");
    const rows = this.parseCsv(text.replace(/^\uFEFF/, ""));
    const [headers, ...body] = rows;
    return body
      .filter((row) => row.some((cell) => cell.trim().length > 0))
      .map((row) =>
        Object.fromEntries(headers.map((header, index) => [header, row[index] ?? ""]))
      );
  }

  private parseCsv(text: string): string[][] {
    const rows: string[][] = [];
    let row: string[] = [];
    let cell = "";
    let inQuotes = false;

    for (let i = 0; i < text.length; i += 1) {
      const char = text[i];
      const next = text[i + 1];
      if (char === '"' && inQuotes && next === '"') {
        cell += '"';
        i += 1;
      } else if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === "," && !inQuotes) {
        row.push(cell);
        cell = "";
      } else if ((char === "\n" || char === "\r") && !inQuotes) {
        if (char === "\r" && next === "\n") {
          i += 1;
        }
        row.push(cell);
        rows.push(row);
        row = [];
        cell = "";
      } else {
        cell += char;
      }
    }

    if (cell.length > 0 || row.length > 0) {
      row.push(cell);
      rows.push(row);
    }
    return rows;
  }

  private optional(value: string | undefined): string | undefined {
    const trimmed = value?.trim();
    return trimmed ? trimmed : undefined;
  }

  private optionalNumber(value: string | undefined): number | undefined {
    const trimmed = value?.trim();
    if (!trimmed) {
      return undefined;
    }
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : undefined;
  }

  private splitList(value: string | undefined): string[] {
    return (value ?? "")
      .split(/[;,，；、]/)
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }

  private splitSemicolonList(value: string | undefined): string[] {
    return (value ?? "")
      .split(";")
      .map((item) => item.trim())
      .filter((item) => item.length > 0 && !item.startsWith("(外部)"));
  }
}
