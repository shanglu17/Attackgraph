import { z } from "zod";
import {
  assetEdgeSchema,
  assetNodeSchema,
  do326aLinkSchema,
  graphChangeSetSchema,
  threatPointSchema,
  type SingleSheetImportRequest
} from "../types/api.js";
import type {
  AssetEdge,
  AssetNode,
  DO326ALink,
  GraphChangeSet,
  ThreatPoint
} from "../types/domain.js";

const singleSheetRowTypeSchema = z.enum(["AssetNode", "AssetEdge", "ThreatPoint", "DO326A_Link"]);

type SingleSheetRowType = z.infer<typeof singleSheetRowTypeSchema>;
type ImportErrorCategory = "template" | "field" | "binding";
type NormalizedRow = Record<string, unknown>;

const requiredTemplateHeaders = [
  "row_type",
  "id",
  "asset_name",
  "asset_type",
  "criticality",
  "security_domain",
  "description",
  "data_classification",
  "tags",
  "source_asset_id",
  "target_asset_id",
  "link_type",
  "protocol_or_medium",
  "direction",
  "trust_level",
  "security_mechanism",
  "related_asset_id",
  "name",
  "stride_category",
  "attack_vector",
  "entry_likelihood_level",
  "attack_complexity_level",
  "threat_source",
  "preconditions",
  "detection_status",
  "cve_reference",
  "expert_modifier",
  "expert_adjustment_note",
  "mitigation_reference",
  "standard_id",
  "clause_title",
  "semantic_element_id",
  "linkage_type",
  "evidence_reference",
  "review_status",
  "reviewer",
  "mapping_version"
] as const;

const optionalTemplateHeaders = ["template_version"] as const;
const allowedTemplateHeaders = [...requiredTemplateHeaders, ...optionalTemplateHeaders];

const rowTypeToSummaryKey = {
  AssetNode: "asset_nodes",
  AssetEdge: "asset_edges",
  ThreatPoint: "threat_points",
  DO326A_Link: "do326a_links"
} as const;

export interface ImportErrorDetail {
  type: ImportErrorCategory;
  row?: number;
  row_type?: SingleSheetRowType;
  field?: string;
  message: string;
}

export interface ImportSummary {
  asset_nodes: number;
  asset_edges: number;
  threat_points: number;
  do326a_links: number;
}

export interface ImportPreviewResult {
  accepted: number;
  rejected: number;
  errors: string[];
  error_details: ImportErrorDetail[];
  summary: ImportSummary;
}

export interface ImportPreparedChangeSet extends ImportPreviewResult {
  change_set?: GraphChangeSet;
}

interface RowParseSuccess<T> {
  data: T;
  errors: [];
}

interface RowParseFailure {
  data?: undefined;
  errors: ImportErrorDetail[];
}

type RowParseResult<T> = RowParseSuccess<T> | RowParseFailure;

export class ImportService {
  preview(input: SingleSheetImportRequest): ImportPreviewResult {
    const prepared = this.prepareInternal(input);
    return {
      accepted: prepared.accepted,
      rejected: prepared.rejected,
      errors: prepared.errors,
      error_details: prepared.error_details,
      summary: prepared.summary
    };
  }

  prepareChangeSet(input: SingleSheetImportRequest, graphVersion: string): ImportPreparedChangeSet {
    return this.prepareInternal(input, graphVersion);
  }

  createBindingErrors(messages: string[]): ImportErrorDetail[] {
    return messages.map((message) => ({
      type: "binding",
      message
    }));
  }

  private prepareInternal(input: SingleSheetImportRequest, graphVersion?: string): ImportPreparedChangeSet {
    const summary = this.createEmptySummary();
    const headers = this.resolveHeaders(input);
    const templateErrors = this.validateTemplateHeaders(headers);

    if (templateErrors.length > 0) {
      return this.buildResult(input.rows.length, input.rows.length, summary, templateErrors);
    }

    const assetNodes: AssetNode[] = [];
    const assetEdges: AssetEdge[] = [];
    const threatPoints: ThreatPoint[] = [];
    const do326aLinks: DO326ALink[] = [];
    const rowErrors: ImportErrorDetail[] = [];
    const rejectedRows = new Set<number>();

    for (const [index, sourceRow] of input.rows.entries()) {
      const rowNumber = index + 2;
      const row = this.normalizeRow(sourceRow);
      const rowTypeValue = this.getOptionalString(row, "row_type");
      const rowTypeResult = singleSheetRowTypeSchema.safeParse(rowTypeValue);

      if (!rowTypeResult.success) {
        rejectedRows.add(index);
        rowErrors.push({
          type: "field",
          row: rowNumber,
          field: "row_type",
          message: "row_type must be one of AssetNode, AssetEdge, ThreatPoint, DO326A_Link"
        });
        continue;
      }

      const rowType = rowTypeResult.data;
      summary[rowTypeToSummaryKey[rowType]] += 1;

      switch (rowType) {
        case "AssetNode": {
          const parsed = this.parseEntityRow(assetNodeSchema, row, rowType, rowNumber, {
            asset_id: this.getOptionalString(row, "id"),
            asset_name: this.getOptionalString(row, "asset_name"),
            asset_type: this.getOptionalString(row, "asset_type"),
            criticality: this.getOptionalString(row, "criticality"),
            security_domain: this.getOptionalString(row, "security_domain"),
            description: this.getOptionalString(row, "description"),
            data_classification: this.getOptionalString(row, "data_classification"),
            tags: this.getOptionalStringArray(row, "tags")
          });
          if (!parsed.data) {
            rejectedRows.add(index);
            rowErrors.push(...parsed.errors);
            continue;
          }
          assetNodes.push(parsed.data);
          break;
        }
        case "AssetEdge": {
          const parsed = this.parseEntityRow(assetEdgeSchema, row, rowType, rowNumber, {
            edge_id: this.getOptionalString(row, "id"),
            source_asset_id: this.getOptionalString(row, "source_asset_id"),
            target_asset_id: this.getOptionalString(row, "target_asset_id"),
            link_type: this.getOptionalString(row, "link_type"),
            protocol_or_medium: this.getOptionalString(row, "protocol_or_medium"),
            direction: this.getOptionalString(row, "direction"),
            trust_level: this.getOptionalString(row, "trust_level"),
            security_mechanism: this.getOptionalString(row, "security_mechanism"),
            description: this.getOptionalString(row, "description")
          });
          if (!parsed.data) {
            rejectedRows.add(index);
            rowErrors.push(...parsed.errors);
            continue;
          }
          assetEdges.push(parsed.data);
          break;
        }
        case "ThreatPoint": {
          const parsed = this.parseEntityRow(threatPointSchema, row, rowType, rowNumber, {
            threatpoint_id: this.getOptionalString(row, "id"),
            name: this.getOptionalString(row, "name"),
            related_asset_id: this.getOptionalString(row, "related_asset_id"),
            stride_category: this.getOptionalString(row, "stride_category"),
            attack_vector: this.getOptionalString(row, "attack_vector"),
            entry_likelihood_level: this.getOptionalString(row, "entry_likelihood_level"),
            attack_complexity_level: this.getOptionalString(row, "attack_complexity_level"),
            threat_source: this.getOptionalString(row, "threat_source"),
            preconditions: this.getOptionalString(row, "preconditions"),
            detection_status: this.getOptionalString(row, "detection_status"),
            cve_reference: this.getOptionalString(row, "cve_reference"),
            expert_modifier: this.getOptionalNumber(row, "expert_modifier"),
            expert_adjustment_note: this.getOptionalString(row, "expert_adjustment_note"),
            mitigation_reference: this.getOptionalString(row, "mitigation_reference")
          });
          if (!parsed.data) {
            rejectedRows.add(index);
            rowErrors.push(...parsed.errors);
            continue;
          }
          threatPoints.push(parsed.data);
          break;
        }
        case "DO326A_Link": {
          const parsed = this.parseEntityRow(do326aLinkSchema, row, rowType, rowNumber, {
            link_id: this.getOptionalString(row, "id"),
            standard_id: this.getOptionalString(row, "standard_id"),
            clause_title: this.getOptionalString(row, "clause_title"),
            semantic_element_id: this.getOptionalStringArray(row, "semantic_element_id"),
            linkage_type: this.getOptionalString(row, "linkage_type"),
            evidence_reference: this.getOptionalString(row, "evidence_reference"),
            review_status: this.getOptionalString(row, "review_status"),
            reviewer: this.getOptionalString(row, "reviewer"),
            mapping_version: this.getOptionalString(row, "mapping_version")
          });
          if (!parsed.data) {
            rejectedRows.add(index);
            rowErrors.push(...parsed.errors);
            continue;
          }
          do326aLinks.push(parsed.data);
          break;
        }
      }
    }

    const accepted = input.rows.length - rejectedRows.size;
    const rejected = rejectedRows.size;

    if (rowErrors.length > 0 || !graphVersion) {
      return this.buildResult(accepted, rejected, summary, rowErrors);
    }

    const changeSetCandidate: GraphChangeSet = {
      graph_version: graphVersion,
      asset_nodes: { add: assetNodes, update: [], delete: [] },
      asset_edges: { add: assetEdges, update: [], delete: [] },
      threat_points: { add: threatPoints, update: [], delete: [] },
      do326a_links: { add: do326aLinks, update: [], delete: [] }
    };

    const changeSetResult = graphChangeSetSchema.safeParse(changeSetCandidate);
    if (!changeSetResult.success) {
      const changeSetErrors = changeSetResult.error.issues.map((issue) => ({
        type: "field" as const,
        field: issue.path.join("."),
        message: issue.message
      }));
      return this.buildResult(accepted, rejected, summary, changeSetErrors);
    }

    return {
      ...this.buildResult(accepted, rejected, summary, []),
      change_set: changeSetResult.data
    };
  }

  private parseEntityRow<TSchema extends z.ZodTypeAny>(
    schema: TSchema,
    row: NormalizedRow,
    rowType: SingleSheetRowType,
    rowNumber: number,
    candidate: Record<string, unknown>
  ): RowParseResult<z.output<TSchema>> {
    const parsed = schema.safeParse(candidate);
    if (parsed.success) {
      return { data: parsed.data, errors: [] };
    }

    return {
      errors: parsed.error.issues.map((issue) => {
        const schemaField = typeof issue.path[0] === "string" ? issue.path[0] : undefined;
        const field = schemaField ? this.toTemplateFieldName(rowType, schemaField) : undefined;
        return {
          type: "field" as const,
          row: rowNumber,
          row_type: rowType,
          field,
          message: this.formatIssueMessage(issue, row, field)
        };
      })
    };
  }

  private buildResult(
    accepted: number,
    rejected: number,
    summary: ImportSummary,
    errorDetails: ImportErrorDetail[]
  ): ImportPreviewResult {
    return {
      accepted,
      rejected,
      errors: errorDetails.map((detail) => this.toErrorMessage(detail)),
      error_details: errorDetails,
      summary
    };
  }

  private createEmptySummary(): ImportSummary {
    return {
      asset_nodes: 0,
      asset_edges: 0,
      threat_points: 0,
      do326a_links: 0
    };
  }

  private resolveHeaders(input: SingleSheetImportRequest): string[] {
    if (input.headers && input.headers.length > 0) {
      return input.headers.map((header) => this.normalizeHeader(header));
    }

    const discovered = new Set<string>();
    for (const row of input.rows) {
      for (const header of Object.keys(row)) {
        discovered.add(this.normalizeHeader(header));
      }
    }
    return Array.from(discovered);
  }

  private validateTemplateHeaders(headers: string[]): ImportErrorDetail[] {
    const normalized = headers.filter((header) => header.length > 0);
    const headerSet = new Set(normalized);
    const duplicates = Array.from(new Set(normalized.filter((header, index) => normalized.indexOf(header) !== index)));
    const missing = requiredTemplateHeaders.filter((header) => !headerSet.has(header));
    const illegal = normalized.filter((header) => !allowedTemplateHeaders.includes(header as (typeof allowedTemplateHeaders)[number]));
    const errors: ImportErrorDetail[] = [];

    if (duplicates.length > 0) {
      errors.push({
        type: "template",
        message: `duplicate template headers: ${duplicates.join(", ")}`
      });
    }

    if (missing.length > 0) {
      errors.push({
        type: "template",
        message: `missing required template headers: ${missing.join(", ")}`
      });
    }

    if (illegal.length > 0) {
      errors.push({
        type: "template",
        message: `unexpected template headers: ${illegal.join(", ")}`
      });
    }

    return errors;
  }

  private normalizeRow(row: Record<string, unknown>): NormalizedRow {
    const normalized: NormalizedRow = {};
    for (const [key, value] of Object.entries(row)) {
      normalized[this.normalizeHeader(key)] = value;
    }
    return normalized;
  }

  private normalizeHeader(value: string): string {
    return value.trim();
  }

  private getOptionalString(row: NormalizedRow, field: string): string | undefined {
    const value = row[field];
    if (typeof value === "string") {
      const trimmed = value.trim();
      return trimmed.length > 0 ? trimmed : undefined;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
    return undefined;
  }

  private getOptionalNumber(row: NormalizedRow, field: string): number | string | undefined {
    const value = row[field];
    if (typeof value === "number") {
      return Number.isFinite(value) ? value : String(value);
    }
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed.length === 0) {
        return undefined;
      }
      const numericValue = Number(trimmed);
      return Number.isFinite(numericValue) ? numericValue : trimmed;
    }
    return undefined;
  }

  private getOptionalStringArray(row: NormalizedRow, field: string): string[] | undefined {
    const value = row[field];
    if (Array.isArray(value)) {
      const normalizedValues = value
        .map((item) => (typeof item === "string" || typeof item === "number" || typeof item === "boolean" ? String(item).trim() : ""))
        .filter((item) => item.length > 0);
      return normalizedValues.length > 0 ? normalizedValues : undefined;
    }

    const scalar = this.getOptionalString(row, field);
    if (!scalar) {
      return undefined;
    }

    const values = scalar
      .split(/[\n,;，；]+/)
      .map((item) => item.trim())
      .filter((item) => item.length > 0);

    return values.length > 0 ? values : undefined;
  }

  private toTemplateFieldName(rowType: SingleSheetRowType, schemaField: string): string {
    if (schemaField === "asset_id" || schemaField === "edge_id" || schemaField === "threatpoint_id" || schemaField === "link_id") {
      return "id";
    }

    if (rowType === "DO326A_Link" && schemaField === "linkage_type") {
      return "linkage_type";
    }

    return schemaField;
  }

  private formatIssueMessage(issue: z.ZodIssue, row: NormalizedRow, field?: string): string {
    if (issue.message === "Required" && field) {
      return `${field} is required`;
    }

    if (issue.code === z.ZodIssueCode.invalid_type && field) {
      const rawValue = row[field];
      if (rawValue === undefined || rawValue === null || rawValue === "") {
        return `${field} is required`;
      }
      return `${field} has an invalid value`;
    }

    if (issue.code === z.ZodIssueCode.invalid_enum_value && field) {
      return `${field} must be one of ${issue.options.join(", ")}`;
    }

    return issue.message;
  }

  private toErrorMessage(detail: ImportErrorDetail): string {
    const prefix: string[] = [];
    if (detail.type) {
      prefix.push(detail.type);
    }
    if (detail.row) {
      prefix.push(`row ${detail.row}`);
    }
    if (detail.row_type) {
      prefix.push(detail.row_type);
    }
    if (detail.field) {
      prefix.push(detail.field);
    }
    return prefix.length > 0 ? `${prefix.join(" / ")}: ${detail.message}` : detail.message;
  }
}
