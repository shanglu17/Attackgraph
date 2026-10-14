import {
  assuranceWorkProductContractVersion,
  type AssuranceWorkProduct,
  type ImpactEntityRef,
  type TraceabilityGap,
  type TraceabilityMatrixRow,
  type WorkProductQuery,
} from "@attackgraph/contracts";
import { ImpactRepository } from "../repositories/impactRepository.js";
import { impactHash } from "./impact/impactEngine.js";
import { TraceabilityReportService } from "./traceabilityReportService.js";

export const assuranceWorkProductGeneratorVersion = "astra.assurance-work-product/1.0.0";

function reviewStatus(status?: string): TraceabilityMatrixRow["review_status"] {
  if (!status) return "Unknown";
  if (status === "Approved") return "Approved";
  if (status === "Reviewed" || status === "Promoted") return "Reviewed";
  if (status === "Stale") return "Stale";
  if (status === "Rejected") return "Rejected";
  if (["Draft", "Candidate", "Experimental", "PendingReview"].includes(status)) return "Draft";
  return "Unknown";
}

function ref(type: string, item: { business_id: string; name: string; status?: string }): ImpactEntityRef {
  return { type, business_id: item.business_id, name: item.name, status: item.status };
}

export class AssuranceWorkProductService {
  constructor(
    private readonly traceability = new TraceabilityReportService(),
    private readonly impactRepository = new ImpactRepository(),
  ) {}

  async generate(query: WorkProductQuery): Promise<AssuranceWorkProduct> {
    const report = await this.traceability.generate({ project_id: query.project_id, revision_id: query.revision_id, baseline_id: query.baseline_id }, query.actor);
    const assessments = await this.impactRepository.readAssessments(query.project_id, report.context.revision.id);
    const matrix: TraceabilityMatrixRow[] = report.chains.map((chain) => {
      const status = [reviewStatus(chain.source.status), reviewStatus(chain.target.status)].sort((a, b) => {
        const order = ["Stale", "Rejected", "Draft", "Unknown", "Reviewed", "Approved"];
        return order.indexOf(a) - order.indexOf(b);
      })[0] as TraceabilityMatrixRow["review_status"];
      const provenance: TraceabilityMatrixRow["provenance_status"] = chain.source_record_business_id ? "Linked" : "Missing";
      const coverage: TraceabilityMatrixRow["coverage_status"] = provenance === "Missing" || status === "Stale" || status === "Rejected" ? "Gap" : status === "Approved" || status === "Reviewed" ? "Covered" : "Partial";
      return { trace_link_business_id: chain.trace_link_business_id, link_type: chain.link_type, source: chain.source, target: chain.target, source_record_business_id: chain.source_record_business_id, provenance_status: provenance, review_status: status, coverage_status: coverage };
    }).sort((a, b) => a.trace_link_business_id.localeCompare(b.trace_link_business_id));

    const gaps: TraceabilityGap[] = [];
    for (const row of matrix) {
      if (row.provenance_status === "Missing") gaps.push({ gap_type: "MissingProvenance", entity_type: row.source.type, business_id: row.source.business_id, message: "Trace link has no resolvable SourceRecord." });
      if (row.review_status === "Stale") gaps.push({ gap_type: "StaleAnalysis", entity_type: row.source.type, business_id: row.source.business_id, message: "Trace chain contains a stale analysis result." });
      if (row.review_status === "Draft") gaps.push({ gap_type: "UnreviewedConclusion", entity_type: row.source.type, business_id: row.source.business_id, message: "Trace chain contains a Draft or candidate conclusion." });
    }
    const linked = new Set(matrix.flatMap((row) => [row.source.type + ":" + row.source.business_id, row.target.type + ":" + row.target.business_id]));
    const formal: ImpactEntityRef[] = [];
    const engineering = report.engineering_case;
    if (engineering) {
      const collections = [
        ["ThreatCondition", engineering.threat_conditions], ["ThreatScenario", engineering.threat_scenarios], ["RiskAssessment", engineering.risk_assessments],
        ["SecurityObjective", engineering.security_objectives], ["SecurityRequirement", engineering.security_requirements], ["Control", engineering.controls], ["VerificationCase", engineering.verification_cases],
      ] as const;
      for (const [type, values] of collections) for (const item of values) formal.push(ref(type, item));
    }
    for (const promotion of report.promotions) formal.push({ type: promotion.target_type, business_id: promotion.target_business_id, name: promotion.target_name, status: promotion.target_status });
    for (const entity of formal) {
      if (!linked.has(entity.type + ":" + entity.business_id)) gaps.push({ gap_type: "UntracedEntity", entity_type: entity.type, business_id: entity.business_id, message: "Formal engineering entity is not connected by a report-visible TraceLink." });
    }
    for (const assessment of assessments) for (const item of assessment.items.filter((value) => value.status === "Open")) {
      gaps.push({ gap_type: "OpenImpact", entity_type: item.entity.type, business_id: item.entity.business_id, message: "Change impact item has no recorded disposition." });
    }
    const uniqueGaps = [...new Map(gaps.map((gap) => [gap.gap_type + ":" + gap.entity_type + ":" + gap.business_id, gap])).values()].sort((a, b) => (a.gap_type + a.entity_type + a.business_id).localeCompare(b.gap_type + b.entity_type + b.business_id));
    const covered = matrix.filter((row) => row.coverage_status === "Covered").length;
    const partial = matrix.filter((row) => row.coverage_status === "Partial").length;
    const gapCount = matrix.filter((row) => row.coverage_status === "Gap").length;
    const packageStatus: AssuranceWorkProduct["metadata"]["package_status"] = report.context.baseline?.status === "Approved" && uniqueGaps.length === 0 && matrix.length > 0 ? "Reviewable" : "Draft";
    const references = report.context.standard_profile_version.standard_references;
    const sectionSpecs = [
      references.some((value) => /DO-?326/i.test(value)) ? { section_id: "DO326-TRACEABILITY", title: "DO-326A engineering traceability", basis: references.filter((value) => /DO-?326/i.test(value)) } : undefined,
      references.some((value) => /DO-?356/i.test(value)) ? { section_id: "DO356-SECURITY-ASSESSMENT", title: "DO-356A security assessment evidence", basis: references.filter((value) => /DO-?356/i.test(value)) } : undefined,
      engineering?.profile_configuration.adapters.some((adapter) => adapter.adapter_id === "f3532" && adapter.enabled) ? { section_id: "F3532-COMPATIBILITY-ANNEX", title: "F3532 compatibility projection", basis: ["enabled adapter:f3532"] } : undefined,
    ].filter((value): value is { section_id: string; title: string; basis: string[] } => value !== undefined);
    const basisIds = matrix.map((row) => row.trace_link_business_id);
    const sections = sectionSpecs.map((section) => ({
      section_id: section.section_id, title: section.title, profile_basis: section.basis, status: packageStatus,
      conclusions: matrix.length === 0 ? [] : [{ statement: `${matrix.length} trace links were evaluated; ${covered} are covered, ${partial} are partial, and ${gapCount} have direct coverage gaps.`, basis_trace_link_business_ids: basisIds }],
    }));
    const stable = {
      context: { project_id: query.project_id, revision_id: report.context.revision.id, baseline_id: report.context.baseline?.id, baseline_status: report.context.baseline?.status, profile_business_id: report.context.standard_profile_version.business_id, profile_version: report.context.standard_profile_version.profile_version, standard_references: references },
      coverage: { covered, partial, gaps: uniqueGaps.length, percentage: matrix.length === 0 ? 0 : Number(((covered / matrix.length) * 100).toFixed(2)) }, matrix, gaps: uniqueGaps, impact_assessments: assessments, sections,
    };
    return {
      contract_version: assuranceWorkProductContractVersion,
      metadata: {
        generator_version: assuranceWorkProductGeneratorVersion, generated_at: new Date().toISOString(), generated_by: query.actor,
        content_hash: impactHash(stable), package_status: packageStatus,
        disclaimer: "Engineering support output only. Coverage and review status do not constitute a compliance finding or airworthiness approval.",
      },
      ...stable,
    };
  }
}
