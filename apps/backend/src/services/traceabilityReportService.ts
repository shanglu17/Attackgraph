import { createHash } from "node:crypto";
import {
  traceabilityReportContractVersion,
  type TraceabilityReport,
  type TraceabilityReportChain,
  type TraceabilityReportEndpoint,
  type TraceabilityReportQuery,
} from "@attackgraph/contracts";
import { SystemModelRepository } from "../repositories/systemModelRepository.js";
import { TraceabilityReportRepository } from "../repositories/traceabilityReportRepository.js";
import { EngineeringCaseRepository } from "../repositories/engineeringCaseRepository.js";

export const traceabilityReportGeneratorVersion = "astra.traceability-report/2.0.0";

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  throw new TypeError(`unsupported traceability report value: ${typeof value}`);
}

function contentHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

export class TraceabilityReportService {
  constructor(
    private readonly reportRepository = new TraceabilityReportRepository(),
    private readonly systemModelRepository = new SystemModelRepository(),
    private readonly engineeringCaseRepository = new EngineeringCaseRepository(),
  ) {}

  async generate(query: TraceabilityReportQuery, actor: string): Promise<TraceabilityReport> {
    const context = await this.reportRepository.resolveContext(query);
    const model = await this.systemModelRepository.read(query.project_id, context.revision.id);
    const [traceSources, audit, engineeringCase] = await Promise.all([
      this.reportRepository.readTraceSourceMap(query.project_id, context.revision.id),
      this.reportRepository.readAudit(query.project_id, context.revision.id),
      this.engineeringCaseRepository.read(query.project_id, context.revision.id),
    ]);

    const endpointIndex = new Map<string, TraceabilityReportEndpoint>();
    const addEndpoint = (type: TraceabilityReportEndpoint["type"], businessId: string, name: string, status?: string) => {
      endpointIndex.set(`${type}:${businessId}`, { type, business_id: businessId, name, status });
    };
    for (const item of model.entities.assets) addEndpoint("Asset", item.business_id, item.name, item.lifecycle_status);
    for (const item of model.entities.functions) addEndpoint("Function", item.business_id, item.name);
    for (const item of model.entities.interfaces) addEndpoint("Interface", item.business_id, item.name);
    for (const item of model.entities.data_flows) addEndpoint("DataFlow", item.business_id, item.name);
    for (const item of model.entities.security_boundaries) addEndpoint("SecurityBoundary", item.business_id, item.name);
    for (const item of model.entities.external_entities) addEndpoint("ExternalEntity", item.business_id, item.name);
    for (const item of model.entities.evidence_records) addEndpoint("EvidenceRecord", item.business_id, item.title);
    for (const item of model.entities.draft_threats) addEndpoint("DraftThreat", item.business_id, item.name, item.status);
    if (engineeringCase) {
      addEndpoint("ProfileConfiguration", engineeringCase.profile_configuration.business_id, engineeringCase.profile_configuration.name, engineeringCase.profile_configuration.status);
      const engineeringCollections = [
        ["TailoringDecision", engineeringCase.tailoring_decisions],
        ["ThreatPoint", engineeringCase.threat_points],
        ["ThreatCondition", engineeringCase.threat_conditions],
        ["ThreatScenario", engineeringCase.threat_scenarios],
        ["RiskAssessment", engineeringCase.risk_assessments],
        ["SecurityObjective", engineeringCase.security_objectives],
        ["SecurityRequirement", engineeringCase.security_requirements],
        ["Control", engineeringCase.controls],
        ["VerificationCase", engineeringCase.verification_cases],
      ] as const;
      for (const [type, values] of engineeringCollections) {
        for (const item of values) addEndpoint(type, item.business_id, item.name, item.status);
      }
    }

    const allTraceLinks = [...model.entities.trace_links, ...(engineeringCase?.trace_links ?? [])];
    const chains: TraceabilityReportChain[] = allTraceLinks.map((link) => {
      const source = endpointIndex.get(`${link.source.type}:${link.source.business_id}`);
      const target = endpointIndex.get(`${link.target.type}:${link.target.business_id}`);
      if (!source || !target) throw new Error(`trace link '${link.business_id}' has an unresolved report endpoint`);
      const threat = source.type === "DraftThreat"
        ? model.entities.draft_threats.find((item) => item.business_id === source.business_id)
        : target.type === "DraftThreat"
          ? model.entities.draft_threats.find((item) => item.business_id === target.business_id)
          : undefined;
      const engineeringStandardReference = "standard_reference" in link && typeof link.standard_reference === "string"
        ? link.standard_reference
        : undefined;
      return {
        trace_link_business_id: link.business_id,
        link_type: link.link_type,
        source,
        target,
        standard_reference: engineeringStandardReference ?? threat?.standard_reference,
        source_record_business_id: traceSources.get(link.business_id) ?? engineeringCase?.source_record_business_id,
      };
    });

    const stableSnapshot = {
      project: context.project,
      model: context.model,
      revision: { id: context.revision.id, business_id: context.revision.business_id },
      standard_profile_version: context.standard_profile_version,
      sources: model.sources,
      assets: model.entities.assets,
      draft_threats: model.entities.draft_threats,
      evidence_records: model.entities.evidence_records,
      trace_links: model.entities.trace_links,
      chains,
      engineering_case: engineeringCase ? { ...engineeringCase, revision_version: undefined } : undefined,
    };
    const hash = contentHash(stableSnapshot);
    const integrityStatus = context.baseline
      ? context.baseline.content_hash === hash ? "matched" : "mismatch"
      : "not_frozen";

    return {
      metadata: {
        contract_version: traceabilityReportContractVersion,
        generator_version: traceabilityReportGeneratorVersion,
        generated_at: new Date().toISOString(),
        generated_by: actor,
        content_hash: hash,
        integrity_status: integrityStatus,
        disclaimer: "Draft engineering traceability view; it is not a compliance claim or airworthiness approval.",
      },
      context,
      sources: model.sources,
      assets: model.entities.assets,
      draft_threats: model.entities.draft_threats,
      evidence_records: model.entities.evidence_records,
      trace_links: allTraceLinks,
      engineering_case: engineeringCase,
      chains,
      audit,
    };
  }
}
