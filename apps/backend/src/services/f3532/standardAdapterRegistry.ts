import type {
  EngineeringThreatCondition,
  EngineeringThreatScenario,
} from "@attackgraph/contracts";

export const standardAdapterDefinitions = [{
  adapter_id: "f3532",
  adapter_version: "astra.f3532-compat/1.0.0",
  standard: "ASTM F3532",
  work_products: ["01", "02", "03", "04"],
  mode: "compatibility-preview",
}] as const;

export interface LegacyF353204Input {
  threat_conditions: Array<{
    tc_id: string;
    name?: string;
    description?: string;
    affected_element_type: EngineeringThreatCondition["affected_elements"][number]["type"];
    affected_element_business_id: string;
    cia: Array<"Confidentiality" | "Integrity" | "Availability">;
    operational_context?: string;
    effect?: string;
    severity_reference?: string;
    review_status?: string;
  }>;
  threat_scenarios: Array<{
    ts_id: string;
    name?: string;
    description?: string;
    threat_source?: string;
    preconditions?: string[];
    actions: string[];
    entry_point_business_ids: string[];
    target_type: EngineeringThreatScenario["target"]["type"];
    target_business_id: string;
    tc_ids: string[];
    existing_control_business_ids?: string[];
    review_status?: string;
  }>;
}

export interface F353204AdapterPreview {
  adapter_id: "f3532";
  adapter_version: string;
  external_review_assertions_ignored: boolean;
  warnings: string[];
  mapped: {
    threat_conditions: EngineeringThreatCondition[];
    threat_scenarios: EngineeringThreatScenario[];
  };
}

export function mapF353204ToCoreDraft(input: LegacyF353204Input): F353204AdapterPreview {
  const warnings: string[] = [];
  const reviewAssertions = [
    ...input.threat_conditions.map((item) => item.review_status),
    ...input.threat_scenarios.map((item) => item.review_status),
  ].filter((value) => value && value !== "Draft");
  if (reviewAssertions.length > 0) warnings.push("External review assertions were ignored; only a core ReviewDecision can change Draft status.");
  return {
    adapter_id: "f3532",
    adapter_version: standardAdapterDefinitions[0].adapter_version,
    external_review_assertions_ignored: reviewAssertions.length > 0,
    warnings,
    mapped: {
      threat_conditions: input.threat_conditions.map((item) => ({
        business_id: item.tc_id,
        name: item.name ?? item.tc_id,
        description: item.description,
        tags: ["adapter:f3532", "work-product:04"],
        status: "Draft",
        standard_references: ["ASTM F3532 Work Product 04"],
        affected_elements: [{ type: item.affected_element_type, business_id: item.affected_element_business_id }],
        security_attributes: item.cia,
        operational_context: item.operational_context ?? "Imported compatibility context; human confirmation required.",
        effect: item.effect ?? "Imported compatibility effect; human confirmation required.",
        severity_reference: item.severity_reference ?? "unresolved",
        assumptions: [],
      })),
      threat_scenarios: input.threat_scenarios.map((item) => ({
        business_id: item.ts_id,
        name: item.name ?? item.ts_id,
        description: item.description,
        tags: ["adapter:f3532", "work-product:04"],
        status: "Draft",
        standard_references: ["ASTM F3532 Work Product 04"],
        threat_source: item.threat_source ?? "unresolved",
        preconditions: item.preconditions ?? [],
        actions: item.actions,
        entry_point_business_ids: item.entry_point_business_ids,
        target: { type: item.target_type, business_id: item.target_business_id },
        threat_condition_business_ids: item.tc_ids,
        existing_control_business_ids: item.existing_control_business_ids ?? [],
      })),
    },
  };
}
