import { z } from "zod";

const id = z.string().trim().min(1).max(500);
const ids = z.array(id).max(1000).refine(xs => new Set(xs).size === xs.length, "Duplicate reference");
const text = z.string().trim().min(1);
const nullableText = text.nullable();
const domain = z.enum(["FUN", "INT", "DAT", "SUP"]);
const group = z.object({ any_of: ids.refine(xs => xs.length > 0, "Empty condition") }).strict();
const fact = z.object({ feature_id: id, state: z.enum(["present", "absent", "unknown", "ambiguous"]),
  evidence_refs: ids, scope: ids, note: z.string().nullable() }).strict();
const facts = z.array(fact).max(1000);
const asset = z.object({ asset_id: id, asset_type: z.enum(["FUN", "INT", "DAT", "SUP", "unknown"]),
  name: text, layer: nullableText, operational_phase: ids, evidence_refs: ids,
  prototype_asset_id: nullableText, version: id }).strict();
const feature = z.object({ feature_record_id: id, asset_id: id, EXP: facts, TRU: facts, PCX: facts,
  EXE: facts, INF: facts, FUN: facts, protections: facts,
  context: z.object({ operational_phase: ids, access_window: nullableText, modification_window: nullableText,
    assumptions: ids, evidence_refs: ids }).strict(), evidence_refs: ids, version: id }).strict();
const rule = z.object({ rule_id: id, asset_type: domain, required_features: z.array(group).min(1).max(100),
  supporting_features: ids, excluding_features: ids, context_requirements: z.array(group).max(100),
  output_threat_id: z.enum(["T.INT.UNAU", "T.INT.TAMP", "T.INT.MITM", "T.INT.DENI", "T.DAT.UNAC",
    "T.DAT.TAMP", "T.FUN.UNAU", "T.FUN.TAMP", "T.SUP.UNAU", "T.INT.SNIF", "T.SUP.THEF"]),
  explanation_template: text, version: id, source: text, source_required_text: text,
  exclusion_effect: z.enum(["block", "downgrade", "TODO_REVIEW"]),
  review_status: z.enum(["TODO_REVIEW", "APPROVED"]), reviewer: nullableText, review_basis: nullableText,
  enabled: z.boolean(), review_notes: ids }).strict();
const evidence = z.object({ evidence_id: id, source: text,
  source_locator: z.object({ section: nullableText, page: z.number().int().min(1).nullable(), figure: nullableText,
    sheet: nullableText, row: z.number().int().min(1).nullable() }).strict(), excerpt: z.string().nullable(),
  source_sha256: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  extraction_method: z.enum(["manual", "document_parser", "llm_assisted"]),
  confidence: z.number().min(0).max(1).nullable(), review_status: z.enum(["pending_review", "verified", "rejected"]),
  version: id }).strict();
const scope = z.object({ scope_id: id, asset_id: id, boundary_id: id, operational_phase: id,
  attacker_profile: text, evidence_refs: ids }).strict();
const policy = z.object({ rule_id: id, rule_version: id, version: id, feature_version: id,
  applicable_attacker_profiles: ids.refine(xs => xs.length > 0, "Explicit attacker profiles required"),
  applicable_phases: ids.refine(xs => xs.length > 0, "Explicit phases required"), review_evidence_refs: ids,
  protection_actions: z.array(z.object({ feature_id: id, action: z.enum(["block", "downgrade"]),
    effect_description: text, basis_evidence_refs: ids }).strict()).max(1000) }).strict();

export const previewSchema = z.object({ contract_version: z.literal("feature-preview-0.1"), scenario_id: id,
  assets: z.array(asset).max(1000), features: z.array(feature).max(1000), rules: z.array(rule).max(100),
  evidence: z.array(evidence).max(10000), scopes: z.array(scope).max(1000), policies: z.array(policy).max(100)
}).strict().refine(x => x.scopes.length * x.rules.length <= 10000, "At most 10000 scope/rule pairs per preview");

export type PreviewInput = z.infer<typeof previewSchema>;
export type Fact = z.infer<typeof fact>;
export const dimensions = ["EXP", "TRU", "PCX", "EXE", "INF", "FUN"] as const;

export class PreviewReferenceError extends Error {}

export function validateReferences(input: PreviewInput) {
  function unique<T>(records: T[], key: (r: T) => string, label: string) {
    const keys = records.map(key);
    if (new Set(keys).size !== keys.length) throw new PreviewReferenceError(`Duplicate ${label}`);
  }
  unique(input.assets, x => x.asset_id, "asset_id");
  unique(input.features, x => x.feature_record_id, "feature_record_id");
  unique(input.features, x => x.asset_id, "active feature record for asset");
  unique(input.rules, x => x.rule_id, "rule_id");
  unique(input.evidence, x => x.evidence_id, "evidence_id");
  unique(input.scopes, x => x.scope_id, "scope_id");
  unique(input.policies, x => x.rule_id, "policy rule_id");
  const assets = new Set(input.assets.map(x => x.asset_id));
  const rules = new Set(input.rules.map(x => x.rule_id));
  const evidence = new Set(input.evidence.map(x => x.evidence_id));
  const scopes = new Map(input.scopes.map(x => [x.scope_id, x]));
  const refs = (xs: string[]) => { for (const x of xs) if (!evidence.has(x)) throw new PreviewReferenceError(`Unknown evidence: ${x}`); };
  for (const a of input.assets) refs(a.evidence_refs);
  for (const s of input.scopes) {
    if (!assets.has(s.asset_id)) throw new PreviewReferenceError(`Unknown asset: ${s.asset_id}`);
    refs(s.evidence_refs);
  }
  for (const f of input.features) {
    if (!assets.has(f.asset_id)) throw new PreviewReferenceError(`Unknown asset: ${f.asset_id}`);
    refs(f.evidence_refs); refs(f.context.evidence_refs);
    for (const fact of [...dimensions.flatMap(d => f[d]), ...f.protections]) {
      refs(fact.evidence_refs);
      for (const s of fact.scope) if (scopes.get(s)?.asset_id !== f.asset_id)
        throw new PreviewReferenceError(`Unknown or foreign scope: ${s}`);
    }
  }
  for (const p of input.policies) {
    if (!rules.has(p.rule_id)) throw new PreviewReferenceError(`Unknown policy rule: ${p.rule_id}`);
    unique(p.protection_actions, x => x.feature_id, "protection action");
    refs(p.review_evidence_refs);
    for (const action of p.protection_actions) refs(action.basis_evidence_refs);
  }
}
