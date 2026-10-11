import { Router } from "express";
import { z } from "zod";
import { EngineeringCaseRepository } from "../repositories/engineeringCaseRepository.js";
import {
  mapF353204ToCoreDraft,
  standardAdapterDefinitions,
  type LegacyF353204Input,
} from "../services/f3532/standardAdapterRegistry.js";

const router = Router();
const repository = new EngineeringCaseRepository();
const querySchema = z.object({
  project_id: z.string().uuid(),
  revision_id: z.string().uuid(),
});
const bodySchema = z.object({
  project_id: z.string().uuid(),
  revision_id: z.string().uuid(),
  threat_conditions: z.array(z.object({
    tc_id: z.string().min(1),
    name: z.string().optional(),
    description: z.string().optional(),
    affected_element_type: z.enum(["Asset", "Function", "Interface", "DataFlow", "SecurityBoundary", "ExternalEntity"]),
    affected_element_business_id: z.string().min(1),
    cia: z.array(z.enum(["Confidentiality", "Integrity", "Availability"])).min(1),
    operational_context: z.string().optional(),
    effect: z.string().optional(),
    severity_reference: z.string().optional(),
    review_status: z.string().optional(),
  })),
  threat_scenarios: z.array(z.object({
    ts_id: z.string().min(1),
    name: z.string().optional(),
    description: z.string().optional(),
    threat_source: z.string().optional(),
    preconditions: z.array(z.string()).optional(),
    actions: z.array(z.string().min(1)).min(1),
    entry_point_business_ids: z.array(z.string().min(1)).min(1),
    target_type: z.enum(["Asset", "Function", "Interface", "DataFlow", "SecurityBoundary", "ExternalEntity"]),
    target_business_id: z.string().min(1),
    tc_ids: z.array(z.string().min(1)).min(1),
    existing_control_business_ids: z.array(z.string().min(1)).optional(),
    review_status: z.string().optional(),
  })),
});

router.get("/definitions", (_req, res) => res.json({ adapters: standardAdapterDefinitions }));

router.get("/f3532/status", async (req, res, next) => {
  try {
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ code: "INVALID_ADAPTER_SCOPE", errors: parsed.error.issues });
    const engineeringCase = await repository.read(parsed.data.project_id, parsed.data.revision_id);
    const binding = engineeringCase?.profile_configuration.adapters.find((item) => item.adapter_id === "f3532");
    return res.json({ adapter_id: "f3532", enabled: binding?.enabled === true, binding: binding ?? null });
  } catch (error) {
    return next(error);
  }
});

router.post("/f3532/04/preview", async (req, res, next) => {
  try {
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ code: "INVALID_F3532_ADAPTER_INPUT", errors: parsed.error.issues });
    const engineeringCase = await repository.read(parsed.data.project_id, parsed.data.revision_id);
    const binding = engineeringCase?.profile_configuration.adapters.find((item) => item.adapter_id === "f3532");
    if (!binding?.enabled) return res.status(409).json({ code: "STANDARD_ADAPTER_DISABLED", message: "The F3532 compatibility adapter is not enabled by this revision profile configuration." });
    const { project_id: _project, revision_id: _revision, ...legacy } = parsed.data;
    return res.json(mapF353204ToCoreDraft(legacy as LegacyF353204Input));
  } catch (error) {
    return next(error);
  }
});

export default router;
