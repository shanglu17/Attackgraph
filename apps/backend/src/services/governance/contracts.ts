import { z } from "zod";

const businessIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(120)
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/,
    "business_id must start with an alphanumeric character and contain only letters, numbers, '.', '_', ':', or '-'",
  );

const commandEnvelopeSchema = z.object({
  actor: z.string().trim().min(1).max(200),
  command_id: z.string().trim().min(1).max(200),
});

export const revisionWriteEnvelopeSchema = commandEnvelopeSchema.extend({
  project_id: z.string().uuid().transform((value) => value.toLowerCase()),
  revision_id: z.string().uuid().transform((value) => value.toLowerCase()),
  expected_revision_version: z.number().int().positive(),
});

export const createProjectWorkspaceSchema = commandEnvelopeSchema.extend({
  project: z.object({
    business_id: businessIdSchema,
    name: z.string().trim().min(1).max(200),
    description: z.string().trim().max(2_000).optional(),
  }),
  model: z.object({
    business_id: businessIdSchema,
    name: z.string().trim().min(1).max(200),
    level: z.string().trim().min(1).max(120),
  }),
  revision: z.object({
    business_id: businessIdSchema,
  }),
  standard_profile: z.object({
    business_id: businessIdSchema,
    name: z.string().trim().min(1).max(200),
    profile_version: z.string().trim().min(1).max(80),
    standard_references: z
      .array(z.string().trim().min(1).max(200))
      .min(1)
      .transform((values) => [...new Set(values)].sort()),
  }),
});

export const freezeRevisionSchema = commandEnvelopeSchema.extend({
  project_id: z.string().uuid(),
  revision_id: z.string().uuid(),
  expected_revision_version: z.number().int().positive(),
  baseline: z.object({
    business_id: businessIdSchema,
    content_hash: z
      .string()
      .trim()
      .regex(/^[a-fA-F0-9]{64}$/)
      .transform((value) => value.toLowerCase()),
  }),
});

export const approveBaselineSchema = commandEnvelopeSchema.extend({
  project_id: z.string().uuid(),
  baseline_id: z.string().uuid(),
  expected_baseline_version: z.number().int().positive(),
  rationale: z.string().trim().min(1).max(2_000),
});

export type CreateProjectWorkspaceInput = z.infer<typeof createProjectWorkspaceSchema>;
export type FreezeRevisionInput = z.infer<typeof freezeRevisionSchema>;
export type ApproveBaselineInput = z.infer<typeof approveBaselineSchema>;
export type RevisionWriteEnvelope = z.infer<typeof revisionWriteEnvelopeSchema>;
