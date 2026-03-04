import { z } from "zod";

export const assetNodeSchema = z.object({
  assetId: z.string().min(1),
  name: z.string().min(1),
  assetType: z.string().min(1),
  criticality: z.number().int().min(1).max(5),
  owner: z.string().optional(),
  tags: z.array(z.string()).optional()
});

export const assetEdgeSchema = z.object({
  edgeId: z.string().min(1),
  sourceAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  relationType: z.string().min(1),
  trustBoundary: z.boolean(),
  directionality: z.enum(["UNI", "BI"])
});

export const threatPointSchema = z.object({
  threatId: z.string().min(1),
  name: z.string().min(1),
  category: z.string().min(1),
  severityBase: z.number().int().min(1).max(5),
  preconditionText: z.string().optional(),
  assetId: z.string().min(1)
});

const changeSetSchema = <T extends z.ZodTypeAny>(schema: T) =>
  z.object({
    add: z.array(schema),
    update: z.array(schema),
    delete: z.array(z.string())
  });

export const graphChangeSetSchema = z.object({
  graphVersion: z.string().min(1),
  assets: changeSetSchema(assetNodeSchema),
  edges: changeSetSchema(assetEdgeSchema),
  threats: changeSetSchema(threatPointSchema)
});

export const runAnalysisSchema = z.object({
  analysisBatchId: z.string().min(1),
  maxHops: z.number().int().min(1).max(6).default(3),
  generatedBy: z.string().min(1),
  scopeAssetIds: z.array(z.string()).optional()
});

export const persistPathsSchema = z.object({
  paths: z.array(
    z.object({
      pathId: z.string().min(1),
      analysisBatchId: z.string().min(1),
      hopCount: z.number().int().min(1),
      score: z.number().min(0),
      priority: z.enum(["P1", "P2", "P3"]),
      explanations: z.array(z.string()),
      generatedBy: z.string().min(1),
      generatedAt: z.string().min(1),
      startsFromThreatId: z.string().min(1),
      hits: z.array(z.object({ hop: z.number().int().min(0), assetId: z.string().min(1) })),
      traverses: z.array(
        z.object({ hop: z.number().int().min(1), edgeId: z.string().min(1), assetId: z.string().min(1) })
      )
    })
  )
});
