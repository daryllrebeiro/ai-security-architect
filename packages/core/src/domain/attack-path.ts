import { z } from 'zod';
import { RelationshipTypeSchema } from './relationship.js';

export const AttackStepSchema = z.object({
  stepNumber: z.number().int().min(1),
  sourceAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  relationshipType: RelationshipTypeSchema,
  findingId: z.string().optional(),
  evidenceRef: z.string().optional(),
  explanation: z.string(),
  isCrossBoundaryRedacted: z.boolean().optional(),
  redactedScope: z.string().optional(),
});

export type AttackStep = z.infer<typeof AttackStepSchema>;

export const RiskScoreBreakdownSchema = z.object({
  impact: z.number().min(0).max(10),
  exploitability: z.number().min(0).max(10),
  reachability: z.number().min(0).max(1),
  assetCriticality: z.number().min(0).max(10),
  confidence: z.number().min(0).max(1),
  totalRisk: z.number().min(0).max(10),
});

export type RiskScoreBreakdown = z.infer<typeof RiskScoreBreakdownSchema>;

export const ChokePointCandidateSchema = z.object({
  edgeId: z.string().min(1),
  sourceAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  relationshipType: RelationshipTypeSchema,
  actionDescription: z.string(),
  pathsEliminatedCount: z.number().int().min(1),
  riskReductionPercentage: z.number().min(0).max(100),
  engineeringEffort: z.enum(['LOW', 'MEDIUM', 'HIGH']),
  blastRadius: z.enum(['LOW', 'MEDIUM', 'HIGH']),
});

export type ChokePointCandidate = z.infer<typeof ChokePointCandidateSchema>;

export const GlobalCutSetSchema = z.object({
  chokePoints: z.array(ChokePointCandidateSchema),
  totalCapacityCost: z.number(),
  pathsEliminatedCount: z.number(),
  fullySevered: z.boolean(),
});

export type GlobalCutSet = z.infer<typeof GlobalCutSetSchema>;

export const DiffClosureReasonSchema = z.enum(['remediated', 'asset-removed', 'unknown']);
export type DiffClosureReason = z.infer<typeof DiffClosureReasonSchema>;

export const PathDiffBucketSchema = z.enum(['introduced', 'closed', 'unchanged', 'severity-changed']);
export type PathDiffBucket = z.infer<typeof PathDiffBucketSchema>;

export const AttackPathSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  entryAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  pathLength: z.number().int().min(1),
  steps: z.array(AttackStepSchema).min(1),
  riskScore: RiskScoreBreakdownSchema,
  recommendedChokePoint: ChokePointCandidateSchema.optional(),
  recommendedCutSet: z.array(ChokePointCandidateSchema).optional(),
  verifiedEliminated: z.boolean().default(false),
  fingerprint: z.string().optional(),
  isSimulation: z.boolean().optional(),
  isWhatIf: z.boolean().optional(),
  whatIfContext: z
    .object({
      hypothesisId: z.string(),
      description: z.string(),
    })
    .optional(),
  threatIntelContext: z
    .object({
      isKevExploited: z.boolean().optional(),
      epssScore: z.number().optional(),
      cisaDueDate: z.string().optional(),
      explanation: z.string().optional(),
    })
    .optional(),
  simulationContext: z
    .object({
      rootAssetId: z.string(),
      direction: z.enum(['FORWARD', 'REVERSE']),
      hypothesis: z.string().optional(),
    })
    .optional(),
});

export type AttackPath = z.infer<typeof AttackPathSchema>;

export function calculateRiskScore(params: {
  impact: number;
  exploitability: number;
  reachability: number;
  assetCriticality: number;
  confidence: number;
}): RiskScoreBreakdown {
  // Normalize formula: Risk = (Impact * 0.3 + Exploitability * 0.3 + AssetCriticality * 0.4) * Reachability * Confidence
  const rawScore =
    (params.impact * 0.3 + params.exploitability * 0.3 + params.assetCriticality * 0.4) *
    params.reachability *
    params.confidence;
  const totalRisk = Math.min(10, Math.max(0, Math.round(rawScore * 10) / 10));

  return {
    impact: params.impact,
    exploitability: params.exploitability,
    reachability: params.reachability,
    assetCriticality: params.assetCriticality,
    confidence: params.confidence,
    totalRisk,
  };
}
