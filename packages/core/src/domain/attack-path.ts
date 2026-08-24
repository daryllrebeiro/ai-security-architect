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

export const AttackPathSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  entryAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  pathLength: z.number().int().min(1),
  steps: z.array(AttackStepSchema).min(1),
  riskScore: RiskScoreBreakdownSchema,
  recommendedChokePoint: ChokePointCandidateSchema.optional(),
  verifiedEliminated: z.boolean().default(false),
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
