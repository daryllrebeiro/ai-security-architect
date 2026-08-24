import { z } from 'zod';
import { AttackStepSchema, RiskScoreBreakdownSchema } from './attack-path.js';
import { RelationshipTypeSchema } from './relationship.js';

export const AIContextHandoffSchema = z.object({
  attackPathId: z.string().min(1),
  deterministicMetrics: z.object({
    entryNode: z.string().min(1),
    targetNode: z.string().min(1),
    pathLength: z.number().int().min(1),
    calculatedRiskScore: z.number().min(0).max(10),
    riskBreakdown: RiskScoreBreakdownSchema,
    optimalChokePointEdge: z.object({
      source: z.string().min(1),
      relationship: RelationshipTypeSchema,
      target: z.string().min(1),
    }),
  }),
  graphChain: z.array(AttackStepSchema),
  evidenceReferences: z.array(
    z.object({
      evidenceId: z.string().min(1),
      sourceType: z.string(),
      repository: z.string(),
      filePath: z.string(),
      lineRange: z.string(),
      snippet: z.string(),
    })
  ),
  findingsSummary: z.array(
    z.object({
      findingId: z.string(),
      category: z.string(),
      title: z.string(),
      severity: z.string(),
      ruleId: z.string(),
    })
  ),
});

export type AIContextHandoff = z.infer<typeof AIContextHandoffSchema>;

export const PatchChangeSchema = z.object({
  filePath: z.string().min(1),
  action: z.enum(['MODIFY', 'CREATE', 'DELETE']),
  diff: z.string(),
  description: z.string(),
});

export type PatchChange = z.infer<typeof PatchChangeSchema>;

export const AIReasoningOutputSchema = z.object({
  summary: z.string().min(1),
  rootCauseAnalysis: z.string().min(1),
  businessImpact: z.string().min(1),
  evidenceReferences: z.array(z.string()),
  recommendedRemediation: z.object({
    description: z.string().min(1),
    targetChokePoint: z.string().min(1),
    expectedRiskReductionPercentage: z.number().min(0).max(100),
    engineeringEffort: z.enum(['LOW', 'MEDIUM', 'HIGH']),
    patches: z.array(PatchChangeSchema),
  }),
  alternativeRemediations: z.array(
    z.object({
      description: z.string(),
      tradeoff: z.string(),
    })
  ),
  confidence: z.enum(['MEDIUM', 'HIGH', 'VERY_HIGH']),
});

export type AIReasoningOutput = z.infer<typeof AIReasoningOutputSchema>;
