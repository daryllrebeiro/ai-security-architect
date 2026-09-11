import { z } from 'zod';
import { RelationshipTypeSchema, type AttackPath } from '@ai-security-architect/core';

export const SecurityBudgetPolicySchema = z.object({
  name: z.string().default('Default Security Budget'),
  maxTotalPaths: z.number().int().min(0).optional(),
  maxCriticalPaths: z.number().int().min(0).default(0),
  maxNewPathsPerPR: z.number().int().min(0).default(0),
  maxRiskScorePerPath: z.number().min(0).max(10).default(8.5),
  maxTotalRiskScore: z.number().min(0).optional(),
  prohibitedRelationshipTypes: z.array(RelationshipTypeSchema).default([]),
  grandfatherExisting: z.boolean().default(true),
  allowlistFingerprints: z.array(z.string()).default([]),
  serviceSelector: z
    .object({
      tag: z.string().optional(),
      namespace: z.string().optional(),
    })
    .optional(),
});

export type SecurityBudgetPolicy = z.infer<typeof SecurityBudgetPolicySchema>;

export interface BudgetViolation {
  rule: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  pathId?: string;
  pathFingerprint?: string;
  serviceName?: string;
  actualValue: number | string;
  limitValue: number | string;
}

export interface BudgetEvaluationResult {
  passed: boolean;
  policy: SecurityBudgetPolicy;
  violations: BudgetViolation[];
  grandfatheredPaths: AttackPath[];
  diffEvaluated: boolean;
  newPathsEvaluationStatus: 'EVALUATED' | 'NOT_EVALUABLE';
  summary: {
    totalViolations: number;
    criticalViolations: number;
    grandfatheredCount: number;
    totalEvaluated: number;
  };
}
