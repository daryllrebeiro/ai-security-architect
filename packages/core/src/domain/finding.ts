import { z } from 'zod';
import { EvidenceSchema } from './evidence.js';

export const FindingCategorySchema = z.enum([
  'SECRET_EXPOSURE',
  'SSRF',
  'SQL_INJECTION',
  'REMOTE_CODE_EXECUTION',
  'IAM_OVERPRIVILEGE',
  'PUBLIC_EXPOSURE',
  'VULNERABLE_DEPENDENCY',
  'CONTAINER_MISCONFIGURATION',
  'KUBERNETES_PRIVILEGE_ESCALATION',
  'PROMPT_INJECTION',
  'INSECURE_COMMUNICATION',
]);

export type FindingCategory = z.infer<typeof FindingCategorySchema>;

export const FindingSeveritySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type FindingSeverity = z.infer<typeof FindingSeveritySchema>;

export const FindingConfidenceSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CERTAIN']);
export type FindingConfidence = z.infer<typeof FindingConfidenceSchema>;

export const FindingSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  assetId: z.string().min(1),
  category: FindingCategorySchema,
  ruleId: z.string().min(1),
  title: z.string().min(1),
  description: z.string(),
  severity: FindingSeveritySchema,
  confidence: FindingConfidenceSchema,
  scanner: z.string(),
  cve: z.string().optional(),
  cwe: z.string().optional(),
  evidence: EvidenceSchema,
  remediationRecommendation: z.string().optional(),
  metadata: z.record(z.unknown()).default({}),
});

export type Finding = z.infer<typeof FindingSchema>;
