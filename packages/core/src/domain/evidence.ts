import { z } from 'zod';
import { createHash } from 'crypto';

export const EvidenceSourceTypeSchema = z.enum([
  'SOURCE_CODE',
  'TERRAFORM',
  'KUBERNETES',
  'DOCKERFILE',
  'DEPENDENCY_LOCKFILE',
  'STATIC_ANALYSIS',
  'SECRET_SCAN',
  'CLOUD_API',
  'RUNTIME_TRACE',
]);

export type EvidenceSourceType = z.infer<typeof EvidenceSourceTypeSchema>;

export const EvidenceSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  sourceType: EvidenceSourceTypeSchema,
  repository: z.string().min(1),
  filePath: z.string().min(1),
  lineStart: z.number().int().min(1),
  lineEnd: z.number().int().min(1),
  snippet: z.string(),
  snippetSha256: z.string().length(64),
  scanner: z.string(),
  timestamp: z.string().datetime(),
});

export type Evidence = z.infer<typeof EvidenceSchema>;

export function createEvidence(params: {
  id: string;
  tenantId: string;
  sourceType: EvidenceSourceType;
  repository: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  scanner: string;
}): Evidence {
  const snippetSha256 = createHash('sha256').update(params.snippet).digest('hex');
  return {
    ...params,
    snippetSha256,
    timestamp: new Date().toISOString(),
  };
}
