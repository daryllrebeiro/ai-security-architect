import { z } from 'zod';

export const AssetTypeSchema = z.enum([
  'INTERNET',
  'REPOSITORY',
  'SERVICE',
  'API_CONTROLLER',
  'ENDPOINT',
  'CONTAINER',
  'POD',
  'KUBERNETES_SERVICE',
  'KUBERNETES_SERVICE_ACCOUNT',
  'LOAD_BALANCER',
  'DATABASE',
  'BUCKET',
  'QUEUE',
  'TOPIC',
  'IAM_ROLE',
  'SERVICE_ACCOUNT',
  'SECRET',
  'NETWORK',
  'DEPENDENCY',
  'LLM',
  'AI_AGENT',
  'VECTOR_DATABASE',
]);

export type AssetType = z.infer<typeof AssetTypeSchema>;

export const CriticalitySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type Criticality = z.infer<typeof CriticalitySchema>;

export const AssetSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  type: AssetTypeSchema,
  name: z.string().min(1),
  environment: z.string().default('production'),
  isPublic: z.boolean().default(false),
  isSensitiveData: z.boolean().default(false),
  criticality: CriticalitySchema.default('MEDIUM'),
  metadata: z.record(z.unknown()).default({}),
  tags: z.array(z.string()).default([]),
});

export type Asset = z.infer<typeof AssetSchema>;
