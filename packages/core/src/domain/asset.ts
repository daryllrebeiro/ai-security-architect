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
  'CONTAINER_IMAGE',
  'REGISTRY',
  'LOG_AGGREGATOR',
  'MESSAGE_BROKER',
  'WAREHOUSE',
]);

export type AssetType = z.infer<typeof AssetTypeSchema>;

export const CriticalitySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type Criticality = z.infer<typeof CriticalitySchema>;

export const AssetSourceSchema = z.enum(['declared-iac', 'live-cloud']);
export type AssetSource = z.infer<typeof AssetSourceSchema>;

export const AssetSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  type: AssetTypeSchema,
  name: z.string().min(1),
  environment: z.string().default('production'),
  isPublic: z.boolean().default(false),
  isSensitiveData: z.boolean().default(false),
  criticality: CriticalitySchema.default('MEDIUM'),
  source: AssetSourceSchema.optional(),
  metadata: z.record(z.unknown()).default({}),
  tags: z.array(z.string()).default([]),
});

export type Asset = z.infer<typeof AssetSchema>;

export const CloudProviderSchema = z.enum(['AWS', 'GCP', 'KUBERNETES', 'AZURE']);
export type CloudProvider = z.infer<typeof CloudProviderSchema>;

export const CloudAssetSchema = AssetSchema.extend({
  source: z.literal('live-cloud').default('live-cloud'),
  cloudProvider: CloudProviderSchema,
  cloudArnOrId: z.string().optional(),
  region: z.string().optional(),
  accountOrProject: z.string().optional(),
});

export type CloudAsset = z.infer<typeof CloudAssetSchema>;
