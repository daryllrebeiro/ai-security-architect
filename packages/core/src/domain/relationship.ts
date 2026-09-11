import { z } from 'zod';

export const RelationshipTypeSchema = z.enum([
  'EXPOSES_HTTP',
  'ROUTES_TO',
  'CALLS',
  'DEPENDS_ON',
  'COMPROMISES',
  'READS_FROM',
  'WRITES_TO',
  'ASSUMES_ROLE',
  'RUNS_AS',
  'DEPLOYED_TO',
  'AUTHENTICATES_TO',
  'TRUSTS',
  'CONTAINS',
  'HAS_VULNERABILITY',
  'CAN_READ',
  'CAN_WRITE',
  'CAN_ADMIN',
  'REACHES',
  'BUILT_FROM',
  'DEPLOYED_AS',
  'HOSTED_ON',
  'DATA_FLOW',
]);

export type RelationshipType = z.infer<typeof RelationshipTypeSchema>;

export const RelationshipNatureSchema = z.enum(['DECLARED', 'OBSERVED', 'INFERRED']);
export type RelationshipNature = z.infer<typeof RelationshipNatureSchema>;

export const RelationshipSourceSchema = z.enum(['declared-iac', 'live-cloud']);
export type RelationshipSource = z.infer<typeof RelationshipSourceSchema>;

export const RelationshipSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  sourceAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  type: RelationshipTypeSchema,
  nature: RelationshipNatureSchema.default('DECLARED'),
  confidence: z.number().min(0).max(1).default(1.0),
  source: RelationshipSourceSchema.optional(),
  evidenceRef: z.string().optional(),
  metadata: z.record(z.unknown()).default({}),
});

export type Relationship = z.infer<typeof RelationshipSchema>;

export const CloudRelationshipSchema = RelationshipSchema.extend({
  source: z.literal('live-cloud').default('live-cloud'),
  cloudProvider: z.enum(['AWS', 'GCP', 'KUBERNETES', 'AZURE']),
});

export type CloudRelationship = z.infer<typeof CloudRelationshipSchema>;
