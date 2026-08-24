import { z } from 'zod';

export const RelationshipTypeSchema = z.enum([
  'EXPOSES_HTTP',
  'ROUTES_TO',
  'CALLS',
  'DEPENDS_ON',
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
]);

export type RelationshipType = z.infer<typeof RelationshipTypeSchema>;

export const RelationshipNatureSchema = z.enum(['DECLARED', 'OBSERVED', 'INFERRED']);
export type RelationshipNature = z.infer<typeof RelationshipNatureSchema>;

export const RelationshipSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  sourceAssetId: z.string().min(1),
  targetAssetId: z.string().min(1),
  type: RelationshipTypeSchema,
  nature: RelationshipNatureSchema.default('DECLARED'),
  confidence: z.number().min(0).max(1).default(1.0),
  evidenceRef: z.string().optional(),
  metadata: z.record(z.unknown()).default({}),
});

export type Relationship = z.infer<typeof RelationshipSchema>;
