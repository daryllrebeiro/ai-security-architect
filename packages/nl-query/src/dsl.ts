import { z } from 'zod';
import { AssetTypeSchema, RelationshipTypeSchema } from '@ai-security-architect/core';

export const NLQueryDslSchema = z.object({
  startNodeType: AssetTypeSchema.optional(),
  startAssetId: z.string().optional(),
  startAssetName: z.string().optional(),
  direction: z.enum(['FORWARD', 'REVERSE', 'ANY']).default('FORWARD'),
  relationshipTypes: z.array(RelationshipTypeSchema).optional(),
  targetNodeType: AssetTypeSchema.optional(),
  targetAssetId: z.string().optional(),
  targetTagFilters: z.array(z.string()).optional(),
  isSensitiveDataOnly: z.boolean().optional(),
  isPublicOnly: z.boolean().optional(),
  maxHops: z.number().int().min(1).max(10).default(5),
  declinedReason: z.string().optional(),
});

export type NLQueryDsl = z.infer<typeof NLQueryDslSchema>;

export interface GroundedPathStep {
  sourceAssetId: string;
  sourceAssetName: string;
  sourceAssetType: string;
  relationshipId: string;
  relationshipType: string;
  targetAssetId: string;
  targetAssetName: string;
  targetAssetType: string;
}

export interface GroundedPathResult {
  pathLength: number;
  nodeIds: string[];
  edgeIds: string[];
  steps: GroundedPathStep[];
  explanation: string;
}

export interface NLQueryResult {
  query: string;
  dsl: NLQueryDsl;
  declined: boolean;
  declinedReason?: string;
  matchedPaths: GroundedPathResult[];
  groundedAnswer: string;
  totalPathsFound: number;
}
