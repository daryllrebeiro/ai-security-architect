import type { AttackPath } from '@ai-security-architect/core';

export type UserRole = 'ADMIN' | 'ENGINEER' | 'VIEWER' | 'AUDITOR';

export interface UserScope {
  userId: string;
  tenantId: string;
  role: UserRole;
  allowedEnvironments?: string[];
  allowedTeams?: string[];
  allowedAssetIds?: string[];
}

export interface AccessDecision {
  granted: boolean;
  reason?: string;
  isPartialDisclosure?: boolean;
}

export interface ScopedPathRedactionResult {
  path: AttackPath | null;
  hasRedactions: boolean;
  redactedStepIndices: number[];
}
