import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export interface RepositoryGraphInput {
  repository: string;
  graph: SecurityGraphEngine;
}

export interface FederationOptions {
  tenantId?: string;
  conflictStrategy?: 'UNION' | 'PREFER_FIRST';
}

export interface FederatedGraphResult {
  graph: SecurityGraphEngine;
  federatedRepos: string[];
  mergedNodeCount: number;
  totalNodes: number;
  totalEdges: number;
  crossRepoEdgesCount: number;
}
