import type {
  AttackPath,
  ChokePointCandidate,
  Asset,
} from '@ai-security-architect/core';

export interface AttackPathAnalysisOptions {
  maxPathLength?: number;
  entryPointAssetTypes?: string[];
  targetAssetTypes?: string[];
  minRiskThreshold?: number;
  memoizeReachability?: boolean;
}

export interface AttackPathAnalysisResult {
  tenantId: string;
  entryPoints: Asset[];
  sensitiveTargets: Asset[];
  attackPaths: AttackPath[];
  recommendedChokePoints: ChokePointCandidate[];
  highestRiskScore: number;
  criticalPathsCount: number;
}
