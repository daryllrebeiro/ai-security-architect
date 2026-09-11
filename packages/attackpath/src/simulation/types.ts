import type { Asset, AttackPath } from '@ai-security-architect/core';

export type SimulationMode = 'FORWARD' | 'REVERSE' | 'BIDIRECTIONAL';

export interface SimulationHypothesis {
  assumedBreachedAssetId: string;
  description: string;
  threatActor?: string;
  mode?: SimulationMode;
  maxHops?: number;
}

export interface SimulationResult {
  hypothesis: SimulationHypothesis;
  breachedAsset: Asset;
  blastRadiusPaths: AttackPath[];
  upstreamEntrypointPaths: AttackPath[];
  reachableCrownJewels: Asset[];
  potentialExternalIngressAssets: Asset[];
  summary: {
    totalBlastRadiusPaths: number;
    totalUpstreamPaths: number;
    highestRiskScore: number;
  };
}
