import type { AttackPath } from '@ai-security-architect/core';

export type WhatIfAction = 'SEVER_EDGE' | 'RESTRICT_PERMISSION' | 'REMOVE_ASSET';

export interface WhatIfTarget {
  sourceAssetId?: string;
  targetAssetId?: string;
  edgeType?: string;
  edgeId?: string;
  assetId?: string;
  revokedPermissions?: string[];
}

export interface WhatIfHypothesis {
  id: string;
  action: WhatIfAction;
  target: WhatIfTarget;
  description: string;
}

export interface WhatIfOutcome {
  hypothesis: WhatIfHypothesis;
  baselinePathsCount: number;
  remainingPathsCount: number;
  closedPaths: AttackPath[];
  remainingPaths: AttackPath[];
  riskDelta: {
    pathsReductionPct: number;
    baselineTotalRisk: number;
    remainingTotalRisk: number;
    riskReductionPct: number;
  };
  isSimulatedOnly: true;
}
