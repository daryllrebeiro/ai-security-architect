import type { Asset } from '@ai-security-architect/core';

export interface AssetHistoricalChangeRecord {
  scanId: string;
  timestamp: string;
  permissionsAddedCount: number;
  permissionsRemovedCount: number;
  relationshipsAddedCount: number;
  relationshipsRemovedCount: number;
  exposureChanged: boolean;
  hasWildcardGrant: boolean;
  addedPermissions: string[];
}

export interface AssetBaseline {
  assetId: string;
  totalScansObserved: number;
  totalChangeEventsCount: number;
  changeFrequency: number; // changeEvents / totalScans (0.0 to 1.0)
  meanPermissionsChanged: number;
  stdDevPermissionsChanged: number;
  hasHistoricalWildcardGrant: boolean;
  changeHistory: AssetHistoricalChangeRecord[];
}

export interface CurrentAssetChange {
  asset: Asset;
  newPermissions: string[];
  removedPermissions: string[];
  newRelationshipsCount: number;
  removedRelationshipsCount: number;
  exposureChanged: boolean;
}

export interface AnomalyEvaluationResult {
  assetId: string;
  assetName: string;
  status: 'ANOMALY_DETECTED' | 'NORMAL' | 'INSUFFICIENT_HISTORY';
  anomalyScore: number; // 0.0 to 10.0
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  explanation: string;
  baselineSummary: {
    scansObserved: number;
    changeFrequencyPercentage: number;
    typicalChangeMagnitude: number;
  };
}

export interface AnomalyDetectorConfig {
  minScansThreshold?: number; // default: 3
  zScoreThreshold?: number; // default: 2.0
  wildcardAnomalyScore?: number; // default: 8.5
}
