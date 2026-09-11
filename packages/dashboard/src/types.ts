export interface RiskTrendPoint {
  scanId: string;
  commitSha: string;
  timestamp: string;
  totalPaths: number;
  criticalPaths: number;
  highPaths: number;
  mediumPaths: number;
  lowPaths: number;
}

export interface MttrMetric {
  fingerprint: string;
  introducedAt: string;
  closedAt: string;
  durationHours: number;
  closureReason: 'remediated';
  originAssetId: string;
}

export interface DashboardSummary {
  repository: string;
  tenantId: string;
  totalScans: number;
  currentTotalPaths: number;
  currentCriticalPaths: number;
  meanTimeToRemediationHours: number | null;
  remediatedPathsCount: number;
  assetRemovedCount: number;
  riskTrendSeries: RiskTrendPoint[];
  mttrDetails: MttrMetric[];
}
