export type DealRiskRating = 'LOW' | 'MODERATE' | 'HIGH' | 'PROHIBITIVE';

export interface DueDiligenceConfig {
  targetCompanyName: string;
  anonymize: boolean;
  currency?: string; // default "USD"
  baseRemediationHourlyRate?: number; // default $150/hr
}

export interface DueDiligenceMetrics {
  totalAssetsAnalyzed: number;
  totalFindingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  attackPathsCount: number;
  estimatedRemediationLiabilityUsd: number;
  dealRiskRating: DealRiskRating;
}

export interface DueDiligenceReport {
  targetIdentifier: string; // Target company or REDACTED_TARGET_CORP
  isAnonymized: boolean;
  generatedAt: string;
  metrics: DueDiligenceMetrics;
  executiveSummary: string;
  technicalAppendix: string;
  anonymizationTokensUsed: number;
}
