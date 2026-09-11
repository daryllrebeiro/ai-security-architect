export const ORPHAN_OBSERVATION_DISCLAIMER =
  'No observed activity in 90-day visibility window (Observation-based, unconfirmed. May represent rare disaster recovery, periodic batch, or out-of-scope external integrations).';

export interface OrphanDetectionOptions {
  dormancyWindowDays?: number; // default 90 days
  estimatedMonthlyCostTable?: Record<string, number>;
}

export interface OrphanedAssetSummary {
  assetId: string;
  name: string;
  type: string;
  daysDormant: number;
  lastActivityDate?: string;
  estimatedMonthlyWasteUsd: number;
  securityRiskDescription: string;
  observationDisclaimer: string;
}
