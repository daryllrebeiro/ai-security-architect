export type PostureTrend = 'IMPROVING' | 'DEGRADING' | 'STABLE';

export interface ExecutiveBriefingInput {
  tenantId: string;
  reportingPeriod: string;
  startMttrDays: number;
  endMttrDays: number;
  startCriticalPathsCount: number;
  endCriticalPathsCount: number;
  estimatedDollarExposureMin: number;
  estimatedDollarExposureMax: number;
  expectedAnnualLoss: number;
  currency?: string;
  topRiskThemes: string[];
  technicalNotes?: string[];
}

export interface BriefingMetricItem {
  label: string;
  value: string;
  isModelEstimate: boolean;
  estimateDisclaimer: string;
}

export interface ExecutiveBriefingReport {
  tenantId: string;
  reportingPeriod: string;
  generatedAt: string;
  postureTrend: PostureTrend;
  executiveSummary: string;
  keyMetrics: BriefingMetricItem[];
  strategicRiskThemes: string[];
  markdown: string;
}
