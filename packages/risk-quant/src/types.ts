import { z } from 'zod';

export interface CostBand {
  low: number;
  likely: number;
  high: number;
}

export const CostBandSchema = z.object({
  low: z.number().min(0),
  likely: z.number().min(0),
  high: z.number().min(0),
});

export interface BreachCostReferenceTable {
  version: string;
  source: string;
  baseForensicCost: CostBand;
  baseDowntimeCost: CostBand;
  costPerRecord: {
    pii: CostBand;
    paymentData: CostBand;
    secretsOrCredentials: CostBand;
    general: CostBand;
  };
  regulatoryFineMultiplier: CostBand;
}

export const BreachCostReferenceTableSchema = z.object({
  version: z.string().default('2024-ponemon-ibm-benchmark-v1'),
  source: z.string().default('Industry Cost of Data Breach Benchmark'),
  baseForensicCost: CostBandSchema.default({ low: 30000, likely: 75000, high: 180000 }),
  baseDowntimeCost: CostBandSchema.default({ low: 20000, likely: 50000, high: 150000 }),
  costPerRecord: z
    .object({
      pii: CostBandSchema.default({ low: 90, likely: 165, high: 280 }),
      paymentData: CostBandSchema.default({ low: 120, likely: 210, high: 390 }),
      secretsOrCredentials: CostBandSchema.default({ low: 150, likely: 250, high: 500 }),
      general: CostBandSchema.default({ low: 50, likely: 100, high: 180 }),
    })
    .default({}),
  regulatoryFineMultiplier: CostBandSchema.default({ low: 0.1, likely: 0.25, high: 0.6 }),
});

export const FairParametersSchema = z.object({
  defaultRecordsEstimate: z.number().int().min(1).default(10000),
  costPerRecord: z.number().min(1).default(165),
  baseForensicCost: z.number().min(0).default(75000),
  baseDowntimeCost: z.number().min(0).default(50000),
  regulatoryFineMultiplier: z.number().min(0).default(0.2),
  currency: z.string().default('USD'),
  referenceTable: BreachCostReferenceTableSchema.optional(),
});

export type FairParameters = z.infer<typeof FairParametersSchema>;

export interface PathFinancialExposure {
  pathId: string;
  fingerprint?: string;
  estimateLabel: '[ESTIMATE]';
  threatEventFrequencyBand: CostBand;
  vulnerabilityProbabilityBand: CostBand;
  lossEventFrequencyBand: CostBand;
  singleLossExpectancyBand: CostBand;
  annualizedLossExpectancyBand: CostBand;
  // Backward compatibility point estimates
  threatEventFrequency: number;
  vulnerabilityProbability: number;
  lossEventFrequency: number;
  primaryLoss: number;
  secondaryLoss: number;
  singleLossExpectancy: number;
  annualizedLossExpectancy: number;
  currency: string;
  drivingInputs: {
    terminalAssetId: string;
    terminalAssetTags: string[];
    sensitivityClassifications: string[];
    pathHops: number;
    referenceTableVersion: string;
    heuristicRationale: string;
  };
}

export interface PortfolioFinancialRiskReport {
  tenantId: string;
  generatedAt: string;
  evaluatedPathCount: number;
  referenceTableVersion: string;
  estimateLabel: '[ESTIMATE]';
  totalAnnualizedLossExpectancyBand: CostBand;
  maximumSingleEventLossBand: CostBand;
  // Backward compatibility point estimates
  totalAnnualizedLossExpectancy: number;
  maximumSingleEventLoss: number;
  currency: string;
  paths: PathFinancialExposure[];
  disclaimer: string;
}
