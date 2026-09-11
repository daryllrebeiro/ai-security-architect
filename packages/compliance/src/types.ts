import { z } from 'zod';
import type { Finding } from '@ai-security-architect/core';

export const ComplianceFrameworkSchema = z.enum([
  'SOC2',
  'PCI-DSS',
  'NIST-800-53',
  'HIPAA',
  'ISO27001',
]);
export type ComplianceFramework = z.infer<typeof ComplianceFrameworkSchema>;

export type ControlCoveragePartition =
  | 'COVERED_CLEAN'
  | 'COVERED_WITH_FINDINGS'
  | 'NOT_OBSERVABLE_BY_TOOL';

export interface FrameworkControlDefinition {
  controlId: string;
  title: string;
  description: string;
  observableByTool: boolean;
  findingCategories?: string[];
  attackPathPattern?: string | null;
  mappingRationale: string;
}

export interface FrameworkData {
  framework: ComplianceFramework;
  name: string;
  version: string;
  controls: FrameworkControlDefinition[];
}

export interface ControlAssessment {
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  partition: ControlCoveragePartition;
  observableByTool: boolean;
  mappingRationale: string;
  violatingPathIds: string[];
  violatingAssetIds: string[];
  findingIds: string[];
  evidence: string[];
}

export interface UnmappedFindingRecord {
  findingId: string;
  category: string;
  title: string;
  severity: string;
  assetId: string;
}

export interface ComplianceReport {
  tenantId: string;
  generatedAt: string;
  frameworks: ComplianceFramework[];
  summary: {
    totalFrameworkControls: number;
    totalControls: number;
    coveredCleanCount: number;
    coveredWithFindingsCount: number;
    notObservableCount: number;
    unmappedFindingsCount: number;
  };
  controls: ControlAssessment[];
  unmappedFindings: UnmappedFindingRecord[];
  disclaimer: string;
}
