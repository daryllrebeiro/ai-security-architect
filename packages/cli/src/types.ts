import type { AttackPath, Finding, RiskScoreBreakdown } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export interface CliScanOptions {
  path: string;
  format?: 'table' | 'json' | 'sarif';
  tenantId?: string;
  repository?: string;
  failOnRiskScore?: number;
  outputFile?: string;
}

export interface CliRemediateOptions {
  path: string;
  pathId?: string;
  apply?: boolean;
  tenantId?: string;
}

export interface CliScanResult {
  tenantId: string;
  repository: string;
  totalAssets: number;
  totalFindings: number;
  attackPaths: AttackPath[];
  highestRiskScore: number;
  graph: SecurityGraphEngine;
  findings: Finding[];
}

export interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: {
        startLine: number;
        endLine: number;
        snippet?: { text: string };
      };
    };
  }>;
}

export interface SarifReport {
  version: '2.1.0';
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          help: { text: string };
        }>;
      };
    };
    results: SarifResult[];
  }>;
}
