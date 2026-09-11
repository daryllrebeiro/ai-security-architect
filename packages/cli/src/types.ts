import type { AttackPath, Finding, RiskScoreBreakdown } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export interface CliScanOptions {
  path: string;
  format?: 'table' | 'json' | 'sarif';
  tenantId?: string;
  repository?: string;
  failOnRiskScore?: number;
  outputFile?: string;
  withCloud?: boolean;
  region?: string;
  silent?: boolean;
}

export interface CliRemediateOptions {
  path: string;
  pathId?: string;
  apply?: boolean;
  tenantId?: string;
}

export interface CliAgentOptions {
  path: string;
  pathId?: string;
  autoApprove?: boolean;
  tenantId?: string;
  maxIterations?: number;
}

export interface CliComplianceOptions {
  path: string;
  frameworks?: string[];
  format?: 'markdown' | 'json';
  outputFile?: string;
  tenantId?: string;
}

export interface CliFairOptions {
  path: string;
  format?: 'table' | 'json';
  currency?: string;
  outputFile?: string;
  tenantId?: string;
}

export interface CliRunbookOptions {
  path: string;
  pathId?: string;
  format?: 'markdown' | 'confluence';
  outputFile?: string;
  tenantId?: string;
}

export interface CliQueryOptions {
  path: string;
  prompt: string;
  tenantId?: string;
}

export interface CliSimulateOptions {
  path: string;
  assumedBreachNode?: string;
  blockEdgeId?: string;
  tenantId?: string;
}

export interface CliPolicyOptions {
  path: string;
  baseRef?: string;
  failOnBreach?: boolean;
  tenantId?: string;
}

export interface CliDashboardOptions {
  path: string;
  outputFile?: string;
  tenantId?: string;
  serve?: boolean;
  port?: number;
}

export interface CliDiffOptions {
  basePath: string;
  headPath: string;
  format?: 'table' | 'markdown' | 'json';
  prComment?: boolean;
  outputFile?: string;
  tenantId?: string;
}

export interface CliFederateOptions {
  manifestPath: string;
  outputFile?: string;
  tenantId?: string;
  sqlitePath?: string;
}

export interface CliSbomOptions {
  path: string;
  format?: 'cyclonedx' | 'spdx';
  outputFile?: string;
  tenantId?: string;
}

export interface CliLineageOptions {
  path: string;
  entryAssetId?: string;
  direction?: 'forward' | 'reverse';
  outputFile?: string;
  tenantId?: string;
}

export interface CliLeastPrivilegeOptions {
  path: string;
  serviceId?: string;
  roleId?: string;
  outputFile?: string;
  tenantId?: string;
}

export interface CliBriefingOptions {
  path: string;
  reportingPeriod?: string;
  currency?: string;
  outputFile?: string;
  tenantId?: string;
}

export interface CliWhatIfOptions {
  path: string;
  action: 'SEVER_EDGE' | 'RESTRICT_PERMISSION' | 'REMOVE_ASSET';
  sourceAssetId?: string;
  targetAssetId?: string;
  edgeType?: string;
  assetId?: string;
  outputFile?: string;
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
