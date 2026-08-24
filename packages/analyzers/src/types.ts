import type { Asset, Finding, Evidence } from '@ai-security-architect/core';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export interface AnalyzerContext {
  tenantId: string;
  repository: string;
  workspace: EphemeralWorkspace;
  discoveredAssets: Asset[];
}

export interface AnalyzerResult {
  findings: Finding[];
  evidence: Evidence[];
}

export interface SecurityAnalyzer {
  readonly name: string;
  supports(workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean>;
  analyze(context: AnalyzerContext, fileList: string[]): Promise<AnalyzerResult>;
}
