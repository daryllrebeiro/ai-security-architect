import type { Diagnostic } from 'vscode-languageserver';

export interface LspServerConfig {
  tenantId?: string;
  repository?: string;
  offlineMode?: boolean;
  workspaceRoot?: string;
  debounceMs?: number;
}

export interface DocumentAnalysisResult {
  uri: string;
  filePath: string;
  diagnostics: Diagnostic[];
  attackPathsCount: number;
  criticalFindingsCount: number;
  durationMs: number;
}
