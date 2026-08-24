import type {
  AttackPath,
  AIReasoningOutput,
} from '@ai-security-architect/core';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export interface VerificationResult {
  verified: boolean;
  initialRiskScore: number;
  postRemediationRiskScore: number;
  riskReductionPercentage: number;
  pathsEliminatedCount: number;
  remainingPathsCount: number;
  severedEdges: string[];
  newRegressionsCount: number;
  verificationTimestamp: string;
}

export interface PullRequestPayload {
  title: string;
  branchName: string;
  bodyMarkdown: string;
  modifiedFiles: string[];
  verification: VerificationResult;
}

export interface RemediationPlan {
  tenantId: string;
  repository: string;
  attackPath: AttackPath;
  reasoningOutput: AIReasoningOutput;
  workspace: EphemeralWorkspace;
  initialFindings?: import('@ai-security-architect/core').Finding[];
}
