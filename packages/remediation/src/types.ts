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

export interface PolicyConstraint {
  maxRiskIncreasePercent: number;
  requireApprovalForProduction: boolean;
  allowedBlastRadius: 'narrow' | 'moderate' | 'broad';
}

export interface PolicyEvaluationInput {
  tenantId: string;
  repository: string;
  attackPathId: string;
  riskScore: number;
  candidatePatches: Array<{
    filePath: string;
    action: 'MODIFY' | 'CREATE';
    diff: string;
    description: string;
  }>;
  policy: PolicyConstraint;
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  requiresApproval: boolean;
}

export interface CommandCenterSummaryInput {
  tenantId: string;
  findings: Array<{
    id: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    assetId: string;
  }>;
  openRemediations: number;
  verifiedRemediations: number;
}

export interface CommandCenterSummary {
  tenantId: string;
  totalFindings: number;
  highRiskCount: number;
  remediationStatus: string;
}
