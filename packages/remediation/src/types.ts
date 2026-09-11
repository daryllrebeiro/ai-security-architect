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

export class PatchApplicationError extends Error {
  constructor(
    message: string,
    public readonly filePath: string,
    public readonly expectedSnippet?: string,
    public readonly actualSnippet?: string,
    public readonly brokenHunkIndex?: number
  ) {
    super(`[PatchApplicationError] ${filePath}: ${message}`);
    this.name = 'PatchApplicationError';
  }
}

export interface CandidatePatch {
  filePath: string;
  diff: string;
  action?: string;
  description?: string;
}

export interface PolicyConstraint {
  requireApprovalForProduction?: boolean;
  maxRiskIncreasePercent?: number;
  allowedBlastRadius?: string;
}

export interface PolicyEvaluationInput {
  tenantId: string;
  repository?: string;
  attackPathId?: string;
  candidatePatches: CandidatePatch[];
  policy: PolicyConstraint;
  riskScore: number;
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  requiresApproval: boolean;
}

export interface CommandCenterSummaryInput {
  tenantId: string;
  findings: Array<Pick<import('@ai-security-architect/core').Finding, 'id' | 'severity'> & Partial<import('@ai-security-architect/core').Finding>>;
  openRemediations: number;
  verifiedRemediations: number;
}

export interface CommandCenterSummary {
  tenantId: string;
  totalFindings: number;
  highRiskCount: number;
  remediationStatus: string;
}

