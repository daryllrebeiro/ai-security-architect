import type { AttackPath, AIReasoningOutput, Finding } from '@ai-security-architect/core';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import type { PullRequestPayload, VerificationResult } from '@ai-security-architect/remediation';

export type AgentState =
  | 'IDLE'
  | 'REASONING'
  | 'PROPOSING'
  | 'SANDBOX_TESTING'
  | 'VERIFYING'
  | 'AWAITING_HUMAN_APPROVAL'
  | 'DONE'
  | 'FAILED';

export interface AgentBudgetConfig {
  maxIterations: number;
  timeoutMs: number;
  maxLlmCalls: number;
}

export interface AgentStepLog {
  iteration: number;
  timestamp: string;
  fromState: AgentState;
  toState: AgentState;
  message: string;
  details?: Record<string, unknown>;
}

import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export interface AutonomousAgentPlan {
  tenantId: string;
  repository: string;
  attackPath: AttackPath;
  workspace: EphemeralWorkspace;
  graph?: SecurityGraphEngine;
  initialFindings?: Finding[];
  autoApprove?: boolean;
  onApprovalRequest?: (proposal: { prPayload: PullRequestPayload; verification: VerificationResult }) => Promise<boolean>;
}

export interface AgentExecutionResult {
  state: AgentState;
  success: boolean;
  incomplete: boolean;
  reason?: string;
  iterations: number;
  llmCallsCount: number;
  durationMs: number;
  prPayload?: PullRequestPayload;
  verification?: VerificationResult;
  history: AgentStepLog[];
}
