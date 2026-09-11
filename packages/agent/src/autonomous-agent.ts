import {
  type AttackPath,
  type Finding,
  type AIReasoningOutput,
} from '@ai-security-architect/core';
import {
  AIReasoningEngine,
  type LLMProvider,
} from '@ai-security-architect/ai';
import {
  PatchApplier,
  VerificationRunner,
  PullRequestGenerator,
  type PullRequestPayload,
  type VerificationResult,
} from '@ai-security-architect/remediation';
import {
  PersistentWormAuditLogger,
  type SecurityContext,
} from '@ai-security-architect/enterprise';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type {
  AgentState,
  AgentBudgetConfig,
  AgentStepLog,
  AutonomousAgentPlan,
  AgentExecutionResult,
} from './types.js';

export interface AutonomousAgentOptions {
  budget?: Partial<AgentBudgetConfig>;
  auditLogger?: PersistentWormAuditLogger;
  patchApplier?: PatchApplier;
  verificationRunner?: VerificationRunner;
  prGenerator?: PullRequestGenerator;
  reasoningEngine?: AIReasoningEngine;
  llmProvider?: LLMProvider;
}

export class AutonomousRemediationAgent {
  private readonly budget: AgentBudgetConfig;
  private readonly auditLogger: PersistentWormAuditLogger;
  private readonly patchApplier: PatchApplier;
  private readonly verificationRunner: VerificationRunner;
  private readonly prGenerator: PullRequestGenerator;
  private readonly reasoningEngine: AIReasoningEngine;
  private readonly llmProvider?: LLMProvider;

  constructor(options: AutonomousAgentOptions = {}) {
    this.budget = {
      maxIterations: options.budget?.maxIterations ?? 5,
      timeoutMs: options.budget?.timeoutMs ?? 120_000,
      maxLlmCalls: options.budget?.maxLlmCalls ?? 10,
    };
    this.auditLogger = options.auditLogger ?? new PersistentWormAuditLogger();
    this.patchApplier = options.patchApplier ?? new PatchApplier();
    this.verificationRunner = options.verificationRunner ?? new VerificationRunner();
    this.prGenerator = options.prGenerator ?? new PullRequestGenerator();
    this.reasoningEngine = options.reasoningEngine ?? new AIReasoningEngine({
      defaultProvider: options.llmProvider,
    });
    this.llmProvider = options.llmProvider;
  }

  public async runRemediationLoop(plan: AutonomousAgentPlan): Promise<AgentExecutionResult> {
    const startTime = performance.now();
    const history: AgentStepLog[] = [];
    let currentState: AgentState = 'IDLE';
    let iteration = 0;
    let llmCallsCount = 0;
    let failureFeedback: string | null = null;

    const secCtx: SecurityContext = {
      tenantId: plan.tenantId,
      userId: 'autonomous-remediation-agent',
      userRole: 'SECURITY_ADMIN',
      permissions: ['remediation:apply', 'remediation:propose', 'audit:read'],
      scopes: ['*'],
    };

    const recordTransition = (
      toState: AgentState,
      message: string,
      details: Record<string, unknown> = {}
    ): void => {
      const fromState = currentState;
      currentState = toState;
      const stepLog: AgentStepLog = {
        iteration,
        timestamp: new Date().toISOString(),
        fromState,
        toState,
        message,
        details,
      };
      history.push(stepLog);

      try {
        this.auditLogger.log(
          secCtx,
          `AGENT_TRANSITION_${toState}`,
          plan.attackPath.id,
          { fromState, toState, iteration, message, ...details }
        );
      } catch {
        // Audit logger failure should not break remediation loop
      }
    };

    recordTransition('IDLE', 'Autonomous remediation agent initialized');

    while (iteration < this.budget.maxIterations) {
      const elapsed = performance.now() - startTime;
      if (elapsed > this.budget.timeoutMs) {
        recordTransition('FAILED', `Timeout budget exceeded (${Math.round(elapsed)}ms > ${this.budget.timeoutMs}ms)`, {
          incomplete: true,
          elapsed,
        });
        return {
          state: 'FAILED',
          success: false,
          incomplete: true,
          reason: `Timeout budget exceeded (${Math.round(elapsed)}ms)`,
          iterations: iteration,
          llmCallsCount,
          durationMs: elapsed,
          history,
        };
      }

      if (llmCallsCount >= this.budget.maxLlmCalls) {
        recordTransition('FAILED', `LLM call budget exceeded (${llmCallsCount} calls >= limit ${this.budget.maxLlmCalls})`, {
          incomplete: true,
          llmCallsCount,
        });
        return {
          state: 'FAILED',
          success: false,
          incomplete: true,
          reason: `LLM call budget exhausted (${llmCallsCount} calls)`,
          iterations: iteration,
          llmCallsCount,
          durationMs: elapsed,
          history,
        };
      }

      // 1. REASONING STATE
      recordTransition('REASONING', `Iteration ${iteration + 1}: Analyzing attack path and synthesizing choke-point remediation`, {
        failureFeedback,
      });

      let reasoningOutput: AIReasoningOutput;
      try {
        llmCallsCount++;
        const graph = plan.graph ?? new SecurityGraphEngine(plan.tenantId);
        const reasoningRes = await this.reasoningEngine.reasonAboutAttackPath({
          repository: plan.repository,
          attackPath: plan.attackPath,
          graph,
          llmProvider: this.llmProvider,
        });
        reasoningOutput = reasoningRes.output;
      } catch (err: any) {
        recordTransition('FAILED', `Reasoning engine error: ${err.message}`);
        iteration++;
        failureFeedback = `LLM reasoning failed: ${err.message}`;
        continue;
      }

      // 2. PROPOSING STATE
      const patches = reasoningOutput.recommendedRemediation.patches || [];
      if (patches.length === 0) {
        recordTransition('REASONING', `Iteration ${iteration + 1}: No patches produced by reasoning model`);
        iteration++;
        failureFeedback = 'No remediation patches were generated by reasoning model.';
        continue;
      }

      recordTransition('PROPOSING', `Generated patch proposal for ${patches.length} file(s)`, {
        patches: patches.map((p) => p.filePath || (p as any).targetFile),
      });

      // Backup target files before mutating workspace
      const backups = new Map<string, string>();
      for (const patch of patches) {
        const targetPath = patch.filePath || (patch as any).targetFile;
        try {
          const content = await plan.workspace.readSafeFile(targetPath);
          backups.set(targetPath, content);
        } catch {
          // New file creation or unreadable
        }
      }

      // 3. SANDBOX_TESTING STATE
      recordTransition('SANDBOX_TESTING', `Applying unified diff patch in isolated sandbox workspace`);
      let patchSuccess = false;
      try {
        await this.patchApplier.applyPatches(plan.workspace, patches);
        patchSuccess = true;
      } catch (patchErr: any) {
        // Rollback on patch error
        for (const [filePath, content] of backups.entries()) {
          await plan.workspace.writeSafeFile(filePath, content).catch(() => {});
        }
        recordTransition('REASONING', `Patch application failed: ${patchErr.message}`, {
          error: patchErr.message,
        });
        iteration++;
        failureFeedback = `Patch application syntax error: ${patchErr.message}`;
        continue;
      }

      // 4. VERIFYING STATE
      recordTransition('VERIFYING', `Executing dynamic closed-loop verification via AST re-parsing and graph traversal`);
      let verification: VerificationResult;
      try {
        verification = await this.verificationRunner.verifyRemediation({
          tenantId: plan.tenantId,
          repository: plan.repository,
          workspace: plan.workspace,
          initialAttackPath: plan.attackPath,
          initialFindings: plan.initialFindings || [],
        });
      } catch (verifErr: any) {
        // Rollback
        for (const [filePath, content] of backups.entries()) {
          await plan.workspace.writeSafeFile(filePath, content).catch(() => {});
        }
        recordTransition('REASONING', `Verification runner encountered error: ${verifErr.message}`);
        iteration++;
        failureFeedback = `Verification engine error: ${verifErr.message}`;
        continue;
      }

      // If verified clean:
      if (verification.verified) {
        recordTransition('AWAITING_HUMAN_APPROVAL', `Remediation verified clean! Risk score reduced by ${verification.riskReductionPercentage}%. Awaiting human approval.`, {
          verification,
        });

        const prPayload = this.prGenerator.generatePullRequest({
          attackPath: plan.attackPath,
          reasoningOutput,
          verification,
          modifiedFiles: patches.map((p) => p.filePath || (p as any).targetFile),
        });

        let approved = false;
        if (plan.autoApprove) {
          approved = true;
        } else if (plan.onApprovalRequest) {
          approved = await plan.onApprovalRequest({ prPayload, verification });
        } else {
          // Without autoApprove or approval handler, stop at gate
          approved = false;
        }

        if (approved) {
          recordTransition('DONE', `Human approved remediation proposal. Pull request generated successfully.`, {
            branch: prPayload.branchName,
          });
          return {
            state: 'DONE',
            success: true,
            incomplete: false,
            iterations: iteration + 1,
            llmCallsCount,
            durationMs: performance.now() - startTime,
            prPayload,
            verification,
            history,
          };
        } else {
          // Revert changes if rejected
          for (const [filePath, content] of backups.entries()) {
            await plan.workspace.writeSafeFile(filePath, content).catch(() => {});
          }
          recordTransition('FAILED', `Human reviewer rejected the remediation proposal or approval was withheld.`);
          return {
            state: 'FAILED',
            success: false,
            incomplete: false,
            reason: 'Remediation proposal was rejected or withheld by human reviewer',
            iterations: iteration + 1,
            llmCallsCount,
            durationMs: performance.now() - startTime,
            prPayload,
            verification,
            history,
          };
        }
      } else {
        // Verification failed to sever path or introduced regressions
        // Revert files for next iteration
        for (const [filePath, content] of backups.entries()) {
          await plan.workspace.writeSafeFile(filePath, content).catch(() => {});
        }

        iteration++;
        failureFeedback = `Verification failed: Target path still active (Remaining paths: ${verification.remainingPathsCount}, Regressions: ${verification.newRegressionsCount}).`;
        recordTransition('REASONING', `Iteration ${iteration} failed verification: path not eliminated. Preparing re-prompt with failure feedback.`);
      }
    }

    // Budget exhausted
    recordTransition('FAILED', `Iteration budget exhausted (${this.budget.maxIterations} iterations) without proving path elimination.`, {
      incomplete: true,
      iterations: iteration,
    });

    return {
      state: 'FAILED',
      success: false,
      incomplete: true,
      reason: `Iteration budget exhausted: reached maximum ${this.budget.maxIterations} iterations without eliminating attack path`,
      iterations: iteration,
      llmCallsCount,
      durationMs: performance.now() - startTime,
      history,
    };
  }
}
