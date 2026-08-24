import type { RemediationPlan, PullRequestPayload, VerificationResult } from './types.js';
import { PatchApplier } from './patch-applier.js';
import { VerificationRunner } from './verification-runner.js';
import { PullRequestGenerator } from './pr-generator.js';

export class RemediationCoordinator {
  private readonly patchApplier: PatchApplier;
  private readonly verificationRunner: VerificationRunner;
  private readonly prGenerator: PullRequestGenerator;

  constructor(options: {
    patchApplier?: PatchApplier;
    verificationRunner?: VerificationRunner;
    prGenerator?: PullRequestGenerator;
  } = {}) {
    this.patchApplier = options.patchApplier ?? new PatchApplier();
    this.verificationRunner = options.verificationRunner ?? new VerificationRunner();
    this.prGenerator = options.prGenerator ?? new PullRequestGenerator();
  }

  public async executeRemediationWorkflow(
    plan: RemediationPlan
  ): Promise<{ prPayload: PullRequestPayload; verification: VerificationResult }> {
    const { tenantId, repository, attackPath, reasoningOutput, workspace } = plan;

    // 1. Apply Synthesized Patches inside Sandbox Workspace
    const modifiedFiles = await this.patchApplier.applyPatches(
      workspace,
      reasoningOutput.recommendedRemediation.patches
    );

    // 2. Execute Dynamic Closed-Loop Verification
    const verification = await this.verificationRunner.verifyRemediation({
      tenantId,
      repository,
      workspace,
      initialAttackPath: attackPath,
      initialFindings: plan.initialFindings || [],
    });

    if (!verification.verified) {
      throw new Error(
        `Remediation verification failed: Attack path could not be proved eliminated (Remaining paths: ${verification.remainingPathsCount}, Regressions: ${verification.newRegressionsCount})`
      );
    }

    // 3. Generate Verified Pull Request
    const prPayload = this.prGenerator.generatePullRequest({
      attackPath,
      reasoningOutput,
      verification,
      modifiedFiles,
    });

    return { prPayload, verification };
  }
}
