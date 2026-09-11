import { describe, it, expect } from 'vitest';
import { AutonomousPrBot } from '../src/pr-bot.js';
import type { AttackPath, AIReasoningOutput } from '@ai-security-architect/core';
import type { VerificationResult, CandidatePatch } from '../src/types.js';

describe('Milestone 3.1: Autonomous PR Auto-Remediation Bot', () => {
  const samplePath: AttackPath = {
    id: 'path-042',
    tenantId: 'tenant-acme',
    entryAssetId: 'alb-public',
    targetAssetId: 's3-customer-vault',
    pathLength: 3,
    steps: [],
    riskScore: {
      totalRisk: 9.2,
      exploitability: 9.0,
      impact: 9.5,
      reachability: 1.0,
      assetCriticality: 10.0,
      confidence: 1.0,
    },
    verifiedEliminated: false,
  };

  const sampleReasoning: AIReasoningOutput = {
    summary: 'Public ALB routes directly to an overprivileged pod capable of reading S3 customer vault.',
    rootCauseAnalysis: 'Wildcard Action s3:* on IAM role assigned to public-facing ingress service.',
    businessImpact: 'Complete exfiltration of customer personally identifiable information (PII).',
    evidenceReferences: ['ev-iam-wildcard-1234', 'ev-ingress-alb-5678'],
    reasoningFailed: false,
    confidence: 'HIGH',
    recommendedRemediation: {
      description: 'Constrain IAM policy to read-only on specific prefix and enforce VPC endpoint.',
      targetChokePoint: 'role-payment -> s3-customer-vault:CAN_READ',
      expectedRiskReductionPercentage: 77.2,
      engineeringEffort: 'LOW',
      patches: [],
    },
    alternativeRemediations: [],
  };

  const sampleVerification: VerificationResult = {
    verified: true,
    initialRiskScore: 9.2,
    postRemediationRiskScore: 2.1,
    riskReductionPercentage: 77.2,
    pathsEliminatedCount: 1,
    remainingPathsCount: 0,
    severedEdges: ['role-payment -> s3-customer-vault:CAN_READ'],
    newRegressionsCount: 0,
    verificationTimestamp: '2026-09-11T20:00:00.000Z',
  };

  const samplePatches: CandidatePatch[] = [
    {
      filePath: 'terraform/iam.tf',
      diff: `--- a/terraform/iam.tf\n+++ b/terraform/iam.tf\n- "Action": "s3:*"\n+ "Action": "s3:GetObject"`,
      action: 'UPDATE',
    },
  ];

  it('builds a complete PR package with min-cut security proof and sign-off', () => {
    const bot = new AutonomousPrBot({
      authorName: 'SecArch Bot',
      authorEmail: 'secbot@acme.corp',
      signOff: true,
    });

    const pr = bot.buildPrPackage({
      attackPath: samplePath,
      reasoningOutput: sampleReasoning,
      verification: sampleVerification,
      candidatePatches: samplePatches,
    });

    expect(pr.title).toContain('fix(security): sever attack path path-042');
    expect(pr.headBranch).toContain('security/remediate-path-042');
    expect(pr.commitMessage).toContain('Signed-off-by: SecArch Bot <secbot@acme.corp>');
    expect(pr.bodyMarkdown).toContain('Min-Cut Security Proof & Verification Delta');
    expect(pr.bodyMarkdown).toContain('77.2%');
    expect(pr.bodyMarkdown).toContain('role-payment -> s3-customer-vault:CAN_READ');
    expect(pr.unifiedDiff).toContain('+ "Action": "s3:GetObject"');
    expect(pr.modifiedFiles).toEqual(['terraform/iam.tf']);
    expect(pr.minCutProof.riskBefore).toBe(9.2);
    expect(pr.minCutProof.riskAfter).toBe(2.1);
  });

  it('generates reproducible git execution commands', () => {
    const bot = new AutonomousPrBot();
    const pr = bot.buildPrPackage({
      attackPath: samplePath,
      reasoningOutput: sampleReasoning,
      verification: sampleVerification,
      candidatePatches: samplePatches,
    });

    const cmds = bot.prepareGitCommands(pr);
    expect(cmds).toHaveLength(4);
    expect(cmds[0]).toContain('git checkout -b');
    expect(cmds[1]).toContain('git apply');
    expect(cmds[2]).toContain('git commit -m');
    expect(cmds[3]).toContain('git push origin');
  });
});
