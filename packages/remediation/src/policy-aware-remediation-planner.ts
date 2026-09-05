import type { PolicyConstraint, PolicyDecision, PolicyEvaluationInput } from './types.js';

export class PolicyAwareRemediationPlanner {
  public evaluate(input: PolicyEvaluationInput): PolicyDecision {
    const patchText = input.candidatePatches
      .map((patch) => `${patch.filePath}:${patch.diff}`)
      .join('\n');

    const broadensPrivileges = /\+\s*Action\s*=\s*\[.*\*.*\]|\+\s*Action\s*=\s*["']iam:\*["']|\+\s*Action\s*=\s*["']s3:\*["']/.test(patchText);
    const productionGate = input.policy.requireApprovalForProduction && input.tenantId.includes('prod');
    const riskViolation = input.riskScore > 8 && input.policy.maxRiskIncreasePercent === 0;

    if (broadensPrivileges || riskViolation) {
      return {
        allowed: false,
        reason: 'policy: candidate patch broadens privilege scope or violates zero-risk-increase policy',
        requiresApproval: true,
      };
    }

    if (productionGate && input.policy.allowedBlastRadius !== 'narrow') {
      return {
        allowed: false,
        reason: 'policy: production remediations must use narrow blast radius changes',
        requiresApproval: true,
      };
    }

    return {
      allowed: true,
      reason: 'policy: candidate patch satisfies the configured guardrails',
      requiresApproval: false,
    };
  }
}
