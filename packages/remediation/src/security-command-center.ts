import type { CommandCenterSummary, CommandCenterSummaryInput } from './types.js';

export class SecurityCommandCenter {
  public summarize(input: CommandCenterSummaryInput): CommandCenterSummary {
    const totalFindings = input.findings.length;
    const highRiskCount = input.findings.filter((f) => f.severity === 'CRITICAL').length;
    const remediationStatus = `${input.openRemediations} pending, ${input.verifiedRemediations} verified`;

    return {
      tenantId: input.tenantId,
      totalFindings,
      highRiskCount,
      remediationStatus,
    };
  }
}
