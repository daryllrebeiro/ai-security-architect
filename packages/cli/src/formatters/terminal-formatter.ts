import type { CliScanResult } from '../types.js';

export class TerminalFormatter {
  public formatScanResult(result: CliScanResult): string {
    const lines: string[] = [];

    lines.push('\n================================================================================');
    lines.push('  AI SECURITY ARCHITECT — ATTACK PATH REASONING PLATFORM');
    lines.push('================================================================================\n');

    lines.push(`  Tenant:      ${result.tenantId}`);
    lines.push(`  Repository:  ${result.repository}`);
    lines.push(`  Assets:      ${result.totalAssets}`);
    lines.push(`  Findings:    ${result.totalFindings}`);
    lines.push(`  Paths Found: ${result.attackPaths.length}`);
    lines.push(`  Peak Risk:   ${result.highestRiskScore.toFixed(1)} / 10.0\n`);

    if (result.attackPaths.length === 0) {
      lines.push('  ✅ Clean: No critical attack paths discovered reaching crown jewels.\n');
      return lines.join('\n');
    }

    lines.push('--------------------------------------------------------------------------------');
    lines.push('  DISCOVERED ATTACK PATHS & EXPLOIT CHAINS');
    lines.push('--------------------------------------------------------------------------------\n');

    result.attackPaths.forEach((path, idx) => {
      lines.push(`  [Path #${idx + 1}] ID: ${path.id} | Risk Score: ${path.riskScore.totalRisk.toFixed(1)}/10.0`);
      lines.push(`  Entry:  ${path.entryAssetId}`);
      lines.push(`  Target: ${path.targetAssetId}`);
      lines.push('  Exploit Progression:');

      path.steps.forEach((step) => {
        const vulnTag = step.findingId ? ' [VULNERABLE]' : '';
        lines.push(`    ${step.stepNumber}. (${step.relationshipType}) ${step.sourceAssetId} -> ${step.targetAssetId}${vulnTag}`);
        lines.push(`       └─ ${step.explanation}`);
      });

      if (path.recommendedChokePoint) {
        lines.push('\n  🎯 Recommended Min-Cut Choke Point:');
        lines.push(`     Action:       ${path.recommendedChokePoint.actionDescription}`);
        lines.push(`     Risk Delta:   -${path.recommendedChokePoint.riskReductionPercentage}%`);
        lines.push(`     Blast Radius: ${path.recommendedChokePoint.blastRadius} | Effort: ${path.recommendedChokePoint.engineeringEffort}`);
      }
      lines.push('\n');
    });

    return lines.join('\n');
  }
}
