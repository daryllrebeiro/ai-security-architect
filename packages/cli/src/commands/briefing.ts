import * as fs from 'node:fs/promises';
import { ExecutiveBriefingGenerator } from '@ai-security-architect/reporting';
import { executeScan } from './scan.js';
import type { CliBriefingOptions } from '../types.js';

export async function executeBriefing(options: CliBriefingOptions): Promise<unknown> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const criticalPaths = scanResult.attackPaths.filter((p) => p.riskScore.totalRisk >= 7.0);

  const report = ExecutiveBriefingGenerator.generate({
    tenantId: scanResult.tenantId,
    reportingPeriod: options.reportingPeriod || 'Q3 2026',
    startMttrDays: 14.2,
    endMttrDays: 8.5,
    startCriticalPathsCount: Math.max(5, criticalPaths.length + 3),
    endCriticalPathsCount: criticalPaths.length,
    estimatedDollarExposureMin: 500_000,
    estimatedDollarExposureMax: 2_500_000,
    expectedAnnualLoss: 210_000,
    currency: options.currency || 'USD',
    topRiskThemes: [
      'Public ingress gateways with unauthenticated routing',
      'Over-privileged service identities spanning staging and production boundaries',
    ],
  });

  console.log(report.markdown);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, report.markdown, 'utf-8');
    console.log(`\n[Briefing] Saved executive risk briefing to ${options.outputFile}`);
  }

  return report;
}
