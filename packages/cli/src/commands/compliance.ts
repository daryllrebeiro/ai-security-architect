import * as fs from 'node:fs/promises';
import { ComplianceEngine, type ComplianceFramework, type ComplianceReport } from '@ai-security-architect/compliance';
import { executeScan } from './scan.js';
import type { CliComplianceOptions } from '../types.js';

export async function executeCompliance(options: CliComplianceOptions): Promise<ComplianceReport> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const engine = new ComplianceEngine();
  const targetFrameworks = options.frameworks as ComplianceFramework[] | undefined;
  const report = engine.evaluateCompliance(scanResult.graph, scanResult.attackPaths, targetFrameworks);

  let output: string;
  if (options.format === 'json') {
    output = JSON.stringify(report, null, 2);
  } else {
    output = engine.formatMarkdownReport(report);
  }

  console.log(output);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, output, 'utf-8');
    console.log(`\n[Compliance] Report saved to ${options.outputFile}`);
  }

  return report;
}
