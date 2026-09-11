import * as fs from 'node:fs/promises';
import { FairCalculator, FAIR_DISCLAIMER, type PortfolioFinancialRiskReport } from '@ai-security-architect/risk-quant';
import { executeScan } from './scan.js';
import type { CliFairOptions } from '../types.js';

export async function executeFair(options: CliFairOptions): Promise<PortfolioFinancialRiskReport> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const calculator = new FairCalculator();
  const report = calculator.calculatePortfolioExposure(scanResult.attackPaths, scanResult.graph, {
    currency: options.currency || 'USD',
  });

  let output: string;
  if (options.format === 'json') {
    output = JSON.stringify(report, null, 2);
  } else {
    const lines: string[] = [
      `================================================================================`,
      `  FAIR FINANCIAL RISK & EXPOSURE QUANTIFICATION (ALE) [ESTIMATE]`,
      `================================================================================`,
      `  Repository:                  ${scanResult.repository}`,
      `  Total Discovered Paths:      ${report.paths.length}`,
      `  Total ALE Range:             ${report.currency} $${report.totalAnnualizedLossExpectancyBand.low.toLocaleString()} - $${report.totalAnnualizedLossExpectancyBand.likely.toLocaleString()} - $${report.totalAnnualizedLossExpectancyBand.high.toLocaleString()} [ESTIMATE]`,
      `  Max Single Event Loss:       ${report.currency} $${report.maximumSingleEventLossBand.low.toLocaleString()} - $${report.maximumSingleEventLossBand.likely.toLocaleString()} - $${report.maximumSingleEventLossBand.high.toLocaleString()} [ESTIMATE]`,
      `  Reference Table Version:     ${report.referenceTableVersion}`,
      `--------------------------------------------------------------------------------`,
      `  PER-PATH FINANCIAL EXPOSURE BREAKDOWN`,
      `--------------------------------------------------------------------------------`,
    ];

    for (let i = 0; i < report.paths.length; i++) {
      const exp = report.paths[i];
      lines.push(`  [#${i + 1}] Path ID: ${exp.pathId} [ESTIMATE]`);
      lines.push(`      - Threat Frequency (TEF):     ${exp.threatEventFrequencyBand.low} - ${exp.threatEventFrequencyBand.likely} - ${exp.threatEventFrequencyBand.high} attempts/yr`);
      lines.push(`      - Vulnerability Prob (V_P):   ${Math.round(exp.vulnerabilityProbabilityBand.likely * 100)}%`);
      lines.push(`      - Single Loss (SLE):          ${exp.currency} $${exp.singleLossExpectancyBand.low.toLocaleString()} - $${exp.singleLossExpectancyBand.likely.toLocaleString()} - $${exp.singleLossExpectancyBand.high.toLocaleString()}`);
      lines.push(`      - Annualized Loss (ALE):      ${exp.currency} $${exp.annualizedLossExpectancyBand.low.toLocaleString()} - $${exp.annualizedLossExpectancyBand.likely.toLocaleString()} - $${exp.annualizedLossExpectancyBand.high.toLocaleString()}`);
      lines.push(`      - Driving Inputs:             Terminal: ${exp.drivingInputs.terminalAssetId} | Classifications: ${exp.drivingInputs.sensitivityClassifications.join(', ') || 'standard'}`);
      lines.push(``);
    }

    lines.push(`  ℹ️  ${FAIR_DISCLAIMER}`);
    lines.push(`================================================================================`);
    output = lines.join('\n');
  }

  console.log(output);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, output, 'utf-8');
    console.log(`\n[Risk Quantification] Report saved to ${options.outputFile}`);
  }

  return report;
}
