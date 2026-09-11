import type { AttackPath } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import {
  FairParametersSchema,
  BreachCostReferenceTableSchema,
  type FairParameters,
  type PathFinancialExposure,
  type PortfolioFinancialRiskReport,
  type CostBand,
  type BreachCostReferenceTable,
} from './types.js';

export const FAIR_DISCLAIMER =
  '[ESTIMATE] DISCLAIMER: All financial loss figures, frequencies, and ranges are heuristic model estimates derived from the FAIR framework for prioritization and risk budgeting only. They are not actuarial guarantees, insurance policy warranties, or audited financial liabilities.';

export const DEFAULT_BREACH_COST_TABLE: BreachCostReferenceTable = {
  version: '2024-ponemon-ibm-benchmark-v1',
  source: 'Cost of a Data Breach Report 2024 Benchmark',
  baseForensicCost: { low: 25000, likely: 75000, high: 175000 },
  baseDowntimeCost: { low: 15000, likely: 50000, high: 150000 },
  costPerRecord: {
    pii: { low: 100, likely: 180, high: 320 },
    paymentData: { low: 140, likely: 240, high: 450 },
    secretsOrCredentials: { low: 160, likely: 260, high: 500 },
    general: { low: 50, likely: 100, high: 200 },
  },
  regulatoryFineMultiplier: { low: 0.1, likely: 0.25, high: 0.6 },
};

export class FairCalculator {
  public calculatePathExposure(
    path: AttackPath,
    graph: SecurityGraphEngine,
    config: Partial<FairParameters> = {}
  ): PathFinancialExposure {
    const params = FairParametersSchema.parse(config);
    const refTable: BreachCostReferenceTable =
      params.referenceTable ?? DEFAULT_BREACH_COST_TABLE;

    const entryNode = graph.getNode(path.entryAssetId);
    const targetNode = graph.getNode(path.targetAssetId);

    // 1. Threat Event Frequency (TEF) Band
    const isPublicIngress =
      entryNode?.asset.isPublic === true || entryNode?.asset.type === 'INTERNET';

    const threatEventFrequencyBand: CostBand = isPublicIngress
      ? { low: 6.0, likely: 12.0, high: 24.0 }
      : { low: 0.5, likely: 1.5, high: 4.0 };

    // 2. Vulnerability Probability Band
    // Heuristic: Shorter paths and fewer privilege steps have higher exploitability
    const hopDecay = Math.pow(0.88, Math.max(0, path.pathLength - 1));
    const baseProb = (path.riskScore.exploitability / 10) * hopDecay * path.riskScore.confidence;

    const vulnerabilityProbabilityBand: CostBand = {
      low: Math.max(0.05, Math.round(baseProb * 0.7 * 100) / 100),
      likely: Math.min(0.95, Math.max(0.05, Math.round(baseProb * 100) / 100)),
      high: Math.min(0.99, Math.round(baseProb * 1.3 * 100) / 100),
    };

    // 3. Loss Event Frequency (LEF) Band
    const lossEventFrequencyBand: CostBand = {
      low: Math.round(threatEventFrequencyBand.low * vulnerabilityProbabilityBand.low * 100) / 100,
      likely:
        Math.round(threatEventFrequencyBand.likely * vulnerabilityProbabilityBand.likely * 100) /
        100,
      high:
        Math.round(threatEventFrequencyBand.high * vulnerabilityProbabilityBand.high * 100) / 100,
    };

    // 4. Primary Loss Band (Forensics, Downtime, Response)
    const criticality = targetNode?.asset.criticality ?? 'HIGH';
    let critMultiplier = 1.0;
    if (criticality === 'CRITICAL') critMultiplier = 2.0;
    else if (criticality === 'LOW') critMultiplier = 0.3;

    const primaryLossBand: CostBand = {
      low: Math.round(
        (refTable.baseForensicCost.low + refTable.baseDowntimeCost.low) * critMultiplier
      ),
      likely: Math.round(
        (refTable.baseForensicCost.likely + refTable.baseDowntimeCost.likely) * critMultiplier
      ),
      high: Math.round(
        (refTable.baseForensicCost.high + refTable.baseDowntimeCost.high) * critMultiplier
      ),
    };

    // 5. Secondary Loss Band (Data Breach Notifications, Regulatory Fines)
    const targetTags = targetNode?.asset.tags ?? [];
    const sensitivityClassifications: string[] = [];

    if (targetTags.some((t) => /payment|card|pci/i.test(t))) {
      sensitivityClassifications.push('contains-payment-data');
    }
    if (targetTags.some((t) => /pii|gdpr|customer/i.test(t)) || targetNode?.asset.isSensitiveData) {
      sensitivityClassifications.push('contains-pii');
    }
    if (targetTags.some((t) => /secret|token|credential/i.test(t))) {
      sensitivityClassifications.push('contains-secrets');
    }

    let perRecordBand = refTable.costPerRecord.general;
    if (sensitivityClassifications.includes('contains-payment-data')) {
      perRecordBand = refTable.costPerRecord.paymentData;
    } else if (sensitivityClassifications.includes('contains-pii')) {
      perRecordBand = refTable.costPerRecord.pii;
    } else if (sensitivityClassifications.includes('contains-secrets')) {
      perRecordBand = refTable.costPerRecord.secretsOrCredentials;
    }

    const records = params.defaultRecordsEstimate;
    const hasSensitivity = sensitivityClassifications.length > 0 || targetNode?.asset.isSensitiveData;

    let secondaryLossBand: CostBand = { low: 0, likely: 0, high: 0 };

    if (hasSensitivity) {
      const recordsLossLow = records * perRecordBand.low;
      const recordsLossLikely = records * perRecordBand.likely;
      const recordsLossHigh = records * perRecordBand.high;

      secondaryLossBand = {
        low: Math.round(recordsLossLow * (1 + refTable.regulatoryFineMultiplier.low)),
        likely: Math.round(recordsLossLikely * (1 + refTable.regulatoryFineMultiplier.likely)),
        high: Math.round(recordsLossHigh * (1 + refTable.regulatoryFineMultiplier.high)),
      };
    }

    // 6. Single Loss Expectancy (SLE) Band
    const singleLossExpectancyBand: CostBand = {
      low: primaryLossBand.low + secondaryLossBand.low,
      likely: primaryLossBand.likely + secondaryLossBand.likely,
      high: primaryLossBand.high + secondaryLossBand.high,
    };

    // 7. Annualized Loss Expectancy (ALE) Band
    const annualizedLossExpectancyBand: CostBand = {
      low: Math.round(lossEventFrequencyBand.low * singleLossExpectancyBand.low),
      likely: Math.round(lossEventFrequencyBand.likely * singleLossExpectancyBand.likely),
      high: Math.round(lossEventFrequencyBand.high * singleLossExpectancyBand.high),
    };

    return {
      pathId: path.id,
      fingerprint: path.fingerprint,
      estimateLabel: '[ESTIMATE]',
      threatEventFrequencyBand,
      vulnerabilityProbabilityBand,
      lossEventFrequencyBand,
      singleLossExpectancyBand,
      annualizedLossExpectancyBand,
      // Backward compatibility point estimates
      threatEventFrequency: threatEventFrequencyBand.likely,
      vulnerabilityProbability: vulnerabilityProbabilityBand.likely,
      lossEventFrequency: lossEventFrequencyBand.likely,
      primaryLoss: primaryLossBand.likely,
      secondaryLoss: secondaryLossBand.likely,
      singleLossExpectancy: singleLossExpectancyBand.likely,
      annualizedLossExpectancy: annualizedLossExpectancyBand.likely,
      currency: params.currency,
      drivingInputs: {
        terminalAssetId: path.targetAssetId,
        terminalAssetTags: targetTags,
        sensitivityClassifications,
        pathHops: path.pathLength,
        referenceTableVersion: refTable.version,
        heuristicRationale: `Target sensitivity: [${sensitivityClassifications.join(', ') || 'unclassified'}], Hops: ${path.pathLength} (${Math.round(hopDecay * 100)}% decay), Ingress: ${isPublicIngress ? 'PUBLIC' : 'INTERNAL'}, Ref Table: ${refTable.version}`,
      },
    };
  }

  public calculatePortfolioExposure(
    paths: AttackPath[],
    graph: SecurityGraphEngine,
    config: Partial<FairParameters> = {}
  ): PortfolioFinancialRiskReport {
    const params = FairParametersSchema.parse(config);
    const refTable: BreachCostReferenceTable =
      params.referenceTable ?? DEFAULT_BREACH_COST_TABLE;

    const exposures = paths.map((p) => this.calculatePathExposure(p, graph, config));

    const totalAleBand: CostBand = {
      low: exposures.reduce((sum, exp) => sum + exp.annualizedLossExpectancyBand.low, 0),
      likely: exposures.reduce((sum, exp) => sum + exp.annualizedLossExpectancyBand.likely, 0),
      high: exposures.reduce((sum, exp) => sum + exp.annualizedLossExpectancyBand.high, 0),
    };

    const maxSleBand: CostBand = {
      low: exposures.length > 0 ? Math.max(...exposures.map((e) => e.singleLossExpectancyBand.low)) : 0,
      likely: exposures.length > 0 ? Math.max(...exposures.map((e) => e.singleLossExpectancyBand.likely)) : 0,
      high: exposures.length > 0 ? Math.max(...exposures.map((e) => e.singleLossExpectancyBand.high)) : 0,
    };

    // Sort descending by ALE likely
    exposures.sort((a, b) => b.annualizedLossExpectancy - a.annualizedLossExpectancy);

    return {
      tenantId: graph.tenantId,
      generatedAt: new Date().toISOString(),
      evaluatedPathCount: paths.length,
      referenceTableVersion: refTable.version,
      estimateLabel: '[ESTIMATE]',
      totalAnnualizedLossExpectancyBand: totalAleBand,
      maximumSingleEventLossBand: maxSleBand,
      // Backward compatibility point estimates
      totalAnnualizedLossExpectancy: totalAleBand.likely,
      maximumSingleEventLoss: maxSleBand.likely,
      currency: params.currency,
      paths: exposures,
      disclaimer: FAIR_DISCLAIMER,
    };
  }

  public formatMarkdownSummary(report: PortfolioFinancialRiskReport): string {
    const lines: string[] = [
      `# 💰 FAIR Cyber Risk Financial Quantification Report`,
      `**Tenant:** \`${report.tenantId}\` | **Generated At:** ${report.generatedAt}`,
      `**Reference Cost Table Version:** \`${report.referenceTableVersion}\``,
      ``,
      `> ⚠️ **${report.estimateLabel}**: ${report.disclaimer}`,
      ``,
      `## 📈 Portfolio Annualized Financial Exposure Band`,
      `| Metric | Low Band [ESTIMATE] | Likely Band [ESTIMATE] | High Band [ESTIMATE] |`,
      `| :--- | :--- | :--- | :--- |`,
      `| **Annualized Loss Expectancy (ALE)** | ${report.currency} ${report.totalAnnualizedLossExpectancyBand.low.toLocaleString()} | **${report.currency} ${report.totalAnnualizedLossExpectancyBand.likely.toLocaleString()}** | ${report.currency} ${report.totalAnnualizedLossExpectancyBand.high.toLocaleString()} |`,
      `| **Maximum Single Loss (SLE)** | ${report.currency} ${report.maximumSingleEventLossBand.low.toLocaleString()} | **${report.currency} ${report.maximumSingleEventLossBand.likely.toLocaleString()}** | ${report.currency} ${report.maximumSingleEventLossBand.high.toLocaleString()} |`,
      ``,
      `## 🎯 Prioritized Attack Path Exposure Breakdown`,
      `| Path ID | Risk | SLE Likely Range [ESTIMATE] | ALE Likely Range [ESTIMATE] | Driving Inputs & Tags |`,
      `| :--- | :--- | :--- | :--- | :--- |`,
    ];

    for (const exp of report.paths) {
      const sleRange = `${report.currency} ${exp.singleLossExpectancyBand.low.toLocaleString()} - ${exp.singleLossExpectancyBand.high.toLocaleString()}`;
      const aleRange = `${report.currency} ${exp.annualizedLossExpectancyBand.low.toLocaleString()} - ${exp.annualizedLossExpectancyBand.high.toLocaleString()}`;
      const inputs = exp.drivingInputs.sensitivityClassifications.join(', ') || 'unclassified';
      lines.push(
        `| \`${exp.pathId}\` | ${(exp.vulnerabilityProbability * 10).toFixed(1)}/10 | ${sleRange} | **${aleRange}** | \`${exp.drivingInputs.terminalAssetId}\` (${inputs}, ${exp.drivingInputs.pathHops} hops) |`
      );
    }

    return lines.join('\n');
  }
}
