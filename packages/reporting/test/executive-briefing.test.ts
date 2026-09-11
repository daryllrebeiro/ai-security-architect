import { describe, expect, it } from 'vitest';
import { ExecutiveBriefingGenerator } from '../src/executive-briefing/briefing-generator.js';
import { JargonFilter } from '../src/executive-briefing/jargon-filter.js';
import type { ExecutiveBriefingInput } from '../src/executive-briefing/types.js';

describe('Executive Risk Briefing Generator', () => {
  it('identifies an improving quarter and generates constructive executive narrative', () => {
    const input: ExecutiveBriefingInput = {
      tenantId: 'tenant-finance',
      reportingPeriod: 'Q3 2026',
      startMttrDays: 14.5,
      endMttrDays: 6.2,
      startCriticalPathsCount: 12,
      endCriticalPathsCount: 3,
      estimatedDollarExposureMin: 1_200_000,
      estimatedDollarExposureMax: 4_500_000,
      expectedAnnualLoss: 350_000,
      topRiskThemes: [
        'Public database exposure in legacy staging accounts',
        'Over-privileged service accounts spanning payment clusters',
      ],
    };

    const report = ExecutiveBriefingGenerator.generate(input);

    expect(report.postureTrend).toBe('IMPROVING');
    expect(report.executiveSummary).toContain('demonstrated measurable improvement');
    expect(report.markdown).toContain('Executive Cybersecurity Risk Briefing');
    expect(report.markdown).toContain('**Status:** IMPROVING');
  });

  it('identifies a degrading quarter when critical exposure routes expand', () => {
    const input: ExecutiveBriefingInput = {
      tenantId: 'tenant-retail',
      reportingPeriod: 'Q4 2026',
      startMttrDays: 5.0,
      endMttrDays: 11.2,
      startCriticalPathsCount: 2,
      endCriticalPathsCount: 9,
      estimatedDollarExposureMin: 3_000_000,
      estimatedDollarExposureMax: 12_000_000,
      expectedAnnualLoss: 1_850_000,
      topRiskThemes: ['Rapid infrastructure expansion without default access boundaries'],
    };

    const report = ExecutiveBriefingGenerator.generate(input);

    expect(report.postureTrend).toBe('DEGRADING');
    expect(report.executiveSummary).toContain('cybersecurity risk increased');
    expect(report.executiveSummary).toContain('prioritize remediation capacity');
    expect(report.markdown).toContain('**Status:** DEGRADING');
  });

  it('rigorously purges practitioner jargon (CVEs, control IDs, IAM actions, file paths) from board markdown', () => {
    const input: ExecutiveBriefingInput = {
      tenantId: 'tenant-healthcare',
      reportingPeriod: 'Q2 2026',
      startMttrDays: 8.0,
      endMttrDays: 8.0,
      startCriticalPathsCount: 4,
      endCriticalPathsCount: 4,
      estimatedDollarExposureMin: 500_000,
      estimatedDollarExposureMax: 1_500_000,
      expectedAnnualLoss: 120_000,
      topRiskThemes: [
        'Critical vulnerability CVE-2024-3094 affecting SSH gateway',
        'Non-compliance with NIST-800-53 AC-2 and SOC 2 CC6.1 in payment pipeline',
        'Excessive s3:GetObject permissions on internal buckets referenced in src/config.yaml',
      ],
    };

    const report = ExecutiveBriefingGenerator.generate(input);

    // Markdown should NOT contain technical practitioner codes
    expect(report.markdown).not.toMatch(/CVE-\d{4}-\d+/i);
    expect(report.markdown).not.toMatch(/AC-2/i);
    expect(report.markdown).not.toMatch(/CC6\.1/i);
    expect(report.markdown).not.toMatch(/s3:GetObject/);
    expect(report.markdown).not.toMatch(/src\/config\.yaml/);

    // Filter check directly
    expect(JargonFilter.containsJargon('Contains CVE-2023-1234 in report')).toBe(true);
    expect(JargonFilter.containsJargon('Clean high level summary of operational risks')).toBe(false);
  });

  it('consistently labels financial risk metrics with honest Model Estimate disclaimers', () => {
    const input: ExecutiveBriefingInput = {
      tenantId: 'tenant-media',
      reportingPeriod: 'Q1 2026',
      startMttrDays: 10,
      endMttrDays: 7,
      startCriticalPathsCount: 8,
      endCriticalPathsCount: 5,
      estimatedDollarExposureMin: 2_000_000,
      estimatedDollarExposureMax: 6_000_000,
      expectedAnnualLoss: 450_000,
      topRiskThemes: ['Supply chain dependency risks in public API gateways'],
    };

    const report = ExecutiveBriefingGenerator.generate(input);

    const financialMetrics = report.keyMetrics.filter((m) => m.isModelEstimate);
    expect(financialMetrics.length).toBeGreaterThanOrEqual(2);
    for (const metric of financialMetrics) {
      expect(metric.estimateDisclaimer).toContain('Model Estimate');
    }

    // Board-level markdown notice
    expect(report.markdown).toContain('Model Estimate');
    expect(report.markdown).toContain('FAIR quantitative cyber risk simulation');
    expect(report.markdown).toContain('Notice to the Board of Directors: Quantitative financial values are heuristic model estimates');
  });
});
