import { JargonFilter } from './jargon-filter.js';
import type {
  BriefingMetricItem,
  ExecutiveBriefingInput,
  ExecutiveBriefingReport,
  PostureTrend,
} from './types.js';

export class ExecutiveBriefingGenerator {
  public static generate(input: ExecutiveBriefingInput): ExecutiveBriefingReport {
    const currency = input.currency ?? 'USD';
    const generatedAt = new Date().toISOString().split('T')[0];

    // 1. Determine Posture Trend Direction
    let postureTrend: PostureTrend = 'STABLE';
    const mttrImproved = input.endMttrDays < input.startMttrDays;
    const pathsImproved = input.endCriticalPathsCount < input.startCriticalPathsCount;
    const mttrWorsened = input.endMttrDays > input.startMttrDays;
    const pathsWorsened = input.endCriticalPathsCount > input.startCriticalPathsCount;

    if (mttrImproved && pathsImproved) {
      postureTrend = 'IMPROVING';
    } else if (mttrWorsened || pathsWorsened) {
      postureTrend = 'DEGRADING';
    }

    // 2. Synthesize Strategic Risk Themes (sanitizing technical jargon)
    const sanitizedThemes = input.topRiskThemes.map((t) => JargonFilter.sanitize(t));

    // 3. Format Key Metrics with Honest Estimate Disclaimers
    const keyMetrics: BriefingMetricItem[] = [
      {
        label: 'Remediation Velocity (Mean Time to Remediate)',
        value: `${input.endMttrDays.toFixed(1)} days (from ${input.startMttrDays.toFixed(1)} days)`,
        isModelEstimate: false,
        estimateDisclaimer: 'Observed operational telemetry',
      },
      {
        label: 'High-Impact Exposure Routes',
        value: `${input.endCriticalPathsCount} critical paths (from ${input.startCriticalPathsCount})`,
        isModelEstimate: false,
        estimateDisclaimer: 'Verified topological attack path graph count',
      },
      {
        label: 'Modeled Dollar Risk Exposure Range',
        value: `$${(input.estimatedDollarExposureMin / 1_000_000).toFixed(1)}M - $${(
          input.estimatedDollarExposureMax / 1_000_000
        ).toFixed(1)}M ${currency}`,
        isModelEstimate: true,
        estimateDisclaimer: 'Model Estimate based on FAIR quantitative cyber risk simulation',
      },
      {
        label: 'Expected Annual Loss',
        value: `$${Math.round(input.expectedAnnualLoss).toLocaleString()} ${currency} / year`,
        isModelEstimate: true,
        estimateDisclaimer: 'Model Estimate based on FAIR quantitative cyber risk simulation',
      },
    ];

    // 4. Generate Narrative Summary
    const mttrChangePct = Math.round(
      Math.abs((input.endMttrDays - input.startMttrDays) / (input.startMttrDays || 1)) * 100
    );
    const pathChangePct = Math.round(
      Math.abs((input.endCriticalPathsCount - input.startCriticalPathsCount) / (input.startCriticalPathsCount || 1)) * 100
    );

    let trendNarrative = '';
    if (postureTrend === 'IMPROVING') {
      trendNarrative = `During ${input.reportingPeriod}, organizational cybersecurity posture demonstrated measurable improvement. Critical exposure routes decreased by ${pathChangePct}%, while engineering remediation velocity improved by ${mttrChangePct}%, reducing mean resolution time to ${input.endMttrDays.toFixed(1)} days. Estimated cyber risk exposure is projected between $${(input.estimatedDollarExposureMin / 1_000_000).toFixed(1)}M and $${(input.estimatedDollarExposureMax / 1_000_000).toFixed(1)}M (Model Estimate).`;
    } else if (postureTrend === 'DEGRADING') {
      trendNarrative = `During ${input.reportingPeriod}, organizational cybersecurity risk increased. Critical exposure routes expanded by ${pathChangePct}%, with mean resolution time lengthening to ${input.endMttrDays.toFixed(1)} days. Estimated cyber risk exposure is projected between $${(input.estimatedDollarExposureMin / 1_000_000).toFixed(1)}M and $${(input.estimatedDollarExposureMax / 1_000_000).toFixed(1)}M (Model Estimate). Recommended leadership intervention: prioritize remediation capacity on core business workloads.`;
    } else {
      trendNarrative = `During ${input.reportingPeriod}, organizational cybersecurity posture remained stable across core services. Mean resolution time is steady at ${input.endMttrDays.toFixed(1)} days with ${input.endCriticalPathsCount} active exposure routes. Estimated annual loss exposure is modeled at $${Math.round(input.expectedAnnualLoss).toLocaleString()} (Model Estimate).`;
    }

    const executiveSummary = JargonFilter.sanitize(trendNarrative);

    // 5. Generate Markdown
    const markdown = [
      `# Executive Cybersecurity Risk Briefing`,
      `**Reporting Period:** ${input.reportingPeriod} | **Date:** ${generatedAt} | **Status:** ${postureTrend}`,
      '',
      `## Executive Summary`,
      executiveSummary,
      '',
      `## Key Financial & Operational Risk Metrics`,
      ...keyMetrics.map(
        (m) => `- **${m.label}**: ${m.value}\n  _${m.estimateDisclaimer}_`
      ),
      '',
      `## Top Strategic Business Risk Themes`,
      ...sanitizedThemes.map((theme, i) => `${i + 1}. **${theme}**`),
      '',
      `---`,
      `*Notice to the Board of Directors: Quantitative financial values are heuristic model estimates derived via the FAIR cyber risk methodology and Monte Carlo simulation. Operational metrics represent measured engineering telemetry.*`,
    ].join('\n');

    return {
      tenantId: input.tenantId,
      reportingPeriod: input.reportingPeriod,
      generatedAt,
      postureTrend,
      executiveSummary,
      keyMetrics,
      strategicRiskThemes: sanitizedThemes,
      markdown,
    };
  }
}
