import type { CliScanResult, SarifReport, SarifResult } from '../types.js';

export class SarifFormatter {
  public format(result: CliScanResult): SarifReport {
    const rulesMap = new Map<string, { id: string; name: string; shortDescription: { text: string }; help: { text: string } }>();
    const sarifResults: SarifResult[] = [];

    for (const finding of result.findings) {
      if (!rulesMap.has(finding.ruleId)) {
        rulesMap.set(finding.ruleId, {
          id: finding.ruleId,
          name: finding.category,
          shortDescription: { text: finding.title },
          help: { text: finding.remediationRecommendation || finding.description },
        });
      }

      const level: 'error' | 'warning' | 'note' =
        finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
          ? 'error'
          : finding.severity === 'MEDIUM'
          ? 'warning'
          : 'note';

      const filePath = finding.evidence?.filePath || 'unknown';
      const startLine = finding.evidence?.lineStart || 1;
      const endLine = finding.evidence?.lineEnd || 1;
      const snippetText = finding.evidence?.snippet;

      sarifResults.push({
        ruleId: finding.ruleId,
        level,
        message: {
          text: `[${finding.severity}] ${finding.title}: ${finding.description}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: filePath.replace(/\\/g, '/') },
              region: {
                startLine,
                endLine,
                snippet: snippetText ? { text: snippetText } : undefined,
              },
            },
          },
        ],
      });
    }

    return {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'AISecurityArchitect',
              version: '1.0.0',
              rules: Array.from(rulesMap.values()),
            },
          },
          results: sarifResults,
        },
      ],
    };
  }
}
