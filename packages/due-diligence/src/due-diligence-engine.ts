import { Asset, Finding } from '@ai-security-architect/core';
import {
  DueDiligenceConfig,
  DueDiligenceMetrics,
  DueDiligenceReport,
  DealRiskRating,
} from './types.js';

export class DueDiligenceEngine {
  /**
   * Generates M&A Due Diligence Assessment Packet from point-in-time repository snapshot.
   * Can emit unredacted version for authorized technical deal team or anonymized version for wide deal room.
   */
  generateAssessment(
    assets: Asset[],
    findings: Finding[],
    attackPathCount: number,
    config: DueDiligenceConfig
  ): DueDiligenceReport {
    // 1. Calculate deterministic quantitative risk metrics
    const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = findings.filter((f) => f.severity === 'HIGH').length;
    const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
    const lowCount = findings.filter((f) => f.severity === 'LOW').length;

    // Determine Deal Risk Rating
    let dealRiskRating: DealRiskRating = 'LOW';
    if (criticalCount >= 3 || attackPathCount >= 5) {
      dealRiskRating = 'PROHIBITIVE';
    } else if (criticalCount >= 1 || highCount >= 5 || attackPathCount >= 2) {
      dealRiskRating = 'HIGH';
    } else if (highCount >= 1 || mediumCount >= 5 || attackPathCount >= 1) {
      dealRiskRating = 'MODERATE';
    }

    // Estimate remediation engineering hours & liability cost
    // Critical = 40 hrs ($6,000), High = 20 hrs ($3,000), Med = 8 hrs ($1,200), Low = 2 hrs ($300)
    // Plus path architecture redesign = $12,000 per critical path
    const rate = config.baseRemediationHourlyRate ?? 150;
    const engineeringLiability =
      criticalCount * 40 * rate +
      highCount * 20 * rate +
      mediumCount * 8 * rate +
      lowCount * 2 * rate +
      attackPathCount * 12000;

    const metrics: DueDiligenceMetrics = {
      totalAssetsAnalyzed: assets.length,
      totalFindingsCount: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      attackPathsCount: attackPathCount,
      estimatedRemediationLiabilityUsd: engineeringLiability,
      dealRiskRating,
    };

    // 2. Build Redaction Token Map if anonymization is enabled
    const tokenMap = new Map<string, string>();
    let tokenCounter = 1;

    if (config.anonymize) {
      tokenMap.set(config.targetCompanyName, 'PROJECT_ACQUISITION_TARGET');

      for (const asset of assets) {
        if (!tokenMap.has(asset.id)) {
          tokenMap.set(asset.id, `TARGET_ASSET_${String(tokenCounter).padStart(2, '0')}`);
          tokenCounter++;
        }
        if (!tokenMap.has(asset.name)) {
          tokenMap.set(asset.name, `TARGET_SERVICE_${String(tokenCounter).padStart(2, '0')}`);
          tokenCounter++;
        }
      }
    }

    const redactText = (text: string): string => {
      if (!config.anonymize) return text;
      let sanitized = text;
      for (const [raw, replacement] of tokenMap.entries()) {
        sanitized = sanitized.replaceAll(raw, replacement);
      }
      return sanitized;
    };

    // 3. Construct Executive Summary
    const targetDisplay = config.anonymize ? 'PROJECT_ACQUISITION_TARGET (CONFIDENTIAL)' : config.targetCompanyName;
    const currency = config.currency ?? 'USD';

    const rawExecSummary = [
      `# M&A Cyber Diligence: Executive Risk Assessment`,
      `**Target Entity**: \`${targetDisplay}\` | **Anonymized Deal-Room Copy**: \`${config.anonymize ? 'YES' : 'NO'}\``,
      '',
      `## 1. Deal Risk Verdict: **${dealRiskRating} RISK**`,
      `- **Estimated Post-Close Security Remediation Liability**: $${engineeringLiability.toLocaleString()} ${currency} *(Model Estimate based on FAIR quantitative engineering metrics)*`,
      `- **Total Critical Attack Paths Into Core Infrastructure**: ${attackPathCount}`,
      `- **Identified High/Critical Vulnerabilities**: ${criticalCount + highCount} (${criticalCount} Critical, ${highCount} High)`,
      '',
      `## 2. Investment Committee Summary`,
      `Analysis of target infrastructure declarations (${assets.length} modeled components) indicates a **${dealRiskRating}** security posture. Key exposure vectors center around ${
        criticalCount > 0 ? 'unmitigated remote execution and data store accessibility' : 'identity permissions and network perimeter boundaries'
      }.`,
    ].join('\n');

    // 4. Construct Technical Appendix
    const rawAppendix = [
      `# Technical Diligence Appendix: Vulnerability Inventory & Architecture Detail`,
      `**Evaluated Target**: \`${targetDisplay}\``,
      '',
      `| Severity | Rule ID | Title | Affected Asset |`,
      `| :--- | :--- | :--- | :--- |`,
      ...findings.map((f) => `| **${f.severity}** | \`${f.ruleId}\` | ${f.title} | \`${f.assetId}\` |`),
      '',
      `## Crown-Jewel Asset Inventory`,
      ...assets
        .filter((a) => a.criticality === 'CRITICAL' || a.isSensitiveData)
        .map((a) => `- **${a.name}** (\`${a.id}\`) - Type: \`${a.type}\`, Environment: \`${a.environment}\``),
    ].join('\n');

    return {
      targetIdentifier: targetDisplay,
      isAnonymized: config.anonymize,
      generatedAt: new Date().toISOString(),
      metrics,
      executiveSummary: redactText(rawExecSummary),
      technicalAppendix: redactText(rawAppendix),
      anonymizationTokensUsed: config.anonymize ? tokenMap.size : 0,
    };
  }
}
