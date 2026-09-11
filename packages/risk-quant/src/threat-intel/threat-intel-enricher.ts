import type { Finding } from '@ai-security-architect/core';
import type { ThreatIntelClient } from './threat-intel-client.js';
import type {
  EnrichedFinding,
  ThreatIntelEnrichmentResult,
} from './types.js';

export class ThreatIntelEnricher {
  private static readonly SEVERITY_BASE_SCORES: Record<string, number> = {
    CRITICAL: 9.0,
    HIGH: 7.0,
    MEDIUM: 5.0,
    LOW: 3.0,
  };

  public static enrichFindings(
    findings: Finding[],
    client: ThreatIntelClient,
    options: { now?: Date } = {}
  ): ThreatIntelEnrichmentResult {
    const staleness = client.checkStaleness(options.now);
    let prioritizedKevCount = 0;
    let highEpssCount = 0;

    const enrichedFindings: EnrichedFinding[] = findings.map((finding) => {
      const cve = this.extractCve(finding);
      const baseScore = this.SEVERITY_BASE_SCORES[finding.severity] ?? 5.0;

      let isKevExploited = false;
      let cisaKevDetails = undefined;
      let epssScore = undefined;
      let epssPercentile = undefined;
      let prioritizationOverride = false;
      let adjustedRankScore = baseScore;
      let explanation: string | undefined = undefined;

      if (cve) {
        const kev = client.lookupKev(cve);
        const epss = client.lookupEpss(cve);

        if (kev) {
          isKevExploited = true;
          cisaKevDetails = kev;
          prioritizationOverride = true;
          prioritizedKevCount++;
          // Hard override: Boost score above maximum internal severity (100.0 + base)
          adjustedRankScore = 100.0 + baseScore;
          explanation = `[KEV OVERRIDE] Elevated above internal severity: ${cve} is confirmed actively exploited in the wild on the CISA KEV catalog (added: ${kev.dateAdded}, ransomware use: ${kev.knownRansomwareCampaignUse}). Required Action: ${kev.requiredAction}.`;
        }

        if (epss) {
          epssScore = epss.epss;
          epssPercentile = epss.percentile;
          if (epss.epss >= 0.20) {
            highEpssCount++;
          }

          if (!isKevExploited) {
            // Gradual weighting within severity tier based on EPSS probability
            adjustedRankScore = baseScore + epss.epss * 2.0;
            explanation = `[EPSS ENRICHED] Exploit Prediction Scoring System probability: ${(epss.epss * 100).toFixed(1)}% (${(epss.percentile * 100).toFixed(1)}th percentile).`;
          }
        }
      }

      return {
        ...finding,
        threatIntel: {
          isKevExploited,
          cisaKevDetails,
          epssScore,
          epssPercentile,
          prioritizationOverride,
          adjustedRankScore: Number(adjustedRankScore.toFixed(2)),
          explanation,
        },
      };
    });

    // Sort descending by adjustedRankScore
    enrichedFindings.sort((a, b) => b.threatIntel.adjustedRankScore - a.threatIntel.adjustedRankScore);

    return {
      enrichedFindings,
      prioritizedKevCount,
      highEpssCount,
      cacheMetadata: staleness,
    };
  }

  private static extractCve(finding: Finding): string | undefined {
    if (finding.cve) return finding.cve;
    // Check tags or title
    const cveTag = (finding.metadata?.tags as string[] | undefined)?.find((t) =>
      t.toUpperCase().startsWith('CVE:')
    );
    if (cveTag) return cveTag.split(':')[1];

    const match = /(CVE-\d{4}-\d{4,7})/i.exec(`${finding.title} ${finding.description}`);
    return match ? match[1].toUpperCase() : undefined;
  }
}
