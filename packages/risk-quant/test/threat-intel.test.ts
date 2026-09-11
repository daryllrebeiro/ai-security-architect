import { describe, it, expect } from 'vitest';
import type { Finding } from '@ai-security-architect/core';
import { createEvidence } from '@ai-security-architect/core';
import {
  ThreatIntelClient,
  ThreatIntelEnricher,
  type CisaKevEntry,
  type EpssEntry,
} from '../src/index.js';

describe('Task E.2 — Active Threat Intelligence Enrichment (CISA KEV & EPSS)', () => {
  const sampleKev: Record<string, CisaKevEntry> = {
    'CVE-2021-44228': {
      cveID: 'CVE-2021-44228',
      vendorProject: 'Apache',
      product: 'Log4j',
      vulnerabilityName: 'Apache Log4j Remote Code Execution Vulnerability',
      dateAdded: '2021-12-10',
      shortDescription: 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP',
      requiredAction: 'Apply updates per vendor instructions.',
      dueDate: '2021-12-24',
      knownRansomwareCampaignUse: 'Known',
      notes: '',
    },
  };

  const sampleEpss: Record<string, EpssEntry> = {
    'CVE-2021-44228': {
      cve: 'CVE-2021-44228',
      epss: 0.975,
      percentile: 0.999,
    },
    'CVE-2023-11111': {
      cve: 'CVE-2023-11111',
      epss: 0.85,
      percentile: 0.94,
    },
    'CVE-2023-22222': {
      cve: 'CVE-2023-22222',
      epss: 0.05,
      percentile: 0.20,
    },
  };

  const mockEvidence = createEvidence({
    id: 'ev-1',
    tenantId: 'tenant-01',
    sourceType: 'DEPENDENCY_LOCKFILE',
    repository: 'repo-core',
    filePath: 'pom.xml',
    lineStart: 1,
    lineEnd: 5,
    snippet: 'log4j-core',
    scanner: 'DependencyScanner',
  });

  const findingNonKevCritical: Finding = {
    id: 'finding-crit-non-kev',
    tenantId: 'tenant-01',
    assetId: 'asset-svc-1',
    category: 'SQL_INJECTION',
    ruleId: 'SEC-SQLI-001',
    title: 'Theoretical SQL Injection (Internal)',
    description: 'Internal SQL injection requiring authenticated admin access',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    scanner: 'RuleScanner',
    cve: 'CVE-2023-99999',
    evidence: mockEvidence,
    metadata: {},
  };

  const findingKevMedium: Finding = {
    id: 'finding-med-kev',
    tenantId: 'tenant-01',
    assetId: 'asset-svc-2',
    category: 'VULNERABLE_DEPENDENCY',
    ruleId: 'SEC-LOG4J-001',
    title: 'Log4Shell in logging pipeline',
    description: 'Vulnerable Log4j 2.14.1 installed',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    scanner: 'DependencyScanner',
    cve: 'CVE-2021-44228',
    evidence: mockEvidence,
    metadata: {},
  };

  it('elevates KEV-matched finding above higher internal severity non-KEV finding', () => {
    const client = new ThreatIntelClient({
      lastFetchedAt: new Date().toISOString(),
      kevCatalog: sampleKev,
      epssScores: sampleEpss,
    });

    const result = ThreatIntelEnricher.enrichFindings(
      [findingNonKevCritical, findingKevMedium],
      client
    );

    expect(result.prioritizedKevCount).toBe(1);
    expect(result.enrichedFindings).toHaveLength(2);

    // Finding B (MEDIUM severity, but on KEV) MUST be ranked first!
    const firstFinding = result.enrichedFindings[0];
    const secondFinding = result.enrichedFindings[1];

    expect(firstFinding.id).toBe(findingKevMedium.id);
    expect(firstFinding.threatIntel.isKevExploited).toBe(true);
    expect(firstFinding.threatIntel.prioritizationOverride).toBe(true);
    expect(firstFinding.threatIntel.adjustedRankScore).toBeGreaterThan(100);
    expect(firstFinding.threatIntel.explanation).toContain('[KEV OVERRIDE]');
    expect(firstFinding.threatIntel.explanation).toContain('CISA KEV');
    expect(firstFinding.threatIntel.explanation).toContain('2021-12-10');

    // Finding A (CRITICAL, but non-KEV) ranks below
    expect(secondFinding.id).toBe(findingNonKevCritical.id);
    expect(secondFinding.threatIntel.isKevExploited).toBe(false);
    expect(secondFinding.threatIntel.prioritizationOverride).toBe(false);
    expect(secondFinding.threatIntel.adjustedRankScore).toBe(9.0);
  });

  it('detects and warns on stale cached threat intelligence data exceeding threshold', () => {
    // 10 days old cache
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const staleClient = new ThreatIntelClient(
      {
        lastFetchedAt: tenDaysAgo,
        kevCatalog: sampleKev,
        epssScores: sampleEpss,
      },
      { stalenessThresholdDays: 7 }
    );

    const result = ThreatIntelEnricher.enrichFindings([findingKevMedium], staleClient);

    expect(result.cacheMetadata.isStale).toBe(true);
    expect(result.cacheMetadata.cacheAgeDays).toBeGreaterThanOrEqual(9.9);
    expect(result.cacheMetadata.warning).toBeDefined();
    expect(result.cacheMetadata.warning).toContain('[WARNING] Threat intelligence cache is');
    expect(result.cacheMetadata.warning).toContain('configured staleness threshold: 7 days');

    // Fresh cache test
    const freshClient = new ThreatIntelClient(
      {
        lastFetchedAt: new Date().toISOString(),
        kevCatalog: sampleKev,
        epssScores: sampleEpss,
      },
      { stalenessThresholdDays: 7 }
    );

    const freshResult = ThreatIntelEnricher.enrichFindings([findingKevMedium], freshClient);
    expect(freshResult.cacheMetadata.isStale).toBe(false);
    expect(freshResult.cacheMetadata.warning).toBeUndefined();
  });

  it('uses EPSS scores to refine ordering within the same internal severity tier', () => {
    const findingHighA: Finding = {
      ...findingNonKevCritical,
      id: 'f-high-a',
      severity: 'HIGH',
      cve: 'CVE-2023-11111', // EPSS 0.85
    };

    const findingHighB: Finding = {
      ...findingNonKevCritical,
      id: 'f-high-b',
      severity: 'HIGH',
      cve: 'CVE-2023-22222', // EPSS 0.05
    };

    const client = new ThreatIntelClient({
      lastFetchedAt: new Date().toISOString(),
      kevCatalog: {},
      epssScores: sampleEpss,
    });

    const result = ThreatIntelEnricher.enrichFindings([findingHighB, findingHighA], client);

    expect(result.enrichedFindings[0].id).toBe('f-high-a');
    expect(result.enrichedFindings[1].id).toBe('f-high-b');
    expect(result.enrichedFindings[0].threatIntel.adjustedRankScore).toBeGreaterThan(
      result.enrichedFindings[1].threatIntel.adjustedRankScore
    );
  });
});
