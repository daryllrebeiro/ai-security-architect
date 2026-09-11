import { describe, it, expect } from 'vitest';
import type { AttackPath } from '@ai-security-architect/core';
import { ScanHistoryStore } from '@ai-security-architect/graph';
import { HistoricalDashboardEngine } from '../src/historical-dashboard-engine.js';

describe('Task B.3 — Historical Risk Trend Dashboard & MTTR Tracking', () => {
  const repository = 'enterprise/core-banking';
  const tenantId = 'tenant-dash-test';

  function makeMockPath(id: string, totalRisk: number, fingerprint: string): AttackPath {
    return {
      id,
      tenantId,
      entryAssetId: 'asset-internet',
      targetAssetId: 'asset-s3-vault',
      pathLength: 3,
      fingerprint,
      steps: [
        {
          stepNumber: 1,
          sourceAssetId: 'asset-internet',
          targetAssetId: 'asset-alb',
          relationshipType: 'EXPOSES_HTTP',
          explanation: 'ingress to alb',
        },
      ],
      riskScore: {
        impact: 9.0,
        exploitability: 9.0,
        reachability: 1.0,
        assetCriticality: 9.0,
        confidence: 1.0,
        totalRisk,
      },
      verifiedEliminated: false,
    };
  }

  it('calculates true MTTR strictly excluding paths closed via asset-removed', () => {
    const store = new ScanHistoryStore(':memory:');
    const dashboardEngine = new HistoricalDashboardEngine(store);

    const fp1 = 'fp-remediated-path-001';
    const fp2 = 'fp-decommissioned-path-002';

    const path1 = makeMockPath('path-001', 9.5, fp1);
    const path2 = makeMockPath('path-002', 8.0, fp2);

    // Day 1: Scan 1 introduces both paths
    const t0 = new Date('2026-09-01T10:00:00Z').toISOString();
    store.recordScan('scan-001', tenantId, repository, 'commit-sha-1', [path1, path2], t0);

    // Day 2 (24 hours later): Path 1 is genuinely remediated!
    const t1 = new Date('2026-09-02T10:00:00Z').toISOString();
    store.recordScan('scan-002', tenantId, repository, 'commit-sha-2', [path2], t1);
    store.recordClosures(
      'scan-002',
      repository,
      [
        {
          path: path1,
          fingerprint: fp1,
          closureReason: 'remediated',
          originAssetId: 'asset-alb',
        },
      ],
      t1
    );

    // Day 3 (48 hours after Day 1): Path 2 service is deleted/decommissioned (asset-removed)
    const t2 = new Date('2026-09-03T10:00:00Z').toISOString();
    store.recordScan('scan-003', tenantId, repository, 'commit-sha-3', [], t2);
    store.recordClosures(
      'scan-003',
      repository,
      [
        {
          path: path2,
          fingerprint: fp2,
          closureReason: 'asset-removed',
          originAssetId: 'asset-alb',
        },
      ],
      t2
    );

    const summary = dashboardEngine.calculateDashboardSummary(repository);

    expect(summary.totalScans).toBe(3);
    expect(summary.currentTotalPaths).toBe(0); // All paths closed by scan 3
    expect(summary.currentCriticalPaths).toBe(0);

    // Closures check
    expect(summary.remediatedPathsCount).toBe(1);
    expect(summary.assetRemovedCount).toBe(1);

    // MTTR check: exactly 24 hours for path 1. Path 2 (48 hrs) was asset-removed and MUST NOT be included!
    expect(summary.meanTimeToRemediationHours).toBe(24);
    expect(summary.mttrDetails.length).toBe(1);
    expect(summary.mttrDetails[0].fingerprint).toBe(fp1);
    expect(summary.mttrDetails[0].durationHours).toBe(24);

    store.close();
  });

  it('renders complete HTML dashboard containing MTTR KPIs and scan history table', () => {
    const store = new ScanHistoryStore(':memory:');
    const dashboardEngine = new HistoricalDashboardEngine(store);

    const path1 = makeMockPath('path-001', 9.2, 'fp-01');
    store.recordScan('scan-001', tenantId, repository, 'sha-12345678', [path1]);

    const summary = dashboardEngine.calculateDashboardSummary(repository);
    const html = dashboardEngine.renderHtmlDashboard(summary);

    expect(html).toContain('Security Risk Trend & MTTR Dashboard');
    expect(html).toContain('enterprise/core-banking');
    expect(html).toContain('Active Attack Paths');
    expect(html).toContain('True Mean Time To Remediate (MTTR)');
    expect(html).toContain('sha-1234');

    store.close();
  });

  it('serves dashboard via startLocalDashboardServer and shuts down cleanly', async () => {
    const store = new ScanHistoryStore(':memory:');
    const dashboardEngine = new HistoricalDashboardEngine(store);

    const path1 = makeMockPath('path-001', 8.5, 'fp-srv');
    store.recordScan('scan-srv', tenantId, repository, 'sha-srv-test', [path1]);

    const summary = dashboardEngine.calculateDashboardSummary(repository);
    const serverInstance = await dashboardEngine.startLocalDashboardServer(summary, 0);

    try {
      expect(serverInstance.url).toMatch(/^http:\/\/localhost:\d+$/);
      const res = await fetch(serverInstance.url);
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toContain('Security Risk Trend & MTTR Dashboard');
      expect(text).toContain(repository);
    } finally {
      await serverInstance.close();
      store.close();
    }
  });
});

