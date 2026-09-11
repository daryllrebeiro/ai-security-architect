import { describe, it, expect } from 'vitest';
import type { Asset } from '@ai-security-architect/core';
import {
  AssetBaselineStore,
  AnomalyDetector,
} from '../src/index.js';

describe('Task E.4 — Anomaly Detection on Permission & Infrastructure Changes', () => {
  const tenantId = 'tenant-anomaly-01';

  const stableDbRole: Asset = {
    id: 'asset-iam-role-prod-db',
    tenantId,
    type: 'IAM_ROLE',
    name: 'prod-database-access-role',
    environment: 'production',
    isPublic: false,
    isSensitiveData: true,
    criticality: 'CRITICAL',
    tags: ['iam-role', 'database'],
    metadata: {},
  };

  const churnyDevService: Asset = {
    id: 'asset-svc-dev-sandbox',
    tenantId,
    type: 'SERVICE',
    name: 'dev-sandbox-service',
    environment: 'development',
    isPublic: false,
    isSensitiveData: false,
    criticality: 'LOW',
    tags: ['service', 'dev'],
    metadata: {},
  };

  const newlyDiscoveredAsset: Asset = {
    id: 'asset-svc-new-microservice',
    tenantId,
    type: 'SERVICE',
    name: 'new-microservice',
    environment: 'production',
    isPublic: false,
    isSensitiveData: false,
    criticality: 'MEDIUM',
    tags: ['service'],
    metadata: {},
  };

  it('flags sudden out-of-pattern permission spike on historically stable asset with concrete explanation', () => {
    const store = new AssetBaselineStore();

    // Simulate 6 historical scans where this database role NEVER had permission changes
    for (let i = 1; i <= 6; i++) {
      store.recordScanEvent(stableDbRole.id); // scan observed, 0 change events
    }

    const baseline = store.getBaseline(stableDbRole.id);
    expect(baseline?.totalScansObserved).toBe(6);
    expect(baseline?.totalChangeEventsCount).toBe(0);
    expect(baseline?.changeFrequency).toBe(0);

    const detector = new AnomalyDetector(store, { minScansThreshold: 3 });

    // Current scan: suddenly introduces 3 new permissions including wildcard 's3:*'
    const result = detector.evaluateChange({
      asset: stableDbRole,
      newPermissions: ['s3:GetObject', 's3:ListBucket', 's3:*'],
      removedPermissions: [],
      newRelationshipsCount: 0,
      removedRelationshipsCount: 0,
      exposureChanged: false,
    });

    expect(result.status).toBe('ANOMALY_DETECTED');
    expect(result.severity).toBe('CRITICAL');
    expect(result.anomalyScore).toBeGreaterThanOrEqual(8.0);
    expect(result.explanation).toContain("Asset 'prod-database-access-role'");
    expect(result.explanation).toContain('0 permission changes in 6 previous scans');
    expect(result.explanation).toContain('sudden permission spike on historically stable asset');
    expect(result.baselineSummary.scansObserved).toBe(6);
    expect(result.baselineSummary.changeFrequencyPercentage).toBe(0);
  });

  it('does NOT falsely flag regular established churn on frequently redeployed services', () => {
    const store = new AssetBaselineStore();

    // Simulate an asset with frequent regular churn (e.g. 4 change events across 5 scans, mean 2 permissions)
    for (let i = 1; i <= 5; i++) {
      const isChange = i !== 3; // 4 out of 5 had changes
      store.recordScanEvent(
        churnyDevService.id,
        isChange
          ? {
              scanId: `scan-${i}`,
              timestamp: new Date().toISOString(),
              permissionsAddedCount: 1,
              permissionsRemovedCount: 1,
              relationshipsAddedCount: 0,
              relationshipsRemovedCount: 0,
              exposureChanged: false,
              hasWildcardGrant: false,
              addedPermissions: ['sqs:SendMessage'],
            }
          : undefined
      );
    }

    const baseline = store.getBaseline(churnyDevService.id);
    expect(baseline?.totalScansObserved).toBe(5);
    expect(baseline?.changeFrequency).toBe(0.8);
    expect(baseline?.meanPermissionsChanged).toBe(2.0);

    const detector = new AnomalyDetector(store, { minScansThreshold: 3 });

    // Current scan: introduces typical 2 permission changes (1 added, 1 removed)
    const result = detector.evaluateChange({
      asset: churnyDevService,
      newPermissions: ['sqs:ReceiveMessage'],
      removedPermissions: ['sqs:DeleteMessage'],
      newRelationshipsCount: 0,
      removedRelationshipsCount: 0,
      exposureChanged: false,
    });

    expect(result.status).toBe('NORMAL');
    expect(result.explanation).toContain('conforms to its established churn pattern');
    expect(result.explanation).toContain('observed in 80% of scans');
    expect(result.baselineSummary.scansObserved).toBe(5);
  });

  it('suppresses anomaly detection for cold-start assets with insufficient history', () => {
    const store = new AssetBaselineStore();

    // Only 1 historical scan observed for brand new asset
    store.recordScanEvent(newlyDiscoveredAsset.id);

    const detector = new AnomalyDetector(store, { minScansThreshold: 3 });

    const result = detector.evaluateChange({
      asset: newlyDiscoveredAsset,
      newPermissions: ['s3:PutObject'],
      removedPermissions: [],
      newRelationshipsCount: 0,
      removedRelationshipsCount: 0,
      exposureChanged: false,
    });

    expect(result.status).toBe('INSUFFICIENT_HISTORY');
    expect(result.anomalyScore).toBe(0.0);
    expect(result.explanation).toContain('Insufficient scan history to evaluate baseline');
    expect(result.explanation).toContain('1 scan(s) observed, minimum required: 3');
    expect(result.explanation).toContain('Anomaly evaluation suppressed to prevent false alerts');
  });
});
