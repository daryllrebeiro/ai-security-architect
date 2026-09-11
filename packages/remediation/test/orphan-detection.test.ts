import { describe, it, expect } from 'vitest';
import { Asset, Relationship } from '@ai-security-architect/core';
import {
  OrphanDetector,
  ORPHAN_OBSERVATION_DISCLAIMER,
} from '../src/orphan-detection/index.js';

describe('Task I.5: Orphaned Resource & Stale Access Cleanup', () => {
  const detector = new OrphanDetector({ dormancyWindowDays: 90 });
  const now = new Date('2026-09-11T12:00:00Z');

  it('flags resources with zero observed activity across the dormancy window with dual security and cost framing', () => {
    const assets: Asset[] = [
      // 1. Defunct unattached database: 150 days dormant
      {
        id: 'asset-db-legacy-test',
        tenantId: 'tenant-1',
        type: 'DATABASE',
        name: 'legacy-staging-db',
        environment: 'staging',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        tags: [],
        metadata: {
          lastActivityDate: '2026-04-14T12:00:00Z', // 150 days ago (> 90 days)
        },
      },
      // 2. Idle load balancer with no targets
      {
        id: 'asset-alb-idle',
        tenantId: 'tenant-1',
        type: 'LOAD_BALANCER',
        name: 'abandoned-marketing-alb',
        environment: 'production',
        isPublic: true,
        isSensitiveData: false,
        criticality: 'LOW',
        tags: [],
        metadata: {
          createdDate: '2026-01-01T00:00:00Z',
        },
      },
    ];

    const relationships: Relationship[] = []; // No operational connections

    const result = detector.detectOrphans(assets, relationships, now);

    expect(result.findings.length).toBe(2);
    expect(result.summaries.length).toBe(2);

    // Database summary
    const dbSummary = result.summaries.find((s) => s.assetId === 'asset-db-legacy-test')!;
    expect(dbSummary).toBeDefined();
    expect(dbSummary.daysDormant).toBe(150);
    expect(dbSummary.estimatedMonthlyWasteUsd).toBe(75);
    expect(dbSummary.observationDisclaimer).toBe(ORPHAN_OBSERVATION_DISCLAIMER);

    // ALB summary
    const albSummary = result.summaries.find((s) => s.assetId === 'asset-alb-idle')!;
    expect(albSummary).toBeDefined();
    expect(albSummary.estimatedMonthlyWasteUsd).toBe(25);

    // Finding category & label
    const dbFinding = result.findings.find((f) => f.assetId === 'asset-db-legacy-test')!;
    expect(dbFinding.category).toBe('ORPHANED_RESOURCE');
    expect(dbFinding.description).toContain(ORPHAN_OBSERVATION_DISCLAIMER);
    expect(dbFinding.description).toContain('$75 USD');
  });

  it('does NOT flag resources with recent activity within the dormancy window', () => {
    const assets: Asset[] = [
      // Active database: last activity 20 days ago (well under 90-day threshold)
      {
        id: 'asset-db-active',
        tenantId: 'tenant-1',
        type: 'DATABASE',
        name: 'quarterly-analytics-db',
        environment: 'production',
        isPublic: false,
        isSensitiveData: true,
        criticality: 'HIGH',
        tags: [],
        metadata: {
          lastActivityDate: '2026-08-22T12:00:00Z', // 20 days ago (< 90 days)
        },
      },
    ];

    const relationships: Relationship[] = [];

    const result = detector.detectOrphans(assets, relationships, now);

    expect(result.findings.length).toBe(0);
    expect(result.summaries.length).toBe(0);
  });

  it('does NOT flag resources with active operational relationships in the security graph', () => {
    const assets: Asset[] = [
      {
        id: 'asset-svc-order',
        tenantId: 'tenant-1',
        type: 'SERVICE',
        name: 'order-service',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        tags: [],
        metadata: {},
      },
      {
        id: 'asset-db-active-rel',
        tenantId: 'tenant-1',
        type: 'DATABASE',
        name: 'order-database',
        environment: 'production',
        isPublic: false,
        isSensitiveData: true,
        criticality: 'HIGH',
        tags: [],
        metadata: {},
      },
    ];

    const relationships: Relationship[] = [
      {
        id: 'rel-1',
        tenantId: 'tenant-1',
        sourceAssetId: 'asset-svc-order',
        targetAssetId: 'asset-db-active-rel',
        type: 'READS_FROM',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      },
    ];

    const result = detector.detectOrphans(assets, relationships, now);

    // Because asset-db-active-rel has an active operational edge, it is suppressed
    expect(result.findings.length).toBe(0);
    expect(result.summaries.length).toBe(0);
  });
});
