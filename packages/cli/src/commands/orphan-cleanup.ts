import { OrphanDetector } from '@ai-security-architect/remediation';
import { Asset, Relationship } from '@ai-security-architect/core';

export async function executeOrphanCleanup(options: {
  dormancyDays?: number;
}): Promise<void> {
  const detector = new OrphanDetector({ dormancyWindowDays: options.dormancyDays ?? 90 });

  const sampleAssets: Asset[] = [
    {
      id: 'asset-alb-dormant',
      tenantId: 'tenant-default',
      type: 'LOAD_BALANCER',
      name: 'deprecated-v1-ingress',
      environment: 'staging',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'LOW',
      tags: [],
      metadata: { lastActivityDate: '2026-01-01T00:00:00Z' },
    },
  ];

  const sampleRels: Relationship[] = [];
  const res = detector.detectOrphans(sampleAssets, sampleRels);

  console.log('\n=== Orphaned Resource & Stale Access Cleanup ===');
  console.log(`Identified ${res.summaries.length} dormant resource(s):`);
  for (const s of res.summaries) {
    console.log(`- [${s.type}] ${s.name} (${s.daysDormant} days dormant, est. waste: $${s.estimatedMonthlyWasteUsd}/mo)`);
    console.log(`  * ${s.observationDisclaimer}`);
  }
}
