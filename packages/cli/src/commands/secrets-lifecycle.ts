import { SecretLifecycleTracker } from '@ai-security-architect/discovery';
import { Asset } from '@ai-security-architect/core';

export async function executeSecretsLifecycle(options: {
  maxAgeDays?: number;
  sampleAssets?: Asset[];
}): Promise<void> {
  const tracker = new SecretLifecycleTracker({ maxAgeDays: options.maxAgeDays ?? 90 });
  const sampleAssets: Asset[] = options.sampleAssets || [
    {
      id: 'sec-db-master',
      tenantId: 'tenant-default',
      type: 'SECRET',
      name: 'production-database-master-password',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      tags: ['secret', 'credential'],
      metadata: {
        createdDate: '2026-01-01T00:00:00Z',
      },
    },
  ];

  const result = await tracker.evaluateSecrets(sampleAssets);
  console.log('\n=== Secrets Lifecycle & Credential Rotation Report ===');
  console.log(`Evaluated ${result.summaries.length} credential(s)`);
  for (const s of result.summaries) {
    console.log(`- [${s.isOverdue ? 'OVERDUE' : 'OK'}] ${s.name} (Age: ${s.ageDays}d, Last Rotated: ${s.daysSinceLastRotation}d ago)`);
  }
  if (result.findings.length > 0) {
    console.log(`\nRaised ${result.findings.length} rotation overdue finding(s):`);
    for (const f of result.findings) {
      console.log(`  * [${f.severity}] ${f.title}`);
    }
  }
}
