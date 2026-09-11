import { DueDiligenceEngine } from '@ai-security-architect/due-diligence';
import { Asset, Finding } from '@ai-security-architect/core';

export async function executeDueDiligence(options: {
  targetName?: string;
  anonymize?: boolean;
}): Promise<void> {
  const engine = new DueDiligenceEngine();
  const targetName = options.targetName || 'AcquisitionTargetCorp';
  const anonymize = Boolean(options.anonymize);

  const sampleAssets: Asset[] = [
    {
      id: 'asset-db-target',
      tenantId: 'tenant-target',
      type: 'DATABASE',
      name: 'target-customer-db',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'HIGH',
      tags: ['pii'],
      metadata: {},
    },
  ];

  const sampleFindings: Finding[] = [];

  const report = engine.generateAssessment(sampleAssets, sampleFindings, 1, {
    targetCompanyName: targetName,
    anonymize,
  });

  console.log(report.executiveSummary);
}
