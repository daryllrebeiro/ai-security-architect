import { InsuranceReportExporter } from '@ai-security-architect/reporting';
import { Asset, Relationship, Finding } from '@ai-security-architect/core';

export async function executeInsuranceExport(options: {
  tenantId?: string;
}): Promise<void> {
  const exporter = new InsuranceReportExporter();
  const tenantId = options.tenantId || 'tenant-default';

  const sampleAssets: Asset[] = [
    {
      id: 'asset-db-main',
      tenantId,
      type: 'DATABASE',
      name: 'production-rds',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      tags: ['pii'],
      metadata: {},
    },
  ];

  const sampleRels: Relationship[] = [];
  const sampleFindings: Finding[] = [];

  const summary = exporter.generateReport(tenantId, sampleAssets, sampleRels, sampleFindings);
  const markdown = exporter.exportToMarkdown(summary);
  console.log(markdown);
}
