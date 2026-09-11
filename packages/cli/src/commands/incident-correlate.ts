import { IncidentCorrelator, InboundSecurityAlert } from '@ai-security-architect/incident-correlation';
import { Asset, Relationship } from '@ai-security-architect/core';

export async function executeIncidentCorrelate(options: {
  alertIdentifier?: string;
}): Promise<void> {
  const correlator = new IncidentCorrelator();
  const alertId = options.alertIdentifier || 'i-0abcdef1234567890';

  const alert: InboundSecurityAlert = {
    alertId: 'alert-cli-trigger-001',
    sourceSystem: 'CLI Security Incident Bridge',
    severity: 'CRITICAL',
    assetIdentifier: alertId,
    timestamp: new Date().toISOString(),
    description: 'Triggered from CLI correlation runner',
  };

  const sampleAssets: Asset[] = [
    {
      id: 'asset-host-ec2',
      tenantId: 'tenant-default',
      type: 'CONTAINER',
      name: 'worker-node-01',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      tags: [],
      metadata: { instanceId: 'i-0abcdef1234567890' },
    },
    {
      id: 'asset-db-pii',
      tenantId: 'tenant-default',
      type: 'DATABASE',
      name: 'customer-records',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      tags: ['pii'],
      metadata: {},
    },
  ];

  const sampleRelationships: Relationship[] = [
    {
      id: 'rel-1',
      tenantId: 'tenant-default',
      sourceAssetId: 'asset-host-ec2',
      targetAssetId: 'asset-db-pii',
      type: 'CAN_READ',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    },
  ];

  const res = correlator.processAlert(alert, sampleAssets, sampleRelationships);
  console.log('\n=== Live Incident Response Correlation ===');
  if (!res.resolved) {
    console.log(`Resolution Failed: ${res.reason} (Status: ${res.status})`);
  } else {
    console.log(`Resolved Target: ${res.matchedAsset.name} (${res.matchedAsset.id})`);
    console.log(`Blast Radius Assets Reachable: ${res.incidentContext.blastRadiusNodes.length}`);
    console.log(`Critical Assets At Risk: ${res.incidentContext.criticalAssetsAtRisk.join(', ')}`);
    console.log(`Recommended Choke Points: ${res.incidentContext.recommendedChokePoints.length}`);
  }
}
