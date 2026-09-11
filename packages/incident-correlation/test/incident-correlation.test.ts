import { describe, it, expect } from 'vitest';
import { Asset, Relationship } from '@ai-security-architect/core';
import {
  IncidentCorrelator,
  InboundSecurityAlert,
  LIVE_INCIDENT_CONTEXT_LABEL,
} from '../src/index.js';

describe('Task H.3: Live Incident Response Correlation (SIEM/EDR Bridge)', () => {
  const correlator = new IncidentCorrelator({ maxTraversalHops: 5 });

  const assets: Asset[] = [
    {
      id: 'asset-internet',
      tenantId: 'tenant-1',
      type: 'INTERNET',
      name: 'public-internet',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'LOW',
      tags: [],
      metadata: {},
    },
    {
      id: 'asset-host-compromised',
      tenantId: 'tenant-1',
      type: 'CONTAINER',
      name: 'order-processing-worker',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      tags: [],
      metadata: {
        instanceId: 'i-0abcdef1234567890',
        arn: 'arn:aws:ecs:us-east-1:123456789012:task/order-worker',
      },
    },
    {
      id: 'asset-role-db-accessor',
      tenantId: 'tenant-1',
      type: 'IAM_ROLE',
      name: 'order-worker-iam-role',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      tags: [],
      metadata: {},
    },
    {
      id: 'asset-db-customer-pii',
      tenantId: 'tenant-1',
      type: 'DATABASE',
      name: 'customer-pii-database',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      tags: ['pii'],
      metadata: {},
    },
    // Ambiguous assets for ambiguity test
    {
      id: 'asset-api-gateway-1',
      tenantId: 'tenant-1',
      type: 'API_CONTROLLER',
      name: 'shared-api-gateway',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      tags: [],
      metadata: {},
    },
    {
      id: 'asset-api-gateway-2',
      tenantId: 'tenant-1',
      type: 'API_CONTROLLER',
      name: 'shared-api-gateway',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      tags: [],
      metadata: {},
    },
  ];

  const relationships: Relationship[] = [
    {
      id: 'rel-1',
      tenantId: 'tenant-1',
      sourceAssetId: 'asset-internet',
      targetAssetId: 'asset-host-compromised',
      type: 'EXPOSES_HTTP',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    },
    {
      id: 'rel-2',
      tenantId: 'tenant-1',
      sourceAssetId: 'asset-host-compromised',
      targetAssetId: 'asset-role-db-accessor',
      type: 'ASSUMES_ROLE',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    },
    {
      id: 'rel-3',
      tenantId: 'tenant-1',
      sourceAssetId: 'asset-role-db-accessor',
      targetAssetId: 'asset-db-customer-pii',
      type: 'CAN_READ',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    },
  ];

  it('resolves an exact ARN/instanceId alert, calculates blast radius, and recommends choke points', () => {
    const alert: InboundSecurityAlert = {
      alertId: 'alert-crowdstrike-99881',
      sourceSystem: 'CrowdStrike Falcon',
      severity: 'CRITICAL',
      assetIdentifier: 'i-0abcdef1234567890',
      timestamp: '2026-09-11T19:00:00Z',
      description: 'Reverse shell detected on container order-processing-worker',
    };

    const result = correlator.processAlert(alert, assets, relationships);

    expect(result.resolved).toBe(true);
    if (!result.resolved) return;

    expect(result.matchedAsset.id).toBe('asset-host-compromised');
    expect(result.incidentContext.alertId).toBe('alert-crowdstrike-99881');
    expect(result.incidentContext.sourceSystem).toBe('CrowdStrike Falcon');
    expect(result.incidentContext.contextLabel).toBe(LIVE_INCIDENT_CONTEXT_LABEL);

    // Blast radius includes IAM role and customer database
    const blastIds = result.incidentContext.blastRadiusNodes.map((n) => n.assetId);
    expect(blastIds).toContain('asset-role-db-accessor');
    expect(blastIds).toContain('asset-db-customer-pii');

    // Critical asset at risk flagged
    expect(result.incidentContext.criticalAssetsAtRisk.length).toBeGreaterThan(0);
    expect(result.incidentContext.criticalAssetsAtRisk[0]).toContain('customer-pii-database');

    // Choke point proposed
    expect(result.incidentContext.recommendedChokePoints.length).toBe(1);
    expect(result.incidentContext.recommendedChokePoints[0].action).toContain('Sever egress connectivity');
  });

  it('rejects ambiguous identifier when multiple assets share the same identifier', () => {
    const alert: InboundSecurityAlert = {
      alertId: 'alert-guardduty-4422',
      sourceSystem: 'AWS GuardDuty',
      severity: 'HIGH',
      assetIdentifier: 'shared-api-gateway', // matches both asset-api-gateway-1 and asset-api-gateway-2
      timestamp: '2026-09-11T19:00:00Z',
      description: 'Suspicious credential exfiltration activity',
    };

    const result = correlator.processAlert(alert, assets, relationships);

    expect(result.resolved).toBe(false);
    if (result.resolved) return;

    expect(result.status).toBe('REJECTED_AMBIGUOUS');
    expect(result.reason).toContain('Ambiguous match');
    expect(result.reason).toContain('Refusing to execute incident response on ambiguous target');
  });

  it('returns explicit NOT_FOUND for unresolvable identifier without fuzzy guessing', () => {
    const alert: InboundSecurityAlert = {
      alertId: 'alert-splunk-1122',
      sourceSystem: 'Splunk SIEM',
      severity: 'LOW',
      assetIdentifier: 'i-nonexistent-99999999999',
      timestamp: '2026-09-11T19:00:00Z',
      description: 'Port scan from unknown host',
    };

    const result = correlator.processAlert(alert, assets, relationships);

    expect(result.resolved).toBe(false);
    if (result.resolved) return;

    expect(result.status).toBe('NOT_FOUND');
    expect(result.reason).toContain('Could not confidently resolve asset identifier');
  });
});
