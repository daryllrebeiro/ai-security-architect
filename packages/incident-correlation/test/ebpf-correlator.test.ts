import { describe, it, expect } from 'vitest';
import {
  EbpfTrajectoryCorrelator,
  type EbpfEvent,
  EBPF_DISCLOSURE_LABEL,
} from '../src/ebpf-correlator.js';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { AttackPath, Asset, Relationship } from '@ai-security-architect/core';

describe('Milestone 3.3: eBPF Runtime Trajectory Correlator', () => {
  const graph = new SecurityGraphEngine('test-tenant');

  const alb: Asset = {
    id: 'alb-ingress',
    tenantId: 'test-tenant',
    name: 'alb-ingress',
    type: 'LOAD_BALANCER',
    criticality: 'MEDIUM',
    environment: 'production',
    isPublic: true,
    isSensitiveData: false,
    metadata: {},
    tags: [],
  };

  const paymentPod: Asset = {
    id: 'payment-pod',
    tenantId: 'test-tenant',
    name: 'payment-pod',
    type: 'POD',
    criticality: 'HIGH',
    environment: 'production',
    isPublic: false,
    isSensitiveData: false,
    metadata: {},
    tags: [],
  };

  const dbCustomer: Asset = {
    id: 'db-customer-pii',
    tenantId: 'test-tenant',
    name: 'db-customer-pii',
    type: 'DATABASE',
    criticality: 'CRITICAL',
    environment: 'production',
    isPublic: false,
    isSensitiveData: true,
    metadata: {},
    tags: [],
  };

  graph.addAsset(alb);
  graph.addAsset(paymentPod);
  graph.addAsset(dbCustomer);

  const rel1: Relationship = {
    id: 'rel-1',
    tenantId: 'test-tenant',
    sourceAssetId: 'alb-ingress',
    targetAssetId: 'payment-pod',
    type: 'ROUTES_TO',
    nature: 'DECLARED',
    confidence: 1.0,
    metadata: {},
  };

  const rel2: Relationship = {
    id: 'rel-2',
    tenantId: 'test-tenant',
    sourceAssetId: 'payment-pod',
    targetAssetId: 'db-customer-pii',
    type: 'CAN_READ',
    nature: 'DECLARED',
    confidence: 1.0,
    metadata: {},
  };

  graph.addRelationship(rel1);
  graph.addRelationship(rel2);

  const attackPath: AttackPath = {
    id: 'path-ebpf-01',
    tenantId: 'test-tenant',
    entryAssetId: 'alb-ingress',
    targetAssetId: 'db-customer-pii',
    pathLength: 2,
    steps: [
      {
        stepNumber: 1,
        sourceAssetId: 'alb-ingress',
        targetAssetId: 'payment-pod',
        relationshipType: 'ROUTES_TO',
        explanation: 'ALB forwards traffic to payment-pod',
      },
      {
        stepNumber: 2,
        sourceAssetId: 'payment-pod',
        targetAssetId: 'db-customer-pii',
        relationshipType: 'CAN_READ',
        explanation: 'Payment pod reads customer PII',
      },
    ],
    riskScore: {
      totalRisk: 9.5,
      exploitability: 9.0,
      impact: 9.5,
      reachability: 1.0,
      assetCriticality: 10.0,
      confidence: 1.0,
    },
    verifiedEliminated: false,
  };

  it('detects active runtime exploitation from kernel socket and process events', () => {
    const correlator = new EbpfTrajectoryCorrelator();

    const kernelTelemetry: EbpfEvent[] = [
      {
        eventId: 'evt-kernel-01',
        timestamp: '2026-09-11T20:15:00Z',
        eventType: 'PROCESS_EXEC',
        sourceWorkload: 'payment-pod',
        processName: 'bash',
        commandLine: '/bin/bash -c curl http://169.254.169.254/latest/meta-data/',
      },
      {
        eventId: 'evt-kernel-02',
        timestamp: '2026-09-11T20:15:05Z',
        eventType: 'SOCKET_CONNECT',
        sourceWorkload: 'payment-pod',
        destinationHost: 'db-customer-pii.internal',
        destinationPort: 5432,
      },
    ];

    const report = correlator.correlate(kernelTelemetry, [attackPath], graph);

    expect(report.totalEventsAnalyzed).toBe(2);
    expect(report.activeExploitationsCount).toBe(1);
    expect(report.label).toBe(EBPF_DISCLOSURE_LABEL);

    const correlated = report.correlatedPaths[0];
    expect(correlated.attackPathId).toBe('path-ebpf-01');
    expect(correlated.exploitStatus).toBe('ACTIVE_EXPLOIT');
    expect(correlated.confidenceScore).toBeGreaterThanOrEqual(0.85);
    expect(correlated.matchedHops).toHaveLength(2);
    expect(correlated.suggestedContainment).toContain('Tetragon SIGKILL / Cilium NetworkPolicy');
  });
});
