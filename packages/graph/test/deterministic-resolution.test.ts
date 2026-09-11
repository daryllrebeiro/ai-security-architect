import { describe, it, expect } from 'vitest';
import { DeterministicEntityResolver } from '../src/entity-resolver.js';
import type { Asset } from '@ai-security-architect/core';

describe('DeterministicEntityResolver', () => {
  it('strictly isolates services and pods by namespace without cross-namespace links', () => {
    const resolver = new DeterministicEntityResolver();

    const assets: Asset[] = [
      // Production namespace
      {
        id: 'svc-prod-payments',
        tenantId: 't1',
        type: 'KUBERNETES_SERVICE',
        name: 'payments-svc',
        environment: 'prod',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: { namespace: 'prod', selector: { app: 'payments' } },
        tags: [],
      },
      {
        id: 'pod-prod-payments',
        tenantId: 't1',
        type: 'POD',
        name: 'payments-pod-prod',
        environment: 'prod',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: { namespace: 'prod', labels: { app: 'payments' }, serviceAccountName: 'payments-sa' },
        tags: [],
      },
      // Staging namespace (same names!)
      {
        id: 'svc-staging-payments',
        tenantId: 't1',
        type: 'KUBERNETES_SERVICE',
        name: 'payments-svc',
        environment: 'staging',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'LOW',
        metadata: { namespace: 'staging', selector: { app: 'payments' } },
        tags: [],
      },
      {
        id: 'pod-staging-payments',
        tenantId: 't1',
        type: 'POD',
        name: 'payments-pod-staging',
        environment: 'staging',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'LOW',
        metadata: { namespace: 'staging', labels: { app: 'payments' }, serviceAccountName: 'payments-sa' },
        tags: [],
      },
    ];

    const graph = resolver.resolve({
      tenantId: 't1',
      assets,
      relationships: [],
      findings: [],
      evidence: [],
    });

    // Check edges
    const prodEdges = graph.getOutgoingEdges('svc-prod-payments');
    expect(prodEdges.length).toBe(1);
    expect(prodEdges[0].targetAssetId).toBe('pod-prod-payments');
    expect(prodEdges[0].relationship.nature).toBe('DECLARED');
    expect(prodEdges[0].relationship.confidence).toBe(1.0);

    const stagingEdges = graph.getOutgoingEdges('svc-staging-payments');
    expect(stagingEdges.length).toBe(1);
    expect(stagingEdges[0].targetAssetId).toBe('pod-staging-payments');

    // Cross-namespace link must NOT exist!
    const crossEdges = prodEdges.filter((e) => e.targetAssetId === 'pod-staging-payments');
    expect(crossEdges.length).toBe(0);
  });

  it('does not link pods when selector labels do not match', () => {
    const resolver = new DeterministicEntityResolver();

    const assets: Asset[] = [
      {
        id: 'svc-auth',
        tenantId: 't1',
        type: 'KUBERNETES_SERVICE',
        name: 'auth-svc',
        environment: 'default',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: { namespace: 'default', selector: { app: 'auth', tier: 'backend' } },
        tags: [],
      },
      {
        id: 'pod-other',
        tenantId: 't1',
        type: 'POD',
        name: 'other-pod',
        environment: 'default',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'LOW',
        metadata: { namespace: 'default', labels: { app: 'frontend' } },
        tags: [],
      },
    ];

    const graph = resolver.resolve({
      tenantId: 't1',
      assets,
      relationships: [],
      findings: [],
      evidence: [],
    });

    expect(graph.getOutgoingEdges('svc-auth').length).toBe(0);
  });

  it('emits UNRESOLVED_REFERENCE finding when pod references missing service account instead of fallback', () => {
    const resolver = new DeterministicEntityResolver();

    const assets: Asset[] = [
      {
        id: 'pod-orphaned',
        tenantId: 't1',
        type: 'POD',
        name: 'orphaned-pod',
        environment: 'prod',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: { namespace: 'prod', serviceAccountName: 'non-existent-sa' },
        tags: [],
      },
      {
        id: 'sa-unrelated',
        tenantId: 't1',
        type: 'KUBERNETES_SERVICE_ACCOUNT',
        name: 'unrelated-sa',
        environment: 'staging',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'LOW',
        metadata: { namespace: 'staging' },
        tags: [],
      },
    ];

    const graph = resolver.resolve({
      tenantId: 't1',
      assets,
      relationships: [],
      findings: [],
      evidence: [],
    });

    // Must NOT link to unrelated-sa (no greedy fallback!)
    const saEdges = graph.getOutgoingEdges('pod-orphaned');
    expect(saEdges.length).toBe(0);

    // Must emit an UNRESOLVED_REFERENCE finding on pod-orphaned
    const podFindings = graph.getFindingsForNode('pod-orphaned');
    expect(podFindings.length).toBe(1);
    expect(podFindings[0].category).toBe('UNRESOLVED_REFERENCE');
    expect(podFindings[0].ruleId).toBe('K8S-UNRESOLVED-SERVICE-ACCOUNT');
  });

  it('handles 1,000 services x 1,000 pods efficiently without cartesian performance cliff', () => {
    const resolver = new DeterministicEntityResolver();
    const assets: Asset[] = [];

    const COUNT = 1000;
    for (let i = 0; i < COUNT; i++) {
      const ns = `ns-${i % 10}`;
      assets.push({
        id: `svc-${i}`,
        tenantId: 't1',
        type: 'KUBERNETES_SERVICE',
        name: `svc-${i}`,
        environment: ns,
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: { namespace: ns, selector: { app: `app-${i}` } },
        tags: [],
      });
      assets.push({
        id: `pod-${i}`,
        tenantId: 't1',
        type: 'POD',
        name: `pod-${i}`,
        environment: ns,
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: { namespace: ns, labels: { app: `app-${i}` } },
        tags: [],
      });
    }

    const start = Date.now();
    const graph = resolver.resolve({
      tenantId: 't1',
      assets,
      relationships: [],
      findings: [],
      evidence: [],
    });
    const elapsed = Date.now() - start;

    // Sub-linear / indexed matching should comfortably complete in < 500ms even under test runner load
    expect(elapsed).toBeLessThan(500);
    // Each service should match exactly 1 pod
    expect(graph.getAllEdges().length).toBe(COUNT);
  });
});
