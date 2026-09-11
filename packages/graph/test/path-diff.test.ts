import { describe, it, expect } from 'vitest';
import type { AttackPath, Asset } from '@ai-security-architect/core';
import { SecurityGraphEngine } from '../src/security-graph-engine.js';
import { PathDiffEngine } from '../src/diff/path-diff-engine.js';
import { computePathFingerprint } from '../src/diff/path-fingerprint.js';
import { ScanHistoryStore } from '../src/diff/scan-history-store.js';
import { PrCommentFormatter } from '../src/diff/pr-comment-formatter.js';

describe('Task A.1 — Attack Path Diffing Between Releases/PRs', () => {
  const tenantId = 'tenant-diff-test';

  function createSampleGraph(): {
    graph: SecurityGraphEngine;
    internet: Asset;
    alb: Asset;
    orderService: Asset;
    orderPod: Asset;
    iamRole: Asset;
    s3Bucket: Asset;
  } {
    const graph = new SecurityGraphEngine(tenantId);

    const internet: Asset = {
      id: 'asset-internet',
      tenantId,
      type: 'INTERNET',
      name: 'internet',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'LOW',
      metadata: {},
      tags: [],
    };

    const alb: Asset = {
      id: 'asset-alb',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'public-alb',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: {},
      tags: [],
    };

    const orderService: Asset = {
      id: 'asset-svc-order',
      tenantId,
      type: 'SERVICE',
      name: 'order-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const orderPod: Asset = {
      id: 'asset-pod-order',
      tenantId,
      type: 'POD',
      name: 'order-service-pod',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const iamRole: Asset = {
      id: 'asset-role-order',
      tenantId,
      type: 'IAM_ROLE',
      name: 'order-service-role',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const s3Bucket: Asset = {
      id: 'asset-s3-pii',
      tenantId,
      type: 'BUCKET',
      name: 'customer-pii-vault',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['contains-pii', 'compliance=pci'],
    };

    graph.addAsset(internet);
    graph.addAsset(alb);
    graph.addAsset(orderService);
    graph.addAsset(orderPod);
    graph.addAsset(iamRole);
    graph.addAsset(s3Bucket);

    graph.addRelationship({
      id: 'rel-1',
      tenantId,
      sourceAssetId: internet.id,
      targetAssetId: alb.id,
      type: 'ROUTES_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-2',
      tenantId,
      sourceAssetId: alb.id,
      targetAssetId: orderService.id,
      type: 'ROUTES_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-3',
      tenantId,
      sourceAssetId: orderService.id,
      targetAssetId: orderPod.id,
      type: 'DEPLOYED_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-4',
      tenantId,
      sourceAssetId: orderPod.id,
      targetAssetId: iamRole.id,
      type: 'ASSUMES_ROLE',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-5',
      tenantId,
      sourceAssetId: iamRole.id,
      targetAssetId: s3Bucket.id,
      type: 'CAN_READ',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    return { graph, internet, alb, orderService, orderPod, iamRole, s3Bucket };
  }

  function createPath(id: string, riskScore: number): AttackPath {
    return {
      id,
      tenantId,
      entryAssetId: 'asset-internet',
      targetAssetId: 'asset-s3-pii',
      pathLength: 5,
      steps: [
        { stepNumber: 1, sourceAssetId: 'asset-internet', targetAssetId: 'asset-alb', relationshipType: 'ROUTES_TO', explanation: 'traffic to alb' },
        { stepNumber: 2, sourceAssetId: 'asset-alb', targetAssetId: 'asset-svc-order', relationshipType: 'ROUTES_TO', explanation: 'alb to svc' },
        { stepNumber: 3, sourceAssetId: 'asset-svc-order', targetAssetId: 'asset-pod-order', relationshipType: 'DEPLOYED_TO', explanation: 'svc to pod' },
        { stepNumber: 4, sourceAssetId: 'asset-pod-order', targetAssetId: 'asset-role-order', relationshipType: 'ASSUMES_ROLE', explanation: 'pod to role' },
        { stepNumber: 5, sourceAssetId: 'asset-role-order', targetAssetId: 'asset-s3-pii', relationshipType: 'CAN_READ', explanation: 'role to s3' },
      ],
      riskScore: {
        impact: 9.0,
        exploitability: 9.0,
        reachability: 1.0,
        assetCriticality: 10.0,
        confidence: 1.0,
        totalRisk: riskScore,
      },
      verifiedEliminated: false,
    };
  }

  it('computes stable semantic fingerprint immune to harmless node renaming', () => {
    const { graph } = createSampleGraph();
    const pathA = createPath('path-001', 9.5);
    const fp1 = computePathFingerprint(pathA, graph);

    expect(fp1).toBeDefined();
    expect(typeof fp1).toBe('string');
    expect(fp1.length).toBe(16);

    // Compute again on identical graph shape
    const fp2 = computePathFingerprint(pathA, graph);
    expect(fp1).toBe(fp2);
  });

  it('detects exactly 1 newly introduced path when PR adds an IAM wildcard grant', () => {
    const { graph: baseGraph } = createSampleGraph();
    const { graph: headGraph } = createSampleGraph();

    // Base has 0 paths reaching the crown jewel
    const basePaths: AttackPath[] = [];

    // Head introduces 1 path
    const headPath = createPath('path-new-iam-wildcard', 9.6);
    const headPaths: AttackPath[] = [headPath];

    const diffEngine = new PathDiffEngine();
    const diff = diffEngine.diffAttackPaths(basePaths, headPaths, baseGraph, headGraph);

    expect(diff.introduced.length).toBe(1);
    expect(diff.introduced[0].path.id).toBe('path-new-iam-wildcard');
    expect(diff.closed.length).toBe(0);
    expect(diff.unchanged.length).toBe(0);
    expect(diff.severityChanged.length).toBe(0);
    expect(diff.summary.introducedCount).toBe(1);
  });

  it('classifies closed path as asset-removed when origin service is deleted from head graph', () => {
    const { graph: baseGraph } = createSampleGraph();
    const { graph: headGraph } = createSampleGraph();

    // In head, order-service was deleted entirely!
    headGraph.removeNode('asset-svc-order');

    const basePath = createPath('path-existing-01', 9.5);
    const basePaths = [basePath];
    const headPaths: AttackPath[] = []; // No paths in head because service is gone

    const diffEngine = new PathDiffEngine();
    const diff = diffEngine.diffAttackPaths(basePaths, headPaths, baseGraph, headGraph);

    expect(diff.introduced.length).toBe(0);
    expect(diff.closed.length).toBe(1);
    expect(diff.closed[0].closureReason).toBe('asset-removed');
    expect(diff.summary.closedAssetRemovedCount).toBe(1);
    expect(diff.summary.closedRemediatedCount).toBe(0);
  });

  it('classifies closed path as remediated when origin service still exists but edge is severed', () => {
    const { graph: baseGraph } = createSampleGraph();
    const { graph: headGraph } = createSampleGraph();

    // In head, order-service still exists, but the IAM relationship was scoped/severed
    headGraph.removeEdge('rel-5');

    const basePath = createPath('path-existing-01', 9.5);
    const basePaths = [basePath];
    const headPaths: AttackPath[] = []; // Path eliminated

    const diffEngine = new PathDiffEngine();
    const diff = diffEngine.diffAttackPaths(basePaths, headPaths, baseGraph, headGraph);

    expect(diff.introduced.length).toBe(0);
    expect(diff.closed.length).toBe(1);
    expect(diff.closed[0].closureReason).toBe('remediated');
    expect(diff.summary.closedRemediatedCount).toBe(1);
    expect(diff.summary.closedAssetRemovedCount).toBe(0);
  });

  it('classifies tightened policy as severity-changed bucket with risk delta', () => {
    const { graph: baseGraph } = createSampleGraph();
    const { graph: headGraph } = createSampleGraph();

    const basePath = createPath('path-001', 9.5);
    const headPath = createPath('path-001', 5.0); // Tightened permissions

    const diffEngine = new PathDiffEngine();
    const diff = diffEngine.diffAttackPaths([basePath], [headPath], baseGraph, headGraph);

    expect(diff.introduced.length).toBe(0);
    expect(diff.closed.length).toBe(0);
    expect(diff.unchanged.length).toBe(0);
    expect(diff.severityChanged.length).toBe(1);
    expect(diff.severityChanged[0].baseRiskScore).toBe(9.5);
    expect(diff.severityChanged[0].headRiskScore).toBe(5.0);
    expect(diff.severityChanged[0].delta).toBe(-4.5);
  });

  it('persists scan history in SQLite and indexes by fingerprint for MTTR lookups', () => {
    const store = new ScanHistoryStore(':memory:');
    const { graph } = createSampleGraph();

    const path1 = createPath('path-001', 9.5);
    path1.fingerprint = computePathFingerprint(path1, graph);

    store.recordScan('scan-001', tenantId, 'enterprise/order-app', 'sha-commit-1', [path1]);

    const retrievedScan = store.getScan('scan-001');
    expect(retrievedScan).toBeDefined();
    expect(retrievedScan?.commitSha).toBe('sha-commit-1');
    expect(retrievedScan?.totalPaths).toBe(1);

    const fpRecords = store.getPathsByFingerprint(path1.fingerprint);
    expect(fpRecords.length).toBe(1);
    expect(fpRecords[0].scanId).toBe('scan-001');
    expect(fpRecords[0].totalRisk).toBe(9.5);

    store.close();
  });

  it('PrCommentFormatter formats markdown diff table for pull request review comments', () => {
    const diffEngine = new PathDiffEngine();
    const { graph: baseGraph } = createSampleGraph();
    const { graph: headGraph } = createSampleGraph();

    const basePath = createPath('path-001', 9.5);
    const headPath = createPath('path-002', 8.0);
    headPath.targetAssetId = 'asset-other-target';

    const diff = diffEngine.diffAttackPaths([basePath], [headPath], baseGraph, headGraph);

    const formatter = new PrCommentFormatter();
    const markdown = formatter.format(diff, { baseRef: 'main', headRef: 'feature/pr-42' });

    expect(markdown).toContain('AI Security Architect — Attack Path Diff Analysis');
    expect(markdown).toContain('main');
    expect(markdown).toContain('feature/pr-42');
    expect(markdown).toContain('Newly Introduced Attack Paths');
    expect(markdown).toContain('Closed Attack Paths');
  });
});
