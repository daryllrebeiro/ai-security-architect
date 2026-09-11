import { describe, it, expect } from 'vitest';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import {
  MinCutOptimizer,
  FlowNetwork,
  type RemediationCostStrategy,
} from '../src/index.js';
import type { AttackPath, Asset, Relationship } from '@ai-security-architect/core';

describe('Task 2.1: Dinic Residual Flow Network Min-Cut', () => {
  it('computes max flow and min cut correctly on textbook flow network', () => {
    // S -> A (cap 10), S -> C (cap 10)
    // A -> B (cap 4), A -> C (cap 2), A -> D (cap 8)
    // C -> D (cap 9)
    // B -> T (cap 10)
    // D -> T (cap 10)
    const net = new FlowNetwork();
    net.addEdge('S', 'A', 10);
    net.addEdge('S', 'C', 10);
    net.addEdge('A', 'B', 4);
    net.addEdge('A', 'C', 2);
    net.addEdge('A', 'D', 8);
    net.addEdge('C', 'D', 9);
    net.addEdge('B', 'T', 10);
    net.addEdge('D', 'T', 10);

    const maxFlow = net.computeMaxFlow('S', 'T');
    expect(maxFlow).toBe(14);

    const minCut = net.findMinCut('S');
    const cutCapacity = minCut.reduce((sum, e) => sum + e.capacity, 0);
    expect(cutCapacity).toBe(14);
  });

  it('severs dual-ingress attack paths that defeat greedy single-path heuristics', () => {
    const graph = new SecurityGraphEngine('tenant-cut');

    // Topology:
    // Ingress 1: public-alb -> payment-api -> crown-jewel-db
    // Ingress 2: bastion-host -> admin-api -> crown-jewel-db
    const assets: Asset[] = [
      { id: 'public-alb', tenantId: 'tenant-cut', type: 'LOAD_BALANCER', name: 'Public ALB', environment: 'production', isPublic: true, isSensitiveData: false, criticality: 'HIGH', metadata: {}, tags: [] },
      { id: 'payment-api', tenantId: 'tenant-cut', type: 'SERVICE', name: 'Payment API', environment: 'production', isPublic: false, isSensitiveData: false, criticality: 'HIGH', metadata: {}, tags: [] },
      { id: 'bastion-host', tenantId: 'tenant-cut', type: 'SERVICE', name: 'Bastion Host', environment: 'production', isPublic: true, isSensitiveData: false, criticality: 'HIGH', metadata: {}, tags: [] },
      { id: 'admin-api', tenantId: 'tenant-cut', type: 'SERVICE', name: 'Admin API', environment: 'production', isPublic: false, isSensitiveData: false, criticality: 'HIGH', metadata: {}, tags: [] },
      { id: 'crown-jewel-db', tenantId: 'tenant-cut', type: 'DATABASE', name: 'Crown Jewel DB', environment: 'production', isPublic: false, isSensitiveData: true, criticality: 'CRITICAL', metadata: {}, tags: [] },
    ];

    for (const a of assets) graph.addAsset(a);

    const rels: Relationship[] = [
      { id: 'r1', tenantId: 'tenant-cut', sourceAssetId: 'public-alb', targetAssetId: 'payment-api', type: 'ROUTES_TO', nature: 'DECLARED', confidence: 1.0, metadata: {} },
      { id: 'r2', tenantId: 'tenant-cut', sourceAssetId: 'payment-api', targetAssetId: 'crown-jewel-db', type: 'CAN_READ', nature: 'DECLARED', confidence: 1.0, metadata: {} },
      { id: 'r3', tenantId: 'tenant-cut', sourceAssetId: 'bastion-host', targetAssetId: 'admin-api', type: 'ROUTES_TO', nature: 'DECLARED', confidence: 1.0, metadata: {} },
      { id: 'r4', tenantId: 'tenant-cut', sourceAssetId: 'admin-api', targetAssetId: 'crown-jewel-db', type: 'CAN_READ', nature: 'DECLARED', confidence: 1.0, metadata: {} },
    ];

    for (const r of rels) graph.addRelationship(r);

    const path1: AttackPath = {
      id: 'path-001',
      tenantId: 'tenant-cut',
      entryAssetId: 'public-alb',
      targetAssetId: 'crown-jewel-db',
      pathLength: 2,
      steps: [
        { stepNumber: 1, sourceAssetId: 'public-alb', targetAssetId: 'payment-api', relationshipType: 'ROUTES_TO', explanation: 'ALB routes to payment API' },
        { stepNumber: 2, sourceAssetId: 'payment-api', targetAssetId: 'crown-jewel-db', relationshipType: 'CAN_READ', explanation: 'Payment API reads DB' },
      ],
      riskScore: { impact: 9, exploitability: 9, reachability: 1, assetCriticality: 10, confidence: 1, totalRisk: 9.5 },
      verifiedEliminated: false,
    };

    const path2: AttackPath = {
      id: 'path-002',
      tenantId: 'tenant-cut',
      entryAssetId: 'bastion-host',
      targetAssetId: 'crown-jewel-db',
      pathLength: 2,
      steps: [
        { stepNumber: 1, sourceAssetId: 'bastion-host', targetAssetId: 'admin-api', relationshipType: 'ROUTES_TO', explanation: 'Bastion routes to admin API' },
        { stepNumber: 2, sourceAssetId: 'admin-api', targetAssetId: 'crown-jewel-db', relationshipType: 'CAN_READ', explanation: 'Admin API reads DB' },
      ],
      riskScore: { impact: 9, exploitability: 9, reachability: 1, assetCriticality: 10, confidence: 1, totalRisk: 9.5 },
      verifiedEliminated: false,
    };

    const optimizer = new MinCutOptimizer();

    // 1. Single-candidate greedy behavior: picking 1 candidate leaves 1 path open
    const singleCandidates = optimizer.findOptimalChokePoints(graph, [path1, path2]);
    expect(singleCandidates.length).toBeGreaterThan(0);
    // Any single edge only eliminates 1 of the 2 paths (50% risk reduction)
    expect(singleCandidates[0].riskReductionPercentage).toBe(50);

    // 2. Dinic Global Min-Cut: finds the multi-edge cut-set that completely severs ALL paths (100%)
    const globalCut = optimizer.findGlobalMinCut(graph, [path1, path2]);
    expect(globalCut.fullySevered).toBe(true);
    expect(globalCut.pathsEliminatedCount).toBe(2);
    expect(globalCut.chokePoints.length).toBeGreaterThanOrEqual(2);

    // Verify each path now has recommendedCutSet attached
    expect(path1.recommendedCutSet).toBeDefined();
    expect(path1.recommendedCutSet).toHaveLength(globalCut.chokePoints.length);
  });

  it('respects pluggable RemediationCostStrategy to minimize blast radius', () => {
    const graph = new SecurityGraphEngine('tenant-cost');

    // S -> A -> T
    // S -> A has HIGH blast radius (e.g. severing internet ingress)
    // A -> T has LOW blast radius (e.g. scoping DB IAM role)
    const assets: Asset[] = [
      { id: 'S', tenantId: 'tenant-cost', type: 'LOAD_BALANCER', name: 'Gateway', environment: 'prod', isPublic: true, isSensitiveData: false, criticality: 'HIGH', metadata: {}, tags: [] },
      { id: 'A', tenantId: 'tenant-cost', type: 'SERVICE', name: 'Service', environment: 'prod', isPublic: false, isSensitiveData: false, criticality: 'HIGH', metadata: {}, tags: [] },
      { id: 'T', tenantId: 'tenant-cost', type: 'DATABASE', name: 'Database', environment: 'prod', isPublic: false, isSensitiveData: true, criticality: 'CRITICAL', metadata: {}, tags: [] },
    ];
    for (const a of assets) graph.addAsset(a);

    graph.addRelationship({ id: 'r-sa', tenantId: 'tenant-cost', sourceAssetId: 'S', targetAssetId: 'A', type: 'EXPOSES_HTTP', nature: 'DECLARED', confidence: 1, metadata: {} });
    graph.addRelationship({ id: 'r-at', tenantId: 'tenant-cost', sourceAssetId: 'A', targetAssetId: 'T', type: 'CAN_READ', nature: 'DECLARED', confidence: 1, metadata: {} });

    const path: AttackPath = {
      id: 'path-cost',
      tenantId: 'tenant-cost',
      entryAssetId: 'S',
      targetAssetId: 'T',
      pathLength: 2,
      steps: [
        { stepNumber: 1, sourceAssetId: 'S', targetAssetId: 'A', relationshipType: 'EXPOSES_HTTP', explanation: 'HTTP' },
        { stepNumber: 2, sourceAssetId: 'A', targetAssetId: 'T', relationshipType: 'CAN_READ', explanation: 'Read' },
      ],
      riskScore: { impact: 9, exploitability: 9, reachability: 1, assetCriticality: 10, confidence: 1, totalRisk: 9.5 },
      verifiedEliminated: false,
    };

    const optimizer = new MinCutOptimizer();

    // Default cost strategy penalizes HIGH blast radius (EXPOSES_HTTP = 25 * 2 = 50 vs CAN_READ = 1 * 1 = 1)
    const globalCut = optimizer.findGlobalMinCut(graph, [path]);
    expect(globalCut.chokePoints).toHaveLength(1);
    expect(globalCut.chokePoints[0].edgeId).toBe('r-at');
    expect(globalCut.chokePoints[0].blastRadius).toBe('LOW');

    // Inverted custom cost strategy: force severing at ingress
    const invertedStrategy: RemediationCostStrategy = {
      getEdgeCost(params) {
        return params.relationshipType === 'EXPOSES_HTTP' ? 1 : 100;
      },
    };

    const invertedCut = optimizer.findGlobalMinCut(graph, [path], invertedStrategy);
    expect(invertedCut.chokePoints).toHaveLength(1);
    expect(invertedCut.chokePoints[0].edgeId).toBe('r-sa');
  });
});
