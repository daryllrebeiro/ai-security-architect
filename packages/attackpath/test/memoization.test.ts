import { describe, it, expect } from 'vitest';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { AttackPathEngine } from '../src/attack-path-engine.js';
import type { Asset, Relationship } from '@ai-security-architect/core';

describe('Milestone 2.1: Graph Traversal Reachability Memoization', () => {
  it('memoizes reachability and prunes disconnected targets during path analysis', () => {
    const graph = new SecurityGraphEngine('test-tenant');

    const internet: Asset = {
      id: 'internet',
      tenantId: 'test-tenant',
      name: 'Public Internet',
      type: 'INTERNET',
      criticality: 'LOW',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      metadata: {},
      tags: [],
    };

    const reachableDb: Asset = {
      id: 'db-reachable',
      tenantId: 'test-tenant',
      name: 'Reachable Database',
      type: 'DATABASE',
      criticality: 'CRITICAL',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      metadata: {},
      tags: [],
    };

    const disconnectedDb: Asset = {
      id: 'db-isolated',
      tenantId: 'test-tenant',
      name: 'Airgapped Database',
      type: 'DATABASE',
      criticality: 'CRITICAL',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      metadata: {},
      tags: [],
    };

    graph.addAsset(internet);
    graph.addAsset(reachableDb);
    graph.addAsset(disconnectedDb);

    const rel: Relationship = {
      id: 'rel-1',
      tenantId: 'test-tenant',
      sourceAssetId: 'internet',
      targetAssetId: 'db-reachable',
      type: 'EXPOSES_HTTP',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    };
    graph.addRelationship(rel);

    const engine = new AttackPathEngine();
    const paths = engine.analyzePaths(graph, { memoizeReachability: true });

    expect(paths).toHaveLength(1);
    expect(paths[0].entryAssetId).toBe('internet');
    expect(paths[0].targetAssetId).toBe('db-reachable');

    const stats = engine.getMemoizationStats();
    expect(stats.prunedPairs).toBe(1); // db-isolated pruned without full DFS
    expect(stats.cacheMisses).toBe(2);

    // Subsequent query should hit cache
    const reachable = engine.isReachable(graph, 'internet', 'db-reachable');
    expect(reachable).toBe(true);
    expect(engine.getMemoizationStats().cacheHits).toBe(1);
  });
});
