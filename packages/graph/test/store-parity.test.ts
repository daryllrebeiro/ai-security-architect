import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  SecurityGraphEngine,
  InMemoryGraphStore,
  SqliteGraphStore,
} from '../src/index.js';
import type { Asset, Relationship, Finding } from '@ai-security-architect/core';
import { createEvidence } from '@ai-security-architect/core';

describe('Graph Store Parity (InMemory vs SQLite)', () => {
  const tempFiles: string[] = [];

  afterEach(() => {
    for (const f of tempFiles) {
      try {
        if (fs.existsSync(f)) {
          fs.unlinkSync(f);
        }
      } catch {}
    }
    tempFiles.length = 0;
  });

  function getStores() {
    const memStore = new InMemoryGraphStore('parity-tenant');
    const dbPath = path.join(os.tmpdir(), `test-graph-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    tempFiles.push(dbPath);
    const sqliteStore = new SqliteGraphStore('parity-tenant', dbPath);
    return [
      { name: 'InMemoryGraphStore', store: memStore },
      { name: 'SqliteGraphStore', store: sqliteStore },
    ];
  }

  it.each(getStores())('$name adds and retrieves assets identically', ({ store }) => {
    const asset1: Asset = {
      id: 'asset-1',
      tenantId: 'parity-tenant',
      type: 'SERVICE',
      name: 'api-service',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: { port: 8080 },
      tags: ['web', 'backend'],
    };

    const node1 = store.addAsset(asset1);
    expect(node1.asset.id).toBe('asset-1');
    expect(node1.inDegree).toBe(0);
    expect(node1.outDegree).toBe(0);
    expect(node1.findings).toHaveLength(0);

    expect(store.hasNode('asset-1')).toBe(true);
    expect(store.hasNode('non-existent')).toBe(false);

    const retrieved = store.getNode('asset-1');
    expect(retrieved).toBeDefined();
    expect(retrieved?.asset.name).toBe('api-service');
    expect(retrieved?.asset.isPublic).toBe(true);

    const allNodes = store.getAllNodes();
    expect(allNodes).toHaveLength(1);
    expect(allNodes[0].asset.id).toBe('asset-1');

    store.close?.();
  });

  it.each(getStores())('$name maintains relationships and degree indexes', ({ store }) => {
    const assetA: Asset = {
      id: 'node-a',
      tenantId: 'parity-tenant',
      type: 'SERVICE',
      name: 'service-a',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };
    const assetB: Asset = {
      id: 'node-b',
      tenantId: 'parity-tenant',
      type: 'DATABASE',
      name: 'db-b',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: [],
    };

    store.addAsset(assetA);
    store.addAsset(assetB);

    const rel: Relationship = {
      id: 'rel-ab',
      tenantId: 'parity-tenant',
      sourceAssetId: 'node-a',
      targetAssetId: 'node-b',
      type: 'READS_FROM',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    };

    store.addRelationship(rel);

    const edge = store.getEdge('rel-ab');
    expect(edge).toBeDefined();
    expect(edge?.sourceAssetId).toBe('node-a');
    expect(edge?.targetAssetId).toBe('node-b');

    expect(store.getNode('node-a')?.outDegree).toBe(1);
    expect(store.getNode('node-a')?.inDegree).toBe(0);
    expect(store.getNode('node-b')?.outDegree).toBe(0);
    expect(store.getNode('node-b')?.inDegree).toBe(1);

    const outgoingA = store.getOutgoingEdges('node-a');
    expect(outgoingA).toHaveLength(1);
    expect(outgoingA[0].relationship.id).toBe('rel-ab');

    const incomingB = store.getIncomingEdges('node-b');
    expect(incomingB).toHaveLength(1);
    expect(incomingB[0].relationship.id).toBe('rel-ab');

    const neighborsOut = store.getNeighbors('node-a', 'OUTGOING');
    expect(neighborsOut).toHaveLength(1);
    expect(neighborsOut[0].asset.id).toBe('node-b');

    const neighborsIn = store.getNeighbors('node-b', 'INCOMING');
    expect(neighborsIn).toHaveLength(1);
    expect(neighborsIn[0].asset.id).toBe('node-a');

    store.close?.();
  });

  it.each(getStores())('$name executes DFS path traversal with cycle breaking and depth limit', ({ store }) => {
    // A -> B -> C -> D
    // A -> C (shortcut)
    // C -> A (cycle)
    const rels: Relationship[] = [
      { id: 'r-ab', tenantId: 'parity-tenant', sourceAssetId: 'A', targetAssetId: 'B', type: 'CALLS', nature: 'INFERRED', confidence: 0.9, metadata: {} },
      { id: 'r-bc', tenantId: 'parity-tenant', sourceAssetId: 'B', targetAssetId: 'C', type: 'CALLS', nature: 'INFERRED', confidence: 0.9, metadata: {} },
      { id: 'r-cd', tenantId: 'parity-tenant', sourceAssetId: 'C', targetAssetId: 'D', type: 'CALLS', nature: 'INFERRED', confidence: 0.9, metadata: {} },
      { id: 'r-ac', tenantId: 'parity-tenant', sourceAssetId: 'A', targetAssetId: 'C', type: 'CALLS', nature: 'INFERRED', confidence: 0.9, metadata: {} },
      { id: 'r-ca', tenantId: 'parity-tenant', sourceAssetId: 'C', targetAssetId: 'A', type: 'CALLS', nature: 'INFERRED', confidence: 0.9, metadata: {} },
    ];

    for (const r of rels) {
      store.addRelationship(r);
    }

    const paths = store.findAllPaths('A', 'D');
    // Paths should be: [A->B->C->D] and [A->C->D], no infinite loop from C->A
    expect(paths).toHaveLength(2);

    const pathLengths = paths.map((p) => p.length).sort();
    expect(pathLengths).toEqual([2, 3]);

    // Test with blocked edge
    const filteredPaths = store.findAllPaths('A', 'D', {
      blockedEdgeIds: new Set(['r-ac']),
    });
    expect(filteredPaths).toHaveLength(1);
    expect(filteredPaths[0].map((e) => e.relationship.id)).toEqual(['r-ab', 'r-bc', 'r-cd']);

    store.close?.();
  });

  it.each(getStores())('$name attaches and deduplicates findings', ({ store }) => {
    const finding: Finding = {
      id: 'f-001',
      tenantId: 'parity-tenant',
      assetId: 'service-x',
      ruleId: 'RULE-001',
      category: 'CONTAINER_MISCONFIGURATION',
      severity: 'HIGH',
      confidence: 'HIGH',
      title: 'Open port',
      description: 'Port 22 open',
      evidence: createEvidence({
        id: 'ev-001',
        tenantId: 'parity-tenant',
        sourceType: 'TERRAFORM',
        repository: 'repo-1',
        filePath: 'file.tf',
        lineStart: 10,
        lineEnd: 15,
        snippet: 'port = 22',
        scanner: 'tf-scanner',
      }),
      scanner: 'tf-scanner',
      remediationRecommendation: 'Close port',
      metadata: {},
    };

    store.attachFinding(finding);
    // Attaching duplicate finding should not duplicate in findings array
    store.attachFinding(finding);

    const findings = store.getFindingsForNode('service-x');
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('f-001');

    const allFindings = store.getAllFindings();
    expect(allFindings).toHaveLength(1);

    store.close?.();
  });

  it.each(getStores())('$name removes nodes and cascades edge deletion', ({ store }) => {
    store.addRelationship({
      id: 'r-xy',
      tenantId: 'parity-tenant',
      sourceAssetId: 'X',
      targetAssetId: 'Y',
      type: 'CALLS',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    });

    expect(store.getAllNodes()).toHaveLength(2);
    expect(store.getAllEdges()).toHaveLength(1);

    const removed = store.removeNode('X');
    expect(removed).toBe(true);

    expect(store.hasNode('X')).toBe(false);
    expect(store.getAllEdges()).toHaveLength(0);
    expect(store.getNode('Y')?.inDegree).toBe(0);

    store.close?.();
  });

  it('SecurityGraphEngine auto-spills from memory to SQLite when threshold is exceeded', () => {
    const engine = new SecurityGraphEngine('auto-tenant', {
      backend: 'auto',
      nodeThreshold: 3,
    });

    expect(engine.getStore() instanceof InMemoryGraphStore).toBe(true);

    for (let i = 1; i <= 5; i++) {
      engine.addAsset({
        id: `node-${i}`,
        tenantId: 'auto-tenant',
        type: 'SERVICE',
        name: `service-${i}`,
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'LOW',
        metadata: {},
        tags: [],
      });
    }

    expect(engine.getStore() instanceof SqliteGraphStore).toBe(true);
    expect(engine.getAllNodes()).toHaveLength(5);
    engine.close();
  });

  it('SqliteGraphStore supports WAL mode and vacuumInto export', () => {
    const dbPath = path.join(os.tmpdir(), `test-wal-${Date.now()}.db`);
    const backupPath = path.join(os.tmpdir(), `test-backup-${Date.now()}.db`);
    tempFiles.push(dbPath, backupPath);

    const sqliteStore = new SqliteGraphStore('wal-tenant', dbPath);
    sqliteStore.addAsset({
      id: 'asset-backup',
      tenantId: 'wal-tenant',
      type: 'SERVICE',
      name: 'backup-svc',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'LOW',
      metadata: {},
      tags: [],
    });

    sqliteStore.vacuumInto(backupPath);
    sqliteStore.close();

    expect(fs.existsSync(backupPath)).toBe(true);
    expect(fs.statSync(backupPath).size).toBeGreaterThan(0);

    // Verify backup can be opened by another store
    const restoredStore = new SqliteGraphStore('wal-tenant', backupPath);
    expect(restoredStore.hasNode('asset-backup')).toBe(true);
    restoredStore.close();
  });
});
