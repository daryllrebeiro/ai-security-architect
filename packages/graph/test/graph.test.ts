import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
  type EphemeralWorkspace,
} from '@ai-security-architect/ingestion';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import { AnalyzerRunner } from '@ai-security-architect/analyzers';
import {
  SecurityGraphEngine,
  EntityResolver,
  GraphSnapshotRepository,
} from '../src/index.js';

describe('Phase 4 - Security Graph Engine & Cross-Layer Entity Resolution', () => {
  let createdWorkspaces: EphemeralWorkspace[] = [];

  afterEach(async () => {
    for (const ws of createdWorkspaces) {
      await ws.cleanup().catch(() => {});
    }
    createdWorkspaces = [];
  });

  async function setupFixtureWorkspace(): Promise<EphemeralWorkspace> {
    const manager = new WorkspaceManager();
    const workspace = await manager.createWorkspace();
    createdWorkspaces.push(workspace);

    const acquirer = new RepositoryAcquisitionManager();
    const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');
    await acquirer.acquire(
      {
        type: 'LOCAL_DIRECTORY',
        path: fixturePath,
      },
      workspace
    );

    return workspace;
  }

  describe('SecurityGraphEngine Fundamentals', () => {
    it('manages nodes, edges, findings, and degree indexes', () => {
      const graph = new SecurityGraphEngine('tenant-01');

      const nodeA = graph.addAsset({
        id: 'node-a',
        tenantId: 'tenant-01',
        type: 'SERVICE',
        name: 'service-a',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: {},
        tags: [],
      });

      const nodeB = graph.addAsset({
        id: 'node-b',
        tenantId: 'tenant-01',
        type: 'DATABASE',
        name: 'database-b',
        environment: 'production',
        isPublic: false,
        isSensitiveData: true,
        criticality: 'CRITICAL',
        metadata: {},
        tags: [],
      });

      expect(nodeA.inDegree).toBe(0);
      expect(nodeA.outDegree).toBe(0);

      graph.addRelationship({
        id: 'rel-a-b',
        tenantId: 'tenant-01',
        sourceAssetId: 'node-a',
        targetAssetId: 'node-b',
        type: 'READS_FROM',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });

      expect(graph.getNode('node-a')?.outDegree).toBe(1);
      expect(graph.getNode('node-b')?.inDegree).toBe(1);

      const neighbors = graph.getNeighbors('node-a', 'OUTGOING');
      expect(neighbors).toHaveLength(1);
      expect(neighbors[0].asset.id).toBe('node-b');
    });

    it('finds paths and prevents infinite loops on cyclic graphs', () => {
      const graph = new SecurityGraphEngine('tenant-01');

      // Create cycle: A -> B -> C -> A, and C -> Target
      graph.addRelationship({
        id: 'r1',
        tenantId: 'tenant-01',
        sourceAssetId: 'A',
        targetAssetId: 'B',
        type: 'CALLS',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });
      graph.addRelationship({
        id: 'r2',
        tenantId: 'tenant-01',
        sourceAssetId: 'B',
        targetAssetId: 'C',
        type: 'CALLS',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });
      graph.addRelationship({
        id: 'r3',
        tenantId: 'tenant-01',
        sourceAssetId: 'C',
        targetAssetId: 'A',
        type: 'CALLS',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });
      graph.addRelationship({
        id: 'r4',
        tenantId: 'tenant-01',
        sourceAssetId: 'C',
        targetAssetId: 'TARGET',
        type: 'CAN_READ',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });

      const paths = graph.findAllPaths('A', 'TARGET');
      expect(paths).toHaveLength(1);
      expect(paths[0]).toHaveLength(3); // A -> B -> C -> TARGET
    });

    it('serializes to snapshot and calculates graph diffs accurately', () => {
      const graphBefore = new SecurityGraphEngine('tenant-01');
      graphBefore.addRelationship({
        id: 'edge-1',
        tenantId: 'tenant-01',
        sourceAssetId: 'service-a',
        targetAssetId: 's3-bucket',
        type: 'CAN_READ',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });

      const snapshot = graphBefore.toSnapshot();
      const restored = SecurityGraphEngine.fromSnapshot(snapshot);
      expect(restored.getAllNodes()).toHaveLength(2);
      expect(restored.getAllEdges()).toHaveLength(1);

      const graphAfter = SecurityGraphEngine.fromSnapshot(snapshot);
      graphAfter.removeEdge('edge-1'); // Simulate remediation

      const diff = SecurityGraphEngine.diff(graphBefore, graphAfter);
      expect(diff.removedEdges).toHaveLength(1);
      expect(diff.removedEdges[0].id).toBe('edge-1');
    });

    it('persists snapshots and invalidates stale source versions', () => {
      const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-snapshots-'));
      const repository = new GraphSnapshotRepository({ storageDir });
      const graph = new SecurityGraphEngine('tenant-01');
      const snapshot = graph.toSnapshot('source-v1');

      repository.save(snapshot);

      expect(repository.load({ tenantId: 'tenant-01', sourceFingerprint: 'source-v1' })).toEqual(snapshot);
      expect(repository.load({ tenantId: 'tenant-01', sourceFingerprint: 'source-v2' })).toBeUndefined();
      expect(repository.invalidate({ tenantId: 'tenant-01', sourceFingerprint: 'source-v1' })).toBe(true);
      expect(repository.load({ tenantId: 'tenant-01', sourceFingerprint: 'source-v1' })).toBeUndefined();

      fs.rmSync(storageDir, { recursive: true, force: true });
    });

    it('tracks incremental graph deltas and lists saved snapshots for change consumers', () => {
      const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-delta-'));
      const repository = new GraphSnapshotRepository({ storageDir });
      const before = new SecurityGraphEngine('tenant-graph-01');
      before.addAsset({
        id: 'svc-a',
        tenantId: 'tenant-graph-01',
        type: 'SERVICE',
        name: 'svc-a',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {},
        tags: [],
      });

      const after = new SecurityGraphEngine('tenant-graph-01');
      after.addAsset({
        id: 'svc-a',
        tenantId: 'tenant-graph-01',
        type: 'SERVICE',
        name: 'svc-a',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {},
        tags: [],
      });
      after.addAsset({
        id: 'svc-b',
        tenantId: 'tenant-graph-01',
        type: 'SERVICE',
        name: 'svc-b',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {},
        tags: [],
      });
      after.addRelationship({
        id: 'rel-1',
        tenantId: 'tenant-graph-01',
        sourceAssetId: 'svc-a',
        targetAssetId: 'svc-b',
        type: 'CALLS',
        nature: 'DECLARED',
        confidence: 0.9,
        metadata: {},
      });

      const delta = after.createIncrementalDelta(before);
      repository.save(after.toSnapshot('source-v2'));

      expect(delta.addedNodes).toHaveLength(1);
      expect(delta.addedEdges).toHaveLength(1);
      expect(repository.listSnapshots('tenant-graph-01')).toHaveLength(1);

      fs.rmSync(storageDir, { recursive: true, force: true });
    });
  });

  describe('EntityResolver & Cross-Layer Stitching', () => {
    it('constructs a unified Security Graph from Golden Reference Fixture 001', async () => {
      const workspace = await setupFixtureWorkspace();

      // 1. Discovery
      const discoveryEngine = new DiscoveryEngine();
      const discovery = await discoveryEngine.discover({
        tenantId: 'tenant-enterprise-01',
        repository: 'enterprise/order-app',
        workspace,
      });

      // 2. Deterministic Analysis
      const analyzerRunner = new AnalyzerRunner();
      const analysis = await analyzerRunner.runAnalyzers({
        tenantId: 'tenant-enterprise-01',
        repository: 'enterprise/order-app',
        workspace,
        discoveredAssets: discovery.assets,
      });

      // 3. Entity Resolution & Graph Construction
      const resolver = new EntityResolver();
      const graph = resolver.resolve({
        tenantId: 'tenant-enterprise-01',
        assets: discovery.assets,
        relationships: discovery.relationships,
        findings: analysis.findings,
        evidence: [...discovery.evidence, ...analysis.evidence],
      });

      const allNodes = graph.getAllNodes();
      const allEdges = graph.getAllEdges();

      expect(allNodes.length).toBeGreaterThanOrEqual(7);
      expect(allEdges.length).toBeGreaterThanOrEqual(6);

      // Verify Internet Entry Node exists
      const internetNode = allNodes.find((n) => n.asset.type === 'INTERNET');
      expect(internetNode).toBeDefined();

      // Verify Target S3 PII Bucket exists
      const s3Node = allNodes.find((n) => n.asset.type === 'BUCKET' && n.asset.isSensitiveData);
      expect(s3Node).toBeDefined();

      // Verify findings are attached to graph nodes
      const allFindings = graph.getAllFindings();
      expect(allFindings.some((f) => f.category === 'SSRF')).toBe(true);
      expect(allFindings.some((f) => f.category === 'IAM_OVERPRIVILEGE')).toBe(true);

      // Verify that a continuous path exists from Internet to Sensitive S3 Bucket!
      const pathsToPII = graph.findAllPaths(internetNode!.asset.id, s3Node!.asset.id);
      expect(pathsToPII.length).toBeGreaterThanOrEqual(1);

      const firstPath = pathsToPII[0];
      expect(firstPath.length).toBeGreaterThanOrEqual(4);

      // Check node chain progression: INTERNET -> ALB -> SERVICE -> POD -> SA -> IAM_ROLE -> BUCKET
      const pathAssetTypes = [
        internetNode!.asset.type,
        ...firstPath.map((e) => graph.getNode(e.targetAssetId)!.asset.type),
      ];

      expect(pathAssetTypes).toContain('INTERNET');
      expect(pathAssetTypes).toContain('LOAD_BALANCER');
      expect(pathAssetTypes).toContain('SERVICE');
      expect(pathAssetTypes).toContain('POD');
      expect(pathAssetTypes).toContain('KUBERNETES_SERVICE_ACCOUNT');
      expect(pathAssetTypes).toContain('IAM_ROLE');
      expect(pathAssetTypes).toContain('BUCKET');
    });
  });
});
