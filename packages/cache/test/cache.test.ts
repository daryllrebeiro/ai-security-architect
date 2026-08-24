import { describe, it, expect } from 'vitest';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import {
  AstContentCache,
  ConcurrencyPool,
  IncrementalGraphEngine,
} from '../src/index.js';

describe('Phase 10 - Scalable Execution, AST Caching & Performance Benchmark', () => {
  describe('AST Content-Hash Cache', () => {
    it('caches and retrieves file analysis data on matching SHA-256 hash', () => {
      const cache = new AstContentCache();
      const content = 'resource "aws_s3_bucket" "b" { bucket = "my-bucket" }';
      const contentSha = cache.computeSha256(content);

      cache.set('terraform/s3.tf', contentSha, {
        filePath: 'terraform/s3.tf',
        assets: [
          {
            id: 'asset-s3-my-bucket',
            tenantId: 'tenant-1',
            type: 'BUCKET',
            name: 'my-bucket',
            environment: 'prod',
            isPublic: false,
            isSensitiveData: false,
            criticality: 'HIGH',
            metadata: {},
            tags: [],
          },
        ],
        relationships: [],
        findings: [],
        evidence: [],
      });

      // Hit on identical hash
      const hit = cache.get('terraform/s3.tf', contentSha);
      expect(hit).toBeDefined();
      expect(hit?.assets[0].name).toBe('my-bucket');

      // Miss on modified content hash
      const modifiedSha = cache.computeSha256(content + '\n# modified');
      const miss = cache.get('terraform/s3.tf', modifiedSha);
      expect(miss).toBeUndefined();

      const stats = cache.getStats();
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(1);
      expect(stats.hitRatePercentage).toBe(50);
    });
  });

  describe('Concurrency Worker Pool', () => {
    it('executes tasks in parallel with bounded concurrency', async () => {
      const pool = new ConcurrencyPool({ maxConcurrency: 3 });
      const items = [10, 20, 30, 40, 50];

      const results = await pool.map(items, async (val) => {
        await new Promise((res) => setTimeout(res, 10));
        return val * 2;
      });

      expect(results).toEqual([20, 40, 60, 80, 100]);
    });
  });

  describe('Incremental Graph Engine', () => {
    it('applies file delta updates surgically without resetting graph', () => {
      const graph = new SecurityGraphEngine('tenant-1');
      const incrementalEngine = new IncrementalGraphEngine();

      // Initial Graph
      graph.addAsset({
        id: 'asset-svc-1',
        tenantId: 'tenant-1',
        type: 'SERVICE',
        name: 'service-1',
        environment: 'prod',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: { filePath: 'src/Service1.java' },
        tags: [],
      });

      graph.addAsset({
        id: 'asset-svc-2',
        tenantId: 'tenant-1',
        type: 'SERVICE',
        name: 'service-2',
        environment: 'prod',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: { filePath: 'src/Service2.java' },
        tags: [],
      });

      // Apply Delta: Delete Service 1, Add Service 3
      const delta = {
        added: ['src/Service3.java'],
        modified: [],
        deleted: ['src/Service1.java'],
      };

      const updateResult = incrementalEngine.applyFileDelta(graph, delta, [
        {
          filePath: 'src/Service3.java',
          assets: [
            {
              id: 'asset-svc-3',
              tenantId: 'tenant-1',
              type: 'SERVICE',
              name: 'service-3',
              environment: 'prod',
              isPublic: false,
              isSensitiveData: false,
              criticality: 'HIGH',
              metadata: { filePath: 'src/Service3.java' },
              tags: [],
            },
          ],
          relationships: [],
          findings: [],
          evidence: [],
        },
      ]);

      expect(updateResult.affectedAssetsCount).toBeGreaterThanOrEqual(1);
      expect(graph.getNode('asset-svc-1')).toBeUndefined();
      expect(graph.getNode('asset-svc-2')).toBeDefined();
      expect(graph.getNode('asset-svc-3')).toBeDefined();
    });
  });

  describe('High-Scale Graph Traversal Benchmark (1,000+ Nodes)', () => {
    it('discovers attack paths in <50ms across a 1,000-node graph', () => {
      const graph = new SecurityGraphEngine('tenant-benchmark');

      // Entry
      graph.addAsset({
        id: 'asset-entry-root',
        tenantId: 'tenant-benchmark',
        type: 'INTERNET',
        name: 'Internet',
        environment: 'ext',
        isPublic: true,
        isSensitiveData: false,
        criticality: 'LOW',
        metadata: {},
        tags: [],
      });

      // Target
      graph.addAsset({
        id: 'asset-target-crown-jewel',
        tenantId: 'tenant-benchmark',
        type: 'BUCKET',
        name: 'PII Bucket',
        environment: 'prod',
        isPublic: false,
        isSensitiveData: true,
        criticality: 'CRITICAL',
        metadata: {},
        tags: [],
      });

      // Add 1,000 intermediate nodes and chain them
      let prevId = 'asset-entry-root';
      for (let i = 0; i < 1000; i++) {
        const nodeId = `asset-node-${i}`;
        graph.addAsset({
          id: nodeId,
          tenantId: 'tenant-benchmark',
          type: 'SERVICE',
          name: `Microservice-${i}`,
          environment: 'prod',
          isPublic: false,
          isSensitiveData: false,
          criticality: 'MEDIUM',
          metadata: {},
          tags: [],
        });

        // Add some cross links
        if (i % 20 === 0) {
          graph.addRelationship({
            id: `rel-${prevId}-${nodeId}`,
            tenantId: 'tenant-benchmark',
            sourceAssetId: prevId,
            targetAssetId: nodeId,
            type: 'ROUTES_TO',
            nature: 'INFERRED',
            confidence: 1.0,
            metadata: {},
          });
          prevId = nodeId;
        }
      }

      // Link last chained node to crown jewel
      graph.addRelationship({
        id: 'rel-final-target',
        tenantId: 'tenant-benchmark',
        sourceAssetId: prevId,
        targetAssetId: 'asset-target-crown-jewel',
        type: 'CAN_READ',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });

      const startTime = performance.now();
      const paths = graph.findAllPaths('asset-entry-root', 'asset-target-crown-jewel', {
        maxDepth: 100,
      });
      const durationMs = performance.now() - startTime;

      expect(paths.length).toBeGreaterThanOrEqual(1);
      expect(durationMs).toBeLessThan(50); // Under 50ms requirement
    });
  });
});
