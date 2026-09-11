import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  AstContentCache,
  IncrementalScanManager,
} from '../src/index.js';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { FileAnalysisCacheData } from '../src/types.js';

describe('Task 2.3: Two-Tier Cache & Incremental PR Scanning', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const d of tempDirs) {
      try {
        if (fs.existsSync(d)) {
          fs.rmSync(d, { recursive: true, force: true });
        }
      } catch {}
    }
    tempDirs.length = 0;
  });

  function makeDiskCacheDir(): string {
    const dir = path.join(os.tmpdir(), `test-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    tempDirs.push(dir);
    return dir;
  }

  it('provides two-tier cache behavior: L1 memory hit, L2 disk promotion, and stats tracking', () => {
    const diskDir = makeDiskCacheDir();
    const cache = new AstContentCache({
      maxMemoryEntries: 10,
      diskCacheDir: diskDir,
      enableDiskCache: true,
    });

    const sampleData: FileAnalysisCacheData = {
      filePath: 'terraform/s3.tf',
      assets: [
        {
          id: 'asset-s3-prod',
          tenantId: 't1',
          type: 'BUCKET',
          name: 'prod-bucket',
          environment: 'production',
          isPublic: false,
          isSensitiveData: true,
          criticality: 'CRITICAL',
          metadata: {},
          tags: [],
        },
      ],
      relationships: [],
      findings: [],
      evidence: [],
    };

    const sha = cache.computeSha256('resource "aws_s3_bucket" "prod" {}');
    cache.set('terraform/s3.tf', sha, sampleData);

    // 1. L1 Memory Hit
    const l1Result = cache.get('terraform/s3.tf', sha);
    expect(l1Result).toBeDefined();
    expect(l1Result?.assets[0].name).toBe('prod-bucket');

    let stats = cache.getStats();
    expect(stats.l1Hits).toBe(1);
    expect(stats.l2Hits).toBe(0);

    // 2. Simulate L1 Eviction by invalidating in memory but keeping disk
    cache.invalidate('terraform/s3.tf');

    // 3. L2 Disk Hit & Promotion
    const l2Result = cache.get('terraform/s3.tf', sha);
    expect(l2Result).toBeDefined();
    expect(l2Result?.assets[0].name).toBe('prod-bucket');

    stats = cache.getStats();
    expect(stats.l1Hits).toBe(1);
    expect(stats.l2Hits).toBe(1);
    expect(stats.hits).toBe(2);

    // Subsequent call should hit L1 because it was promoted!
    const promotedResult = cache.get('terraform/s3.tf', sha);
    expect(promotedResult).toBeDefined();
    stats = cache.getStats();
    expect(stats.l1Hits).toBe(2);
  });

  it('detects file deltas accurately via IncrementalScanManager.detectDelta', () => {
    const manager = new IncrementalScanManager();

    const previousFiles = new Map([
      ['file1.tf', 'sha-1-old'],
      ['file2.tf', 'sha-2'],
      ['file3.tf', 'sha-3'],
    ]);

    const currentFiles = new Map([
      ['file1.tf', 'sha-1-new'], // modified
      ['file2.tf', 'sha-2'],     // unchanged
      ['file4.tf', 'sha-4'],     // added
      // file3.tf was deleted
    ]);

    const delta = manager.detectDelta(currentFiles, previousFiles);
    expect(delta.added).toEqual(['file4.tf']);
    expect(delta.modified).toEqual(['file1.tf']);
    expect(delta.deleted).toEqual(['file3.tf']);
  });

  it('performs incremental scan on a SecurityGraph, updating only changed files', async () => {
    const diskDir = makeDiskCacheDir();
    const cache = new AstContentCache({ diskCacheDir: diskDir });
    const manager = new IncrementalScanManager({ cache });
    const graph = new SecurityGraphEngine('tenant-pr');

    // Pre-cache file1
    const file1Sha = cache.computeSha256('file 1 content');
    cache.set('service-1.ts', file1Sha, {
      filePath: 'service-1.ts',
      assets: [{
        id: 'svc-1',
        tenantId: 'tenant-pr',
        type: 'SERVICE',
        name: 'Service 1',
        environment: 'prod',
        isPublic: true,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: { filePath: 'service-1.ts' },
        tags: [],
      }],
      relationships: [],
      findings: [],
      evidence: [],
    });

    const currentFiles = new Map([
      ['service-1.ts', { content: 'file 1 content', sha256: file1Sha }],
      ['service-2.ts', { content: 'file 2 new content', sha256: 'sha-2-new' }],
    ]);

    const delta = {
      added: ['service-2.ts'],
      modified: ['service-1.ts'],
      deleted: [],
    };

    let analyzedFilesCount = 0;
    const summary = await manager.scanIncremental({
      graph,
      delta,
      currentFiles,
      analyzeFile: async (fp, content) => {
        analyzedFilesCount++;
        return {
          filePath: fp,
          assets: [{
            id: 'svc-2',
            tenantId: 'tenant-pr',
            type: 'SERVICE',
            name: 'Service 2',
            environment: 'prod',
            isPublic: false,
            isSensitiveData: false,
            criticality: 'MEDIUM',
            metadata: { filePath: fp },
            tags: [],
          }],
          relationships: [],
          findings: [],
          evidence: [],
        };
      },
    });

    // service-1.ts was in cache -> skipped re-analysis
    // service-2.ts was new -> analyzed
    expect(analyzedFilesCount).toBe(1);
    expect(summary.filesScanned).toBe(1);
    expect(summary.filesSkipped).toBe(1);
    expect(graph.hasNode('svc-1')).toBe(true);
    expect(graph.hasNode('svc-2')).toBe(true);
  });
});
