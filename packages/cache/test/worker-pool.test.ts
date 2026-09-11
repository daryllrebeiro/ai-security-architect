import { describe, it, expect, afterEach } from 'vitest';
import {
  ConcurrencyPool,
  extractFileData,
  type ExtractionWorkerPayload,
} from '../src/index.js';

describe('Task 2.2: Multi-Threaded Worker Pool for Extraction', () => {
  let pool: ConcurrencyPool | null = null;

  afterEach(async () => {
    if (pool) {
      await pool.close();
      pool = null;
    }
  });

  it('extracts file metadata, language, and tokens synchronously via extractFileData', () => {
    const payload: ExtractionWorkerPayload = {
      filePath: 'terraform/s3.tf',
      content: `resource "aws_s3_bucket" "vault" {\n  bucket = "enterprise-vault"\n}\n`,
    };

    const result = extractFileData(payload);
    expect(result.filePath).toBe('terraform/s3.tf');
    expect(result.detectedLanguage).toBe('terraform');
    expect(result.tokensFound).toContain('aws_s3_bucket');
    expect(result.lineCount).toBe(4);
    expect(result.contentSha256).toHaveLength(64);
  });

  it('processes batches in parallel via ConcurrencyPool.extractParallel', async () => {
    pool = new ConcurrencyPool({ maxConcurrency: 4, useWorkerThreads: true });

    const items: ExtractionWorkerPayload[] = [
      {
        filePath: 'src/main/OrderService.java',
        content: 'public class OrderService { private String password = "demo"; }',
      },
      {
        filePath: 'k8s/deploy.yaml',
        content: 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n',
      },
      {
        filePath: 'terraform/main.tf',
        content: 'resource "aws_iam_role" "role" { name = "admin" }',
      },
      {
        filePath: 'src/index.ts',
        content: 'export const config = { apiKey: "secret123" };',
      },
    ];

    const results = await pool.extractParallel(items);
    expect(results).toHaveLength(4);

    expect(results[0].detectedLanguage).toBe('java');
    expect(results[0].tokensFound).toContain('password');

    expect(results[1].detectedLanguage).toBe('yaml');
    expect(results[1].tokensFound).toContain('kind: Deployment');

    expect(results[2].detectedLanguage).toBe('terraform');
    expect(results[2].tokensFound).toContain('aws_iam_role');

    expect(results[3].detectedLanguage).toBe('typescript');
  });

  it('falls back gracefully to in-process execution when useWorkerThreads is false', async () => {
    pool = new ConcurrencyPool({ maxConcurrency: 2, useWorkerThreads: false });
    expect(pool.isUsingWorkerThreads()).toBe(false);

    const items: ExtractionWorkerPayload[] = [
      { filePath: 'a.ts', content: 'const a = 1;' },
      { filePath: 'b.tf', content: 'resource "aws_s3_bucket" "b" {}' },
    ];

    const results = await pool.extractParallel(items);
    expect(results).toHaveLength(2);
    expect(results[0].contentSha256).toHaveLength(64);
    expect(results[1].tokensFound).toContain('aws_s3_bucket');
  });
});
