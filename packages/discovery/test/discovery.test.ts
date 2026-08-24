import { describe, it, expect, afterEach } from 'vitest';
import * as path from 'node:path';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
  type EphemeralWorkspace,
} from '@ai-security-architect/ingestion';
import {
  JavaSpringExtractor,
  KubernetesExtractor,
  TerraformExtractor,
  DiscoveryEngine,
} from '../src/index.js';

describe('Phase 2 - Discovery Engine & AST Extraction', () => {
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

  it('JavaSpringExtractor extracts services, controllers, and endpoints', async () => {
    const workspace = await setupFixtureWorkspace();
    const fileList = await workspace.listFilesSafe();

    const extractor = new JavaSpringExtractor();
    const supports = await extractor.supports(workspace, fileList);
    expect(supports).toBe(true);

    const result = await extractor.extract(
      {
        tenantId: 'tenant-test-01',
        repository: 'enterprise/order-service',
        workspace,
      },
      fileList
    );

    expect(result.assets.some((a) => a.type === 'SERVICE')).toBe(true);
    expect(result.assets.some((a) => a.type === 'API_CONTROLLER' && a.name === 'OrderController')).toBe(true);

    const webhookEndpoint = result.assets.find(
      (a) => a.type === 'ENDPOINT' && a.name === '/api/v1/orders/webhook-callback'
    );
    expect(webhookEndpoint).toBeDefined();
    expect(webhookEndpoint?.metadata.httpMethod).toBe('POST');
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it('KubernetesExtractor extracts Pods, ServiceAccounts, and IAM Role links', async () => {
    const workspace = await setupFixtureWorkspace();
    const fileList = await workspace.listFilesSafe();

    const extractor = new KubernetesExtractor();
    const result = await extractor.extract(
      {
        tenantId: 'tenant-test-01',
        repository: 'enterprise/order-service',
        workspace,
      },
      fileList
    );

    const podAsset = result.assets.find((a) => a.type === 'POD');
    expect(podAsset).toBeDefined();
    expect(podAsset?.name).toContain('order-service');

    const saAsset = result.assets.find((a) => a.type === 'KUBERNETES_SERVICE_ACCOUNT');
    expect(saAsset).toBeDefined();
    expect(saAsset?.metadata.awsRoleArn).toBe('arn:aws:iam::123456789012:role/order-service-role');

    const assumesRel = result.relationships.find((r) => r.type === 'ASSUMES_ROLE');
    expect(assumesRel).toBeDefined();
  });

  it('TerraformExtractor extracts ALBs, IAM Roles, and S3 Buckets', async () => {
    const workspace = await setupFixtureWorkspace();
    const fileList = await workspace.listFilesSafe();

    const extractor = new TerraformExtractor();
    const result = await extractor.extract(
      {
        tenantId: 'tenant-test-01',
        repository: 'enterprise/infrastructure',
        workspace,
      },
      fileList
    );

    const internetNode = result.assets.find((a) => a.type === 'INTERNET');
    expect(internetNode).toBeDefined();

    const albAsset = result.assets.find((a) => a.type === 'LOAD_BALANCER');
    expect(albAsset).toBeDefined();
    expect(albAsset?.isPublic).toBe(true);

    const s3Asset = result.assets.find((a) => a.type === 'BUCKET');
    expect(s3Asset).toBeDefined();
    expect(s3Asset?.isSensitiveData).toBe(true);
    expect(s3Asset?.criticality).toBe('CRITICAL');

    const publicExposureRel = result.relationships.find((r) => r.type === 'EXPOSES_HTTP');
    expect(publicExposureRel).toBeDefined();
  });

  it('DiscoveryEngine executes end-to-end extraction across Golden Reference Fixture', async () => {
    const workspace = await setupFixtureWorkspace();

    const engine = new DiscoveryEngine();
    const discoveryResult = await engine.discover({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/multi-tier-app',
      workspace,
    });

    expect(discoveryResult.assets.length).toBeGreaterThanOrEqual(7);
    expect(discoveryResult.relationships.length).toBeGreaterThanOrEqual(5);
    expect(discoveryResult.evidence.length).toBeGreaterThanOrEqual(4);

    // Verify key architectural assets exist
    const assetTypes = discoveryResult.assets.map((a) => a.type);
    expect(assetTypes).toContain('INTERNET');
    expect(assetTypes).toContain('LOAD_BALANCER');
    expect(assetTypes).toContain('SERVICE');
    expect(assetTypes).toContain('ENDPOINT');
    expect(assetTypes).toContain('POD');
    expect(assetTypes).toContain('KUBERNETES_SERVICE_ACCOUNT');
    expect(assetTypes).toContain('IAM_ROLE');
    expect(assetTypes).toContain('BUCKET');

    // Verify cross-layer relationships exist
    const relTypes = discoveryResult.relationships.map((r) => r.type);
    expect(relTypes).toContain('EXPOSES_HTTP');
    expect(relTypes).toContain('ROUTES_TO');
    expect(relTypes).toContain('CONTAINS');
    expect(relTypes).toContain('DEPLOYED_TO');
    expect(relTypes).toContain('RUNS_AS');
    expect(relTypes).toContain('ASSUMES_ROLE');
    expect(relTypes).toContain('CAN_READ');
  });
});
