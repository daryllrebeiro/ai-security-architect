import { describe, it, expect, afterEach } from 'vitest';
import * as path from 'node:path';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
  type EphemeralWorkspace,
} from '@ai-security-architect/ingestion';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import {
  SecretAnalyzer,
  SastCodeAnalyzer,
  IacTerraformAnalyzer,
  AnalyzerRunner,
} from '../src/index.js';

describe('Phase 3 - Deterministic Security Analyzers', () => {
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

  it('SecretAnalyzer detects hardcoded cloud credentials with line numbers', async () => {
    const manager = new WorkspaceManager();
    const workspace = await manager.createWorkspace();
    createdWorkspaces.push(workspace);

    const safePath = workspace.resolveSafePath('config/secrets.env');
    await import('node:fs/promises').then(async (fs) => {
      await fs.mkdir(path.dirname(safePath), { recursive: true });
      await fs.writeFile(
        safePath,
        'AWS_KEY=AKIAIOSFODNN7EXAMPLE\nSECRET=ghp_123456789012345678901234567890123456'
      );
    });

    const fileList = await workspace.listFilesSafe();
    const analyzer = new SecretAnalyzer();
    const result = await analyzer.analyze(
      {
        tenantId: 'tenant-01',
        repository: 'enterprise/app',
        workspace,
        discoveredAssets: [],
      },
      fileList
    );

    expect(result.findings.length).toBeGreaterThanOrEqual(2);
    expect(result.findings.some((f) => f.ruleId === 'SECRET-AWS-ACCESS-KEY')).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'SECRET-GITHUB-TOKEN')).toBe(true);
    expect(result.evidence[0].snippetSha256).toHaveLength(64);
  });

  it('SastCodeAnalyzer detects SSRF in Spring Boot OrderController', async () => {
    const workspace = await setupFixtureWorkspace();
    const discoveryEngine = new DiscoveryEngine();
    const discovery = await discoveryEngine.discover({
      tenantId: 'tenant-01',
      repository: 'enterprise/order-service',
      workspace,
    });

    const fileList = await workspace.listFilesSafe();
    const analyzer = new SastCodeAnalyzer();
    const result = await analyzer.analyze(
      {
        tenantId: 'tenant-01',
        repository: 'enterprise/order-service',
        workspace,
        discoveredAssets: discovery.assets,
      },
      fileList
    );

    const ssrfFinding = result.findings.find((f) => f.category === 'SSRF');
    expect(ssrfFinding).toBeDefined();
    expect(ssrfFinding?.ruleId).toBe('SSRF-SPRING-URL-CONNECTION');
    expect(ssrfFinding?.severity).toBe('HIGH');
    expect(ssrfFinding?.cwe).toBe('CWE-918');
    expect(ssrfFinding?.evidence.filePath).toContain('OrderController.java');
  });

  it('IacTerraformAnalyzer detects wildcard IAM overprivilege in iam.tf', async () => {
    const workspace = await setupFixtureWorkspace();
    const discoveryEngine = new DiscoveryEngine();
    const discovery = await discoveryEngine.discover({
      tenantId: 'tenant-01',
      repository: 'enterprise/infrastructure',
      workspace,
    });

    const fileList = await workspace.listFilesSafe();
    const analyzer = new IacTerraformAnalyzer();
    const result = await analyzer.analyze(
      {
        tenantId: 'tenant-01',
        repository: 'enterprise/infrastructure',
        workspace,
        discoveredAssets: discovery.assets,
      },
      fileList
    );

    const iamFinding = result.findings.find((f) => f.category === 'IAM_OVERPRIVILEGE');
    expect(iamFinding).toBeDefined();
    expect(iamFinding?.ruleId).toBe('IAM-WILDCARD-S3-PERMISSION');
    expect(iamFinding?.severity).toBe('CRITICAL');
    expect(iamFinding?.evidence.snippet).toContain('s3:*');
  });

  it('AnalyzerRunner executes full scan and validates finding schemas', async () => {
    const workspace = await setupFixtureWorkspace();
    const discoveryEngine = new DiscoveryEngine();
    const discovery = await discoveryEngine.discover({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/multi-tier-app',
      workspace,
    });

    const runner = new AnalyzerRunner();
    const analysis = await runner.runAnalyzers({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/multi-tier-app',
      workspace,
      discoveredAssets: discovery.assets,
    });

    expect(analysis.findings.length).toBeGreaterThanOrEqual(2);
    expect(analysis.evidence.length).toBeGreaterThanOrEqual(2);

    const findingCategories = analysis.findings.map((f) => f.category);
    expect(findingCategories).toContain('SSRF');
    expect(findingCategories).toContain('IAM_OVERPRIVILEGE');

    for (const finding of analysis.findings) {
      expect(finding.tenantId).toBe('tenant-enterprise-01');
      expect(finding.evidence.snippetSha256).toHaveLength(64);
    }
  });
});
