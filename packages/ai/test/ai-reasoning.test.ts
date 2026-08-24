import { describe, it, expect, afterEach } from 'vitest';
import * as path from 'node:path';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
  type EphemeralWorkspace,
} from '@ai-security-architect/ingestion';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import { AnalyzerRunner } from '@ai-security-architect/analyzers';
import { EntityResolver } from '@ai-security-architect/graph';
import { AttackPathEngine, MinCutOptimizer } from '@ai-security-architect/attackpath';
import {
  redactSensitiveData,
  ContextBuilder,
  AIReasoningEngine,
} from '../src/index.js';

describe('Phase 7 - Constrained AI Security Architect & Reasoning Engine', () => {
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

  it('redacts credentials and sensitive tokens from evidence text', () => {
    const rawText = `
      aws_access_key = "AKIAIOSFODNN7EXAMPLE"
      github_token = "ghp_123456789012345678901234567890123456"
      db_password = "superSecretPassword123"
      Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz
    `;

    const redacted = redactSensitiveData(rawText);

    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redacted).not.toContain('ghp_123456789012345678901234567890123456');
    expect(redacted).not.toContain('superSecretPassword123');
    expect(redacted).toContain('[REDACTED_AWS_ACCESS_KEY]');
    expect(redacted).toContain('[REDACTED_GITHUB_TOKEN]');
    expect(redacted).toContain('[REDACTED_SECRET]');
  });

  it('ContextBuilder builds validated AIContextHandoff from Golden Fixture 001', async () => {
    const workspace = await setupFixtureWorkspace();

    const discovery = await new DiscoveryEngine().discover({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      workspace,
    });

    const analysis = await new AnalyzerRunner().runAnalyzers({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      workspace,
      discoveredAssets: discovery.assets,
    });

    const graph = new EntityResolver().resolve({
      tenantId: 'tenant-enterprise-01',
      assets: discovery.assets,
      relationships: discovery.relationships,
      findings: analysis.findings,
      evidence: [...discovery.evidence, ...analysis.evidence],
    });

    const pathEngine = new AttackPathEngine();
    const attackPaths = pathEngine.analyzePaths(graph);
    new MinCutOptimizer().findOptimalChokePoints(graph, attackPaths);

    const builder = new ContextBuilder();
    const handoff = builder.buildContextHandoff(attackPaths[0], graph, 'enterprise/order-app');

    expect(handoff.attackPathId).toBe(attackPaths[0].id);
    expect(handoff.graphChain.length).toBeGreaterThanOrEqual(4);
    expect(handoff.findingsSummary.length).toBeGreaterThanOrEqual(2);
    expect(handoff.evidenceReferences.length).toBeGreaterThanOrEqual(2);
    expect(handoff.deterministicMetrics.calculatedRiskScore).toBeGreaterThanOrEqual(8.5);
  });

  it('AIReasoningEngine generates schema-compliant remediation proposal with patch diffs', async () => {
    const workspace = await setupFixtureWorkspace();

    const discovery = await new DiscoveryEngine().discover({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      workspace,
    });

    const analysis = await new AnalyzerRunner().runAnalyzers({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      workspace,
      discoveredAssets: discovery.assets,
    });

    const graph = new EntityResolver().resolve({
      tenantId: 'tenant-enterprise-01',
      assets: discovery.assets,
      relationships: discovery.relationships,
      findings: analysis.findings,
      evidence: [...discovery.evidence, ...analysis.evidence],
    });

    const attackPaths = new AttackPathEngine().analyzePaths(graph);
    new MinCutOptimizer().findOptimalChokePoints(graph, attackPaths);

    const aiEngine = new AIReasoningEngine();
    const response = await aiEngine.reasonAboutAttackPath({
      attackPath: attackPaths[0],
      graph,
      repository: 'enterprise/order-app',
    });

    expect(response.output).toBeDefined();
    expect(response.output.summary).toContain('SSRF');
    expect(response.output.rootCauseAnalysis).toContain('OrderController.java');
    expect(response.output.rootCauseAnalysis).toContain('terraform/iam.tf');
    expect(response.output.confidence).toBe('VERY_HIGH');

    // Verify recommended patch
    const patches = response.output.recommendedRemediation.patches;
    expect(patches.length).toBeGreaterThanOrEqual(1);
    expect(patches[0].filePath).toBe('terraform/iam.tf');
    expect(patches[0].diff).toContain('+');
    expect(patches[0].diff).toContain('s3:GetObject');

    // Verify all cited evidence references exist in context
    const validEvidenceIds = response.contextHandoff.evidenceReferences.map((e) => e.evidenceId);
    for (const citedId of response.output.evidenceReferences) {
      expect(validEvidenceIds).toContain(citedId);
    }
  });
});
