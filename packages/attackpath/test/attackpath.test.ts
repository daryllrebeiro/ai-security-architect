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
import {
  AttackPathEngine,
  MinCutOptimizer,
} from '../src/index.js';

describe('Phase 5 - Attack Path Traversal & Min-Cut Remediation Engine', () => {
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

  it('computes end-to-end exploit chains on Golden Reference Architecture Fixture 001', async () => {
    const workspace = await setupFixtureWorkspace();

    // 1. Discovery
    const discoveryEngine = new DiscoveryEngine();
    const discovery = await discoveryEngine.discover({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      workspace,
    });

    // 2. Deterministic Analyzers
    const analyzerRunner = new AnalyzerRunner();
    const analysis = await analyzerRunner.runAnalyzers({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      workspace,
      discoveredAssets: discovery.assets,
    });

    // 3. Entity Resolution & Security Graph Construction
    const resolver = new EntityResolver();
    const graph = resolver.resolve({
      tenantId: 'tenant-enterprise-01',
      assets: discovery.assets,
      relationships: discovery.relationships,
      findings: analysis.findings,
      evidence: [...discovery.evidence, ...analysis.evidence],
    });

    // 4. Attack Path Engine Analysis
    const pathEngine = new AttackPathEngine();
    const attackPaths = pathEngine.analyzePaths(graph);

    expect(attackPaths.length).toBeGreaterThanOrEqual(1);

    const primaryPath = attackPaths[0];
    expect(primaryPath.entryAssetId).toBe('asset-internet');
    expect(primaryPath.targetAssetId).toContain('customer-pii');
    expect(primaryPath.steps.length).toBeGreaterThanOrEqual(4);

    // Verify Explainable Risk Score
    expect(primaryPath.riskScore.totalRisk).toBeGreaterThanOrEqual(8.5);
    expect(primaryPath.riskScore.impact).toBeGreaterThanOrEqual(9.0);
    expect(primaryPath.riskScore.exploitability).toBeGreaterThanOrEqual(8.0);
    expect(primaryPath.riskScore.reachability).toBe(1.0);

    // Verify Attack Steps contain meaningful explanations
    for (const step of primaryPath.steps) {
      expect(step.explanation).toBeDefined();
      expect(step.relationshipType).toBeDefined();
    }

    // 5. Min-Cut Choke-Point Optimization
    const minCutOptimizer = new MinCutOptimizer();
    const chokePoints = minCutOptimizer.findOptimalChokePoints(graph, attackPaths);

    expect(chokePoints.length).toBeGreaterThanOrEqual(1);

    const topChokePoint = chokePoints[0];
    expect(topChokePoint.riskReductionPercentage).toBe(100);
    expect(topChokePoint.blastRadius).toBe('LOW');
    expect(topChokePoint.actionDescription).toContain('IAM');

    // Verify choke point is attached to the attack path
    expect(primaryPath.recommendedChokePoint).toBeDefined();
    expect(primaryPath.recommendedChokePoint?.edgeId).toBe(topChokePoint.edgeId);
  });

  it('proves path breakage when optimal choke point edge is severed', async () => {
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
    const initialPaths = pathEngine.analyzePaths(graph);
    expect(initialPaths.length).toBeGreaterThanOrEqual(1);

    const minCut = new MinCutOptimizer();
    const chokePoints = minCut.findOptimalChokePoints(graph, initialPaths);
    const topChokePoint = chokePoints[0];

    // Sever the recommended choke point edge in the graph
    const severed = graph.removeEdge(topChokePoint.edgeId);
    expect(severed).toBe(true);

    // Re-evaluate attack paths
    const postRemediationPaths = pathEngine.analyzePaths(graph);
    const pathsToPII = postRemediationPaths.filter((p) => p.targetAssetId.includes('customer-pii'));
    expect(pathsToPII).toHaveLength(0); // Critical attack path is mathematically eliminated!
  });
});
