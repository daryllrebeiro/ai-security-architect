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
import { AIReasoningEngine } from '@ai-security-architect/ai';
import {
  PatchApplier,
  VerificationRunner,
  PullRequestGenerator,
  RemediationCoordinator,
} from '../src/index.js';

describe('Phase 8 - Closed-Loop Remediation Verification & Automated PR Engine', () => {
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

  it('PatchApplier applies scoped IAM patch to terraform/iam.tf in sandbox', async () => {
    const workspace = await setupFixtureWorkspace();

    const initialIamContent = await workspace.readSafeFile('terraform/iam.tf');
    expect(initialIamContent).toContain('"s3:*"');

    const applier = new PatchApplier();
    const modifiedFiles = await applier.applyPatches(workspace, [
      {
        filePath: 'terraform/iam.tf',
        action: 'MODIFY',
        diff: '- Action = "s3:*"\n+ Action = ["s3:GetObject"]',
        description: 'Scope IAM permissions',
      },
    ]);

    expect(modifiedFiles).toContain('terraform/iam.tf');

    const patchedIamContent = await workspace.readSafeFile('terraform/iam.tf');
    expect(patchedIamContent).not.toContain('"s3:*"');
    expect(patchedIamContent).toContain('s3:GetObject');
  });

  it('VerificationRunner mathematically proves attack path elimination post-patch', async () => {
    const workspace = await setupFixtureWorkspace();

    // 1. Initial Scan & Path Discovery
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

    // 2. Apply IAM least-privilege remediation patch
    const applier = new PatchApplier();
    await applier.applyPatches(workspace, [
      {
        filePath: 'terraform/iam.tf',
        action: 'MODIFY',
        diff: '- Action = "s3:*"',
        description: 'Scope IAM permissions',
      },
    ]);

    // 3. Execute Closed-Loop Verification
    const verificationRunner = new VerificationRunner();
    const verification = await verificationRunner.verifyRemediation({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      workspace,
      initialAttackPath: attackPaths[0],
      initialFindings: analysis.findings,
    });

    expect(verification.verified).toBe(true);
    expect(verification.riskReductionPercentage).toBe(100);
    expect(verification.pathsEliminatedCount).toBe(1);
    expect(verification.remainingPathsCount).toBe(0);
    expect(verification.postRemediationRiskScore).toBe(0.0);
    expect(verification.newRegressionsCount).toBe(0);
  });

  it('RemediationCoordinator executes full workflow and produces verified PR payload', async () => {
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
    const aiResponse = await aiEngine.reasonAboutAttackPath({
      attackPath: attackPaths[0],
      graph,
      repository: 'enterprise/order-app',
    });

    // Run Full Coordinator
    const coordinator = new RemediationCoordinator();
    const { prPayload, verification } = await coordinator.executeRemediationWorkflow({
      tenantId: 'tenant-enterprise-01',
      repository: 'enterprise/order-app',
      attackPath: attackPaths[0],
      reasoningOutput: aiResponse.output,
      workspace,
      initialFindings: analysis.findings,
    });

    expect(verification.verified).toBe(true);
    expect(prPayload.title).toContain('fix(security)');
    expect(prPayload.branchName).toContain('security/remediate');
    expect(prPayload.bodyMarkdown).toContain('```mermaid');
    expect(prPayload.bodyMarkdown).toContain('VERIFIED CLEAN');
    expect(prPayload.modifiedFiles).toContain('terraform/iam.tf');
  });
});
