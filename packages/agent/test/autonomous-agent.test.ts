import { describe, it, expect, afterEach, vi } from 'vitest';
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
import type { LLMProvider } from '@ai-security-architect/ai';
import { AutonomousRemediationAgent } from '../src/autonomous-agent.js';

describe('AutonomousRemediationAgent', () => {
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

  async function setupInitialAttackPath(workspace: EphemeralWorkspace) {
    const tenantId = 'tenant-agent-test';
    const repository = 'enterprise/order-app';

    const discovery = await new DiscoveryEngine().discover({
      tenantId,
      repository,
      workspace,
    });

    const analysis = await new AnalyzerRunner().runAnalyzers({
      tenantId,
      repository,
      workspace,
      discoveredAssets: discovery.assets,
    });

    const graph = new EntityResolver().resolve({
      tenantId,
      assets: discovery.assets,
      relationships: discovery.relationships,
      findings: analysis.findings,
      evidence: [...discovery.evidence, ...analysis.evidence],
    });

    const attackPaths = new AttackPathEngine().analyzePaths(graph);
    new MinCutOptimizer().findOptimalChokePoints(graph, attackPaths);

    return {
      tenantId,
      repository,
      attackPath: attackPaths[0],
      findings: analysis.findings,
      graph,
    };
  }

  it('converges on valid patch, passes verification, obtains human approval, and finishes with DONE', async () => {
    const workspace = await setupFixtureWorkspace();
    const { tenantId, repository, attackPath, findings, graph } = await setupInitialAttackPath(workspace);

    // Mock LLM provider that returns schema-compliant working least-privilege IAM patch
    const mockLlm: LLMProvider = {
      name: 'mock-gemini-agent-solver',
      generateCompletion: vi.fn().mockResolvedValue(
        JSON.stringify({
          summary: 'Sever wildcard IAM access to S3',
          rootCauseAnalysis: 'Order service has wildcard S3 access in terraform/iam.tf',
          businessImpact: 'Data breach of customer PII',
          evidenceReferences: [],
          recommendedRemediation: {
            description: 'Scope IAM role policy',
            targetChokePoint: attackPath.recommendedChokePoint?.edgeId || 'rel-iam-s3',
            expectedRiskReductionPercentage: 100,
            engineeringEffort: 'LOW',
            patches: [
              {
                filePath: 'terraform/iam.tf',
                action: 'MODIFY',
                diff: '- Action = "s3:*"',
                description: 'Scope IAM permissions',
              },
            ],
          },
          alternativeRemediations: [],
          confidence: 'HIGH',
        })
      ),
    };

    const agent = new AutonomousRemediationAgent({
      llmProvider: mockLlm,
      budget: { maxIterations: 3, timeoutMs: 30000, maxLlmCalls: 5 },
    });

    let approvalRequested = false;

    const result = await agent.runRemediationLoop({
      tenantId,
      repository,
      attackPath,
      workspace,
      graph,
      initialFindings: findings,
      onApprovalRequest: async (proposal) => {
        approvalRequested = true;
        expect(proposal.verification.verified).toBe(true);
        expect(proposal.verification.riskReductionPercentage).toBe(100);
        return true; // Approve
      },
    });

    expect(approvalRequested).toBe(true);
    expect(result.success).toBe(true);
    expect(result.state).toBe('DONE');
    expect(result.incomplete).toBe(false);
    expect(result.prPayload).toBeDefined();
    expect(result.prPayload?.branchName).toContain('security/remediate-');
    expect(result.verification?.verified).toBe(true);

    // Verify history transitions
    const states = result.history.map((h) => h.toState);
    expect(states).toContain('REASONING');
    expect(states).toContain('PROPOSING');
    expect(states).toContain('SANDBOX_TESTING');
    expect(states).toContain('VERIFYING');
    expect(states).toContain('AWAITING_HUMAN_APPROVAL');
    expect(states).toContain('DONE');
  });

  it('stops at AWAITING_HUMAN_APPROVAL and rolls back workspace if human rejects proposal', async () => {
    const workspace = await setupFixtureWorkspace();
    const { tenantId, repository, attackPath, findings, graph } = await setupInitialAttackPath(workspace);

    const mockLlm: LLMProvider = {
      name: 'mock-gemini-agent',
      generateCompletion: vi.fn().mockResolvedValue(
        JSON.stringify({
          summary: 'Sever wildcard IAM access',
          rootCauseAnalysis: 'Order service has wildcard S3 access',
          businessImpact: 'Data breach of customer PII',
          evidenceReferences: [],
          recommendedRemediation: {
            description: 'Scope IAM role policy',
            targetChokePoint: attackPath.recommendedChokePoint?.edgeId || 'rel-iam-s3',
            expectedRiskReductionPercentage: 100,
            engineeringEffort: 'LOW',
            patches: [
              {
                filePath: 'terraform/iam.tf',
                action: 'MODIFY',
                diff: '- Action = "s3:*"',
                description: 'Scope IAM permissions',
              },
            ],
          },
          alternativeRemediations: [],
          confidence: 'HIGH',
        })
      ),
    };

    const agent = new AutonomousRemediationAgent({
      llmProvider: mockLlm,
      budget: { maxIterations: 3 },
    });

    const result = await agent.runRemediationLoop({
      tenantId,
      repository,
      attackPath,
      workspace,
      graph,
      initialFindings: findings,
      onApprovalRequest: async () => {
        return false; // Reject!
      },
    });

    expect(result.success).toBe(false);
    expect(result.state).toBe('FAILED');
    expect(result.incomplete).toBe(false);
    expect(result.reason).toContain('rejected');

    // Verify workspace was rolled back to original content
    const iamContent = await workspace.readSafeFile('terraform/iam.tf');
    expect(iamContent).toContain('"s3:*"');
  });

  it('exhausts iteration budget when patches fail verification and sets incomplete: true with rollback', async () => {
    const workspace = await setupFixtureWorkspace();
    const { tenantId, repository, attackPath, findings, graph } = await setupInitialAttackPath(workspace);

    // Mock LLM provider that generates a no-op patch that does not sever the path
    const mockLlm: LLMProvider = {
      name: 'mock-gemini-ineffective-solver',
      generateCompletion: vi.fn().mockResolvedValue(
        JSON.stringify({
          summary: 'Ineffective patch',
          rootCauseAnalysis: 'Testing iteration loop',
          businessImpact: 'None',
          evidenceReferences: [],
          recommendedRemediation: {
            description: 'Ineffective port change',
            targetChokePoint: 'unknown-edge',
            expectedRiskReductionPercentage: 10,
            engineeringEffort: 'LOW',
            patches: [
              {
                filePath: 'terraform/alb.tf',
                action: 'MODIFY',
                diff: '- port              = 80\n+ port              = 9999',
                description: 'Ineffective port change',
              },
            ],
          },
          alternativeRemediations: [],
          confidence: 'MEDIUM',
        })
      ),
    };

    const maxIterations = 2;
    const agent = new AutonomousRemediationAgent({
      llmProvider: mockLlm,
      budget: { maxIterations, timeoutMs: 30000, maxLlmCalls: 5 },
    });

    const result = await agent.runRemediationLoop({
      tenantId,
      repository,
      attackPath,
      workspace,
      graph,
      initialFindings: findings,
      autoApprove: true,
    });

    expect(result.success).toBe(false);
    expect(result.state).toBe('FAILED');
    expect(result.incomplete).toBe(true);
    expect(result.iterations).toBe(maxIterations);
    expect(result.reason).toContain('Iteration budget exhausted');

    // Verify workspace files were reverted
    const albContent = await workspace.readSafeFile('terraform/alb.tf');
    expect(albContent).toContain('port              = 80');
    expect(albContent).not.toContain('9999');
  });
});
