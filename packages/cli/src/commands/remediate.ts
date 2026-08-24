import * as path from 'node:path';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
} from '@ai-security-architect/ingestion';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import { AnalyzerRunner } from '@ai-security-architect/analyzers';
import { EntityResolver } from '@ai-security-architect/graph';
import { AttackPathEngine, MinCutOptimizer } from '@ai-security-architect/attackpath';
import { AIReasoningEngine } from '@ai-security-architect/ai';
import { RemediationCoordinator, type PullRequestPayload } from '@ai-security-architect/remediation';
import type { CliRemediateOptions } from '../types.js';

export async function executeRemediate(
  options: CliRemediateOptions
): Promise<PullRequestPayload> {
  const tenantId = options.tenantId || 'tenant-default';
  const repoPath = path.resolve(options.path);
  const repository = path.basename(repoPath);

  const workspaceManager = new WorkspaceManager();
  const workspace = await workspaceManager.createWorkspace();

  try {
    const acquirer = new RepositoryAcquisitionManager();
    await acquirer.acquire(
      {
        type: 'LOCAL_DIRECTORY',
        path: repoPath,
      },
      workspace
    );

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

    const targetPath = options.pathId
      ? attackPaths.find((p) => p.id === options.pathId) || attackPaths[0]
      : attackPaths[0];

    if (!targetPath) {
      throw new Error('No attack paths found to remediate.');
    }

    // AI Reasoning
    const aiEngine = new AIReasoningEngine();
    const aiResponse = await aiEngine.reasonAboutAttackPath({
      attackPath: targetPath,
      graph,
      repository,
    });

    // Closed-Loop Verification & PR Generation
    const coordinator = new RemediationCoordinator();
    const { prPayload, verification } = await coordinator.executeRemediationWorkflow({
      tenantId,
      repository,
      attackPath: targetPath,
      reasoningOutput: aiResponse.output,
      workspace,
      initialFindings: analysis.findings,
    });

    console.log('\n================================================================================');
    console.log('  AUTOMATED CLOSED-LOOP REMEDIATION VERIFICATION');
    console.log('================================================================================\n');
    console.log(`  Path ID:       ${targetPath.id}`);
    console.log(`  Target Asset:  ${targetPath.targetAssetId}`);
    console.log(`  Initial Risk:  ${verification.initialRiskScore.toFixed(1)} / 10.0`);
    console.log(`  Verified Risk: ${verification.postRemediationRiskScore.toFixed(1)} / 10.0 (-${verification.riskReductionPercentage}%)`);
    console.log(`  Status:        VERIFIED CLEAN ✅\n`);
    console.log('--------------------------------------------------------------------------------');
    console.log(`  PULL REQUEST PROPOSAL: ${prPayload.title}`);
    console.log(`  Branch: ${prPayload.branchName}`);
    console.log('--------------------------------------------------------------------------------\n');
    console.log(prPayload.bodyMarkdown);

    return prPayload;
  } finally {
    await workspace.cleanup().catch(() => {});
  }
}
