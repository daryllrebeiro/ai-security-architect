import * as path from 'node:path';
import * as readline from 'node:readline';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
} from '@ai-security-architect/ingestion';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import { AnalyzerRunner } from '@ai-security-architect/analyzers';
import { EntityResolver } from '@ai-security-architect/graph';
import { AttackPathEngine, MinCutOptimizer } from '@ai-security-architect/attackpath';
import { AutonomousRemediationAgent, type AgentExecutionResult } from '@ai-security-architect/agent';
import type { CliAgentOptions } from '../types.js';

export async function executeAgent(options: CliAgentOptions): Promise<AgentExecutionResult> {
  const tenantId = options.tenantId || 'tenant-default';
  const repoPath = path.resolve(options.path);
  const repository = path.basename(repoPath);

  const workspaceManager = new WorkspaceManager();
  const workspace = await workspaceManager.createWorkspace();

  try {
    // 1. Ingest repository into sandbox
    const acquirer = new RepositoryAcquisitionManager();
    await acquirer.acquire(
      {
        type: 'LOCAL_DIRECTORY',
        path: repoPath,
      },
      workspace
    );

    // 2. Discover
    const discoveryEngine = new DiscoveryEngine();
    const discovery = await discoveryEngine.discover({
      tenantId,
      repository,
      workspace,
    });

    // 3. Analyze
    const analyzerRunner = new AnalyzerRunner();
    const analysis = await analyzerRunner.runAnalyzers({
      tenantId,
      repository,
      workspace,
      discoveredAssets: discovery.assets,
    });

    // 4. Resolve Graph
    const resolver = new EntityResolver();
    const graph = resolver.resolve({
      tenantId,
      assets: discovery.assets,
      relationships: discovery.relationships,
      findings: analysis.findings,
      evidence: [...discovery.evidence, ...analysis.evidence],
    });

    // 5. Traverse Attack Paths
    const pathEngine = new AttackPathEngine();
    const attackPaths = pathEngine.analyzePaths(graph);
    new MinCutOptimizer().findOptimalChokePoints(graph, attackPaths);

    if (attackPaths.length === 0) {
      console.log('✅ Clean: No critical attack paths found reaching crown jewels.');
      return {
        state: 'DONE',
        success: true,
        incomplete: false,
        iterations: 0,
        llmCallsCount: 0,
        durationMs: 0,
        history: [],
      };
    }

    const targetPath = options.pathId
      ? attackPaths.find((p) => p.id === options.pathId) || attackPaths[0]
      : attackPaths[0];

    console.log(`\n================================================================================`);
    console.log(`  AUTONOMOUS MULTI-MODEL REMEDIATION AGENT (BETA)`);
    console.log(`================================================================================`);
    console.log(`  Target Path ID: ${targetPath.id}`);
    console.log(`  Initial Risk:   ${targetPath.riskScore.totalRisk.toFixed(1)} / 10.0`);
    console.log(`  Max Iterations: ${options.maxIterations ?? 5}`);
    console.log(`  Auto Approve:   ${options.autoApprove ? 'YES (--yes flag provided)' : 'INTERACTIVE'}`);
    console.log(`--------------------------------------------------------------------------------\n`);

    const agent = new AutonomousRemediationAgent({
      budget: {
        maxIterations: options.maxIterations ?? 5,
      },
    });

    const result = await agent.runRemediationLoop({
      tenantId,
      repository,
      attackPath: targetPath,
      workspace,
      graph,
      initialFindings: analysis.findings,
      autoApprove: options.autoApprove ?? false,
      onApprovalRequest: async (proposal) => {
        console.log(`\n🎯 REMEDIATION PROPOSAL READY FOR HUMAN APPROVAL:`);
        console.log(`  Title:       ${proposal.prPayload.title}`);
        console.log(`  Branch:      ${proposal.prPayload.branchName}`);
        console.log(`  Risk Delta:  -${proposal.verification.riskReductionPercentage}% (Verified Clean ✅)`);
        console.log(`  Files:       ${proposal.prPayload.modifiedFiles.join(', ')}`);

        if (options.autoApprove) {
          return true;
        }

        // In non-interactive or testing environments without TTY
        if (!process.stdin.isTTY) {
          console.log('\n[Gate] Non-interactive environment without --yes: withholding autonomous merge.');
          return false;
        }

        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        return new Promise((resolve) => {
          rl.question('\nApprove and generate verified pull request branch? (y/N): ', (ans) => {
            rl.close();
            resolve(ans.trim().toLowerCase() === 'y' || ans.trim().toLowerCase() === 'yes');
          });
        });
      },
    });

    console.log(`\nAgent Execution Finished with State: [${result.state}]`);
    console.log(`  Success:    ${result.success ? 'YES' : 'NO'}`);
    console.log(`  Incomplete: ${result.incomplete ? 'YES' : 'NO'}`);
    if (result.reason) {
      console.log(`  Reason:     ${result.reason}`);
    }

    return result;
  } finally {
    await workspace.cleanup().catch(() => {});
  }
}
