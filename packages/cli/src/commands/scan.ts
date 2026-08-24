import * as path from 'node:path';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
} from '@ai-security-architect/ingestion';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import { AnalyzerRunner } from '@ai-security-architect/analyzers';
import { EntityResolver } from '@ai-security-architect/graph';
import { AttackPathEngine, MinCutOptimizer } from '@ai-security-architect/attackpath';
import type { CliScanOptions, CliScanResult } from '../types.js';
import { TerminalFormatter } from '../formatters/terminal-formatter.js';
import { SarifFormatter } from '../formatters/sarif-formatter.js';

export async function executeScan(options: CliScanOptions): Promise<CliScanResult> {
  const tenantId = options.tenantId || 'tenant-default';
  const repoPath = path.resolve(options.path);
  const repository = options.repository || path.basename(repoPath);

  const workspaceManager = new WorkspaceManager();
  const workspace = await workspaceManager.createWorkspace();

  try {
    // 1. Ingest
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

    // 5. Traverse Attack Paths & Optimize Choke Points
    const pathEngine = new AttackPathEngine();
    const attackPaths = pathEngine.analyzePaths(graph);
    new MinCutOptimizer().findOptimalChokePoints(graph, attackPaths);

    const highestRiskScore = attackPaths[0]?.riskScore.totalRisk || 0.0;

    const result: CliScanResult = {
      tenantId,
      repository,
      totalAssets: discovery.assets.length,
      totalFindings: analysis.findings.length,
      attackPaths,
      highestRiskScore,
      graph,
      findings: analysis.findings,
    };

    // Format output
    const format = options.format || 'table';
    if (format === 'sarif') {
      const sarif = new SarifFormatter().format(result);
      console.log(JSON.stringify(sarif, null, 2));
    } else if (format === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else {
      const formatted = new TerminalFormatter().formatScanResult(result);
      console.log(formatted);
    }

    if (options.failOnRiskScore && highestRiskScore >= options.failOnRiskScore) {
      process.exitCode = 1;
    }

    return result;
  } finally {
    await workspace.cleanup().catch(() => {});
  }
}
