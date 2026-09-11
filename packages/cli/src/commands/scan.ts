import * as path from 'node:path';
import * as fs from 'node:fs';
import { execSync } from 'node:child_process';
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

    // Filter to staged files only if --staged mode is requested
    if (options.staged) {
      let stagedFiles: string[] = [];
      try {
        const output = execSync('git diff --name-only --cached', {
          cwd: repoPath,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'ignore'],
        });
        stagedFiles = output
          .split('\n')
          .map((f) => f.trim())
          .filter(Boolean);
      } catch (err: any) {
        if (!options.silent) {
          console.warn(`[Warning] Could not retrieve git staged files: ${err.message}. Scanning full workspace.`);
        }
      }

      const stagedSet = new Set(stagedFiles.map((f) => path.normalize(f)));
      const allFiles = await workspace.listFilesSafe();
      for (const relFile of allFiles) {
        const norm = path.normalize(relFile);
        if (!stagedSet.has(norm)) {
          const fullWorkspaceFilePath = path.join(workspace.workspaceDir, relFile);
          try {
            if (fs.existsSync(fullWorkspaceFilePath)) {
              fs.unlinkSync(fullWorkspaceFilePath);
            }
          } catch {
            // ignore cleanup error
          }
        }
      }
    }

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

    // 4. Resolve Graph (incorporating live cloud if requested)
    let allAssets = [...discovery.assets];
    let allRelationships = [...discovery.relationships];
    let allFindings = [...analysis.findings];
    let allEvidence = [...discovery.evidence, ...analysis.evidence];

    if (options.withCloud) {
      try {
        const { AwsConnector, CloudDiscoveryQueue, DriftDetector } = await import('@ai-security-architect/cloud-connectors');
        const connector = new AwsConnector({ region: options.region });
        const queue = new CloudDiscoveryQueue();
        const liveData = await queue.getLiveSnapshot(connector, tenantId);

        const resolverTemp = new EntityResolver();
        const declaredGraph = resolverTemp.resolve({
          tenantId,
          assets: discovery.assets,
          relationships: discovery.relationships,
          findings: analysis.findings,
          evidence: allEvidence,
        });

        const liveGraph = resolverTemp.resolve({
          tenantId,
          assets: liveData.assets,
          relationships: liveData.relationships,
          findings: [],
          evidence: [],
        });

        const driftDetector = new DriftDetector();
        const drift = driftDetector.detectDrift(declaredGraph, liveGraph);

        allAssets.push(...liveData.assets);
        allRelationships.push(...liveData.relationships);
        allFindings.push(...drift.findings);
        for (const f of drift.findings) {
          allEvidence.push(f.evidence);
        }
      } catch (cloudErr: any) {
        console.warn(`[Warning] Live cloud discovery failed: ${cloudErr.message}. Falling back to static code scan.`);
      }
    }

    const resolver = new EntityResolver();
    const graph = resolver.resolve({
      tenantId,
      assets: allAssets,
      relationships: allRelationships,
      findings: allFindings,
      evidence: allEvidence,
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
    if (!options.silent) {
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
    }

    if (options.failOnRiskScore && highestRiskScore >= options.failOnRiskScore) {
      process.exitCode = 1;
    }

    return result;
  } finally {
    await workspace.cleanup().catch(() => {});
  }
}
