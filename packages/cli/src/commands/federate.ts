import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { FederationEngine, type RepositoryGraphInput, type FederatedGraphResult } from '@ai-security-architect/federation';
import { executeScan } from './scan.js';
import type { CliFederateOptions } from '../types.js';

export interface FederationManifestItem {
  repository: string;
  path: string;
}

export interface FederationManifest {
  tenantId?: string;
  repositories: FederationManifestItem[];
}

export async function executeFederate(options: CliFederateOptions): Promise<FederatedGraphResult> {
  const manifestFullPath = path.resolve(options.manifestPath);
  const rawContent = await fs.readFile(manifestFullPath, 'utf-8');
  const parsed = JSON.parse(rawContent);

  const manifest: FederationManifest = Array.isArray(parsed)
    ? { repositories: parsed }
    : parsed;

  if (!manifest.repositories || manifest.repositories.length === 0) {
    throw new Error(`Federation manifest at ${options.manifestPath} contains no repositories.`);
  }

  const baseDir = path.dirname(manifestFullPath);
  const subgraphs: RepositoryGraphInput[] = [];

  for (const item of manifest.repositories) {
    const repoPath = path.isAbsolute(item.path)
      ? item.path
      : path.resolve(baseDir, item.path);

    const scanResult = await executeScan({
      path: repoPath,
      tenantId: options.tenantId || manifest.tenantId || 'federated-tenant',
      silent: true,
    });

    subgraphs.push({
      repository: item.repository,
      graph: scanResult.graph,
    });
  }

  const engine = new FederationEngine();
  const result = engine.federate(subgraphs, {
    tenantId: options.tenantId || manifest.tenantId || 'federated-tenant',
  });

  console.log(`\n================================================================================`);
  console.log(`  MULTI-REPO GRAPH FEDERATION`);
  console.log(`================================================================================`);
  console.log(`  Federated Repositories: ${result.federatedRepos.length}`);
  for (const repo of result.federatedRepos) {
    console.log(`    - ${repo}`);
  }
  console.log(`  Merged Canonical Nodes: ${result.mergedNodeCount}`);
  console.log(`  Total Federated Nodes:  ${result.totalNodes}`);
  console.log(`  Total Federated Edges:  ${result.totalEdges} (${result.crossRepoEdgesCount} Cross-Repo)`);
  console.log(`================================================================================\n`);

  if (options.outputFile) {
    const serialized = {
      tenantId: result.graph.tenantId,
      federatedRepos: result.federatedRepos,
      mergedNodeCount: result.mergedNodeCount,
      totalNodes: result.totalNodes,
      totalEdges: result.totalEdges,
      crossRepoEdgesCount: result.crossRepoEdgesCount,
      nodes: result.graph.getAllNodes().map((n) => n.asset),
      edges: result.graph.getAllEdges().map((e) => e.relationship),
    };

    const outFullPath = path.resolve(options.outputFile);
    await fs.mkdir(path.dirname(outFullPath), { recursive: true });
    await fs.writeFile(outFullPath, JSON.stringify(serialized, null, 2), 'utf-8');
    console.log(`[FEDERATION] Federated graph exported to ${outFullPath}`);
  }

  return result;
}
