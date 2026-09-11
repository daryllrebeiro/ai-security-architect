import { SimulationEngine, type SimulationResult } from '@ai-security-architect/attackpath';
import { executeScan } from './scan.js';
import type { CliSimulateOptions } from '../types.js';

export async function executeSimulate(options: CliSimulateOptions): Promise<SimulationResult> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const graph = scanResult.graph;
  const allNodes = graph.getAllNodes();

  // If no assumedBreachNode specified, pick the first service/pod/compute node
  let targetNodeId = options.assumedBreachNode;
  if (!targetNodeId) {
    const candidate = allNodes.find((n) =>
      ['SERVICE', 'CONTAINER', 'COMPUTE', 'SERVERLESS'].includes(n.asset.type)
    );
    if (!candidate) {
      throw new Error('No suitable compute or service asset found to simulate compromise on.');
    }
    targetNodeId = candidate.asset.id;
  }

  const engine = new SimulationEngine();
  const result = engine.simulateCompromise(graph, {
    assumedBreachedAssetId: targetNodeId,
    description: `Purple Team simulation: Assumed breach of ${targetNodeId}`,
    mode: 'BIDIRECTIONAL',
  });

  console.log(`\n================================================================================`);
  console.log(`  PURPLE TEAM THREAT MODELING & ATTACK SIMULATION`);
  console.log(`================================================================================`);
  console.log(`  Simulated Compromised Asset: ${result.breachedAsset.name} (${result.breachedAsset.id})`);
  console.log(`  Asset Type:                 ${result.breachedAsset.type}`);
  console.log(`  Peak Simulated Risk:        ${result.summary.highestRiskScore.toFixed(1)} / 10.0`);
  console.log(`  Forward Blast Radius:       ${result.blastRadiusPaths.length} paths to ${result.reachableCrownJewels.length} crown jewel(s)`);
  console.log(`  Upstream Ingress Vectors:   ${result.upstreamEntrypointPaths.length} paths from ${result.potentialExternalIngressAssets.length} ingress point(s)`);
  console.log(`--------------------------------------------------------------------------------`);
  console.log(`  REACHABLE CROWN JEWELS (Forward Blast Radius):`);
  for (const cj of result.reachableCrownJewels) {
    console.log(`    👑 ${cj.name} [${cj.type}] (Criticality: ${cj.criticality})`);
  }
  console.log(`--------------------------------------------------------------------------------`);
  console.log(`  UPSTREAM ENTRY POINTS (How attackers reach this asset):`);
  for (const ing of result.potentialExternalIngressAssets) {
    console.log(`    🌐 ${ing.name} [${ing.type}] (Public: ${ing.isPublic ? 'YES' : 'NO'})`);
  }
  console.log(`================================================================================\n`);

  return result;
}
