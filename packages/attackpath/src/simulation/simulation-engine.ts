import type { SecurityGraphEngine, GraphEdge } from '@ai-security-architect/graph';
import {
  AttackPathSchema,
  type AttackPath,
  type Asset,
} from '@ai-security-architect/core';
import { AttackPathEngine } from '../attack-path-engine.js';
import type { SimulationHypothesis, SimulationResult } from './types.js';

export class SimulationEngine {
  private readonly pathEngine: AttackPathEngine;

  constructor(pathEngine?: AttackPathEngine) {
    this.pathEngine = pathEngine ?? new AttackPathEngine();
  }

  public simulateCompromise(
    graph: SecurityGraphEngine,
    hypothesis: SimulationHypothesis
  ): SimulationResult {
    const breachedNode = graph.getNode(hypothesis.assumedBreachedAssetId);
    if (!breachedNode) {
      throw new Error(`Simulated asset ${hypothesis.assumedBreachedAssetId} does not exist in the graph.`);
    }

    const breachedAsset = breachedNode.asset;
    const mode = hypothesis.mode ?? 'BIDIRECTIONAL';
    const maxDepth = hypothesis.maxHops ?? 10;

    const blastRadiusPaths: AttackPath[] = [];
    const upstreamEntrypointPaths: AttackPath[] = [];
    const reachableCrownJewelsMap = new Map<string, Asset>();
    const ingressAssetsMap = new Map<string, Asset>();

    let pathCounter = 1;

    // 1. FORWARD Blast-Radius Simulation (What can this compromised asset reach?)
    if (mode === 'FORWARD' || mode === 'BIDIRECTIONAL') {
      const targets = this.pathEngine.findSensitiveTargets(graph);

      for (const target of targets) {
        if (target.id === breachedAsset.id) continue;

        const rawPaths = graph.findAllPaths(breachedAsset.id, target.id, { maxDepth });

        for (const rawEdges of rawPaths) {
          if (rawEdges.length === 0) continue;

          const steps = this.pathEngine.buildAttackSteps(graph, rawEdges);
          const riskScore = this.pathEngine.calculatePathRisk(graph, rawEdges, breachedAsset, target);

          const attackPath: AttackPath = {
            id: `sim-blast-${String(pathCounter++).padStart(3, '0')}`,
            tenantId: graph.tenantId,
            entryAssetId: breachedAsset.id,
            targetAssetId: target.id,
            pathLength: rawEdges.length,
            steps,
            riskScore,
            verifiedEliminated: false,
            isSimulation: true,
            simulationContext: {
              rootAssetId: breachedAsset.id,
              direction: 'FORWARD',
              hypothesis: hypothesis.description,
            },
          };

          AttackPathSchema.parse(attackPath);
          blastRadiusPaths.push(attackPath);
          reachableCrownJewelsMap.set(target.id, target);
        }
      }
    }

    // 2. REVERSE Entrypoint Tracing (Who from the outside can compromise this asset?)
    if (mode === 'REVERSE' || mode === 'BIDIRECTIONAL') {
      const entrypoints = this.pathEngine.findEntryPoints(graph);

      for (const entry of entrypoints) {
        if (entry.id === breachedAsset.id) continue;

        const rawPaths = graph.findAllPaths(entry.id, breachedAsset.id, { maxDepth });

        for (const rawEdges of rawPaths) {
          if (rawEdges.length === 0) continue;

          const steps = this.pathEngine.buildAttackSteps(graph, rawEdges);
          const riskScore = this.pathEngine.calculatePathRisk(graph, rawEdges, entry, breachedAsset);

          const attackPath: AttackPath = {
            id: `sim-upstream-${String(pathCounter++).padStart(3, '0')}`,
            tenantId: graph.tenantId,
            entryAssetId: entry.id,
            targetAssetId: breachedAsset.id,
            pathLength: rawEdges.length,
            steps,
            riskScore,
            verifiedEliminated: false,
            isSimulation: true,
            simulationContext: {
              rootAssetId: breachedAsset.id,
              direction: 'REVERSE',
              hypothesis: hypothesis.description,
            },
          };

          AttackPathSchema.parse(attackPath);
          upstreamEntrypointPaths.push(attackPath);
          ingressAssetsMap.set(entry.id, entry);
        }
      }
    }

    blastRadiusPaths.sort((a, b) => b.riskScore.totalRisk - a.riskScore.totalRisk);
    upstreamEntrypointPaths.sort((a, b) => b.riskScore.totalRisk - a.riskScore.totalRisk);

    const allRisks = [
      ...blastRadiusPaths.map((p) => p.riskScore.totalRisk),
      ...upstreamEntrypointPaths.map((p) => p.riskScore.totalRisk),
    ];
    const highestRiskScore = allRisks.length > 0 ? Math.max(...allRisks) : 0;

    return {
      hypothesis,
      breachedAsset,
      blastRadiusPaths,
      upstreamEntrypointPaths,
      reachableCrownJewels: Array.from(reachableCrownJewelsMap.values()),
      potentialExternalIngressAssets: Array.from(ingressAssetsMap.values()),
      summary: {
        totalBlastRadiusPaths: blastRadiusPaths.length,
        totalUpstreamPaths: upstreamEntrypointPaths.length,
        highestRiskScore,
      },
    };
  }
}
