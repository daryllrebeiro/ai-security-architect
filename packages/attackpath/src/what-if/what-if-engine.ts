import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { AttackPath } from '@ai-security-architect/core';
import { AttackPathEngine } from '../attack-path-engine.js';
import type { WhatIfHypothesis, WhatIfOutcome } from './types.js';

export class WhatIfEngine {
  private readonly pathEngine: AttackPathEngine;

  constructor(pathEngine?: AttackPathEngine) {
    this.pathEngine = pathEngine ?? new AttackPathEngine();
  }

  public evaluateHypothesis(
    graph: SecurityGraphEngine,
    hypothesis: WhatIfHypothesis
  ): WhatIfOutcome {
    // 1. Calculate baseline paths on the unmodified original graph
    const baselinePaths = this.pathEngine.analyzePaths(graph);
    const baselineTotalRisk = baselinePaths.reduce((acc, p) => acc + p.riskScore.totalRisk, 0);

    // 2. Clone the graph into an in-memory clone with ZERO mutation to persistent or source store
    const snapshot = graph.toSnapshot();
    const clonedGraph = SecurityGraphEngine.fromSnapshot(snapshot, { backend: 'memory' });

    // 3. Apply hypothesis modification strictly to the in-memory clone
    this.applyHypothesis(clonedGraph, hypothesis);

    // 4. Re-evaluate paths on modified in-memory graph
    const rawRemainingPaths = this.pathEngine.analyzePaths(clonedGraph);

    // Mark remaining paths with whatIfContext
    const remainingPaths: AttackPath[] = rawRemainingPaths.map((p) => ({
      ...p,
      isWhatIf: true,
      whatIfContext: {
        hypothesisId: hypothesis.id,
        description: hypothesis.description,
      },
    }));

    // 5. Compare baseline vs remaining to find closed paths
    const remainingFingerprints = new Set(
      remainingPaths.map((p) => this.computePathFingerprint(p))
    );

    const closedPaths: AttackPath[] = baselinePaths
      .filter((bp) => !remainingFingerprints.has(this.computePathFingerprint(bp)))
      .map((p) => ({
        ...p,
        isWhatIf: true,
        whatIfContext: {
          hypothesisId: hypothesis.id,
          description: `Closed by hypothesis: ${hypothesis.description}`,
        },
      }));

    const remainingTotalRisk = remainingPaths.reduce((acc, p) => acc + p.riskScore.totalRisk, 0);
    const pathsReductionPct =
      baselinePaths.length > 0
        ? Math.round(((baselinePaths.length - remainingPaths.length) / baselinePaths.length) * 100)
        : 0;
    const riskReductionPct =
      baselineTotalRisk > 0
        ? Math.round(((baselineTotalRisk - remainingTotalRisk) / baselineTotalRisk) * 100)
        : 0;

    return {
      hypothesis,
      baselinePathsCount: baselinePaths.length,
      remainingPathsCount: remainingPaths.length,
      closedPaths,
      remainingPaths,
      riskDelta: {
        pathsReductionPct,
        baselineTotalRisk: Math.round(baselineTotalRisk * 10) / 10,
        remainingTotalRisk: Math.round(remainingTotalRisk * 10) / 10,
        riskReductionPct,
      },
      isSimulatedOnly: true,
    };
  }

  private applyHypothesis(graph: SecurityGraphEngine, hypothesis: WhatIfHypothesis): void {
    const { action, target } = hypothesis;

    if (action === 'SEVER_EDGE') {
      if (target.edgeId) {
        graph.removeEdge(target.edgeId);
      }
      if (target.sourceAssetId && target.targetAssetId) {
        const outgoing = graph.getOutgoingEdges(target.sourceAssetId);
        for (const edge of outgoing) {
          if (
            edge.targetAssetId === target.targetAssetId &&
            (!target.edgeType || edge.type === target.edgeType)
          ) {
            graph.removeEdge(edge.relationship.id);
          }
        }
      }
    } else if (action === 'REMOVE_ASSET') {
      if (target.assetId) {
        graph.removeNode(target.assetId);
      }
    } else if (action === 'RESTRICT_PERMISSION') {
      const edgesToRemove = graph.getAllEdges().filter((e) => {
        if (target.sourceAssetId && e.sourceAssetId !== target.sourceAssetId) return false;
        if (target.targetAssetId && e.targetAssetId !== target.targetAssetId) return false;
        if (target.edgeType && e.type === target.edgeType) return true;
        if (target.revokedPermissions && target.revokedPermissions.includes(e.type)) return true;
        return false;
      });

      for (const edge of edgesToRemove) {
        graph.removeEdge(edge.relationship.id);
      }
    }
  }

  private computePathFingerprint(path: AttackPath): string {
    return `${path.entryAssetId}->${path.steps.map((s) => `${s.relationshipType}:${s.targetAssetId}`).join('->')}`;
  }
}
