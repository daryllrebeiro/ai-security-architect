import type {
  AttackPath,
  ChokePointCandidate,
  RelationshipType,
  GlobalCutSet,
} from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import {
  FlowNetwork,
  DefaultRemediationCostStrategy,
  type RemediationCostStrategy,
} from './flow-network.js';

export class MinCutOptimizer {
  public getChokePointMetadata(
    relationshipType: RelationshipType,
    sourceName: string,
    targetName: string
  ): {
    actionDescription: string;
    engineeringEffort: 'LOW' | 'MEDIUM' | 'HIGH';
    blastRadius: 'LOW' | 'MEDIUM' | 'HIGH';
  } {
    let actionDescription = `Sever edge from ${sourceName} to ${targetName}`;
    let engineeringEffort: 'LOW' | 'MEDIUM' | 'HIGH' = 'MEDIUM';
    let blastRadius: 'LOW' | 'MEDIUM' | 'HIGH' = 'MEDIUM';

    if (relationshipType === 'CAN_READ' || relationshipType === 'CAN_WRITE') {
      actionDescription = `Scope IAM policy on ${sourceName} to grant least-privilege access instead of broad access to ${targetName}`;
      engineeringEffort = 'LOW';
      blastRadius = 'LOW';
    } else if (relationshipType === 'ASSUMES_ROLE') {
      actionDescription = `Restrict pod identity IAM role trust policy for ${sourceName} to prevent unauthorized role assumption`;
      engineeringEffort = 'LOW';
      blastRadius = 'LOW';
    } else if (relationshipType === 'EXPOSES_HTTP') {
      actionDescription = `Restrict public exposure on ${targetName} via WAF, security groups, or internal VPC routing`;
      engineeringEffort = 'MEDIUM';
      blastRadius = 'HIGH';
    } else if (relationshipType === 'ROUTES_TO') {
      actionDescription = `Implement internal service mesh authorization (mTLS) between ${sourceName} and ${targetName}`;
      engineeringEffort = 'MEDIUM';
      blastRadius = 'MEDIUM';
    }

    return { actionDescription, engineeringEffort, blastRadius };
  }

  public findOptimalChokePoints(
    graph: SecurityGraphEngine,
    attackPaths: AttackPath[]
  ): ChokePointCandidate[] {
    if (attackPaths.length === 0) return [];

    // Map each edge transition to the paths it appears in
    const edgePathMap = new Map<string, {
      edgeId: string;
      sourceAssetId: string;
      targetAssetId: string;
      relationshipType: RelationshipType;
      pathIds: Set<string>;
    }>();

    for (const path of attackPaths) {
      for (const step of path.steps) {
        const edgeKey = `${step.sourceAssetId}->${step.targetAssetId}:${step.relationshipType}`;
        if (!edgePathMap.has(edgeKey)) {
          const outgoing = graph.getOutgoingEdges(step.sourceAssetId);
          const matchedEdge = outgoing.find(
            (e) => e.targetAssetId === step.targetAssetId && e.type === step.relationshipType
          );

          edgePathMap.set(edgeKey, {
            edgeId: matchedEdge?.relationship.id || `edge-${step.sourceAssetId}-${step.targetAssetId}`,
            sourceAssetId: step.sourceAssetId,
            targetAssetId: step.targetAssetId,
            relationshipType: step.relationshipType,
            pathIds: new Set(),
          });
        }

        edgePathMap.get(edgeKey)!.pathIds.add(path.id);
      }
    }

    const totalPathsCount = attackPaths.length;
    const candidates: ChokePointCandidate[] = [];

    for (const item of edgePathMap.values()) {
      const pathsEliminatedCount = item.pathIds.size;
      const riskReductionPercentage = Math.round((pathsEliminatedCount / totalPathsCount) * 100);

      const sourceNode = graph.getNode(item.sourceAssetId);
      const targetNode = graph.getNode(item.targetAssetId);
      const sourceName = sourceNode?.asset.name ?? item.sourceAssetId;
      const targetName = targetNode?.asset.name ?? item.targetAssetId;

      const meta = this.getChokePointMetadata(item.relationshipType, sourceName, targetName);

      candidates.push({
        edgeId: item.edgeId,
        sourceAssetId: item.sourceAssetId,
        targetAssetId: item.targetAssetId,
        relationshipType: item.relationshipType,
        actionDescription: meta.actionDescription,
        pathsEliminatedCount,
        riskReductionPercentage,
        engineeringEffort: meta.engineeringEffort,
        blastRadius: meta.blastRadius,
      });
    }

    // Rank candidate choke points:
    // Priority: Highest Risk Reduction -> Lowest Blast Radius -> Lowest Engineering Effort
    candidates.sort((a, b) => {
      if (b.riskReductionPercentage !== a.riskReductionPercentage) {
        return b.riskReductionPercentage - a.riskReductionPercentage;
      }
      const blastOrder = { LOW: 1, MEDIUM: 2, HIGH: 3 };
      if (blastOrder[a.blastRadius] !== blastOrder[b.blastRadius]) {
        return blastOrder[a.blastRadius] - blastOrder[b.blastRadius];
      }
      const effortOrder = { LOW: 1, MEDIUM: 2, HIGH: 3 };
      return effortOrder[a.engineeringEffort] - effortOrder[b.engineeringEffort];
    });

    // Attach top choke point to each path
    if (candidates.length > 0) {
      const topChokePoint = candidates[0];
      for (const path of attackPaths) {
        path.recommendedChokePoint = topChokePoint;
      }
    }

    return candidates;
  }

  /**
   * Computes the global minimum cut-set using Dinic's residual flow algorithm.
   * Finds the minimal-capacity set of edges that completely severs all entry points
   * from reaching any target asset across the entire set of attack paths.
   */
  public findGlobalMinCut(
    graph: SecurityGraphEngine,
    attackPaths: AttackPath[],
    costStrategy: RemediationCostStrategy = new DefaultRemediationCostStrategy()
  ): GlobalCutSet {
    if (attackPaths.length === 0) {
      return {
        chokePoints: [],
        totalCapacityCost: 0,
        pathsEliminatedCount: 0,
        fullySevered: true,
      };
    }

    const SUPER_SOURCE = '__SUPER_SOURCE__';
    const SUPER_SINK = '__SUPER_SINK__';
    const flowNetwork = new FlowNetwork();

    const entryPointIds = new Set<string>();
    const targetAssetIds = new Set<string>();
    const uniqueEdges = new Map<string, {
      edgeId: string;
      sourceAssetId: string;
      targetAssetId: string;
      relationshipType: RelationshipType;
      actionDescription: string;
      blastRadius: 'LOW' | 'MEDIUM' | 'HIGH';
      engineeringEffort: 'LOW' | 'MEDIUM' | 'HIGH';
      pathIds: Set<string>;
    }>();

    for (const path of attackPaths) {
      entryPointIds.add(path.entryAssetId);
      targetAssetIds.add(path.targetAssetId);

      for (const step of path.steps) {
        const edgeKey = `${step.sourceAssetId}->${step.targetAssetId}:${step.relationshipType}`;
        if (!uniqueEdges.has(edgeKey)) {
          const outgoing = graph.getOutgoingEdges(step.sourceAssetId);
          const matched = outgoing.find(
            (e) => e.targetAssetId === step.targetAssetId && e.type === step.relationshipType
          );

          const sourceNode = graph.getNode(step.sourceAssetId);
          const targetNode = graph.getNode(step.targetAssetId);
          const sourceName = sourceNode?.asset.name ?? step.sourceAssetId;
          const targetName = targetNode?.asset.name ?? step.targetAssetId;
          const meta = this.getChokePointMetadata(step.relationshipType, sourceName, targetName);

          uniqueEdges.set(edgeKey, {
            edgeId: matched?.relationship.id || `edge-${step.sourceAssetId}-${step.targetAssetId}`,
            sourceAssetId: step.sourceAssetId,
            targetAssetId: step.targetAssetId,
            relationshipType: step.relationshipType,
            actionDescription: meta.actionDescription,
            blastRadius: meta.blastRadius,
            engineeringEffort: meta.engineeringEffort,
            pathIds: new Set(),
          });
        }
        uniqueEdges.get(edgeKey)!.pathIds.add(path.id);
      }
    }

    // Connect super-source to all entry points with Infinity capacity
    for (const entryId of entryPointIds) {
      flowNetwork.addEdge(SUPER_SOURCE, entryId, 1e9);
    }

    // Connect all targets to super-sink with Infinity capacity
    for (const targetId of targetAssetIds) {
      flowNetwork.addEdge(targetId, SUPER_SINK, 1e9);
    }

    // Add path edges with cost strategy capacity
    for (const edge of uniqueEdges.values()) {
      const cost = costStrategy.getEdgeCost({
        edgeId: edge.edgeId,
        sourceAssetId: edge.sourceAssetId,
        targetAssetId: edge.targetAssetId,
        relationshipType: edge.relationshipType,
        blastRadius: edge.blastRadius,
        engineeringEffort: edge.engineeringEffort,
      });

      flowNetwork.addEdge(
        edge.sourceAssetId,
        edge.targetAssetId,
        cost,
        {
          edgeId: edge.edgeId,
          relationshipType: edge.relationshipType,
          sourceAssetId: edge.sourceAssetId,
          targetAssetId: edge.targetAssetId,
          actionDescription: edge.actionDescription,
          blastRadius: edge.blastRadius,
          engineeringEffort: edge.engineeringEffort,
        },
        edge.edgeId
      );
    }

    // Dinic's algorithm
    flowNetwork.computeMaxFlow(SUPER_SOURCE, SUPER_SINK);
    const minCutFlowEdges = flowNetwork.findMinCut(SUPER_SOURCE);

    // Filter cut edges to only internal application/cloud edges
    const cutCandidates: ChokePointCandidate[] = [];
    let totalCost = 0;

    for (const cutEdge of minCutFlowEdges) {
      if (cutEdge.source === SUPER_SOURCE || cutEdge.target === SUPER_SINK) {
        continue;
      }

      if (cutEdge.originalEdge) {
        const edgeKey = `${cutEdge.originalEdge.sourceAssetId}->${cutEdge.originalEdge.targetAssetId}:${cutEdge.originalEdge.relationshipType}`;
        const meta = uniqueEdges.get(edgeKey);
        const pathsEliminated = meta?.pathIds.size ?? 1;

        cutCandidates.push({
          edgeId: cutEdge.originalEdge.edgeId,
          sourceAssetId: cutEdge.originalEdge.sourceAssetId,
          targetAssetId: cutEdge.originalEdge.targetAssetId,
          relationshipType: cutEdge.originalEdge.relationshipType,
          actionDescription: cutEdge.originalEdge.actionDescription,
          pathsEliminatedCount: pathsEliminated,
          riskReductionPercentage: Math.round((pathsEliminated / attackPaths.length) * 100),
          engineeringEffort: cutEdge.originalEdge.engineeringEffort,
          blastRadius: cutEdge.originalEdge.blastRadius,
        });

        totalCost += cutEdge.capacity;
      }
    }

    // Verify whether all attack paths are severed by this cut set
    const cutEdgeKeys = new Set(
      cutCandidates.map((c) => `${c.sourceAssetId}->${c.targetAssetId}:${c.relationshipType}`)
    );

    let eliminatedPathsCount = 0;
    for (const path of attackPaths) {
      const isSevered = path.steps.some((step) =>
        cutEdgeKeys.has(`${step.sourceAssetId}->${step.targetAssetId}:${step.relationshipType}`)
      );
      if (isSevered) {
        eliminatedPathsCount++;
      }
      path.recommendedCutSet = cutCandidates;
      if (cutCandidates.length > 0 && !path.recommendedChokePoint) {
        path.recommendedChokePoint = cutCandidates[0];
      }
    }

    return {
      chokePoints: cutCandidates,
      totalCapacityCost: totalCost,
      pathsEliminatedCount: eliminatedPathsCount,
      fullySevered: eliminatedPathsCount === attackPaths.length,
    };
  }
}
