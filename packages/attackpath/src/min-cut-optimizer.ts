import type { AttackPath, ChokePointCandidate, RelationshipType } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export class MinCutOptimizer {
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
          // Look up corresponding edge in graph
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

      let actionDescription = `Sever edge from ${sourceName} to ${targetName}`;
      let engineeringEffort: 'LOW' | 'MEDIUM' | 'HIGH' = 'MEDIUM';
      let blastRadius: 'LOW' | 'MEDIUM' | 'HIGH' = 'MEDIUM';

      if (item.relationshipType === 'CAN_READ' || item.relationshipType === 'CAN_WRITE') {
        actionDescription = `Scope IAM policy on ${sourceName} to grant least-privilege access instead of broad access to ${targetName}`;
        engineeringEffort = 'LOW';
        blastRadius = 'LOW';
      } else if (item.relationshipType === 'ASSUMES_ROLE') {
        actionDescription = `Restrict pod identity IAM role trust policy for ${sourceName} to prevent unauthorized role assumption`;
        engineeringEffort = 'LOW';
        blastRadius = 'LOW';
      } else if (item.relationshipType === 'EXPOSES_HTTP') {
        actionDescription = `Restrict public exposure on ${targetName} via WAF, security groups, or internal VPC routing`;
        engineeringEffort = 'MEDIUM';
        blastRadius = 'HIGH';
      } else if (item.relationshipType === 'ROUTES_TO') {
        actionDescription = `Implement internal service mesh authorization (mTLS) between ${sourceName} and ${targetName}`;
        engineeringEffort = 'MEDIUM';
        blastRadius = 'MEDIUM';
      }

      candidates.push({
        edgeId: item.edgeId,
        sourceAssetId: item.sourceAssetId,
        targetAssetId: item.targetAssetId,
        relationshipType: item.relationshipType,
        actionDescription,
        pathsEliminatedCount,
        riskReductionPercentage,
        engineeringEffort,
        blastRadius,
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
}
