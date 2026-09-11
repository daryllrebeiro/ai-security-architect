import type { SecurityGraphEngine, GraphEdge } from '@ai-security-architect/graph';
import type { NLQueryDsl, GroundedPathResult, GroundedPathStep } from './dsl.js';

export class GraphQueryExecutor {
  public execute(dsl: NLQueryDsl, graph: SecurityGraphEngine): GroundedPathResult[] {
    if (dsl.declinedReason) {
      return [];
    }

    const allNodes = graph.getAllNodes();

    // 1. Identify start candidate nodes
    let startNodes = allNodes;

    if (dsl.startAssetId) {
      startNodes = startNodes.filter((n) => n.asset.id === dsl.startAssetId);
    }
    if (dsl.startAssetName) {
      const nameLower = dsl.startAssetName.toLowerCase();
      startNodes = startNodes.filter((n) => n.asset.name.toLowerCase().includes(nameLower));
    }
    if (dsl.startNodeType) {
      startNodes = startNodes.filter((n) => n.asset.type === dsl.startNodeType);
    }
    if (dsl.isPublicOnly) {
      startNodes = startNodes.filter((n) => n.asset.isPublic);
    }

    if (startNodes.length === 0) {
      // If specific public flag was set and no start type given, search all public assets
      if (dsl.isPublicOnly) {
        startNodes = allNodes.filter((n) => n.asset.isPublic);
      }
    }

    if (startNodes.length === 0) {
      return [];
    }

    // 2. Define target predicate
    const isTarget = (nodeId: string): boolean => {
      const node = graph.getNode(nodeId);
      if (!node) return false;

      let hasTargetConstraint = false;

      if (dsl.targetAssetId) {
        hasTargetConstraint = true;
        if (node.asset.id !== dsl.targetAssetId) return false;
      }
      if (dsl.targetNodeType) {
        hasTargetConstraint = true;
        if (node.asset.type !== dsl.targetNodeType) return false;
      }
      if (dsl.isSensitiveDataOnly) {
        hasTargetConstraint = true;
        if (!node.asset.isSensitiveData) return false;
      }
      if (dsl.targetTagFilters && dsl.targetTagFilters.length > 0) {
        hasTargetConstraint = true;
        const nodeTags = (node.asset.tags ?? []).map((t) => t.toLowerCase());
        const matchesAll = dsl.targetTagFilters.every((tag) =>
          nodeTags.some((nt) => nt.includes(tag.toLowerCase()))
        );
        if (!matchesAll) return false;
      }

      return hasTargetConstraint;
    };

    // 3. BFS search from each start node
    const maxHops = Math.min(dsl.maxHops ?? 5, 10);
    const matchedPaths: GroundedPathResult[] = [];
    const maxResults = 10;

    interface SearchState {
      currentId: string;
      visitedNodeIds: string[];
      steps: GroundedPathStep[];
    }

    for (const startNode of startNodes) {
      if (matchedPaths.length >= maxResults) break;

      const queue: SearchState[] = [
        {
          currentId: startNode.asset.id,
          visitedNodeIds: [startNode.asset.id],
          steps: [],
        },
      ];

      while (queue.length > 0) {
        if (matchedPaths.length >= maxResults) break;
        const current = queue.shift()!;

        // Check if current node is target (and not the start node itself)
        if (current.steps.length > 0 && isTarget(current.currentId)) {
          const explanation = current.steps
            .map((s) => `${s.sourceAssetName} [${s.sourceAssetId}] -(${s.relationshipType})-> ${s.targetAssetName} [${s.targetAssetId}]`)
            .join(' => ');

          matchedPaths.push({
            pathLength: current.steps.length,
            nodeIds: [...current.visitedNodeIds],
            edgeIds: current.steps.map((s) => s.relationshipId),
            steps: [...current.steps],
            explanation,
          });

          // Stop expanding this path further
          continue;
        }

        if (current.steps.length >= maxHops) {
          continue;
        }

        // Get edges based on direction
        let candidateEdges: GraphEdge[] = [];
        if (dsl.direction === 'REVERSE') {
          candidateEdges = graph.getIncomingEdges(current.currentId);
        } else if (dsl.direction === 'ANY') {
          candidateEdges = [
            ...graph.getOutgoingEdges(current.currentId),
            ...graph.getIncomingEdges(current.currentId),
          ];
        } else {
          // FORWARD
          candidateEdges = graph.getOutgoingEdges(current.currentId);
        }

        if (dsl.relationshipTypes && dsl.relationshipTypes.length > 0) {
          candidateEdges = candidateEdges.filter((e) =>
            dsl.relationshipTypes!.includes(e.relationship.type)
          );
        }

        for (const edge of candidateEdges) {
          const nextNodeId =
            dsl.direction === 'REVERSE'
              ? edge.relationship.sourceAssetId
              : edge.relationship.targetAssetId === current.currentId
                ? edge.relationship.sourceAssetId
                : edge.relationship.targetAssetId;

          if (current.visitedNodeIds.includes(nextNodeId)) {
            continue; // Cycle detection
          }

          const srcNode = graph.getNode(edge.relationship.sourceAssetId);
          const tgtNode = graph.getNode(edge.relationship.targetAssetId);

          if (!srcNode || !tgtNode) continue;

          const step: GroundedPathStep = {
            sourceAssetId: srcNode.asset.id,
            sourceAssetName: srcNode.asset.name,
            sourceAssetType: srcNode.asset.type,
            relationshipId: edge.relationship.id,
            relationshipType: edge.relationship.type,
            targetAssetId: tgtNode.asset.id,
            targetAssetName: tgtNode.asset.name,
            targetAssetType: tgtNode.asset.type,
          };

          queue.push({
            currentId: nextNodeId,
            visitedNodeIds: [...current.visitedNodeIds, nextNodeId],
            steps: [...current.steps, step],
          });
        }
      }
    }

    return matchedPaths;
  }
}
