import type { Node, Edge } from '@xyflow/react';
import type { GraphNode, GraphEdge } from '@ai-security-architect/graph';
import type { AttackPath } from '@ai-security-architect/core';

export interface SecurityNodeData {
  asset: GraphNode['asset'];
  findings: GraphNode['findings'];
  inDegree: number;
  outDegree: number;
  isOnAttackPath: boolean;
  isEntryPoint: boolean;
  isCrownJewel: boolean;
  isChokePointSource: boolean;
}

export function convertToReactFlowElements(
  nodes: GraphNode[],
  edges: GraphEdge[],
  activeAttackPath?: AttackPath,
  severedEdgeId?: string
): { flowNodes: Node[]; flowEdges: Edge[] } {
  const activeEdgeKeys = new Set<string>();
  const activeNodeIds = new Set<string>();

  if (activeAttackPath) {
    activeNodeIds.add(activeAttackPath.entryAssetId);
    activeNodeIds.add(activeAttackPath.targetAssetId);

    for (const step of activeAttackPath.steps) {
      activeNodeIds.add(step.sourceAssetId);
      activeNodeIds.add(step.targetAssetId);
      activeEdgeKeys.add(`${step.sourceAssetId}->${step.targetAssetId}`);
    }
  }

  // Automatic topological layout columns based on layer hierarchy
  const layerWeights: Record<string, number> = {
    INTERNET: 0,
    LOAD_BALANCER: 1,
    SERVICE: 2,
    API_CONTROLLER: 2,
    ENDPOINT: 3,
    POD: 3,
    CONTAINER: 3,
    KUBERNETES_SERVICE: 2,
    KUBERNETES_SERVICE_ACCOUNT: 4,
    IAM_ROLE: 5,
    SERVICE_ACCOUNT: 4,
    BUCKET: 6,
    DATABASE: 6,
    SECRET: 6,
    DEPENDENCY: 2,
  };

  // Group nodes by layer for column positioning
  const layerGroups = new Map<number, GraphNode[]>();
  for (const node of nodes) {
    const layer = layerWeights[node.asset.type] ?? 3;
    if (!layerGroups.has(layer)) {
      layerGroups.set(layer, []);
    }
    layerGroups.get(layer)!.push(node);
  }

  const flowNodes: Node[] = [];
  const columnWidth = 280;
  const rowHeight = 160;

  for (const [layer, groupNodes] of layerGroups.entries()) {
    const xPos = 80 + layer * columnWidth;
    const startY = Math.max(80, 400 - (groupNodes.length * rowHeight) / 2);

    groupNodes.forEach((node, idx) => {
      const yPos = startY + idx * rowHeight;
      const isOnAttackPath = activeNodeIds.has(node.asset.id);
      const isEntryPoint = node.asset.type === 'INTERNET' || node.asset.isPublic;
      const isCrownJewel = node.asset.isSensitiveData || node.asset.criticality === 'CRITICAL';
      const isChokePointSource =
        activeAttackPath?.recommendedChokePoint?.sourceAssetId === node.asset.id;

      flowNodes.push({
        id: node.asset.id,
        type: 'securityAsset',
        position: { x: xPos, y: yPos },
        data: {
          asset: node.asset,
          findings: node.findings,
          inDegree: node.inDegree,
          outDegree: node.outDegree,
          isOnAttackPath,
          isEntryPoint,
          isCrownJewel,
          isChokePointSource,
        } as Record<string, unknown>,
      });
    });
  }

  // Convert Edges
  const flowEdges: Edge[] = [];

  for (const edge of edges) {
    // Skip severed edge if simulated
    if (severedEdgeId && edge.relationship.id === severedEdgeId) {
      continue;
    }

    const edgeKey = `${edge.sourceAssetId}->${edge.targetAssetId}`;
    const isOnPath = activeEdgeKeys.has(edgeKey);
    const isChokePoint = activeAttackPath?.recommendedChokePoint?.edgeId === edge.relationship.id;

    flowEdges.push({
      id: edge.relationship.id,
      source: edge.sourceAssetId,
      target: edge.targetAssetId,
      label: edge.type.replace(/_/g, ' '),
      animated: isOnPath,
      style: {
        stroke: isChokePoint
          ? '#f97316'
          : isOnPath
          ? '#ef4444'
          : '#475569',
        strokeWidth: isOnPath ? 3 : 1.5,
        strokeDasharray: isChokePoint ? '5,5' : undefined,
      },
      labelStyle: {
        fill: isOnPath ? '#f8fafc' : '#94a3b8',
        fontSize: 10,
        fontWeight: 600,
      },
      labelBgStyle: {
        fill: '#0f172a',
        fillOpacity: 0.85,
      },
      labelBgPadding: [6, 3],
      labelBgBorderRadius: 4,
    });
  }

  return { flowNodes, flowEdges };
}
