import React, { useState, useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
} from '@xyflow/react';
import { Header } from './components/Header.js';
import { AttackPathDrawer } from './components/AttackPathDrawer.js';
import { NodeDetailModal } from './components/NodeDetailModal.js';
import { nodeTypes } from './components/CustomNodes.js';
import { convertToReactFlowElements } from './utils/graph-converter.js';
import {
  GOLDEN_FIXTURE_NODES,
  GOLDEN_FIXTURE_EDGES,
  GOLDEN_FIXTURE_ATTACK_PATH,
} from './mockData.js';
import type { GraphNode } from '@ai-security-architect/graph';

export const App: React.FC = () => {
  const [nodesData] = useState<GraphNode[]>(GOLDEN_FIXTURE_NODES);
  const [edgesData] = useState(GOLDEN_FIXTURE_EDGES);
  const [attackPaths] = useState([GOLDEN_FIXTURE_ATTACK_PATH]);

  const [selectedPathId, setSelectedPathId] = useState<string>('path-001');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isRemediationSimulated, setIsRemediationSimulated] = useState(false);

  const activeAttackPath = useMemo(() => {
    if (isRemediationSimulated) return undefined;
    return attackPaths.find((p) => p.id === selectedPathId) || attackPaths[0];
  }, [attackPaths, selectedPathId, isRemediationSimulated]);

  const severedEdgeId = useMemo(() => {
    return isRemediationSimulated
      ? attackPaths[0]?.recommendedChokePoint?.edgeId
      : undefined;
  }, [isRemediationSimulated, attackPaths]);

  // Convert to React Flow elements
  const { initialFlowNodes, initialFlowEdges } = useMemo(() => {
    const { flowNodes, flowEdges } = convertToReactFlowElements(
      nodesData,
      edgesData,
      activeAttackPath,
      severedEdgeId
    );
    return { initialFlowNodes: flowNodes, initialFlowEdges: flowEdges };
  }, [nodesData, edgesData, activeAttackPath, severedEdgeId]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialFlowNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialFlowEdges);

  // Update elements when active attack path or simulated remediation changes
  React.useEffect(() => {
    const { flowNodes, flowEdges } = convertToReactFlowElements(
      nodesData,
      edgesData,
      activeAttackPath,
      severedEdgeId
    );
    setNodes(flowNodes);
    setEdges(flowEdges);
  }, [nodesData, edgesData, activeAttackPath, severedEdgeId, setNodes, setEdges]);

  // Filter nodes based on search query
  const filteredNodes = useMemo(() => {
    if (!searchQuery.trim()) return nodes;
    const query = searchQuery.toLowerCase();
    return nodes.map((node) => {
      const name = (node.data as any).asset?.name?.toLowerCase() || '';
      const type = (node.data as any).asset?.type?.toLowerCase() || '';
      const isMatch = name.includes(query) || type.includes(query);
      return {
        ...node,
        style: {
          ...node.style,
          opacity: isMatch ? 1.0 : 0.25,
        },
      };
    });
  }, [nodes, searchQuery]);

  const selectedGraphNode = useMemo(() => {
    if (!selectedNodeId) return undefined;
    return nodesData.find((n) => n.asset.id === selectedNodeId);
  }, [nodesData, selectedNodeId]);

  const handleNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNodeId(node.id);
  }, []);

  const handleResetGraph = useCallback(() => {
    setIsRemediationSimulated(false);
    setSelectedNodeId(null);
    setSearchQuery('');
  }, []);

  const highestRisk = isRemediationSimulated ? 0.0 : activeAttackPath?.riskScore.totalRisk || 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', width: '100vw', height: '100vh' }}>
      <Header
        totalAssets={nodesData.length}
        totalPaths={isRemediationSimulated ? 0 : attackPaths.length}
        highestRiskScore={highestRisk}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onResetGraph={handleResetGraph}
      />

      <div style={{ display: 'flex', flex: 1, position: 'relative', overflow: 'hidden' }}>
        {/* React Flow Canvas */}
        <div style={{ flex: 1, height: '100%', position: 'relative' }}>
          <ReactFlow
            nodes={filteredNodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
            maxZoom={2.0}
            defaultViewport={{ x: 50, y: 50, zoom: 0.85 }}
          >
            <Background color="#1e293b" gap={20} size={1.5} />
            <Controls position="bottom-left" />
            <MiniMap
              nodeColor={(n) => {
                if ((n.data as any).isCrownJewel) return '#ec4899';
                if ((n.data as any).isOnAttackPath) return '#ef4444';
                return '#38bdf8';
              }}
              style={{
                backgroundColor: '#0f172a',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: 8,
              }}
              position="bottom-right"
            />
          </ReactFlow>

          {/* Remediation Banner Overlay */}
          {isRemediationSimulated && (
            <div
              style={{
                position: 'absolute',
                top: 20,
                left: '50%',
                transform: 'translateX(-50%)',
                background: 'rgba(16, 185, 129, 0.9)',
                backdropFilter: 'blur(8px)',
                border: '1px solid #10b981',
                borderRadius: 8,
                padding: '10px 20px',
                color: '#ffffff',
                fontSize: 13,
                fontWeight: 700,
                boxShadow: '0 8px 32px rgba(16, 185, 129, 0.4)',
                zIndex: 40,
                display: 'flex',
                alignItems: 'center',
                gap: 10,
              }}
            >
              <span>🛡️ Choke Point Severed: Attack Path Eliminated (Risk Score: 0.0)</span>
              <button
                onClick={() => setIsRemediationSimulated(false)}
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  border: 'none',
                  color: '#ffffff',
                  padding: '4px 8px',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                Revert
              </button>
            </div>
          )}
        </div>

        {/* Attack Path Drawer on the Right */}
        <AttackPathDrawer
          attackPaths={attackPaths}
          selectedPathId={selectedPathId}
          onSelectPath={setSelectedPathId}
          isRemediationSimulated={isRemediationSimulated}
          onToggleSimulateRemediation={() => setIsRemediationSimulated(!isRemediationSimulated)}
          onSelectStepAsset={(assetId) => setSelectedNodeId(assetId)}
        />

        {/* Slide-over Asset Detail Inspector */}
        <NodeDetailModal node={selectedGraphNode} onClose={() => setSelectedNodeId(null)} />
      </div>
    </div>
  );
};
