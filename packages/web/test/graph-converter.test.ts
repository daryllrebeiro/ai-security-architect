import { describe, it, expect } from 'vitest';
import { convertToReactFlowElements } from '../src/utils/graph-converter.js';
import {
  GOLDEN_FIXTURE_NODES,
  GOLDEN_FIXTURE_EDGES,
  GOLDEN_FIXTURE_ATTACK_PATH,
} from '../src/mockData.js';

describe('Phase 6 - React Flow Graph Converter & Visualizer Logic', () => {
  it('converts Security Graph into positioned React Flow nodes and edges', () => {
    const { flowNodes, flowEdges } = convertToReactFlowElements(
      GOLDEN_FIXTURE_NODES,
      GOLDEN_FIXTURE_EDGES,
      GOLDEN_FIXTURE_ATTACK_PATH
    );

    expect(flowNodes).toHaveLength(GOLDEN_FIXTURE_NODES.length);
    expect(flowEdges).toHaveLength(GOLDEN_FIXTURE_EDGES.length);

    // Verify Internet Node is placed in left column (x = 80)
    const internetNode = flowNodes.find((n) => n.id === 'asset-internet');
    expect(internetNode).toBeDefined();
    expect(internetNode?.position.x).toBe(80);
    expect((internetNode?.data as any).isEntryPoint).toBe(true);

    // Verify S3 Crown Jewel Node is placed in rightmost storage column
    const s3Node = flowNodes.find((n) => n.id.includes('customer-pii'));
    expect(s3Node).toBeDefined();
    expect(s3Node?.position.x).toBeGreaterThan(1000);
    expect((s3Node?.data as any).isCrownJewel).toBe(true);

    // Verify edges along the attack path are animated and highlighted
    const activeEdges = flowEdges.filter((e) => e.animated === true);
    expect(activeEdges.length).toBeGreaterThanOrEqual(4);
  });

  it('removes severed choke point edge when simulation is enabled', () => {
    const chokePointEdgeId = GOLDEN_FIXTURE_ATTACK_PATH.recommendedChokePoint?.edgeId;
    expect(chokePointEdgeId).toBeDefined();

    const { flowEdges } = convertToReactFlowElements(
      GOLDEN_FIXTURE_NODES,
      GOLDEN_FIXTURE_EDGES,
      GOLDEN_FIXTURE_ATTACK_PATH,
      chokePointEdgeId
    );

    expect(flowEdges.some((e) => e.id === chokePointEdgeId)).toBe(false);
    expect(flowEdges).toHaveLength(GOLDEN_FIXTURE_EDGES.length - 1);
  });
});
