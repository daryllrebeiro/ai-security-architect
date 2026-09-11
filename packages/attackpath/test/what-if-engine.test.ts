import { describe, expect, it } from 'vitest';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { Asset, Relationship } from '@ai-security-architect/core';
import { WhatIfEngine } from '../src/what-if/what-if-engine.js';
import type { WhatIfHypothesis } from '../src/what-if/types.js';

describe('What-If Remediation Sandbox Engine', () => {
  function buildDualPathGraph(): SecurityGraphEngine {
    const graph = new SecurityGraphEngine('test-tenant', { backend: 'memory' });

    const internet: Asset = {
      id: 'asset-internet',
      tenantId: 'test-tenant',
      name: 'Public Internet',
      type: 'INTERNET',
      criticality: 'LOW',
      environment: 'PRODUCTION',
      isPublic: true,
      isSensitiveData: false,
      metadata: {},
      tags: [],
    };

    const ec2Web: Asset = {
      id: 'asset-ec2-web',
      tenantId: 'test-tenant',
      name: 'EC2 Web Server',
      type: 'SERVICE',
      criticality: 'MEDIUM',
      environment: 'PRODUCTION',
      isPublic: false,
      isSensitiveData: false,
      metadata: {},
      tags: [],
    };

    const iamRole: Asset = {
      id: 'asset-iam-role',
      tenantId: 'test-tenant',
      name: 'DataReaderRole',
      type: 'IAM_ROLE',
      criticality: 'HIGH',
      environment: 'PRODUCTION',
      isPublic: false,
      isSensitiveData: false,
      metadata: {},
      tags: [],
    };

    const apiGateway: Asset = {
      id: 'asset-api-gateway',
      tenantId: 'test-tenant',
      name: 'API Gateway',
      type: 'LOAD_BALANCER',
      criticality: 'MEDIUM',
      environment: 'PRODUCTION',
      isPublic: true,
      isSensitiveData: false,
      metadata: {},
      tags: [],
    };

    const customerDb: Asset = {
      id: 'asset-customer-db',
      tenantId: 'test-tenant',
      name: 'Customer Database',
      type: 'DATABASE',
      criticality: 'CRITICAL',
      environment: 'PRODUCTION',
      isPublic: false,
      isSensitiveData: true,
      metadata: {},
      tags: [],
    };

    graph.addAsset(internet);
    graph.addAsset(ec2Web);
    graph.addAsset(iamRole);
    graph.addAsset(apiGateway);
    graph.addAsset(customerDb);

    // Path 1: Internet -> EC2 Web -> IAM Role -> Customer DB
    const rel1: Relationship = {
      id: 'rel-1',
      tenantId: 'test-tenant',
      sourceAssetId: internet.id,
      targetAssetId: ec2Web.id,
      type: 'EXPOSES_HTTP',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    };

    const rel2: Relationship = {
      id: 'rel-2',
      tenantId: 'test-tenant',
      sourceAssetId: ec2Web.id,
      targetAssetId: iamRole.id,
      type: 'ASSUMES_ROLE',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    };

    const rel3: Relationship = {
      id: 'rel-3',
      tenantId: 'test-tenant',
      sourceAssetId: iamRole.id,
      targetAssetId: customerDb.id,
      type: 'CAN_READ',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    };

    // Path 2: API Gateway -> Customer DB (API Gateway is also public entrypoint)
    const rel4: Relationship = {
      id: 'rel-4',
      tenantId: 'test-tenant',
      sourceAssetId: apiGateway.id,
      targetAssetId: customerDb.id,
      type: 'CAN_READ',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    };

    graph.addRelationship(rel1);
    graph.addRelationship(rel2);
    graph.addRelationship(rel3);
    graph.addRelationship(rel4);

    return graph;
  }

  it('evaluates hypothesis by severing an edge and calculating path and risk reduction', () => {
    const graph = buildDualPathGraph();
    const engine = new WhatIfEngine();

    const hypothesis: WhatIfHypothesis = {
      id: 'hyp-sever-role-assumption',
      action: 'SEVER_EDGE',
      target: {
        sourceAssetId: 'asset-ec2-web',
        targetAssetId: 'asset-iam-role',
        edgeType: 'ASSUMES_ROLE',
      },
      description: 'Revoke EC2 Web instance profile assumption of DataReaderRole',
    };

    const outcome = engine.evaluateHypothesis(graph, hypothesis);

    expect(outcome.baselinePathsCount).toBe(2);
    expect(outcome.remainingPathsCount).toBe(1);
    expect(outcome.closedPaths.length).toBe(1);
    expect(outcome.remainingPaths.length).toBe(1);

    // Closed path check
    expect(outcome.closedPaths[0].steps.some((s) => s.relationshipType === 'ASSUMES_ROLE')).toBe(true);
    expect(outcome.closedPaths[0].isWhatIf).toBe(true);
    expect(outcome.closedPaths[0].whatIfContext?.hypothesisId).toBe('hyp-sever-role-assumption');

    // Remaining path check
    expect(outcome.remainingPaths[0].entryAssetId).toBe('asset-api-gateway');
    expect(outcome.remainingPaths[0].isWhatIf).toBe(true);

    // Risk delta calculations
    expect(outcome.riskDelta.pathsReductionPct).toBe(50);
    expect(outcome.riskDelta.riskReductionPct).toBeGreaterThan(0);
    expect(outcome.isSimulatedOnly).toBe(true);
  });

  it('guarantees zero mutation to the underlying graph and persistent state', () => {
    const graph = buildDualPathGraph();
    const initialNodesCount = graph.getAllNodes().length;
    const initialEdgesCount = graph.getAllEdges().length;

    const engine = new WhatIfEngine();
    const hypothesis: WhatIfHypothesis = {
      id: 'hyp-remove-gateway',
      action: 'REMOVE_ASSET',
      target: {
        assetId: 'asset-api-gateway',
      },
      description: 'Decommission legacy API Gateway',
    };

    const outcome = engine.evaluateHypothesis(graph, hypothesis);

    expect(outcome.closedPaths.length).toBe(1);
    expect(outcome.remainingPathsCount).toBe(1);

    // The original graph MUST be completely untouched
    expect(graph.getAllNodes().length).toBe(initialNodesCount);
    expect(graph.getAllEdges().length).toBe(initialEdgesCount);
    expect(graph.hasNode('asset-api-gateway')).toBe(true);
    expect(graph.getEdge('rel-4')).toBeDefined();
  });

  it('handles permission restriction hypotheses across target relationships', () => {
    const graph = buildDualPathGraph();
    const engine = new WhatIfEngine();

    const hypothesis: WhatIfHypothesis = {
      id: 'hyp-restrict-can-read',
      action: 'RESTRICT_PERMISSION',
      target: {
        targetAssetId: 'asset-customer-db',
        edgeType: 'CAN_READ',
      },
      description: 'Apply strict egress filtering blocking all direct CAN_READ access to customer DB',
    };

    const outcome = engine.evaluateHypothesis(graph, hypothesis);

    expect(outcome.baselinePathsCount).toBe(2);
    expect(outcome.remainingPathsCount).toBe(0);
    expect(outcome.closedPaths.length).toBe(2);
    expect(outcome.riskDelta.pathsReductionPct).toBe(100);
  });
});
