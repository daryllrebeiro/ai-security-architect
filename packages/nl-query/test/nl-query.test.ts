import { describe, it, expect } from 'vitest';
import type { Asset } from '@ai-security-architect/core';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { LLMProvider } from '@ai-security-architect/ai';
import { NLQueryPipeline } from '../src/query-pipeline.js';
import { NLQueryTranslator } from '../src/translator.js';
import { GraphQueryExecutor } from '../src/graph-query-executor.js';
import { AnswerGrounder } from '../src/answer-grounder.js';

describe('Task A.2 — Natural-Language Query Interface over Security Graph', () => {
  const tenantId = 'tenant-nl-test';

  function createTestGraph(): SecurityGraphEngine {
    const graph = new SecurityGraphEngine(tenantId);

    const alb: Asset = {
      id: 'asset-alb',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'public-alb',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: {},
      tags: [],
    };

    const orderService: Asset = {
      id: 'asset-svc-order',
      tenantId,
      type: 'SERVICE',
      name: 'order-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const orderPod: Asset = {
      id: 'asset-pod-order',
      tenantId,
      type: 'POD',
      name: 'order-service-pod',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const iamRole: Asset = {
      id: 'asset-role-order',
      tenantId,
      type: 'IAM_ROLE',
      name: 'order-service-role',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const s3Bucket: Asset = {
      id: 'asset-s3-pii',
      tenantId,
      type: 'BUCKET',
      name: 'customer-pii-vault',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['contains-pii'],
    };

    graph.addAsset(alb);
    graph.addAsset(orderService);
    graph.addAsset(orderPod);
    graph.addAsset(iamRole);
    graph.addAsset(s3Bucket);

    graph.addRelationship({
      id: 'rel-alb-svc',
      tenantId,
      sourceAssetId: alb.id,
      targetAssetId: orderService.id,
      type: 'ROUTES_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-svc-pod',
      tenantId,
      sourceAssetId: orderService.id,
      targetAssetId: orderPod.id,
      type: 'DEPLOYED_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-pod-role',
      tenantId,
      sourceAssetId: orderPod.id,
      targetAssetId: iamRole.id,
      type: 'ASSUMES_ROLE',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-role-s3',
      tenantId,
      sourceAssetId: iamRole.id,
      targetAssetId: s3Bucket.id,
      type: 'CAN_READ',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    return graph;
  }

  it('translates and answers natural language query for public paths to PII bucket', async () => {
    const graph = createTestGraph();
    const pipeline = new NLQueryPipeline();

    const result = await pipeline.query(
      'Which public load balancer can reach our customer PII S3 bucket?',
      graph
    );

    expect(result.declined).toBe(false);
    expect(result.totalPathsFound).toBe(1);
    expect(result.matchedPaths[0].pathLength).toBe(4);
    expect(result.matchedPaths[0].nodeIds).toEqual([
      'asset-alb',
      'asset-svc-order',
      'asset-pod-order',
      'asset-role-order',
      'asset-s3-pii',
    ]);
    expect(result.matchedPaths[0].edgeIds).toEqual([
      'rel-alb-svc',
      'rel-svc-pod',
      'rel-pod-role',
      'rel-role-s3',
    ]);

    // Check markdown grounding
    expect(result.groundedAnswer).toContain('asset-alb');
    expect(result.groundedAnswer).toContain('asset-s3-pii');
    expect(result.groundedAnswer).toContain('rel-role-s3');
  });

  it('declines out-of-scope non-security requests gracefully', async () => {
    const graph = createTestGraph();
    const pipeline = new NLQueryPipeline();

    const result = await pipeline.query('Write a poem about the weather in Seattle', graph);

    expect(result.declined).toBe(true);
    expect(result.declinedReason).toBeDefined();
    expect(result.declinedReason).toContain('outside the scope');
    expect(result.totalPathsFound).toBe(0);
    expect(result.groundedAnswer).toContain('Request Declined');
  });

  it('executes query translated by an LLMProvider mock', async () => {
    const graph = createTestGraph();

    const mockLLM: LLMProvider = {
      name: 'mock-gemini',
      generateCompletion: async () => {
        return JSON.stringify({
          startNodeType: 'LOAD_BALANCER',
          targetNodeType: 'BUCKET',
          isSensitiveDataOnly: true,
          direction: 'FORWARD',
          maxHops: 5,
        });
      },
    };

    const pipeline = new NLQueryPipeline(mockLLM);
    const result = await pipeline.query('Find routes from load balancer to sensitive storage', graph);

    expect(result.declined).toBe(false);
    expect(result.totalPathsFound).toBe(1);
    expect(result.matchedPaths[0].steps.length).toBe(4);
  });

  it('strictly validates grounding: fails if any cited node is missing in graph', async () => {
    const graph = createTestGraph();
    const grounder = new AnswerGrounder();

    const fakePath = {
      pathLength: 1,
      nodeIds: ['asset-alb', 'asset-hallucinated-ghost-id'],
      edgeIds: ['fake-edge'],
      steps: [],
      explanation: 'fake explanation',
    };

    await expect(
      grounder.groundAnswer(
        'Find fake asset',
        { direction: 'FORWARD', maxHops: 5 },
        [fakePath as any],
        graph
      )
    ).rejects.toThrowError(/Strict Grounding Violation/);
  });

  it('returns clean message when no path matches query', async () => {
    const graph = createTestGraph();
    const pipeline = new NLQueryPipeline();

    const result = await pipeline.query(
      'Which public load balancer can reach our relational database?',
      graph
    );

    expect(result.declined).toBe(false);
    expect(result.totalPathsFound).toBe(0);
    expect(result.groundedAnswer).toContain('No architectural attack paths or access routes matching');
  });
});
