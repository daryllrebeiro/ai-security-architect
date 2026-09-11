import { describe, it, expect } from 'vitest';
import type { Asset, Relationship } from '@ai-security-architect/core';
import {
  DataFlowExtractor,
  ClassificationPropagator,
  LineageTracer,
} from '../src/index.js';

describe('Task D.2 — Sensitive Data Flow & Lineage Tracing', () => {
  const tenantId = 'tenant-lineage-01';

  // 1. Data assets
  const customerDb: Asset = {
    id: 'asset-db-customer-vault',
    tenantId,
    type: 'DATABASE',
    name: 'customer-vault-db',
    environment: 'production',
    isPublic: false,
    isSensitiveData: true,
    criticality: 'CRITICAL',
    tags: ['database', 'contains-pii', 'gdpr'],
    metadata: {},
  };

  const sharedKafkaBroker: Asset = {
    id: 'asset-broker-kafka-shared',
    tenantId,
    type: 'MESSAGE_BROKER',
    name: 'corp-kafka-cluster',
    environment: 'production',
    isPublic: false,
    isSensitiveData: false,
    criticality: 'HIGH',
    tags: ['message-broker', 'kafka'],
    metadata: {},
  };

  const ingressOrderSvc: Asset = {
    id: 'asset-svc-order-ingress',
    tenantId,
    type: 'SERVICE',
    name: 'order-ingress-service',
    environment: 'production',
    isPublic: true,
    isSensitiveData: false,
    criticality: 'HIGH',
    tags: ['service', 'node'],
    metadata: {},
  };

  const downstreamNotificationSvc: Asset = {
    id: 'asset-svc-notification',
    tenantId,
    type: 'SERVICE',
    name: 'notification-service',
    environment: 'production',
    isPublic: false,
    isSensitiveData: false,
    criticality: 'MEDIUM',
    tags: ['service', 'python'],
    metadata: {},
  };

  const cloudWatchLogs: Asset = {
    id: 'asset-sink-cloudwatch',
    tenantId,
    type: 'LOG_AGGREGATOR',
    name: 'cloudwatch-prod-logs',
    environment: 'production',
    isPublic: false,
    isSensitiveData: false,
    criticality: 'LOW',
    tags: ['logging', 'sink'],
    metadata: {},
  };

  // Unrelated flow sharing the same Kafka broker
  const telemetryProducerSvc: Asset = {
    id: 'asset-svc-metrics-producer',
    tenantId,
    type: 'SERVICE',
    name: 'metrics-producer',
    environment: 'production',
    isPublic: false,
    isSensitiveData: false,
    criticality: 'LOW',
    tags: ['service'],
    metadata: {},
  };

  const telemetryConsumerSvc: Asset = {
    id: 'asset-svc-metrics-consumer',
    tenantId,
    type: 'SERVICE',
    name: 'metrics-consumer',
    environment: 'production',
    isPublic: false,
    isSensitiveData: false,
    criticality: 'LOW',
    tags: ['service'],
    metadata: {},
  };

  const assets: Asset[] = [
    customerDb,
    sharedKafkaBroker,
    ingressOrderSvc,
    downstreamNotificationSvc,
    cloudWatchLogs,
    telemetryProducerSvc,
    telemetryConsumerSvc,
  ];

  // Flow A (Sensitive): DB -> IngressSvc -> Kafka (topic: customer-events) -> NotificationSvc -> CloudWatch
  const flowAEdges: Relationship[] = [
    DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: customerDb.id,
      targetAssetId: ingressOrderSvc.id,
      operation: 'READ',
      dataType: 'PII',
      evidenceSnippet: 'SELECT * FROM customers',
    }),
    DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: ingressOrderSvc.id,
      targetAssetId: sharedKafkaBroker.id,
      operation: 'PUBLISH',
      bindingTopicOrChannel: 'customer-events',
      evidenceSnippet: "kafka.publish('customer-events', userRecord)",
    }),
    DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: sharedKafkaBroker.id,
      targetAssetId: downstreamNotificationSvc.id,
      operation: 'SUBSCRIBE',
      bindingTopicOrChannel: 'customer-events',
      evidenceSnippet: "kafka.subscribe('customer-events')",
    }),
    DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: downstreamNotificationSvc.id,
      targetAssetId: cloudWatchLogs.id,
      operation: 'LOG',
      evidenceSnippet: 'logger.info(customerPayload)',
    }),
  ];

  // Flow B (Non-sensitive): TelemetryProducer -> Kafka (topic: cpu-metrics) -> TelemetryConsumer
  const flowBEdges: Relationship[] = [
    DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: telemetryProducerSvc.id,
      targetAssetId: sharedKafkaBroker.id,
      operation: 'PUBLISH',
      bindingTopicOrChannel: 'cpu-metrics',
      evidenceSnippet: "kafka.publish('cpu-metrics', stats)",
    }),
    DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: sharedKafkaBroker.id,
      targetAssetId: telemetryConsumerSvc.id,
      operation: 'SUBSCRIBE',
      bindingTopicOrChannel: 'cpu-metrics',
      evidenceSnippet: "kafka.subscribe('cpu-metrics')",
    }),
  ];

  const allRelationships = [...flowAEdges, ...flowBEdges];

  it('performs forward trace identifying multi-hop downstream PII handlers and sinks', () => {
    const tracer = new LineageTracer(assets, allRelationships);
    const forwardResult = tracer.traceForward(customerDb.id);

    expect(forwardResult.sourceAsset.id).toBe(customerDb.id);
    expect(forwardResult.propagatedClassifications).toContain('contains-pii');

    const downstreamIds = forwardResult.downstreamAssets.map((n) => n.asset.id);
    // Notification service never touches DB directly, but must be identified as downstream PII handler
    expect(downstreamIds).toContain(ingressOrderSvc.id);
    expect(downstreamIds).toContain(sharedKafkaBroker.id);
    expect(downstreamIds).toContain(downstreamNotificationSvc.id);
    expect(downstreamIds).toContain(cloudWatchLogs.id);

    // Verify inherited classifications on notification service
    const notifNode = forwardResult.downstreamAssets.find((n) => n.asset.id === downstreamNotificationSvc.id);
    expect(notifNode?.inheritedClassifications).toContain('contains-pii');
    expect(notifNode?.inheritedClassifications).toContain('gdpr');
    expect(notifNode?.distanceFromSource).toBeGreaterThanOrEqual(3);
  });

  it('performs reverse trace from sink back to originating sensitive data source', () => {
    const tracer = new LineageTracer(assets, allRelationships);
    const reverseResult = tracer.traceReverse(cloudWatchLogs.id);

    expect(reverseResult.targetAsset.id).toBe(cloudWatchLogs.id);
    const upstreamIds = reverseResult.upstreamSources.map((n) => n.asset.id);
    expect(upstreamIds).toContain(customerDb.id);
    expect(reverseResult.handledClassifications).toContain('contains-pii');
    expect(reverseResult.handledClassifications).toContain('gdpr');

    // Confirm path has 4 hops: DB -> Ingress -> Kafka -> Notification -> CloudWatch
    const longestPath = reverseResult.allPaths.reduce((prev, curr) => (curr.hopsCount > prev.hopsCount ? curr : prev));
    expect(longestPath.hopsCount).toBe(4);
    expect(longestPath.nodes[0].id).toBe(customerDb.id);
    expect(longestPath.nodes[4].id).toBe(cloudWatchLogs.id);
  });

  it('strictly isolates independent flows sharing generic infrastructure with zero false propagation', () => {
    const tracer = new LineageTracer(assets, allRelationships);
    const forwardResult = tracer.traceForward(customerDb.id);

    const downstreamIds = forwardResult.downstreamAssets.map((n) => n.asset.id);
    // Flow B assets share the Kafka broker, but are on 'cpu-metrics', NOT 'customer-events'
    expect(downstreamIds).not.toContain(telemetryConsumerSvc.id);
    expect(downstreamIds).not.toContain(telemetryProducerSvc.id);

    // Propagate all and verify TelemetryConsumer has NO inherited PII tags
    const assetMap = new Map(assets.map((a) => [a.id, a]));
    const lineageMap = ClassificationPropagator.propagate(assetMap, allRelationships);
    const telemetryNode = lineageMap.get(telemetryConsumerSvc.id);

    expect(telemetryNode?.inheritedClassifications).toHaveLength(0);
    expect(telemetryNode?.inheritedClassifications).not.toContain('contains-pii');
  });

  it('protects against infinite loops in cyclic data flows', () => {
    // Service A <-> Service B cycle
    const cyclicEdge1 = DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: ingressOrderSvc.id,
      targetAssetId: downstreamNotificationSvc.id,
      operation: 'WRITE',
    });
    const cyclicEdge2 = DataFlowExtractor.createDataFlowEdge(tenantId, {
      sourceAssetId: downstreamNotificationSvc.id,
      targetAssetId: ingressOrderSvc.id,
      operation: 'WRITE',
    });

    const cyclicRelationships = [
      DataFlowExtractor.createDataFlowEdge(tenantId, {
        sourceAssetId: customerDb.id,
        targetAssetId: ingressOrderSvc.id,
        operation: 'READ',
      }),
      cyclicEdge1,
      cyclicEdge2,
    ];

    const tracer = new LineageTracer([customerDb, ingressOrderSvc, downstreamNotificationSvc], cyclicRelationships);
    // Should terminate gracefully and quickly
    const result = tracer.traceForward(customerDb.id, 5);
    expect(result.downstreamAssets).toHaveLength(2);
  });
});
