import type { Relationship } from '@ai-security-architect/core';
import type { DataBindingSpec } from './types.js';

export class DataFlowExtractor {
  public static createDataFlowEdge(
    tenantId: string,
    binding: DataBindingSpec
  ): Relationship {
    const topicKey = binding.bindingTopicOrChannel ? `-${binding.bindingTopicOrChannel.replace(/[^a-zA-Z0-9_-]/g, '_')}` : '';
    const relId = `rel-dataflow-${binding.sourceAssetId}-${binding.targetAssetId}${topicKey}`;

    return {
      id: relId,
      tenantId,
      sourceAssetId: binding.sourceAssetId,
      targetAssetId: binding.targetAssetId,
      type: 'DATA_FLOW',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {
        dataType: binding.dataType,
        bindingTopicOrChannel: binding.bindingTopicOrChannel,
        operation: binding.operation,
        evidenceSnippet: binding.evidenceSnippet,
      },
    };
  }

  public static inferCodeBindings(
    sourceCode: string,
    serviceAssetId: string,
    knownAssets: { id: string; name: string; type: string }[]
  ): DataBindingSpec[] {
    const bindings: DataBindingSpec[] = [];

    // 1. Topic publish / subscribe bindings
    // e.g. kafka.publish('customer-events', data) or producer.send({ topic: 'customer-events' })
    const publishRegex = /(?:publish|send|emit)\s*\(\s*['"]([^'"]+)['"]/g;
    let match: RegExpExecArray | null;
    while ((match = publishRegex.exec(sourceCode)) !== null) {
      const topicName = match[1];
      const targetBroker = knownAssets.find(
        (a) => a.type === 'QUEUE' || a.type === 'TOPIC' || a.type === 'MESSAGE_BROKER' || a.name.includes(topicName)
      );
      if (targetBroker) {
        bindings.push({
          sourceAssetId: serviceAssetId,
          targetAssetId: targetBroker.id,
          operation: 'PUBLISH',
          bindingTopicOrChannel: topicName,
          evidenceSnippet: match[0],
        });
      }
    }

    // e.g. consumer.subscribe('customer-events') or on('customer-events')
    const subscribeRegex = /(?:subscribe|consume|on)\s*\(\s*['"]([^'"]+)['"]/g;
    while ((match = subscribeRegex.exec(sourceCode)) !== null) {
      const topicName = match[1];
      const sourceBroker = knownAssets.find(
        (a) => a.type === 'QUEUE' || a.type === 'TOPIC' || a.type === 'MESSAGE_BROKER' || a.name.includes(topicName)
      );
      if (sourceBroker) {
        bindings.push({
          sourceAssetId: sourceBroker.id,
          targetAssetId: serviceAssetId,
          operation: 'SUBSCRIBE',
          bindingTopicOrChannel: topicName,
          evidenceSnippet: match[0],
        });
      }
    }

    // 2. ORM/Database direct calls
    // e.g. db.query('SELECT * FROM users') or s3.getObject({ Bucket: 'customer-pii-vault' })
    for (const asset of knownAssets) {
      if (asset.type === 'DATABASE' || asset.type === 'BUCKET' || asset.type === 'SECRET') {
        const assetNamePattern = new RegExp(`['"]${asset.name}['"]|\\b${asset.name}\\b`, 'i');
        if (assetNamePattern.test(sourceCode)) {
          const isWrite = /insert|update|putobject|write|save/i.test(sourceCode);
          if (isWrite) {
            bindings.push({
              sourceAssetId: serviceAssetId,
              targetAssetId: asset.id,
              operation: 'WRITE',
              evidenceSnippet: `Direct reference to ${asset.name}`,
            });
          } else {
            bindings.push({
              sourceAssetId: asset.id,
              targetAssetId: serviceAssetId,
              operation: 'READ',
              evidenceSnippet: `Direct reference to ${asset.name}`,
            });
          }
        }
      }
    }

    // 3. Log aggregator shipping
    // e.g. logger.info(data) or datadog.send(...)
    const logAggregator = knownAssets.find(
      (a) => a.type === 'LOG_AGGREGATOR' || a.name.includes('datadog') || a.name.includes('cloudwatch') || a.name.includes('logger')
    );
    if (logAggregator && /(?:logger\.(?:info|debug|warn|error)|console\.log|datadogLogs\.log)/.test(sourceCode)) {
      bindings.push({
        sourceAssetId: serviceAssetId,
        targetAssetId: logAggregator.id,
        operation: 'LOG',
        evidenceSnippet: 'logger invocation shipping to telemetry sink',
      });
    }

    return bindings;
  }
}
