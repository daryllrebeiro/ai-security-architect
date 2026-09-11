import type { Asset, Relationship } from '@ai-security-architect/core';
import type { DataLineageNode } from './types.js';

export interface PropagationOptions {
  maxDepth?: number;
  sensitivityTagPrefixes?: string[];
}

export class ClassificationPropagator {
  private static readonly DEFAULT_SENSITIVITY_TAGS = [
    'contains-pii',
    'contains-payment-data',
    'sensitive-data',
    'pci-dss',
    'hipaa',
    'gdpr',
  ];

  public static extractSensitivityTags(asset: Asset, customPrefixes?: string[]): string[] {
    const prefixes = customPrefixes ?? this.DEFAULT_SENSITIVITY_TAGS;
    const directTags = asset.tags.filter((t) =>
      prefixes.some((prefix) => t.toLowerCase().includes(prefix.toLowerCase()))
    );

    if (asset.isSensitiveData && !directTags.includes('sensitive-data')) {
      directTags.push('sensitive-data');
    }

    return Array.from(new Set(directTags));
  }

  public static propagate(
    assets: Map<string, Asset>,
    relationships: Relationship[],
    options: PropagationOptions = {}
  ): Map<string, DataLineageNode> {
    const maxDepth = options.maxDepth ?? 10;
    const lineageMap = new Map<string, DataLineageNode>();

    // Initialize all assets in the lineage map
    for (const [id, asset] of assets.entries()) {
      const initialSensitivities = this.extractSensitivityTags(asset, options.sensitivityTagPrefixes);
      lineageMap.set(id, {
        asset,
        inheritedClassifications: [...initialSensitivities],
        distanceFromSource: 0,
        originatingSources: initialSensitivities.length > 0 ? [id] : [],
      });
    }

    // Index DATA_FLOW edges by source
    const dataFlowsBySource = new Map<string, Relationship[]>();
    for (const rel of relationships) {
      if (rel.type === 'DATA_FLOW') {
        const list = dataFlowsBySource.get(rel.sourceAssetId) ?? [];
        list.push(rel);
        dataFlowsBySource.set(rel.sourceAssetId, list);
      }
    }

    // Seed BFS queue with initially sensitive data-bearing assets
    const queue: Array<{
      assetId: string;
      classifications: string[];
      depth: number;
      originatingSource: string;
      activeTopicOrChannel?: string;
    }> = [];

    for (const [id, node] of lineageMap.entries()) {
      if (node.inheritedClassifications.length > 0) {
        queue.push({
          assetId: id,
          classifications: [...node.inheritedClassifications],
          depth: 0,
          originatingSource: id,
        });
      }
    }

    // Cycle & path tracking: (assetId + ':' + originatingSource + ':' + topic)
    const visitedTransitions = new Set<string>();

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.depth >= maxDepth) continue;

      const outgoingEdges = dataFlowsBySource.get(current.assetId) ?? [];

      for (const edge of outgoingEdges) {
        const targetAsset = assets.get(edge.targetAssetId);
        if (!targetAsset) continue;

        const edgeTopic = edge.metadata?.bindingTopicOrChannel as string | undefined;

        // TOPIC ISOLATION CHECK:
        // If current asset is a message broker/queue, only propagate if the outgoing edge
        // matches the incoming activeTopicOrChannel (or neither specifies a topic).
        const currentAsset = assets.get(current.assetId);
        const isGenericBroker =
          currentAsset?.type === 'QUEUE' ||
          currentAsset?.type === 'TOPIC' ||
          currentAsset?.type === 'MESSAGE_BROKER';

        if (isGenericBroker && current.activeTopicOrChannel && edgeTopic) {
          if (edgeTopic !== current.activeTopicOrChannel) {
            // Disconnected flow on same broker! Do not leak!
            continue;
          }
        }

        const effectiveTopic = edgeTopic ?? current.activeTopicOrChannel;
        const transitionKey = `${current.assetId}->${edge.targetAssetId}:${current.originatingSource}:${effectiveTopic ?? '*'}`;

        if (visitedTransitions.has(transitionKey)) {
          continue; // Cycle protection
        }
        visitedTransitions.add(transitionKey);

        const targetNode = lineageMap.get(edge.targetAssetId)!;

        // Add newly inherited classifications
        let changed = false;
        for (const cls of current.classifications) {
          if (!targetNode.inheritedClassifications.includes(cls)) {
            targetNode.inheritedClassifications.push(cls);
            changed = true;
          }
        }
        if (!targetNode.originatingSources.includes(current.originatingSource)) {
          targetNode.originatingSources.push(current.originatingSource);
          changed = true;
        }
        targetNode.distanceFromSource = Math.max(targetNode.distanceFromSource, current.depth + 1);

        // Continue traversal
        queue.push({
          assetId: edge.targetAssetId,
          classifications: current.classifications,
          depth: current.depth + 1,
          originatingSource: current.originatingSource,
          activeTopicOrChannel: effectiveTopic,
        });
      }
    }

    return lineageMap;
  }
}
