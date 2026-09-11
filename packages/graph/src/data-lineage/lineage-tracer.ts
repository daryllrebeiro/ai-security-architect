import type { Asset, Relationship } from '@ai-security-architect/core';
import { ClassificationPropagator } from './classification-propagator.js';
import type {
  ForwardTraceResult,
  ReverseTraceResult,
  DataLineageNode,
  DataLineagePath,
} from './types.js';

export class LineageTracer {
  private readonly assets: Map<string, Asset>;
  private readonly relationships: Relationship[];
  private readonly lineageMap: Map<string, DataLineageNode>;

  constructor(assets: Asset[], relationships: Relationship[]) {
    this.assets = new Map(assets.map((a) => [a.id, a]));
    this.relationships = relationships;
    this.lineageMap = ClassificationPropagator.propagate(this.assets, this.relationships);
  }

  public traceForward(sourceAssetId: string, maxHops: number = 10): ForwardTraceResult {
    const source = this.assets.get(sourceAssetId);
    if (!source) {
      throw new Error(`Asset not found: ${sourceAssetId}`);
    }

    const sourceClassifications = ClassificationPropagator.extractSensitivityTags(source);
    const downstreamAssets: DataLineageNode[] = [];
    const allPaths: DataLineagePath[] = [];

    // Depth-first / BFS path finder along DATA_FLOW edges
    const pathsQueue: Array<{
      currentId: string;
      pathNodes: Asset[];
      pathEdges: Relationship[];
      activeTopic?: string;
    }> = [
      {
        currentId: sourceAssetId,
        pathNodes: [source],
        pathEdges: [],
      },
    ];

    const visitedSet = new Set<string>();

    while (pathsQueue.length > 0) {
      const { currentId, pathNodes, pathEdges, activeTopic } = pathsQueue.shift()!;
      if (pathNodes.length - 1 >= maxHops) continue;

      const outgoing = this.relationships.filter(
        (r) => r.type === 'DATA_FLOW' && r.sourceAssetId === currentId
      );

      for (const edge of outgoing) {
        const target = this.assets.get(edge.targetAssetId);
        if (!target) continue;

        const edgeTopic = edge.metadata?.bindingTopicOrChannel as string | undefined;

        // Broker topic isolation
        const currentAsset = this.assets.get(currentId);
        const isGenericBroker =
          currentAsset?.type === 'QUEUE' ||
          currentAsset?.type === 'TOPIC' ||
          currentAsset?.type === 'MESSAGE_BROKER';

        if (isGenericBroker && activeTopic && edgeTopic && edgeTopic !== activeTopic) {
          continue; // skip disconnected topic
        }

        const effectiveTopic = edgeTopic ?? activeTopic;

        // Cycle check within current path
        if (pathNodes.some((n) => n.id === target.id)) {
          continue;
        }

        const nextNodes = [...pathNodes, target];
        const nextEdges = [...pathEdges, edge];

        allPaths.push({
          nodes: nextNodes,
          relationships: nextEdges,
          classifications: sourceClassifications,
          hopsCount: nextEdges.length,
        });

        if (!visitedSet.has(target.id)) {
          visitedSet.add(target.id);
          const lineageNode = this.lineageMap.get(target.id) ?? {
            asset: target,
            inheritedClassifications: sourceClassifications,
            distanceFromSource: nextEdges.length,
            originatingSources: [sourceAssetId],
          };
          downstreamAssets.push(lineageNode);
        }

        pathsQueue.push({
          currentId: target.id,
          pathNodes: nextNodes,
          pathEdges: nextEdges,
          activeTopic: effectiveTopic,
        });
      }
    }

    return {
      sourceAsset: source,
      downstreamAssets,
      allPaths,
      propagatedClassifications: sourceClassifications,
    };
  }

  public traceReverse(targetAssetId: string, maxHops: number = 10): ReverseTraceResult {
    const target = this.assets.get(targetAssetId);
    if (!target) {
      throw new Error(`Asset not found: ${targetAssetId}`);
    }

    const upstreamSources: DataLineageNode[] = [];
    const allPaths: DataLineagePath[] = [];
    const handledClassifications = new Set<string>();

    const pathsQueue: Array<{
      currentId: string;
      pathNodes: Asset[];
      pathEdges: Relationship[];
      activeTopic?: string;
    }> = [
      {
        currentId: targetAssetId,
        pathNodes: [target],
        pathEdges: [],
      },
    ];

    const visitedSet = new Set<string>();

    while (pathsQueue.length > 0) {
      const { currentId, pathNodes, pathEdges, activeTopic } = pathsQueue.shift()!;
      if (pathNodes.length - 1 >= maxHops) continue;

      const incoming = this.relationships.filter(
        (r) => r.type === 'DATA_FLOW' && r.targetAssetId === currentId
      );

      for (const edge of incoming) {
        const source = this.assets.get(edge.sourceAssetId);
        if (!source) continue;

        const edgeTopic = edge.metadata?.bindingTopicOrChannel as string | undefined;

        // Broker topic isolation
        const currentAsset = this.assets.get(currentId);
        const isGenericBroker =
          currentAsset?.type === 'QUEUE' ||
          currentAsset?.type === 'TOPIC' ||
          currentAsset?.type === 'MESSAGE_BROKER';

        if (isGenericBroker && activeTopic && edgeTopic && edgeTopic !== activeTopic) {
          continue;
        }

        const effectiveTopic = edgeTopic ?? activeTopic;

        // Cycle check
        if (pathNodes.some((n) => n.id === source.id)) {
          continue;
        }

        const nextNodes = [source, ...pathNodes];
        const nextEdges = [edge, ...pathEdges];

        const sourceTags = ClassificationPropagator.extractSensitivityTags(source);
        for (const t of sourceTags) {
          handledClassifications.add(t);
        }

        allPaths.push({
          nodes: nextNodes,
          relationships: nextEdges,
          classifications: sourceTags,
          hopsCount: nextEdges.length,
        });

        if (!visitedSet.has(source.id)) {
          visitedSet.add(source.id);
          const lineageNode = this.lineageMap.get(source.id) ?? {
            asset: source,
            inheritedClassifications: sourceTags,
            distanceFromSource: nextEdges.length,
            originatingSources: [source.id],
          };
          upstreamSources.push(lineageNode);
        }

        pathsQueue.push({
          currentId: source.id,
          pathNodes: nextNodes,
          pathEdges: nextEdges,
          activeTopic: effectiveTopic,
        });
      }
    }

    return {
      targetAsset: target,
      upstreamSources,
      allPaths,
      handledClassifications: Array.from(handledClassifications),
    };
  }
}
