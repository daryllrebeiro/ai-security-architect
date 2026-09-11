import { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { Asset, Relationship } from '@ai-security-architect/core';
import { CanonicalIdResolver } from './canonical-id-resolver.js';
import type {
  RepositoryGraphInput,
  FederationOptions,
  FederatedGraphResult,
} from './types.js';

export class FederationEngine {
  public federate(
    subgraphs: RepositoryGraphInput[],
    options: FederationOptions = {}
  ): FederatedGraphResult {
    const tenantId = options.tenantId ?? (subgraphs[0]?.graph.tenantId || 'federated-tenant');
    const federatedGraph = new SecurityGraphEngine(tenantId);

    const canonicalToUnifiedId = new Map<string, string>();
    const localToUnifiedId = new Map<string, string>(); // `${repo}:${localId}` -> unifiedId
    const nodeRepoMap = new Map<string, string>(); // unifiedId -> primary repository

    let mergedNodeCount = 0;
    const federatedRepos: string[] = [];

    // Phase 1: Determine Unified Node IDs
    for (const input of subgraphs) {
      const { repository, graph } = input;
      federatedRepos.push(repository);

      for (const node of graph.getAllNodes()) {
        const localKey = `${repository}:${node.asset.id}`;
        const canonicalId = CanonicalIdResolver.resolveCanonicalCloudId(node.asset);

        if (canonicalId) {
          const existingUnified = canonicalToUnifiedId.get(canonicalId);
          if (existingUnified) {
            localToUnifiedId.set(localKey, existingUnified);
          } else {
            canonicalToUnifiedId.set(canonicalId, node.asset.id);
            localToUnifiedId.set(localKey, node.asset.id);
          }
        } else {
          // Scoped strictly to repository to avoid collisions between non-canonical identical names
          const namespacedId = `${repository}__${node.asset.id}`;
          localToUnifiedId.set(localKey, namespacedId);
        }
      }
    }

    // Phase 2: Add and Merge Nodes in Federated Graph
    for (const input of subgraphs) {
      const { repository, graph } = input;

      for (const node of graph.getAllNodes()) {
        const localKey = `${repository}:${node.asset.id}`;
        const unifiedId = localToUnifiedId.get(localKey)!;

        if (federatedGraph.hasNode(unifiedId)) {
          // Node already exists via canonical cloud identity -> Merge properties
          const existing = federatedGraph.getNode(unifiedId)!;

          const mergedTags = Array.from(
            new Set([...(existing.asset.tags ?? []), ...(node.asset.tags ?? [])])
          );

          const existingRepos = (existing.asset.metadata?.federatedRepos as string[]) ?? [];
          const updatedRepos = Array.from(new Set([...existingRepos, repository]));

          const isSensitive = existing.asset.isSensitiveData || node.asset.isSensitiveData;
          const isPublic = existing.asset.isPublic || node.asset.isPublic;

          const criticalityRank: Record<string, number> = {
            CRITICAL: 4,
            HIGH: 3,
            MEDIUM: 2,
            LOW: 1,
          };
          const highestCriticality =
            (criticalityRank[node.asset.criticality] ?? 1) >
            (criticalityRank[existing.asset.criticality] ?? 1)
              ? node.asset.criticality
              : existing.asset.criticality;

          const updatedAsset: Asset = {
            ...existing.asset,
            criticality: highestCriticality,
            isSensitiveData: isSensitive,
            isPublic,
            tags: mergedTags,
            metadata: {
              ...existing.asset.metadata,
              ...node.asset.metadata,
              federatedRepos: updatedRepos,
            },
          };

          // Re-insert updated asset
          federatedGraph.removeNode(unifiedId);
          federatedGraph.addAsset(updatedAsset);
          mergedNodeCount++;
        } else {
          // First time seeing this unified node
          const unifiedAsset: Asset = {
            ...node.asset,
            id: unifiedId,
            tenantId,
            metadata: {
              ...node.asset.metadata,
              federatedRepos: [repository],
            },
          };
          federatedGraph.addAsset(unifiedAsset);
          nodeRepoMap.set(unifiedId, repository);
        }

        // Attach existing findings to the unified node
        for (const finding of node.findings) {
          federatedGraph.attachFinding({
            ...finding,
            assetId: unifiedId,
          });
        }
      }
    }

    // Phase 3: Remap and Add Edges
    let crossRepoEdgesCount = 0;
    const addedEdgeKeys = new Set<string>();

    for (const input of subgraphs) {
      const { repository, graph } = input;

      for (const edge of graph.getAllEdges()) {
        const unifiedSource = localToUnifiedId.get(`${repository}:${edge.sourceAssetId}`)!;
        const unifiedTarget = localToUnifiedId.get(`${repository}:${edge.targetAssetId}`)!;

        const edgeDedupeKey = `${unifiedSource}->${edge.type}->${unifiedTarget}`;
        if (addedEdgeKeys.has(edgeDedupeKey)) {
          continue;
        }

        const sourceRepo = nodeRepoMap.get(unifiedSource) ?? repository;
        const targetRepo = nodeRepoMap.get(unifiedTarget) ?? repository;
        const isCrossRepo = sourceRepo !== targetRepo;

        if (isCrossRepo) {
          crossRepoEdgesCount++;
        }

        const remappedRel: Relationship = {
          ...edge.relationship,
          id: `fed-${edge.relationship.id}`,
          tenantId,
          sourceAssetId: unifiedSource,
          targetAssetId: unifiedTarget,
          metadata: {
            ...edge.relationship.metadata,
            isCrossRepo,
            sourceRepo,
            targetRepo,
          },
        };

        federatedGraph.addRelationship(remappedRel);
        addedEdgeKeys.add(edgeDedupeKey);
      }
    }

    return {
      graph: federatedGraph,
      federatedRepos,
      mergedNodeCount,
      totalNodes: federatedGraph.getAllNodes().length,
      totalEdges: federatedGraph.getAllEdges().length,
      crossRepoEdgesCount,
    };
  }
}
